import Foundation
import NetworkExtension

private final class ProxyFlow {
    let id: UInt64
    let flow: NEAppProxyFlow
    let endpoint: NWHostEndpoint
    var pending = Data()
    var reading = false
    var opened = false
    var closed = false
    var dns = false
    var dnsTCPBuffer = Data()
    var dnsRequestBuffer = Data()
    var incomingBeforeOpen: EngineEvent?
    var dnsQueries: [UInt16: (String, NWHostEndpoint)] = [:]
    var destinations: Set<String> = []
    init(id: UInt64, flow: NEAppProxyFlow, endpoint: NWHostEndpoint) { self.id = id; self.flow = flow; self.endpoint = endpoint }
}
private struct PendingResolution {
    let host: String
    let queryID: UInt16
    let resolver: String
    let deadline: Date
    let completion: (String?) -> Void
}
private final class ProxyContext {
    let engine: TunnelEngine
    let summary: ProfileSummary
    let policy: RoutingPolicy
    let cache: DomainCache
    var flows: [UInt64: ProxyFlow] = [:]
    var resolutions: [UInt64: PendingResolution] = [:]
    var diagnostics: [DiagnosticEntry] = []
    var nextID: UInt64 = 1
    var ready = false
    init(engine: TunnelEngine, summary: ProfileSummary, policy: RoutingPolicy, cache: DomainCache) { self.engine = engine; self.summary = summary; self.policy = policy; self.cache = cache }
    func allocateID() -> UInt64 { defer { nextID += 1 }; return nextID }
    func log(_ entry: DiagnosticEntry) { diagnostics.append(entry); if diagnostics.count > 100 { diagnostics.removeFirst(diagnostics.count - 100) } }
}

final class TransparentProxyProvider: NETransparentProxyProvider {
    private let lifecycle = DispatchQueue(label: "com.routebar.proxy.lifecycle")
    private let stateLock = NSLock()
    private var storedContext: ProxyContext?
    private var stopped = true
    private var retry = 0
    private var retryWork: DispatchWorkItem?
    private var pendingStart: ((Error?) -> Void)?
    private var pendingStop: (() -> Void)?
    private var settingsInFlight = false
    private var cleanupComplete = false
    // Transient start options only. Root system extensions cannot read the host user's Keychain.
    private var profileText: String?
    private var sessionCache = DomainCache()
    private var context: ProxyContext? { stateLock.lock(); defer { stateLock.unlock() }; return storedContext }
    private func replace(_ value: ProxyContext?) { stateLock.lock(); storedContext = value; stateLock.unlock() }
    private var ownIdentity: AppIdentity? { SigningIdentity.fromStaticURL(Bundle.main.bundleURL) }

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        lifecycle.async {
            guard self.stopped else { completionHandler(RouteBarError("網絡服務已啟動。")); return }
            guard let profile = options?["wireguardProfile"] as? String else { completionHandler(RouteBarError("請由 RouteBar 開啟連線，以安全傳入 VPN 設定。")); return }
            self.profileText = profile
            self.sessionCache = DomainCache()
            self.stopped = false; self.retry = 0; self.pendingStart = completionHandler
            self.establish(completion: { [weak self] error in
                guard let self else { return }
                if error != nil {
                    self.stopped = true; self.profileText = nil
                    if let old = self.context { self.replace(nil); old.engine.queue.async { old.engine.stop() } }
                }
                let pending = self.pendingStart; self.pendingStart = nil; pending?(error)
            })
        }
    }
    private func establish(completion: ((Error?) -> Void)? = nil) {
        dispatchPrecondition(condition: .onQueue(lifecycle))
        guard !stopped, !settingsInFlight else { return }
        do {
            guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                  config["profileID"] is String, let policyData = config["policy"] as? Data else { throw RouteBarError("缺少 VPN 設定。") }
            let policy = try CoreBridge.validate(JSONDecoder().decode(RoutingPolicy.self, from: policyData))
            guard policy.mode == "whitelist" else { throw RouteBarError("白名單服務收到錯誤模式。") }
            guard let profile = profileText else { throw RouteBarError("VPN 憑證已清除，請由 RouteBar 重新連線。") }
            let summary = try CoreBridge.inspect(profile)
            if policy.domains.contains(where: \.enabled) && summary.dns.isEmpty { throw RouteBarError("Domain 分流需要設定檔提供 DNS 位址。") }
            let engine = try TunnelEngine(profile: profile, raw: false)
            let ctx = ProxyContext(engine: engine, summary: summary, policy: policy, cache: sessionCache)
            replace(ctx)
            engine.onEvent = { [weak self, weak ctx] event in guard let self, let ctx else { return }; self.handle(event, in: ctx) }
            engine.onTick = { [weak self, weak ctx] in
                guard let self, let ctx else { return }
                for flow in Array(ctx.flows.values) where !flow.pending.isEmpty { self.flushTCP(flow, in: ctx) }
                for (id, resolution) in ctx.resolutions where resolution.deadline < Date() {
                    ctx.resolutions.removeValue(forKey: id); _ = rb_engine_close(ctx.engine.pointer, id); resolution.completion(nil)
                }
            }
            engine.onFailure = { [weak self, weak ctx] error in
                guard let self, let ctx, self.context === ctx else { return }
                ctx.ready = false; self.reasserting = true
                for flow in Array(ctx.flows.values) { self.finish(flow, in: ctx, error: error) }
                let pending = Array(ctx.resolutions.values); ctx.resolutions.removeAll(); pending.forEach { $0.completion(nil) }
                ctx.log(DiagnosticEntry(application: "RouteBar", destination: "VPN", route: "blocked", reason: error.localizedDescription))
                self.lifecycle.async { self.scheduleRetry() }
            }
            engine.start(summary: summary) { [weak self, weak ctx] error in
                guard let self, let ctx else { return }
                self.lifecycle.async {
                guard !self.stopped, self.context === ctx else { return }
                if let error { if let completion { completion(error) } else { self.scheduleRetry() }; return }
                let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: summary.endpointHost)
                var rules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)]
                // Destination-domain rules are required by Apple for matching DNS traffic.
                rules += policy.domains.filter(\.enabled).map { NENetworkRule(destinationHost: NWHostEndpoint(hostname: $0.domain, port: "0"), protocol: .any) }
                settings.includedNetworkRules = rules
                self.settingsInFlight = true
                self.setTunnelNetworkSettings(settings) { error in
                    self.lifecycle.async {
                    self.settingsInFlight = false
                    if self.stopped { self.completeStop(); return }
                    guard self.context === ctx else { return }
                    if let error {
                        engine.queue.async { engine.stop() }
                        if let completion { completion(error) } else { self.scheduleRetry() }; return
                    }
                    engine.queue.async {
                        guard self.context === ctx else { return }
                        ctx.ready = true
                        ctx.log(DiagnosticEntry(application: "RouteBar", destination: summary.endpointHost, route: "vpn", reason: "WireGuard 握手成功；白名單服務已啟用。"))
                        self.lifecycle.async {
                            guard !self.stopped, self.context === ctx else { return }
                            self.reasserting = false; self.retry = 0; completion?(nil)
                        }
                    }
                    }
                    }
                }
            }
        } catch { if let completion { completion(error) } else { scheduleRetry() } }
    }
    private func scheduleRetry() {
        dispatchPrecondition(condition: .onQueue(lifecycle))
        guard !stopped, retryWork == nil else { return }; retry += 1
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }; self.retryWork = nil
            if !self.stopped { self.establish() }
        }
        retryWork = work
        lifecycle.asyncAfter(deadline: .now() + min(pow(2, Double(min(retry, 5))), 30), execute: work)
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lifecycle.async {
            self.stopped = true; self.profileText = nil; self.retryWork?.cancel(); self.retryWork = nil
            self.pendingStop = completionHandler; self.cleanupComplete = false
            let pending = self.pendingStart; self.pendingStart = nil; pending?(RouteBarError("VPN 連線已取消。"))
            guard let ctx = self.context else { self.cleanupComplete = true; self.completeStop(); return }
            self.replace(nil)
            ctx.engine.queue.async {
                ctx.ready = false
                for flow in Array(ctx.flows.values) { self.finish(flow, in: ctx, error: RouteBarError("VPN 已停止。")) }
                let pending = Array(ctx.resolutions.values); ctx.resolutions.removeAll(); pending.forEach { $0.completion(nil) }
                ctx.engine.stop()
                self.lifecycle.async { self.cleanupComplete = true; self.completeStop() }
            }
        }
    }
    private func completeStop() {
        guard cleanupComplete, !settingsInFlight else { return }
        let pending = pendingStop; pendingStop = nil; pending?()
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow, let endpoint = tcp.remoteEndpoint as? NWHostEndpoint else { return false }
        return accept(flow, endpoint: endpoint)
    }
    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        guard let endpoint = remoteEndpoint as? NWHostEndpoint else { return false }
        return accept(flow, endpoint: endpoint)
    }
    private func accept(_ flow: NEAppProxyFlow, endpoint: NWHostEndpoint) -> Bool {
        guard let ctx = context else { return false }
        let identity = SigningIdentity.fromAuditToken(flow.metaData.sourceAppAuditToken)
        if let identity, let own = ownIdentity, identity == own { return false }
        let host = flow.remoteHostname ?? (!DNSWire.isIP(endpoint.hostname) ? endpoint.hostname : ctx.cache.hostname(for: endpoint.hostname))
        let decision = (try? CoreBridge.evaluate(ctx.policy, flow: FlowIdentity(signingID: identity?.signingID ?? "", teamID: identity?.teamID ?? "", hostname: host))) ?? RouteDecision(route: "blocked", reason: "規則驗證失敗。")
        let isDNS = endpoint.port == "53" && (decision.route == "vpn" || ctx.policy.domains.contains(where: \.enabled))
        let claim = decision.route != "direct" || isDNS
        ctx.engine.queue.async {
            ctx.log(DiagnosticEntry(application: identity?.signingID ?? flow.metaData.sourceAppSigningIdentifier, destination: "\(host ?? endpoint.hostname):\(endpoint.port)", route: claim ? "vpn" : "direct", reason: isDNS ? "系統 DNS 經 VPN resolver" : decision.reason))
            guard claim else { return }
            guard ctx.ready, ctx.engine.pointer != nil, ctx.flows.count < 256, decision.route != "blocked" else {
                let error = RouteBarError("VPN 尚未可用，已封鎖選中流量。")
                flow.closeReadWithError(error); flow.closeWriteWithError(error); return
            }
            let item = ProxyFlow(id: ctx.allocateID(), flow: flow, endpoint: endpoint); item.dns = isDNS
            ctx.flows[item.id] = item
            let targetHost = isDNS ? (ctx.summary.dns.first ?? endpoint.hostname) : endpoint.hostname
            self.resolve(targetHost, in: ctx) { ip in
                guard !item.closed else { return }
                guard let ip, let port = UInt16(endpoint.port) else { self.finish(item, in: ctx, error: RouteBarError("無法解析 VPN 目的地。")); return }
                if flow is NEAppProxyTCPFlow {
                    let result = ip.withCString { rb_engine_open_tcp(ctx.engine.pointer, item.id, $0, port) }
                    if result < 0 { self.finish(item, in: ctx, error: RouteBarError("無法建立 VPN TCP 連線。")) }
                    ctx.engine.drain()
                } else {
                    if rb_engine_open_udp(ctx.engine.pointer, item.id) < 0 { self.finish(item, in: ctx, error: RouteBarError("無法建立 VPN UDP 連線。")); return }
                    flow.open(withLocalEndpoint: nil) { error in ctx.engine.queue.async {
                        if let error { self.finish(item, in: ctx, error: error) }
                        else { item.opened = true; self.readUDP(item, in: ctx) }
                    } }
                }
            }
        }
        return claim
    }
    private func resolve(_ host: String, in ctx: ProxyContext, completion: @escaping (String?) -> Void) {
        if DNSWire.isIP(host) { completion(host); return }
        guard let resolver = ctx.summary.dns.first, ctx.resolutions.count < 32 else { completion(nil); return }
        let id = ctx.allocateID(), queryID = UInt16.random(in: 0...UInt16.max)
        guard let query = DNSWire.query(host, id: queryID, ipv6: !ctx.summary.addresses.contains(where: { !$0.contains(":") })), rb_engine_open_udp(ctx.engine.pointer, id) == 0 else { completion(nil); return }
        ctx.resolutions[id] = PendingResolution(host: DNSWire.question(query) ?? host.lowercased(), queryID: queryID, resolver: resolver, deadline: Date().addingTimeInterval(8), completion: completion)
        let result = resolver.withCString { address in query.withUnsafeBytes { rb_engine_udp_send(ctx.engine.pointer, id, address, 53, $0.bindMemory(to: UInt8.self).baseAddress, $0.count) } }
        if result < 0 { ctx.resolutions.removeValue(forKey: id); _ = rb_engine_close(ctx.engine.pointer, id); completion(nil) }
        ctx.engine.drain()
    }
    private func readTCP(_ item: ProxyFlow, in ctx: ProxyContext) {
        guard !item.closed, !item.reading, item.pending.isEmpty, let flow = item.flow as? NEAppProxyTCPFlow else { return }
        item.reading = true
        flow.readData { data, error in ctx.engine.queue.async {
            item.reading = false; guard !item.closed else { return }
            if let error { self.finish(item, in: ctx, error: error); return }
            guard let data, !data.isEmpty else { _ = rb_engine_tcp_eof(ctx.engine.pointer, item.id); ctx.engine.drain(); return }
            guard data.count <= 1_048_576 else { self.finish(item, in: ctx, error: RouteBarError("TCP buffer 超過限制。")); return }
            if item.dns {
                item.dnsRequestBuffer.append(data)
                while item.dnsRequestBuffer.count >= 2 {
                    let b = [UInt8](item.dnsRequestBuffer.prefix(2)); let size = (Int(b[0]) << 8) | Int(b[1])
                    guard size > 0 else { self.finish(item, in: ctx, error: RouteBarError("無效 DNS 訊息。")); return }
                    if item.dnsRequestBuffer.count < size + 2 { break }
                    let query = item.dnsRequestBuffer.subdata(in: 2..<size+2)
                    if let id = DNSWire.identifier(query), let host = DNSWire.question(query) {
                        guard item.dnsQueries.count < 64 else { self.finish(item, in: ctx, error: RouteBarError("DNS 查詢超過限制。")); return }
                        item.dnsQueries[id] = (host, item.endpoint)
                    }
                    item.dnsRequestBuffer.removeFirst(size + 2)
                }
                guard item.dnsRequestBuffer.count <= 65537 else { self.finish(item, in: ctx, error: RouteBarError("DNS buffer 超過限制。")); return }
            }
            item.pending = data; self.flushTCP(item, in: ctx)
        } }
    }
    private func flushTCP(_ item: ProxyFlow, in ctx: ProxyContext) {
        guard !item.closed, item.opened else { return }
        while !item.pending.isEmpty {
            let count = min(item.pending.count, 32768)
            let written = item.pending.prefix(count).withUnsafeBytes { rb_engine_tcp_write(ctx.engine.pointer, item.id, $0.bindMemory(to: UInt8.self).baseAddress, $0.count) }
            if written < 0 { finish(item, in: ctx, error: RouteBarError("VPN TCP 傳輸失敗。")); return }
            if written == 0 { break }
            item.pending.removeFirst(written)
        }
        ctx.engine.drain()
        if item.pending.isEmpty { readTCP(item, in: ctx) }
    }
    private func readUDP(_ item: ProxyFlow, in ctx: ProxyContext) {
        guard !item.closed, let flow = item.flow as? NEAppProxyUDPFlow else { return }
        flow.readDatagrams { datagrams, endpoints, error in ctx.engine.queue.async {
            guard !item.closed else { return }
            if let error { self.finish(item, in: ctx, error: error); return }
            guard let datagrams, let endpoints, datagrams.count == endpoints.count, !datagrams.isEmpty, datagrams.count <= 64 else { self.finish(item, in: ctx, error: nil); return }
            let group = DispatchGroup()
            for (data, destination) in zip(datagrams, endpoints) {
                guard let endpoint = destination as? NWHostEndpoint, let port = UInt16(endpoint.port) else { self.finish(item, in: ctx, error: RouteBarError("無效 UDP 目的地。")); return }
                // A UDP socket can send to multiple destinations. Re-evaluate each one.
                let identity = SigningIdentity.fromAuditToken(flow.metaData.sourceAppAuditToken)
                let originalDestination = endpoint.hostname == item.endpoint.hostname && endpoint.port == item.endpoint.port
                let hostname = (originalDestination ? flow.remoteHostname : nil) ?? (!DNSWire.isIP(endpoint.hostname) ? endpoint.hostname : ctx.cache.hostname(for: endpoint.hostname))
                let decision = try? CoreBridge.evaluate(ctx.policy, flow: FlowIdentity(signingID: identity?.signingID ?? "", teamID: identity?.teamID ?? "", hostname: hostname))
                if !item.dns && decision?.route != "vpn" { self.finish(item, in: ctx, error: RouteBarError("UDP 目的地已改變，請重新建立連線。")); return }
                if item.dns {
                    guard port == 53, let queryID = DNSWire.identifier(data), let query = DNSWire.question(data), item.dnsQueries.count < 64 else {
                        self.finish(item, in: ctx, error: RouteBarError("無效或過多 DNS 查詢。")); return
                    }
                    if let old = item.dnsQueries[queryID], old.0 != query || old.1.hostname != endpoint.hostname || old.1.port != endpoint.port {
                        self.finish(item, in: ctx, error: RouteBarError("DNS 查詢識別碼衝突。")); return
                    }
                    item.dnsQueries[queryID] = (query, endpoint)
                }
                group.enter()
                self.resolve(item.dns ? (ctx.summary.dns.first ?? endpoint.hostname) : endpoint.hostname, in: ctx) { ip in
                    defer { group.leave() }; guard !item.closed else { return }
                    guard let ip else { self.finish(item, in: ctx, error: RouteBarError("無法解析 UDP 目的地。")); return }
                    let key = "\(ip):\(port)"
                    guard item.destinations.contains(key) || item.destinations.count < 128 else { self.finish(item, in: ctx, error: RouteBarError("UDP 目的地超過限制。")); return }
                    item.destinations.insert(key)
                    let result = ip.withCString { ip in data.withUnsafeBytes { rb_engine_udp_send(ctx.engine.pointer, item.id, ip, port, $0.bindMemory(to: UInt8.self).baseAddress, $0.count) } }
                    if result < 0 || (result == 0 && !data.isEmpty) { self.finish(item, in: ctx, error: RouteBarError("UDP 傳送失敗：可能超過 MTU 或 buffer 限制。")) }
                    ctx.engine.drain()
                }
            }
            group.notify(queue: ctx.engine.queue) { self.readUDP(item, in: ctx) }
        } }
    }
    private func handle(_ event: EngineEvent, in ctx: ProxyContext) {
        guard context === ctx else { return }
        if let pending = ctx.resolutions[event.flow], event.kind == 5 {
            guard event.address == pending.resolver, event.port == 53, DNSWire.identifier(event.data) == pending.queryID, DNSWire.question(event.data) == pending.host else { _ = rb_engine_resume(ctx.engine.pointer, event.flow); return }
            ctx.resolutions.removeValue(forKey: event.flow); ctx.cache.observe(event.data)
            _ = rb_engine_close(ctx.engine.pointer, event.flow)
            pending.completion(DNSWire.answers(event.data).first(where: { answer in ctx.summary.hasIpv6 || !answer.address.contains(":") })?.address); return
        }
        guard let item = ctx.flows[event.flow], !item.closed else { return }
        switch event.kind {
        case 2:
            item.flow.open(withLocalEndpoint: nil) { error in ctx.engine.queue.async {
                if let error { self.finish(item, in: ctx, error: error) }
                else {
                    item.opened = true
                    if let buffered = item.incomingBeforeOpen { item.incomingBeforeOpen = nil; self.handle(buffered, in: ctx) }
                    self.readTCP(item, in: ctx)
                }
            } }
        case 3:
            guard item.opened else { item.incomingBeforeOpen = event; return }
            if item.dns {
                item.dnsTCPBuffer.append(event.data)
                while item.dnsTCPBuffer.count >= 2 {
                    let b = [UInt8](item.dnsTCPBuffer.prefix(2)); let length = (Int(b[0]) << 8) | Int(b[1])
                    guard length > 0, item.dnsTCPBuffer.count >= length + 2 else { break }
                    let response = item.dnsTCPBuffer.subdata(in: 2..<length+2)
                    if let id = DNSWire.identifier(response), let expected = item.dnsQueries[id], DNSWire.question(response) == expected.0 {
                        ctx.cache.observe(response); item.dnsQueries.removeValue(forKey: id)
                    }
                    item.dnsTCPBuffer.removeFirst(length + 2)
                }
                if item.dnsTCPBuffer.count > 65537 { item.dnsTCPBuffer.removeAll() }
            }
            (item.flow as? NEAppProxyTCPFlow)?.write(event.data) { error in ctx.engine.queue.async {
                if let error { self.finish(item, in: ctx, error: error) }
                else { _ = rb_engine_resume(ctx.engine.pointer, item.id); ctx.engine.drain() }
            } }
        case 5:
            guard item.destinations.contains("\(event.address):\(event.port)") else { _ = rb_engine_resume(ctx.engine.pointer, item.id); return }
            let endpoint: NWHostEndpoint
            if item.dns {
                guard let id = DNSWire.identifier(event.data), let expected = item.dnsQueries[id], DNSWire.question(event.data) == expected.0 else { _ = rb_engine_resume(ctx.engine.pointer, item.id); return }
                ctx.cache.observe(event.data); item.dnsQueries.removeValue(forKey: id); endpoint = expected.1
            } else { endpoint = NWHostEndpoint(hostname: event.address, port: String(event.port)) }
            (item.flow as? NEAppProxyUDPFlow)?.writeDatagrams([event.data], sentBy: [endpoint]) { error in ctx.engine.queue.async {
                if let error { self.finish(item, in: ctx, error: error) }
                else { _ = rb_engine_resume(ctx.engine.pointer, item.id); ctx.engine.drain() }
            } }
        case 9: item.flow.closeWriteWithError(nil)
        case 4: finish(item, in: ctx, error: item.opened ? nil : RouteBarError("VPN 連線逾時或目的地拒絕連線。"))
        default: break
        }
    }
    private func finish(_ item: ProxyFlow, in ctx: ProxyContext, error: Error?) {
        guard !item.closed else { return }; item.closed = true
        item.flow.closeReadWithError(error); item.flow.closeWriteWithError(error)
        _ = rb_engine_close(ctx.engine.pointer, item.id); ctx.flows.removeValue(forKey: item.id)
        if let error { ctx.log(DiagnosticEntry(application: item.flow.metaData.sourceAppSigningIdentifier, destination: item.endpoint.hostname, route: "blocked", reason: error.localizedDescription)) }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let command = try? JSONSerialization.jsonObject(with: messageData) as? [String: String], command["command"] == "status", let ctx = context else { completionHandler?(nil); return }
        ctx.engine.queue.async {
            struct Status: Encodable { let diagnostics: [DiagnosticEntry]; let handshakeAge: Int64; let status: String }
            completionHandler?(try? JSONEncoder().encode(Status(diagnostics: ctx.diagnostics, handshakeAge: ctx.engine.handshakeAge, status: ctx.ready ? "connected" : "reconnecting")))
        }
    }
}
