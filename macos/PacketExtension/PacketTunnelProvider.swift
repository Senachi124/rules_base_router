import Darwin
import Foundation
import Network
import NetworkExtension

/// Full-device mode owns an IP tunnel. The transparent provider is a separate,
/// mutually exclusive configuration; raw IP packets are never sent to a direct proxy.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lifecycle = DispatchQueue(label: "com.routebar.packet.lifecycle")
    private var engine: TunnelEngine?
    private var generation = UUID()
    // The host reads its user Keychain and sends this via startTunnel(options:).
    // Options are transient: secrets never enter persisted providerConfiguration.
    // A system extension cannot read the host user's Data Protection Keychain.
    private var inMemoryProfile: String?
    private var summary: ProfileSummary?
    private var pendingStart: ((Error?) -> Void)?
    private var routesInstalled = false
    private var settingsOperationInFlight = false
    private var deferredTransportError: Error?
    private var pendingStop: (() -> Void)?
    private var reading = false
    private var sleeping = false
    private var stopping = false
    private var reconnectAttempt = 0
    private var reconnectWork: DispatchWorkItem?
    private var pathMonitor: NWPathMonitor?
    private var pathWasUnavailable = false
    private var diagnostics: [DiagnosticEntry] = []
    private var status = "disconnected"
    private var blockedPackets: UInt64 = 0
    private var receivedPackets: UInt64 = 0

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        lifecycle.async {
            guard self.pendingStart == nil, self.engine == nil, !self.routesInstalled else {
                completionHandler(RouteBarError("網絡服務已經啟動。")); return
            }
            self.stopping = false
            self.sleeping = false
            self.deferredTransportError = nil
            self.pendingStart = completionHandler
            do {
                guard let configuration = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                      configuration["profileID"] as? String != nil,
                      let policyData = configuration["policy"] as? Data else {
                    throw RouteBarError("缺少 VPN 設定，請喺 RouteBar 重新儲存設定。")
                }
                guard let profile = options?["wireguardProfile"] as? String else {
                    throw RouteBarError("請由 RouteBar 開啟連線。此版本需要由 App 讀取 Keychain，不支援無 App 嘅自動啟動。")
                }
                let policy = try CoreBridge.validate(JSONDecoder().decode(RoutingPolicy.self, from: policyData))
                guard policy.mode == "full" else { throw RouteBarError("全機網絡服務只接受全機模式。") }
                // Validate before retaining any session configuration. Diagnostics only
                // receive the redacted ProfileSummary; raw options are never logged.
                _ = try CoreBridge.inspect(profile)
                self.inMemoryProfile = profile
                self.startEngine()
            } catch { self.finishInitialFailure(error) }
        }
    }

    /// A failed established tunnel keeps its routes while reasserting. It does not
    /// cancel itself (which would remove the routes and silently restore direct access).
    private func startEngine() {
        dispatchPrecondition(condition: .onQueue(lifecycle))
        guard !stopping, !sleeping, !pathWasUnavailable, !settingsOperationInFlight, engine == nil,
              let profile = inMemoryProfile else { return }
        reconnectWork?.cancel(); reconnectWork = nil
        let token = UUID(); generation = token
        do {
            let metadata = try CoreBridge.inspect(profile)
            guard !metadata.dns.isEmpty else { throw RouteBarError("全機模式需要設定檔內嘅 DNS IP，請重新匯入包含 DNS 嘅 WireGuard 設定。") }
            guard metadata.dns.contains(where: { dns in metadata.addresses.contains(where: { ($0.contains(":")) == dns.contains(":") }) }) else {
                throw RouteBarError("DNS 位址使用嘅 IP 版本未包含喺 VPN 設定。")
            }
            let next = try TunnelEngine(profile: profile, raw: true)
            engine = next; summary = metadata
            status = routesInstalled ? "reconnecting" : "connecting"
            next.onEvent = { [weak self, weak next] event in
                guard let self, let next, event.kind == 6 else { return }
                self.lifecycle.async {
                    guard self.generation == token, self.engine === next, self.routesInstalled, !self.stopping else { return }
                    self.writePacket(event.data)
                }
            }
            next.onFailure = { [weak self, weak next] error in
                guard let self, let next else { return }
                self.lifecycle.async {
                    guard self.generation == token, self.engine === next else { return }
                    self.engine = nil
                    self.connectionFailed(error)
                }
            }
            next.start(summary: metadata) { [weak self, weak next] error in
                guard let self, let next else { return }
                self.lifecycle.async {
                    guard self.generation == token, self.engine === next, !self.stopping else { return }
                    if let error {
                        self.engine = nil; self.connectionFailed(error); return
                    }
                    if self.routesInstalled { self.connected(); return }
                    do {
                        let settings = try Self.settings(for: metadata)
                        self.settingsOperationInFlight = true
                        self.setTunnelNetworkSettings(settings) { [weak self] error in
                            guard let self else { return }
                            self.lifecycle.async {
                                self.settingsOperationInFlight = false
                                if error == nil { self.routesInstalled = true }
                                if self.stopping { self.finishStop(); return }
                                // A sleep or path change can replace the engine while the
                                // system applies settings. Still track those installed routes.
                                if error == nil {
                                    if self.pathMonitor == nil { self.startPathMonitor() }
                                    self.readPackets()
                                }
                                if let deferred = self.deferredTransportError {
                                    self.deferredTransportError = nil
                                    if let error { self.finishInitialFailure(error) }
                                    else { self.connectionFailed(deferred) }
                                    return
                                }
                                guard self.generation == token, self.engine === next else {
                                    if let error { self.finishInitialFailure(error) }
                                    else if self.engine == nil && !self.sleeping { self.startEngine() }
                                    return
                                }
                                if let error { self.stopCurrentEngine(); self.finishInitialFailure(error); return }
                                self.connected()
                            }
                        }
                    } catch { self.stopCurrentEngine(); self.finishInitialFailure(error) }
                }
            }
        } catch { connectionFailed(error) }
    }

    private func connected() {
        status = "connected"; reconnectAttempt = 0; reasserting = false
        appendDiagnostic("vpn", "WireGuard 握手完成；全機 IP 流量經 VPN。")
        if summary?.hasIpv6 == false { appendDiagnostic("blocked", "此設定檔無 IPv6；IPv6 流量已由 tunnel 接收並封鎖，避免直出。") }
        let completion = pendingStart; pendingStart = nil; completion?(nil)
    }

    private func connectionFailed(_ error: Error) {
        guard !stopping else { return }
        if settingsOperationInFlight { deferredTransportError = error; return }
        if !routesInstalled { finishInitialFailure(error); return }
        reasserting = true; status = "reconnecting"
        appendDiagnostic("blocked", "VPN 中斷：\(error.localizedDescription) 保留 tunnel 路由並等待重新連線。")
        scheduleReconnect()
    }

    private func finishInitialFailure(_ error: Error) {
        inMemoryProfile = nil
        status = "failed"
        appendDiagnostic("error", error.localizedDescription)
        let completion = pendingStart; pendingStart = nil
        stopCurrentEngine()
        completion?(error)
    }

    private func scheduleReconnect() {
        guard !sleeping, !stopping, reconnectWork == nil else { return }
        reconnectAttempt += 1
        let delay = min(30.0, pow(2.0, Double(min(reconnectAttempt, 5))))
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.reconnectWork = nil
            self.startEngine()
        }
        reconnectWork = work
        lifecycle.asyncAfter(deadline: .now() + delay, execute: work)
    }

    private func stopCurrentEngine() {
        generation = UUID()
        guard let old = engine else { return }
        engine = nil
        old.queue.async {
            old.onEvent = nil; old.onFailure = nil; old.onTick = nil
            old.stop()
        }
    }

    private func readPackets() {
        guard routesInstalled, !reading, !stopping else { return }
        reading = true
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.lifecycle.async {
                self.reading = false
                guard self.routesInstalled, !self.stopping else { return }
                let accepted = zip(packets, protocols).compactMap { packet, family -> Data? in
                    guard let version = packet.first.map({ $0 >> 4 }),
                          (version == 4 && family.int32Value == AF_INET) || (version == 6 && family.int32Value == AF_INET6) else {
                        self.blockedPackets += 1; return nil
                    }
                    return packet
                }
                guard let active = self.engine, self.status == "connected", !self.sleeping else {
                    self.blockedPackets += UInt64(accepted.count)
                    self.readPackets(); return
                }
                let token = self.generation
                active.queue.async {
                    var rejected: UInt64 = 0
                    if let pointer = active.pointer {
                        for packet in accepted {
                            let result = packet.withUnsafeBytes { raw in
                                rb_engine_feed_ip(pointer, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
                            }
                            if result < 0 { rejected += 1 }
                        }
                        active.drain()
                    } else { rejected = UInt64(accepted.count) }
                    self.lifecycle.async {
                        if self.generation == token { self.blockedPackets += rejected }
                        self.readPackets()
                    }
                }
            }
        }
    }

    private func writePacket(_ data: Data) {
        guard let version = data.first.map({ $0 >> 4 }), version == 4 || version == 6 else { return }
        if packetFlow.writePackets([data], withProtocols: [NSNumber(value: version == 4 ? AF_INET : AF_INET6)]) {
            receivedPackets += 1
        } else { blockedPackets += 1 }
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, !self.stopping else { return }
            let unavailable = path.status != .satisfied
            if unavailable && !self.pathWasUnavailable {
                self.pathWasUnavailable = true
                self.reconnectWork?.cancel(); self.reconnectWork = nil
                self.reasserting = true; self.status = "waitingForNetwork"
                self.stopCurrentEngine()
                self.appendDiagnostic("blocked", "網絡暫時無法使用；已保留 VPN 路由。")
            } else if !unavailable && self.pathWasUnavailable {
                self.pathWasUnavailable = false
                self.reconnectWork?.cancel(); self.reconnectWork = nil
                self.startEngine()
            }
        }
        monitor.start(queue: lifecycle)
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        lifecycle.async {
            self.sleeping = true
            self.reconnectWork?.cancel(); self.reconnectWork = nil
            self.stopCurrentEngine()
            if self.routesInstalled { self.reasserting = true; self.status = "sleeping" }
            completionHandler()
        }
    }

    override func wake() {
        lifecycle.async {
            self.sleeping = false
            guard !self.stopping else { return }
            self.startEngine()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lifecycle.async {
            self.stopping = true; self.status = "disconnected"
            self.inMemoryProfile = nil
            self.reconnectWork?.cancel(); self.reconnectWork = nil
            self.pathMonitor?.cancel(); self.pathMonitor = nil
            self.stopCurrentEngine()
            let pending = self.pendingStart; self.pendingStart = nil
            pending?(RouteBarError("連線已取消。"))
            self.pendingStop = completionHandler
            if !self.settingsOperationInFlight { self.finishStop() }
        }
    }

    private func finishStop() {
        guard let completion = pendingStop else { return }
        pendingStop = nil
        routesInstalled = false
        setTunnelNetworkSettings(nil) { _ in completion() }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard messageData.count < 4096,
              let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
              request["command"] == "status" else { completionHandler?(nil); return }
        lifecycle.async {
            let entries = self.diagnostics
            let status = self.status
            let blocked = self.blockedPackets
            let received = self.receivedPackets
            let reply: (Int64) -> Void = { age in
                let value = StatusReply(diagnostics: entries, handshakeAge: age, status: status, blockedPackets: blocked, receivedPackets: received)
                completionHandler?(try? JSONEncoder().encode(value))
            }
            if let engine = self.engine { engine.queue.async { reply(engine.handshakeAge) } }
            else { reply(-1) }
        }
    }

    private struct StatusReply: Encodable {
        var diagnostics: [DiagnosticEntry]
        var handshakeAge: Int64
        var status: String
        var blockedPackets: UInt64
        var receivedPackets: UInt64
    }

    private func appendDiagnostic(_ route: String, _ reason: String) {
        diagnostics.append(DiagnosticEntry(application: "RouteBar 全機模式", destination: summary?.endpointHost ?? "VPN", route: route, reason: reason))
        if diagnostics.count > 100 { diagnostics.removeFirst(diagnostics.count - 100) }
    }

    /// Claim both families even when the profile supplies only one. Missing-family
    /// packets are rejected by Rust; installing no route would leak them directly.
    static func settings(for summary: ProfileSummary) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: numericHost(summary.endpointHost) ?? "127.0.0.1")
        let v4 = summary.addresses.first { !$0.contains(":") }
        let v6 = summary.addresses.first { $0.contains(":") }
        let v4Parts = (v4 ?? "198.18.0.1/32").split(separator: "/", maxSplits: 1).map(String.init)
        let v6Parts = (v6 ?? "fd00:726f:7574:6562::1/128").split(separator: "/", maxSplits: 1).map(String.init)
        guard v4Parts.count == 2, let v4Prefix = UInt32(v4Parts[1]), v4Prefix <= 32,
              v6Parts.count == 2, let v6Prefix = UInt8(v6Parts[1]), v6Prefix <= 128 else {
            throw RouteBarError("無效嘅 tunnel IP 位址。")
        }
        let bits: UInt32 = v4Prefix == 0 ? 0 : UInt32.max << (32 - v4Prefix)
        let mask = [24, 16, 8, 0].map { String((bits >> $0) & 255) }.joined(separator: ".")
        let ipv4 = NEIPv4Settings(addresses: [v4Parts[0]], subnetMasks: [mask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        let ipv6 = NEIPv6Settings(addresses: [v6Parts[0]], networkPrefixLengths: [NSNumber(value: v6Prefix)])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv4Settings = ipv4; settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: summary.dns.filter { ($0.contains(":") ? v6 : v4) != nil })
        dns.matchDomains = [""]; dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: summary.mtu)
        return settings
    }

    private static func numericHost(_ host: String) -> String? {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_DGRAM
        var results: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &results) == 0, let first = results else { return nil }
        defer { freeaddrinfo(first) }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: buffer)
    }
}
