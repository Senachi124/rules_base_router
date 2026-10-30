import Foundation
import Network

struct EngineEvent {
    let kind: UInt32
    let flow: UInt64
    let address: String
    let port: UInt16
    let data: Data
}

/// All engine and flow operations run on queue. UI never carries packet payloads.
final class TunnelEngine {
    let queue = DispatchQueue(label: "com.routebar.engine", qos: .userInitiated)
    private(set) var pointer: OpaquePointer?
    private var connection: NWConnection?
    private var timer: DispatchSourceTimer?
    private var collected: [EngineEvent] = []
    private var started = DispatchTime.now()
    private var completion: ((Error?) -> Void)?
    private var ready = false
    private var lastReceived = DispatchTime.now()
    private var authenticatedRX: UInt64 = 0
    private var pendingNetworkBytes = 0
    private var timerInterval = 250
    var onEvent: ((EngineEvent) -> Void)?
    var onFailure: ((Error) -> Void)?
    var onTick: (() -> Void)?
    var handshakeAge: Int64 { pointer.map { rb_engine_handshake_age($0) } ?? -1 }

    init(profile: String, raw: Bool) throws {
        pointer = profile.withCString { rb_engine_new($0, raw) }
        guard pointer != nil else { throw RouteBarError("無法建立 VPN 核心。請檢查設定檔。") }
    }
    deinit { if let pointer { rb_engine_free(pointer) } }

    func start(summary: ProfileSummary, completion: @escaping (Error?) -> Void) {
        queue.async {
            self.completion = completion; self.started = .now(); self.lastReceived = .now()
            let parameters = NWParameters.udp
            parameters.includePeerToPeer = false
            let conn = NWConnection(host: .init(summary.endpointHost), port: .init(rawValue: summary.endpointPort)!, using: parameters)
            self.connection = conn
            conn.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    _ = rb_engine_start(self.pointer); self.drain(); self.receive()
                case .failed(let error), .waiting(let error): self.fail(error)
                default: break
                }
            }
            conn.start(queue: self.queue)
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(250), leeway: .milliseconds(10))
            timer.setEventHandler { [weak self] in
                guard let self, let pointer = self.pointer else { return }
                let elapsed = (DispatchTime.now().uptimeNanoseconds - self.started.uptimeNanoseconds) / 1_000_000
                _ = rb_engine_tick(pointer, Int64(elapsed)); self.drain(); self.onTick?()
                guard self.pointer != nil else { return }
                let interval = rb_engine_flow_count(pointer) > 0 ? 20 : 250
                if interval != self.timerInterval {
                    self.timerInterval = interval
                    self.timer?.schedule(deadline: .now() + .milliseconds(interval), repeating: .milliseconds(interval), leeway: .milliseconds(5))
                }
                if !self.ready && elapsed > 15000 { self.fail(RouteBarError("VPN 握手逾時。請檢查伺服器、金鑰同網絡。")) }
                if self.ready && (DispatchTime.now().uptimeNanoseconds - self.lastReceived.uptimeNanoseconds) > 180_000_000_000 { self.fail(RouteBarError("VPN 對端長時間未有回應。已停止 VPN 流量。")) }
            }
            self.timer = timer; timer.resume()
        }
    }
    func stop() {
        dispatchPrecondition(condition: .onQueue(queue))
        timer?.cancel(); timer = nil
        connection?.stateUpdateHandler = nil; connection?.cancel(); connection = nil
        if let pointer { rb_engine_free(pointer); self.pointer = nil }
        let pending = completion; completion = nil; pending?(RouteBarError("連線已取消。"))
        onTick = nil; onEvent = nil; onFailure = nil
    }
    private func fail(_ error: Error) {
        guard pointer != nil else { return }
        let pending = completion; let failure = onFailure; completion = nil; stop()
        if let pending { pending(error) } else { failure?(error) }
    }
    private func receive() {
        connection?.receiveMessage { [weak self] data, _, _, error in
            guard let self, let pointer = self.pointer else { return }
            if let error { self.fail(error); return }
            if let data {
                data.withUnsafeBytes { raw in _ = rb_engine_receive(pointer, raw.bindMemory(to: UInt8.self).baseAddress, raw.count) }
                let count = rb_engine_authenticated_rx_count(pointer)
                if count != self.authenticatedRX { self.authenticatedRX = count; self.lastReceived = .now() }
                self.drain()
            }
            self.receive()
        }
    }
    func drain() {
        guard let pointer else { return }
        _ = rb_engine_drain(pointer, { context, kind, flow, address, port, bytes, length in
            guard let context else { return }
            let owner = Unmanaged<TunnelEngine>.fromOpaque(context).takeUnretainedValue()
            owner.collected.append(EngineEvent(kind: kind, flow: flow, address: address.map(String.init(cString:)) ?? "", port: port, data: bytes.map { Data(bytes: $0, count: length) } ?? Data()))
        }, Unmanaged.passUnretained(self).toOpaque())
        let events = collected; collected.removeAll(keepingCapacity: true)
        for event in events {
            guard self.pointer != nil else { break }
            if event.kind == 1 {
                guard pendingNetworkBytes + event.data.count <= 4 * 1024 * 1024 else { fail(RouteBarError("VPN 傳輸佇列已滿。")); break }
                pendingNetworkBytes += event.data.count
                connection?.send(content: event.data, completion: .contentProcessed { [weak self] error in
                    guard let self else { return }; self.pendingNetworkBytes -= event.data.count
                    if let error { self.fail(error) }
                })
            } else if event.kind == 7 {
                ready = true; let pending = completion; completion = nil; pending?(nil)
            } else if event.kind == 8 && event.flow == 0 {
                fail(RouteBarError("VPN 核心已停止：傳輸資源超過限制。"))
            } else { onEvent?(event) }
        }
    }
}
