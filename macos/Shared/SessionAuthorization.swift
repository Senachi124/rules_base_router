import Combine
import CoreFoundation
import Darwin
import Foundation
import Security

/// One authorization belongs to this running application process. It is never
/// restored from preferences and never refreshed implicitly by a VPN action.
@MainActor
final class SessionAuthorization: ObservableObject {
    static let shared = SessionAuthorization()
    @Published private(set) var authorized = false
    @Published private(set) var isAuthorizing = false
    @Published private(set) var message = "今次開啟 RouteBar 尚未授權。"

    private var endpoint: SessionEndpoint?
    private var pendingEndpoint: SessionEndpoint?
    private var retiredEndpoints: [SessionEndpoint] = []
    private var bootstrap: SessionBootstrap?
    private var generation: UInt64 = 0
    private init() {}

    func authorize() async throws {
        if authorized { return }
        guard !isAuthorizing else { throw SessionAuthorizationError.rejected("管理員授權仍在進行中。") }
        generation &+= 1
        let current = generation
        let candidate = try SessionEndpoint.make()
        let launcher = SessionBootstrap()
        pendingEndpoint = candidate; bootstrap = launcher
        isAuthorizing = true
        message = "等待 macOS 管理員授權…"
        defer {
            if generation == current { isAuthorizing = false; bootstrap = nil; pendingEndpoint = nil }
        }
        do {
            let binary = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/routebar-v2")
            guard FileManager.default.isExecutableFile(atPath: binary.path) else {
                throw SessionAuthorizationError.unavailable("未搵到隨附網絡控制器，請重新編譯 Application。")
            }
            let arguments = ["session-start", "--owner-pid", String(getpid()), "--owner-uid", String(getuid()), "--session-id", candidate.id, "--json"]
            let script = V2Backend.adminScript(executable: binary, arguments: arguments)
            let result = try await Task.detached(priority: .userInitiated) {
                try launcher.run(script: script, timeout: 300)
            }.value
            guard generation == current else { throw SessionAuthorizationError.cancelled }
            try SessionSocketClient.verifyBootstrap(result, endpoint: candidate)
            let ping = try SessionSocketClient.requestData(endpoint: candidate, command: "ping")
            let reply = try await Task.detached(priority: .userInitiated) {
                try SessionSocketClient.exchange(endpoint: candidate, payload: ping, timeout: 5, expectedPeerUID: 0)
            }.value
            try SessionSocketClient.verifyPing(reply, endpoint: candidate)
            guard generation == current else { throw SessionAuthorizationError.cancelled }
            endpoint = candidate; pendingEndpoint = nil
            authorized = true
            message = "今次開啟已授權；連線、停止同讀取日誌毋須再輸入密碼。"
        } catch {
            await Self.close(candidate)
            if generation == current {
                authorized = false; endpoint = nil
                message = error.localizedDescription
            }
            throw error
        }
    }

    func request(command: String, config: [String: Any]? = nil, profiles: [String: String]? = nil, lines: Int? = nil) async throws -> Data {
        guard authorized, let endpoint else {
            throw SessionAuthorizationError.rejected("今次開啟尚未授權，請先按「授權」。")
        }
        let current = generation
        let payload = try SessionSocketClient.requestData(endpoint: endpoint, command: command, config: config, profiles: profiles, lines: lines)
        let timeout: TimeInterval = ["ping", "status", "close"].contains(command) ? 5 : 90
        do {
            let data = try await Task.detached(priority: .userInitiated) {
                try SessionSocketClient.exchange(endpoint: endpoint, payload: payload, timeout: timeout, expectedPeerUID: 0)
            }.value
            guard generation == current else { throw SessionAuthorizationError.cancelled }
            if command == "close" { invalidate() }
            return data
        } catch {
            if generation == current, let failure = error as? SessionAuthorizationError, failure.invalidatesSession {
                invalidate()
                message = "今次授權連線已失效：\(error.localizedDescription) 請重新授權。"
            }
            throw error
        }
    }

    /// Also cancels a pending password dialog. No further dialog is opened.
    func invalidate() {
        generation &+= 1
        bootstrap?.cancel(); bootstrap = nil
        if let endpoint { retiredEndpoints.append(endpoint) }
        if let pendingEndpoint { retiredEndpoints.append(pendingEndpoint) }
        endpoint = nil; pendingEndpoint = nil
        authorized = false; isAuthorizing = false
        message = "今次開啟尚未授權。"
        let stale = retiredEndpoints
        Task { await Self.closeAll(stale) }
    }

    func endSession() async {
        generation &+= 1
        bootstrap?.cancel(); bootstrap = nil
        var closing = retiredEndpoints
        if let endpoint { closing.append(endpoint) }
        if let pendingEndpoint { closing.append(pendingEndpoint) }
        endpoint = nil; pendingEndpoint = nil; retiredEndpoints = []
        authorized = false; isAuthorizing = false
        message = "今次授權已結束；背景 VPN 服務保持原有狀態。"
        await Self.closeAll(closing)
    }

    private static func close(_ endpoint: SessionEndpoint) async {
        await Task.detached(priority: .utility) {
            guard let payload = try? SessionSocketClient.requestData(endpoint: endpoint, command: "close") else { return }
            _ = try? SessionSocketClient.exchange(endpoint: endpoint, payload: payload, timeout: 1.5, expectedPeerUID: 0)
        }.value
    }
    private static func closeAll(_ endpoints: [SessionEndpoint]) async {
        await withTaskGroup(of: Void.self) { group in
            for endpoint in Set(endpoints) { group.addTask { await close(endpoint) } }
        }
    }
}

struct SessionEndpoint: Hashable, Sendable {
    let id: String
    let path: String
    static func make() throws -> SessionEndpoint {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw SessionAuthorizationError.unavailable("無法建立安全嘅授權識別碼。")
        }
        let id = bytes.map { String(format: "%02x", $0) }.joined()
        var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath("/var/db", &resolved) != nil else { throw SessionAuthorizationError.unavailable("無法確認系統授權目錄。") }
        let base = String(cString: resolved)
        guard base == "/private/var/db" else { throw SessionAuthorizationError.unavailable("系統授權目錄位置不符。") }
        return SessionEndpoint(id: id, path: base + "/routebar-s-\(getuid())-\(id)/control.sock")
    }
}

enum SessionAuthorizationError: LocalizedError {
    case cancelled
    case rejected(String)
    case unavailable(String)
    case invalidResponse(String)
    var errorDescription: String? {
        switch self {
        case .cancelled: return "已取消管理員授權；你仍然可以編輯白名單。"
        case .rejected(let message), .unavailable(let message), .invalidResponse(let message): return message
        }
    }
    var invalidatesSession: Bool {
        switch self { case .unavailable, .invalidResponse: return true; case .cancelled, .rejected: return false }
    }
}

/// Production callers always require UID 0. The peer UID argument here is an
/// internal low-level seam for unprivileged socket tests, never UI configuration.
enum SessionSocketClient {
    static let maximumFrameBytes = 4 * 1024 * 1024
    static let commands: Set<String> = ["ping", "status", "up", "reload", "down", "logs", "close"]

    static func requestData(endpoint: SessionEndpoint, command: String, config: [String: Any]? = nil, profiles: [String: String]? = nil, lines: Int? = nil) throws -> Data {
        guard commands.contains(command) else { throw SessionAuthorizationError.rejected("未知網絡服務操作。") }
        var request: [String: Any] = ["session_id": endpoint.id, "command": command]
        if let config { request["config"] = config }
        if let profiles { request["profiles"] = profiles }
        if let lines { request["lines"] = lines }
        let data: Data
        do { data = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]) }
        catch { throw SessionAuthorizationError.rejected("無法編碼網絡服務要求。") }
        guard data.count + 1 <= maximumFrameBytes else { throw SessionAuthorizationError.rejected("網絡配置過大；上限為 4 MB。") }
        return data + Data([10])
    }

    static func verifyBootstrap(_ data: Data, endpoint: SessionEndpoint) throws {
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["socket_path"] as? String == endpoint.path,
              value["session_id"] as? String == endpoint.id,
              protocolIsOne(value["protocol"]) else {
            throw SessionAuthorizationError.invalidResponse("授權服務啟動回應未通過驗證。")
        }
    }
    static func verifyPing(_ data: Data, endpoint: SessionEndpoint) throws {
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["session_id"] as? String == endpoint.id,
              protocolIsOne(value["protocol"]) else {
            throw SessionAuthorizationError.invalidResponse("授權服務識別碼或協定不符。")
        }
    }
    private static func protocolIsOne(_ value: Any?) -> Bool {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
        return value.doubleValue == 1
    }

    static func responseResult(_ frame: Data) throws -> Data {
        guard frame.count <= maximumFrameBytes,
              let value = try? JSONSerialization.jsonObject(with: frame) as? [String: Any],
              let ok = value["ok"] as? NSNumber, CFGetTypeID(ok) == CFBooleanGetTypeID() else {
            throw SessionAuthorizationError.invalidResponse("授權服務回應格式無效。")
        }
        if !ok.boolValue {
            guard let message = value["error"] as? String, !message.isEmpty else { throw SessionAuthorizationError.invalidResponse("授權服務缺少錯誤內容。") }
            throw SessionAuthorizationError.rejected(String(message.prefix(6000)))
        }
        guard let result = value["result"] else { throw SessionAuthorizationError.invalidResponse("授權服務回應缺少結果。") }
        do { return try JSONSerialization.data(withJSONObject: result, options: [.fragmentsAllowed, .sortedKeys]) }
        catch { throw SessionAuthorizationError.invalidResponse("授權服務結果無法讀取。") }
    }

    static func exchange(endpoint: SessionEndpoint, payload: Data, timeout: TimeInterval, expectedPeerUID: uid_t) throws -> Data {
        guard payload.count <= maximumFrameBytes, payload.last == 10 else { throw SessionAuthorizationError.rejected("網絡服務要求格式無效或過大。") }
        let pathBytes = Array(endpoint.path.utf8)
        var address = sockaddr_un()
        guard !pathBytes.contains(0), pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw SessionAuthorizationError.unavailable("授權服務 socket 路徑無效。")
        }
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: pathBytes + [0])
        }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw SessionAuthorizationError.unavailable("無法建立本機授權連線。") }
        defer { Darwin.close(descriptor) }
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else { throw SessionAuthorizationError.unavailable("無法設定本機授權連線。") }
        var noSignal: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw SessionAuthorizationError.unavailable("無法保護本機授權連線。")
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if result != 0 {
            guard errno == EINPROGRESS || errno == EWOULDBLOCK else { throw SessionAuthorizationError.unavailable("今次授權服務無法連接。") }
            try wait(descriptor, event: Int16(POLLOUT), deadline: deadline)
            var socketError: Int32 = 0
            var errorLength = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0, socketError == 0 else {
                throw SessionAuthorizationError.unavailable("今次授權服務無法連接。")
            }
        }
        var peerUID: uid_t = 0; var peerGID: gid_t = 0
        guard getpeereid(descriptor, &peerUID, &peerGID) == 0, peerUID == expectedPeerUID else {
            throw SessionAuthorizationError.unavailable("授權服務身份驗證失敗；未有傳送配置。")
        }
        try payload.withUnsafeBytes { bytes in
            var written = 0
            while written < bytes.count {
                try wait(descriptor, event: Int16(POLLOUT), deadline: deadline)
                let count = Darwin.send(descriptor, bytes.baseAddress!.advanced(by: written), bytes.count - written, 0)
                if count > 0 { written += count }
                else if count < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
                else { throw SessionAuthorizationError.unavailable("傳送配置時授權連線已中斷。") }
            }
        }
        var frame = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            try wait(descriptor, event: Int16(POLLIN), deadline: deadline)
            let count = Darwin.recv(descriptor, &buffer, buffer.count, 0)
            if count < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard count > 0 else { throw SessionAuthorizationError.unavailable("授權連線已中斷，未能確認操作結果；請更新服務狀態。") }
            frame.append(contentsOf: buffer.prefix(count))
            guard frame.count <= maximumFrameBytes else { throw SessionAuthorizationError.invalidResponse("授權服務回應超出 4 MB 上限。") }
            if let newline = frame.firstIndex(of: 10) {
                guard newline == frame.count - 1 else { throw SessionAuthorizationError.invalidResponse("授權服務回應包含多個訊息。") }
                return try responseResult(frame.prefix(upTo: newline))
            }
        }
    }
    private static func wait(_ descriptor: Int32, event: Int16, deadline: TimeInterval) throws {
        while true {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw SessionAuthorizationError.unavailable("授權服務回應逾時；操作可能仍在完成，請更新服務狀態。") }
            var descriptorState = pollfd(fd: descriptor, events: event, revents: 0)
            let result = poll(&descriptorState, 1, Int32(min(remaining * 1000 + 1, Double(Int32.max))))
            if result < 0 && errno == EINTR { continue }
            guard result >= 0, descriptorState.revents & Int16(POLLNVAL) == 0 else { throw SessionAuthorizationError.unavailable("授權連線無法繼續。") }
            if result == 0 { continue }
            return
        }
    }
}

private final class SessionBootstrap: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false

    func cancel() {
        lock.lock(); cancelled = true; let process = self.process; lock.unlock()
        if let process, process.isRunning { process.terminate() }
    }
    private var wasCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }

    func run(script: String, timeout: TimeInterval) throws -> Data {
        let directory = try V2Backend.secureDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let stdout = directory.appendingPathComponent("stdout")
        let stderr = directory.appendingPathComponent("stderr")
        try V2Backend.secureWrite(Data(), to: stdout); try V2Backend.secureWrite(Data(), to: stderr)
        let output = try FileHandle(forWritingTo: stdout); let errors = try FileHandle(forWritingTo: stderr)
        defer { try? output.close(); try? errors.close() }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        child.arguments = ["-e", script]
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        child.standardInput = FileHandle.nullDevice; child.standardOutput = output; child.standardError = errors
        lock.lock()
        if cancelled { lock.unlock(); throw SessionAuthorizationError.cancelled }
        process = child
        do { try child.run(); lock.unlock() }
        catch { lock.unlock(); throw SessionAuthorizationError.unavailable("無法開啟 macOS 管理員授權。") }
        defer {
            // Every exit path owns cleanup, including file I/O and oversized-output errors.
            if child.isRunning {
                child.terminate()
                Thread.sleep(forTimeInterval: 0.1)
                if child.isRunning { _ = Darwin.kill(child.processIdentifier, SIGKILL) }
            }
            child.waitUntilExit()
            lock.lock(); process = nil; lock.unlock()
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while child.isRunning {
            if wasCancelled || ProcessInfo.processInfo.systemUptime >= deadline {
                child.terminate()
                Thread.sleep(forTimeInterval: 0.1)
                if child.isRunning { _ = Darwin.kill(child.processIdentifier, SIGKILL) }
                if wasCancelled { throw SessionAuthorizationError.cancelled }
                throw SessionAuthorizationError.unavailable("管理員授權等候逾時，請按「授權」再試。")
            }
            for url in [stdout, stderr] {
                let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
                if size > SessionSocketClient.maximumFrameBytes {
                    child.terminate()
                    throw SessionAuthorizationError.invalidResponse("授權啟動回應過大。")
                }
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        child.waitUntilExit()
        if wasCancelled { throw SessionAuthorizationError.cancelled }
        let data = try Data(contentsOf: stdout)
        let errorData = try Data(contentsOf: stderr)
        guard data.count <= SessionSocketClient.maximumFrameBytes, errorData.count <= SessionSocketClient.maximumFrameBytes else {
            throw SessionAuthorizationError.invalidResponse("授權啟動回應過大。")
        }
        guard child.terminationStatus == 0 else {
            let text = String(data: errorData.isEmpty ? data : errorData, encoding: .utf8) ?? "管理員授權未能完成。"
            if text.contains("(-128)") || text.contains("User canceled") { throw SessionAuthorizationError.cancelled }
            throw SessionAuthorizationError.unavailable(String(text.prefix(6000)).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return data
    }
}
