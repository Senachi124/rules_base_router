import Darwin
import Foundation

@main
enum SessionAuthorizationTests {
    static func main() throws {
        try testProtocolAndLimits()
        try testFragmentedSocketReply()
        try testRejectsWrongPeerBeforeSending()
        try testClosedSocketAndDeadline()
        try testOversizedReply()
        print("Session authorization protocol, peer identity, framing, limits and timeout tests passed (no root or VPN)")
    }

    private static func expectFailure(_ invalidates: Bool, _ operation: () throws -> Void) {
        do { try operation(); assertionFailure("Operation unexpectedly succeeded") }
        catch let error as SessionAuthorizationError { assert(error.invalidatesSession == invalidates) }
        catch { assertionFailure("Unexpected failure type: \(error)") }
    }
    private static func testProtocolAndLimits() throws {
        let endpoint = try SessionEndpoint.make()
        assert(endpoint.id.count == 32 && endpoint.id.allSatisfy { $0.isNumber || ("a"..."f").contains(String($0)) })
        assert(endpoint.path == "/private/var/db/routebar-s-\(getuid())-\(endpoint.id)/control.sock")
        let bytes = try SessionSocketClient.requestData(endpoint: endpoint, command: "up", config: ["version": 1], profiles: ["jp": "secret-profile"], lines: nil)
        assert(bytes.last == 10)
        let parsed = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        assert(parsed["session_id"] as? String == endpoint.id)
        assert((parsed["profiles"] as? [String: String])?["jp"] == "secret-profile")
        expectFailure(false) { _ = try SessionSocketClient.requestData(endpoint: endpoint, command: "shell") }
        expectFailure(false) { _ = try SessionSocketClient.requestData(endpoint: endpoint, command: "up", profiles: ["jp": String(repeating: "x", count: SessionSocketClient.maximumFrameBytes)]) }
        let bootstrap = try JSONSerialization.data(withJSONObject: ["socket_path": endpoint.path, "session_id": endpoint.id, "protocol": 1])
        try SessionSocketClient.verifyBootstrap(bootstrap, endpoint: endpoint)
        let wrongPath = try JSONSerialization.data(withJSONObject: ["socket_path": "/tmp/attacker", "session_id": endpoint.id, "protocol": 1])
        expectFailure(true) { try SessionSocketClient.verifyBootstrap(wrongPath, endpoint: endpoint) }
        let wrongVersion = try JSONSerialization.data(withJSONObject: ["socket_path": endpoint.path, "session_id": endpoint.id, "protocol": true])
        expectFailure(true) { try SessionSocketClient.verifyBootstrap(wrongVersion, endpoint: endpoint) }
        let ping = try JSONSerialization.data(withJSONObject: ["session_id": endpoint.id, "protocol": 1])
        try SessionSocketClient.verifyPing(ping, endpoint: endpoint)
        expectFailure(true) { try SessionSocketClient.verifyPing(Data(#"{"session_id":"wrong","protocol":1}"#.utf8), endpoint: endpoint) }
        let result = try SessionSocketClient.responseResult(Data(#"{"ok":true,"result":{"running":true}}"#.utf8))
        let resultObject = try JSONSerialization.jsonObject(with: result) as? [String: Bool]
        assert(resultObject?["running"] == true)
        let scalar = try SessionSocketClient.responseResult(Data(#"{"ok":true,"result":"log line"}"#.utf8))
        let scalarObject = try JSONSerialization.jsonObject(with: scalar, options: [.fragmentsAllowed]) as? String
        assert(scalarObject == "log line")
        expectFailure(false) { _ = try SessionSocketClient.responseResult(Data(#"{"ok":false,"error":"existing VPN conflict"}"#.utf8)) }
        for invalid in [#"{"ok":1,"result":{}}"#, #"{"ok":true}"#, #"{"ok":false}"#, "[]", "not JSON"] {
            expectFailure(true) { _ = try SessionSocketClient.responseResult(Data(invalid.utf8)) }
        }
    }
    private static func testFragmentedSocketReply() throws {
        let fixture = try SocketFixture { descriptor, received in
            received.value = readRequest(descriptor)
            for chunk in ["{\"ok\":true,", "\"result\":{\"running\":true", "}}\n"] {
                sendAll(descriptor, Data(chunk.utf8)); Thread.sleep(forTimeInterval: 0.01)
            }
        }
        defer { fixture.finish() }
        let request = try SessionSocketClient.requestData(endpoint: fixture.endpoint, command: "status")
        let result = try SessionSocketClient.exchange(endpoint: fixture.endpoint, payload: request, timeout: 2, expectedPeerUID: getuid())
        let decoded = try JSONSerialization.jsonObject(with: result) as! [String: Bool]
        assert(decoded["running"] == true)
        fixture.finish()
        assert(fixture.received.value == request)
    }
    private static func testRejectsWrongPeerBeforeSending() throws {
        let fixture = try SocketFixture { descriptor, received in received.value = readRequest(descriptor) }
        defer { fixture.finish() }
        let request = try SessionSocketClient.requestData(endpoint: fixture.endpoint, command: "up", profiles: ["jp": "do-not-send"])
        expectFailure(true) {
            _ = try SessionSocketClient.exchange(endpoint: fixture.endpoint, payload: request, timeout: 1, expectedPeerUID: getuid() == 0 ? 501 : 0)
        }
        fixture.finish()
        assert(fixture.received.value.isEmpty, "A failed peer identity check must send no profile bytes")
    }
    private static func testClosedSocketAndDeadline() throws {
        let closed = try SocketFixture { descriptor, _ in _ = readRequest(descriptor) }
        defer { closed.finish() }
        let request = try SessionSocketClient.requestData(endpoint: closed.endpoint, command: "status")
        expectFailure(true) { _ = try SessionSocketClient.exchange(endpoint: closed.endpoint, payload: request, timeout: 1, expectedPeerUID: getuid()) }
        let delayed = try SocketFixture { descriptor, _ in _ = readRequest(descriptor); Thread.sleep(forTimeInterval: 0.3) }
        defer { delayed.finish() }
        let start = ProcessInfo.processInfo.systemUptime
        expectFailure(true) { _ = try SessionSocketClient.exchange(endpoint: delayed.endpoint, payload: request, timeout: 0.05, expectedPeerUID: getuid()) }
        assert(ProcessInfo.processInfo.systemUptime - start < 0.25, "Socket deadline was not enforced")
    }
    private static func testOversizedReply() throws {
        let fixture = try SocketFixture { descriptor, _ in
            _ = readRequest(descriptor)
            sendAll(descriptor, Data(repeating: 65, count: SessionSocketClient.maximumFrameBytes + 1))
        }
        defer { fixture.finish() }
        let request = try SessionSocketClient.requestData(endpoint: fixture.endpoint, command: "status")
        expectFailure(true) { _ = try SessionSocketClient.exchange(endpoint: fixture.endpoint, payload: request, timeout: 2, expectedPeerUID: getuid()) }
        let multiple = try SocketFixture { descriptor, _ in
            _ = readRequest(descriptor)
            sendAll(descriptor, Data("{\"ok\":true,\"result\":{}}\n{}\n".utf8))
        }
        defer { multiple.finish() }
        expectFailure(true) { _ = try SessionSocketClient.exchange(endpoint: multiple.endpoint, payload: request, timeout: 2, expectedPeerUID: getuid()) }
    }
    private static func readRequest(_ descriptor: Int32) -> Data {
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 1024)
        while result.count < SessionSocketClient.maximumFrameBytes {
            let count = recv(descriptor, &buffer, buffer.count, 0)
            if count <= 0 { break }
            result.append(contentsOf: buffer.prefix(count))
            if result.contains(10) { break }
        }
        return result
    }
    private static func sendAll(_ descriptor: Int32, _ bytes: Data) {
        bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = send(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset, 0)
                if count <= 0 { return }
                offset += count
            }
        }
    }
}

private final class ReceivedBytes: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = Data()
    var value: Data { get { lock.lock(); defer { lock.unlock() }; return stored } set { lock.lock(); stored = newValue; lock.unlock() } }
}
private final class SocketFixture {
    let endpoint: SessionEndpoint
    let received = ReceivedBytes()
    private let directory: URL
    private let descriptor: Int32
    private let completed = DispatchSemaphore(value: 0)
    private var finished = false
    init(handler: @escaping @Sendable (Int32, ReceivedBytes) -> Void) throws {
        directory = URL(fileURLWithPath: "/tmp/rb-session-test-" + UUID().uuidString.prefix(12))
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        endpoint = SessionEndpoint(id: "0123456789abcdef0123456789abcdef", path: directory.appendingPathComponent("s").path)
        descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        assert(descriptor >= 0)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(endpoint.path.utf8) + [0]) }
        let bound = withUnsafePointer(to: &address) { pointer in pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        assert(bound == 0 && listen(descriptor, 1) == 0)
        let listener = descriptor; let received = received; let completed = completed
        DispatchQueue.global(qos: .userInitiated).async {
            let client = accept(listener, nil, nil)
            if client >= 0 {
                var noSignal: Int32 = 1
                _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
                var timeout = timeval(tv_sec: 2, tv_usec: 0)
                _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                _ = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                handler(client, received)
                close(client)
            }
            completed.signal()
        }
    }
    func finish() {
        guard !finished else { return }; finished = true
        assert(completed.wait(timeout: .now() + 3) == .success, "Socket fixture did not finish")
        close(descriptor); try? FileManager.default.removeItem(at: directory)
    }
    deinit { finish() }
}
