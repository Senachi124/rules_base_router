import Foundation
import Darwin

struct V2ServiceStatus: Decodable {
    let loaded: Bool
    let running: Bool
    let pid: Int
    let detail: String
    let foreground_unknown: Bool?
}

struct V2Configuration: Decodable {
    struct VPN: Decodable { let wireguard_config: String }
    struct DNS: Decodable { let server: String; let via: String; let strategy: String }
    struct Routing: Decodable { let `default`: String; let rules: [Rule] }
    struct Rule: Decodable {
        let name: String
        let match: Match
        let via: String
    }
    struct Match: Decodable {
        let apps: [String]
        let process_names: [String]
        let domains: [String]
        let domain_suffixes: [String]
        let ip_cidrs: [String]
        var summary: String {
            var parts: [String] = []
            let programs = apps + process_names
            if !programs.isEmpty { parts.append("App／Process: " + programs.joined(separator: " OR ")) }
            let destinations = domains + domain_suffixes.map { "." + $0 } + ip_cidrs
            if !destinations.isEmpty { parts.append("Destination: " + destinations.joined(separator: " OR ")) }
            return parts.joined(separator: "\nAND ")
        }
    }
    let version: Int
    let vpns: [String: VPN]
    let dns: DNS
    let routing: Routing
}

/// Non-privileged CLI utilities and the one-time session bootstrap command.
/// Private profiles travel only through SessionAuthorization's authenticated socket.
enum V2Backend {
    static var executable: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/routebar-v2") }
    static var engine: URL { executable.deletingLastPathComponent().appendingPathComponent("sing-box") }
    static var isAvailable: Bool {
        FileManager.default.isExecutableFile(atPath: executable.path) && FileManager.default.isExecutableFile(atPath: engine.path)
    }
    static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func appleScriptQuote(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
    }
    static func adminScript(executable: URL, arguments: [String]) -> String {
        let command = ([executable.path] + arguments).map(shellQuote).joined(separator: " ")
        return "do shell script " + appleScriptQuote(command) + " with administrator privileges"
    }
    static func command(_ arguments: [String]) async throws -> Data {
        let binary = executable
        return try await Task.detached(priority: .userInitiated) {
            guard FileManager.default.isExecutableFile(atPath: binary.path) else {
                throw RouteBarError("未搵到 Rust 網絡控制器。請重新執行 scripts/build-preview.sh。")
            }
            return try run(binary, arguments: arguments, timeout: 30)
        }.value
    }
    static func run(_ binary: URL, arguments: [String], timeout: TimeInterval) throws -> Data {
        let directory = try secureDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let stdoutURL = directory.appendingPathComponent("stdout")
        let stderrURL = directory.appendingPathComponent("stderr")
        try secureWrite(Data(), to: stdoutURL)
        try secureWrite(Data(), to: stderrURL)
        let output = try FileHandle(forWritingTo: stdoutURL)
        let errors = try FileHandle(forWritingTo: stderrURL)
        defer { try? output.close(); try? errors.close() }
        let process = Process()
        process.executableURL = binary; process.arguments = arguments
        process.standardOutput = output; process.standardError = errors
        process.standardInput = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning {
            process.terminate()
            throw RouteBarError("網絡控制器等候逾時；請重新整理服務狀態。")
        }
        process.waitUntilExit()
        let stdout = try Data(contentsOf: stdoutURL)
        let stderr = try Data(contentsOf: stderrURL)
        guard process.terminationStatus == 0 else {
            let errorData = stderr.isEmpty ? stdout : stderr
            let structured = (try? JSONSerialization.jsonObject(with: errorData)) as? [String: Any]
            let message = (structured?["error"] as? String) ?? String(data: errorData, encoding: .utf8) ?? "網絡服務執行失敗。"
            if message.contains("(-128)") { throw RouteBarError("已取消管理員授權；網絡服務未完成操作。") }
            throw RouteBarError(String(message.prefix(6000)).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return stdout
    }
    static func secureDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("RouteBar-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return directory
    }
    static func secureWrite(_ data: Data, to url: URL) throws {
        let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw RouteBarError("無法建立受保護嘅設定檔。") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do { try handle.write(contentsOf: data); try handle.synchronize(); try handle.close() }
        catch { try? handle.close(); try? FileManager.default.removeItem(at: url); throw error }
    }
    static func basicConfig(policy: RoutingPolicy, profilePath: String, dnsVia: String, dnsStrategy: String) -> [String: Any] {
        var rules: [[String: Any]] = []
        for app in policy.apps where app.enabled {
            rules.append(["name": "App: " + app.name + " " + app.id, "match": ["apps": [app.path]], "via": "vpn"])
        }
        for domain in policy.domains where domain.enabled {
            rules.append(["name": "Domain: " + domain.domain + " " + domain.id, "match": ["domain_suffixes": [domain.domain]], "via": "vpn"])
        }
        return ["version": 1, "vpns": ["vpn": ["wireguard_config": profilePath]],
                "dns": ["via": dnsVia, "strategy": dnsStrategy],
                "routing": ["default": policy.mode == "full" ? "vpn" : "direct", "rules": rules]]
    }
}
