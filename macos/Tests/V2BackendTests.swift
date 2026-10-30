import Foundation

@main
enum V2BackendTests {
    static func main() throws {
        try testShellQuoting()
        testAppleScriptQuoting()
        try testPrivateStaging()
        try testBasicPolicyTranslation()
        try testStatusDecode()
        print("Swift v2 command quoting, private staging, rule translation and status tests passed")
    }
    private static func testShellQuoting() throws {
        let values = ["plain", "/tmp/has space", "a'b", "$(echo injection)", "`echo injection`", "a\"b\\c", "line\nbreak", "semi; colon & >"]
        for value in values {
            let process = Process(); let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", "printf '%s' " + V2Backend.shellQuote(value)]
            process.standardOutput = pipe
            try process.run()
            let result = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            assert(process.terminationStatus == 0)
            assert(String(data: result, encoding: .utf8) == value, "Shell argument changed or expanded")
        }
    }
    private static func testAppleScriptQuoting() {
        assert(V2Backend.appleScriptQuote("a\"b\\c\nd\re") == "\"a\\\"b\\\\c\\nd\\re\"")
        let script = V2Backend.adminScript(executable: URL(fileURLWithPath: "/tmp/User's App/routebar-v2"), arguments: ["up", "-c", "/tmp/$(evil)/config.yaml"])
        assert(script.hasPrefix("do shell script \""))
        assert(script.hasSuffix("with administrator privileges"))
        assert(script.contains("'$(evil)") == false)
        assert(script.contains("'/tmp/$(evil)/config.yaml'"))
    }
    private static func testPrivateStaging() throws {
        let directory = try V2Backend.secureDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let directoryMode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as! NSNumber
        assert(directoryMode.intValue == 0o700)
        let file = directory.appendingPathComponent("profile.conf")
        try V2Backend.secureWrite(Data("secret".utf8), to: file)
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as! NSNumber
        assert(mode.intValue == 0o600)
        do { try V2Backend.secureWrite(Data("overwrite".utf8), to: file); assertionFailure("Overwrote an existing file") } catch { }
        let link = directory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        do { try V2Backend.secureWrite(Data("overwrite".utf8), to: link); assertionFailure("Followed symlink") } catch { }
        let contents = try String(contentsOf: file, encoding: .utf8)
        assert(contents == "secret")
    }
    private static func testBasicPolicyTranslation() throws {
        var policy = RoutingPolicy()
        policy.apps = [AppRule(name: "Example", path: "/Applications/Example.app", identities: [])]
        policy.domains = [DomainRule(domain: "example.com"), DomainRule(domain: "disabled.example", enabled: false)]
        let config = V2Backend.basicConfig(policy: policy, profilePath: "/tmp/private/profile.conf", dnsVia: "direct", dnsStrategy: "auto")
        let routing = config["routing"] as! [String: Any]
        let rules = routing["rules"] as! [[String: Any]]
        assert(routing["default"] as! String == "direct")
        assert(rules.count == 2)
        assert((rules[0]["match"] as! [String: [String]])["apps"] == ["/Applications/Example.app"])
        assert((rules[1]["match"] as! [String: [String]])["domain_suffixes"] == ["example.com"])
        assert((config["dns"] as! [String: String])["via"] == "direct")
        policy.mode = "full"
        let full = V2Backend.basicConfig(policy: policy, profilePath: "/tmp/private/profile.conf", dnsVia: "vpn", dnsStrategy: "ipv4_only")
        assert((full["routing"] as! [String: Any])["default"] as! String == "vpn")
        let serialized = try JSONSerialization.data(withJSONObject: full)
        assert(!String(data: serialized, encoding: .utf8)!.contains("private_key"))
    }
    private static func testStatusDecode() throws {
        let data = Data(#"{"loaded":true,"running":false,"pid":0,"detail":"loaded"}"#.utf8)
        let status = try JSONDecoder().decode(V2ServiceStatus.self, from: data)
        assert(status.loaded && !status.running && status.foreground_unknown == nil)
    }
}
