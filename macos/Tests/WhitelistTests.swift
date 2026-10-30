import Foundation

@main
enum WhitelistTests {
    static func main() throws {
        try legacyMigration()
        try missingExitKeepsDrafts()
        try persistenceKeepsEditingState()
        print("Unified whitelist legacy migration and persistence tests passed")
    }
    private static func profile() -> SavedProfile {
        SavedProfile(id: "existing-keychain-id", name: "Japan", summary: ProfileSummary(endpointHost: "jp.example.com", endpointPort: 51820, addresses: ["10.1.0.2/32"], dns: ["1.1.1.1"], mtu: 1400, hasIpv6: false))
    }
    private static func legacyMigration() throws {
        var policy = RoutingPolicy()
        policy.mode = "full"
        policy.apps = [AppRule(id: "app-1", name: "Browser", path: "/Applications/Browser.app", enabled: false, identities: []),
                       AppRule(id: "app-2", name: "Browser", path: "/Applications/Other Browser.app", enabled: true, identities: [])]
        policy.domains = [DomainRule(id: "domain-1", domain: "example.com", enabled: true)]
        let migrated = WhitelistDocument.migrated(profile: profile(), policy: policy, dnsVia: "vpn", dnsStrategy: "ipv4_only")
        assert(migrated.profiles.count == 1)
        assert(migrated.profiles[0].keychainID == "existing-keychain-id")
        assert(migrated.profiles[0].profilePath == nil)
        assert(migrated.preferredExitID == "vpn")
        assert(migrated.defaultVia == "vpn" && migrated.dnsVia == "vpn" && migrated.dnsStrategy == "ipv4_only")
        assert(migrated.rules.map(\.id) == ["app-1", "app-2", "domain-1"])
        assert(migrated.rules.map(\.enabled) == [false, true, true])
        assert(migrated.rules[0].match.apps == ["/Applications/Browser.app"])
        assert(migrated.rules[1].name == "Browser (2)")
        assert(migrated.rules[2].match.domainSuffixes == ["example.com"])
        assert(migrated.rules.allSatisfy { $0.via == "vpn" })
        let config = migrated.engineConfig(profilePaths: ["vpn": "/protected/profile.conf"])
        let rules = (config["routing"] as! [String: Any])["rules"] as! [[String: Any]]
        assert(rules.count == 2, "Disabled legacy rules must stay disabled after migration")
        assert((config["vpns"] as! [String: [String: String]])["vpn"]?["wireguard_config"] == "/protected/profile.conf")
    }
    private static func missingExitKeepsDrafts() throws {
        var policy = RoutingPolicy()
        policy.mode = "full"
        policy.apps = [AppRule(name: "Example", path: "/Applications/Example.app", identities: [])]
        policy.domains = [DomainRule(domain: "example.com")]
        let migrated = WhitelistDocument.migrated(profile: nil, policy: policy, dnsVia: "vpn")
        assert(migrated.profiles.isEmpty && migrated.preferredExitID.isEmpty)
        assert(migrated.defaultVia == "direct" && migrated.dnsVia == "direct")
        assert(migrated.rules.count == 2 && migrated.rules.allSatisfy { !$0.enabled })
        assert(migrated.rules[0].match.apps == ["/Applications/Example.app"])
        assert(migrated.rules[1].match.domainSuffixes == ["example.com"])
    }
    private static func persistenceKeepsEditingState() throws {
        let document = WhitelistDocument(profiles: [VPNExit(id: "japan", name: "Japan", profilePath: "/profiles/japan.conf")],
            rules: [WhitelistRule(id: "rule-id", name: "Browser websites", enabled: false, via: "japan",
                match: WhitelistMatch(apps: ["/Applications/Browser.app"], processNames: ["Helper"], domains: ["exact.example"], domainSuffixes: ["example.com"], ipCIDRs: ["203.0.113.0/24"]))],
            dnsVia: "japan", dnsStrategy: "ipv4_only", dnsServer: "1.1.1.1", defaultVia: "direct", preferredExitID: "japan")
        let encoded = try JSONEncoder().encode(document)
        let restored = try JSONDecoder().decode(WhitelistDocument.self, from: encoded)
        assert(restored == document)
        assert(restored.rules[0].match.hasApplications && restored.rules[0].match.hasDestinations)
        assert(restored.rules[0].match.summary.contains("只限"))
        assert(!String(data: encoded, encoding: .utf8)!.contains("private_key"))
        assert(restored.preferredExit?.id == "japan")
    }
}
