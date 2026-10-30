import Foundation

struct VPNExit: Codable, Identifiable, Equatable {
    var id: String = "vpn_" + UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    var name: String = "VPN"
    var profilePath: String?
    var keychainID: String?
    var endpoint: String = ""
}

struct WhitelistMatch: Codable, Equatable {
    var apps: [String] = []
    var processNames: [String] = []
    var domains: [String] = []
    var domainSuffixes: [String] = []
    var ipCIDRs: [String] = []
    enum CodingKeys: String, CodingKey {
        case apps, processNames = "process_names", domains
        case domainSuffixes = "domain_suffixes", ipCIDRs = "ip_cidrs"
    }
    var hasApplications: Bool { !apps.isEmpty || !processNames.isEmpty }
    var hasDestinations: Bool { !domains.isEmpty || !domainSuffixes.isEmpty || !ipCIDRs.isEmpty }
    var isEmpty: Bool { !hasApplications && !hasDestinations }
    var applicationSummary: String {
        (apps.map { URL(fileURLWithPath: $0).lastPathComponent } + processNames).joined(separator: "、")
    }
    var destinationSummary: String {
        (domains + domainSuffixes.map { "*." + $0 } + ipCIDRs).joined(separator: "、")
    }
    var summary: String {
        if hasApplications && hasDestinations { return applicationSummary + " · 只限 " + destinationSummary }
        return hasApplications ? applicationSummary : destinationSummary
    }
    var engineMatch: [String: Any] {
        ["apps": apps, "process_names": processNames, "domains": domains,
         "domain_suffixes": domainSuffixes, "ip_cidrs": ipCIDRs]
    }
}

struct WhitelistRule: Codable, Identifiable, Equatable {
    var id: String = UUID().uuidString
    var name: String = "新規則"
    var enabled: Bool = true
    var via: String = "direct"
    var match: WhitelistMatch = WhitelistMatch()
}

struct WhitelistDocument: Codable, Equatable {
    var profiles: [VPNExit] = []
    var rules: [WhitelistRule] = []
    var dnsVia: String = "direct"
    var dnsStrategy: String = "auto"
    var dnsServer: String = ""
    var defaultVia: String = "direct"
    var preferredExitID: String = ""

    var enabledRuleCount: Int { rules.filter(\.enabled).count }
    var preferredExit: VPNExit? { profiles.first { $0.id == preferredExitID } ?? profiles.first }
    func exitName(_ id: String) -> String { id == "direct" ? "直連" : profiles.first { $0.id == id }?.name ?? id }

    /// Rules stay ordered. App selectors are OR, destinations are OR, and the
    /// two groups remain AND. Only the per-rule enabled switch filters rules.
    func engineConfig(profilePaths: [String: String] = [:]) -> [String: Any] {
        var vpns: [String: Any] = [:]
        for profile in profiles {
            vpns[profile.id] = ["wireguard_config": profilePaths[profile.id] ?? profile.profilePath ?? ""]
        }
        let activeRules: [[String: Any]] = rules.filter(\.enabled).map {
            ["name": $0.name, "match": $0.match.engineMatch, "via": $0.via]
        }
        return ["version": 1, "vpns": vpns,
                "dns": ["via": dnsVia, "strategy": dnsStrategy, "server": dnsServer],
                "routing": ["default": defaultVia, "rules": activeRules]]
    }
}

extension WhitelistMatch {
    init(imported value: V2Configuration.Match) {
        self.init(apps: value.apps, processNames: value.process_names, domains: value.domains,
                  domainSuffixes: value.domain_suffixes, ipCIDRs: value.ip_cidrs)
    }
}

extension WhitelistDocument {
    init(imported config: V2Configuration) {
        self.init()
        profiles = config.vpns.keys.sorted().map { id in
            VPNExit(id: id, name: id, profilePath: config.vpns[id]!.wireguard_config, endpoint: "")
        }
        rules = config.routing.rules.map { WhitelistRule(name: $0.name, via: $0.via, match: WhitelistMatch(imported: $0.match)) }
        dnsVia = config.dns.via; dnsStrategy = config.dns.strategy; dnsServer = config.dns.server
        defaultVia = config.routing.default
        preferredExitID = rules.first(where: { $0.via != "direct" })?.via ?? profiles.first?.id ?? ""
    }

    static func migrated(profile: SavedProfile?, policy: RoutingPolicy, dnsVia: String = "direct", dnsStrategy: String = "auto") -> WhitelistDocument {
        var document = WhitelistDocument()
        if let profile {
            document.profiles = [VPNExit(id: "vpn", name: profile.name, keychainID: profile.id, endpoint: profile.summary.endpointHost)]
            document.preferredExitID = "vpn"
        }
        let via = profile == nil ? "direct" : "vpn"
        func uniqueName(_ proposed: String) -> String {
            var name = proposed; var index = 2
            while document.rules.contains(where: { $0.name == name }) { name = "\(proposed) (\(index))"; index += 1 }
            return name
        }
        for app in policy.apps {
            document.rules.append(WhitelistRule(id: app.id, name: uniqueName(app.name), enabled: profile != nil && app.enabled, via: via, match: WhitelistMatch(apps: [app.path])))
        }
        for domain in policy.domains {
            document.rules.append(WhitelistRule(id: domain.id, name: uniqueName(domain.domain), enabled: profile != nil && domain.enabled, via: via, match: WhitelistMatch(domainSuffixes: [domain.domain])))
        }
        document.defaultVia = policy.mode == "full" && profile != nil ? "vpn" : "direct"
        document.dnsVia = dnsVia == "vpn" && profile != nil ? "vpn" : "direct"
        document.dnsStrategy = dnsStrategy
        return document
    }
}
