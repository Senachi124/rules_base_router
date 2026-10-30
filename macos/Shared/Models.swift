import Foundation

struct AppIdentity: Codable, Hashable {
    var signingID: String
    var teamID: String
    enum CodingKeys: String, CodingKey { case signingID = "signing_id", teamID = "team_id" }
}
struct AppRule: Codable, Identifiable {
    var id = UUID().uuidString
    var name: String
    var path: String
    var enabled = true
    var identities: [AppIdentity]
}
struct DomainRule: Codable, Identifiable {
    var id = UUID().uuidString
    var domain: String
    var enabled = true
}
struct RoutingPolicy: Codable {
    var mode = "whitelist"
    var apps: [AppRule] = []
    var domains: [DomainRule] = []
    var enabledCount: Int { apps.filter(\.enabled).count + domains.filter(\.enabled).count }
}
struct ProfileSummary: Codable {
    var endpointHost: String
    var endpointPort: UInt16
    var addresses: [String]
    var dns: [String]
    var mtu: UInt16
    var hasIpv6: Bool
    enum CodingKeys: String, CodingKey {
        case endpointHost = "endpoint_host", endpointPort = "endpoint_port", addresses, dns, mtu, hasIpv6 = "has_ipv6"
    }
}
struct SavedProfile: Codable, Identifiable {
    var id = UUID().uuidString
    var name: String
    var summary: ProfileSummary
}
struct FlowIdentity: Codable {
    var signingID: String
    var teamID: String
    var hostname: String?
    enum CodingKeys: String, CodingKey { case signingID = "signing_id", teamID = "team_id", hostname }
}
struct RouteDecision: Codable { var route: String; var reason: String }
struct DiagnosticEntry: Codable, Identifiable {
    var id = UUID().uuidString
    var date = Date()
    var application: String
    var destination: String
    var route: String
    var reason: String
}
struct RouteBarError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
