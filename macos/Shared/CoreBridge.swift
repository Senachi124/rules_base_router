import Foundation

enum CoreBridge {
    private struct Reply<T: Decodable>: Decodable { var ok: Bool; var value: T?; var error: String? }
    private static func decode<T: Decodable>(_ pointer: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let pointer else { throw RouteBarError("核心未有回應。") }
        defer { rb_string_free(pointer) }
        let reply = try JSONDecoder().decode(Reply<T>.self, from: Data(String(cString: pointer).utf8))
        guard reply.ok, let value = reply.value else { throw RouteBarError(reply.error ?? "核心操作失敗。") }
        return value
    }
    static func inspect(_ profile: String) throws -> ProfileSummary { try profile.withCString { try decode(rb_profile_inspect($0)) } }
    static func validate(_ policy: RoutingPolicy) throws -> RoutingPolicy {
        let json = String(decoding: try JSONEncoder().encode(policy), as: UTF8.self)
        return try json.withCString { try decode(rb_policy_validate($0)) }
    }
    static func evaluate(_ policy: RoutingPolicy, flow: FlowIdentity) throws -> RouteDecision {
        let p = String(decoding: try JSONEncoder().encode(policy), as: UTF8.self)
        let f = String(decoding: try JSONEncoder().encode(flow), as: UTF8.self)
        return try p.withCString { pp in try f.withCString { fp in try decode(rb_policy_evaluate(pp, fp)) } }
    }
}
