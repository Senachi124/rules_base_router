import Foundation

@main
enum SmokeTests {
    static func main() throws {
        var policy = RoutingPolicy()
        policy.domains = [DomainRule(domain: "*.EXAMPLE.com.")]
        policy = try CoreBridge.validate(policy)
        assert(policy.domains[0].domain == "example.com")
        let selected = try CoreBridge.evaluate(policy, flow: FlowIdentity(signingID: "", teamID: "", hostname: "www.example.com"))
        assert(selected.route == "vpn")
        let unrelated = try CoreBridge.evaluate(policy, flow: FlowIdentity(signingID: "", teamID: "", hostname: "evil-example.com"))
        assert(unrelated.route == "direct")
        let unknown = try CoreBridge.evaluate(policy, flow: FlowIdentity(signingID: "", teamID: "", hostname: nil))
        assert(unknown.route == "direct")
        for _ in 0..<1000 { _ = try CoreBridge.validate(policy) }
        let query = DNSWire.query("example.com", id: 0x1234)!
        assert(DNSWire.identifier(query) == 0x1234)
        assert(DNSWire.question(query) == "example.com")
        var reply = [UInt8](query)
        reply[2] = 0x81; reply[3] = 0x80; reply[7] = 1
        reply += [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]
        let answers = DNSWire.answers(Data(reply))
        assert(answers.count == 1 && answers[0].name == "example.com" && answers[0].address == "203.0.113.9")
        let cache = DomainCache(); cache.observe(Data(reply)); assert(cache.hostname(for: "203.0.113.9") == "example.com")
        var invalid = [UInt8](repeating: 0, count: 16); invalid[4] = 0; invalid[5] = 1; invalid[12] = 0xc0; invalid[13] = 12
        assert(DNSWire.question(Data(invalid)) == nil)
        for end in 0..<reply.count { _ = DNSWire.answers(Data(reply.prefix(end))) }
        assert(DNSWire.isIP("127.0.0.1") && DNSWire.isIP("::1") && !DNSWire.isIP("example.com"))
        testAliasLifetimes()
        testBoundedCacheAmbiguity()
        do { _ = try CoreBridge.inspect("[Interface]\nPrivateKey = invalid\n"); assertionFailure("Invalid profile accepted") } catch { }
        print("Swift/C ABI + domain policy + DNS parser/cache tests passed")
    }

    private static func encodedName(_ name: String) -> [UInt8] {
        name.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
    }
    private static func record(_ name: String, type: UInt16, ttl: UInt32, payload: [UInt8]) -> [UInt8] {
        encodedName(name) + [UInt8(type >> 8), UInt8(type & 255), 0, 1,
                            UInt8((ttl >> 24) & 255), UInt8((ttl >> 16) & 255), UInt8((ttl >> 8) & 255), UInt8(ttl & 255),
                            UInt8(payload.count >> 8), UInt8(payload.count & 255)] + payload
    }
    private static func response(_ question: String, records: [[UInt8]]) -> Data {
        var result = [UInt8](DNSWire.query(question, id: 42)!)
        result[2] = 0x81; result[3] = 0x80
        result[6] = UInt8(records.count >> 8); result[7] = UInt8(records.count & 255)
        for record in records { result += record }
        return Data(result)
    }
    private static func addressResponse(_ host: String, ttl: UInt32, ip: [UInt8] = [203, 0, 113, 9]) -> Data {
        response(host, records: [record(host, type: 1, ttl: ttl, payload: ip)])
    }
    private static func testAliasLifetimes() {
        let alias = response("selected.example", records: [
            record("selected.example", type: 5, ttl: 60, payload: encodedName("middle.example")),
            record("middle.example", type: 5, ttl: 2, payload: encodedName("cdn.example")),
            record("cdn.example", type: 1, ttl: 300, payload: [203, 0, 113, 9])
        ])
        let answers = DNSWire.answers(alias)
        assert(answers.count == 1 && answers[0].name == "selected.example" && answers[0].ttl == 2,
               "CNAME attribution must expire with the shortest link, not the terminal address TTL")
        var now = Date(timeIntervalSince1970: 10_000)
        let cache = DomainCache(clock: { now })
        cache.observe(alias)
        assert(cache.hostname(for: "203.0.113.9") == "selected.example")
        now += 3
        assert(cache.hostname(for: "203.0.113.9") == nil, "Expired aliases must not continue routing an IP")
        let zeroTTL = response("selected.example", records: [
            record("selected.example", type: 5, ttl: 0, payload: encodedName("cdn.example")),
            record("cdn.example", type: 1, ttl: 300, payload: [203, 0, 113, 9])
        ])
        cache.observe(zeroTTL)
        assert(cache.hostname(for: "203.0.113.9") == nil, "Zero-TTL aliases must not populate the cache")
        let cycle = response("selected.example", records: [
            record("selected.example", type: 5, ttl: 60, payload: encodedName("cdn.example")),
            record("cdn.example", type: 5, ttl: 60, payload: encodedName("selected.example")),
            record("cdn.example", type: 1, ttl: 300, payload: [203, 0, 113, 9])
        ])
        assert(DNSWire.answers(cycle).isEmpty, "Cyclic aliases must not produce an attributable address")
    }
    private static func testBoundedCacheAmbiguity() {
        var now = Date(timeIntervalSince1970: 20_000)
        let cache = DomainCache(clock: { now })
        cache.observe(addressResponse("long-lived.example", ttl: 300))
        for i in 0..<7 { cache.observe(addressResponse("short-\(i).example", ttl: 1)) }
        cache.observe(addressResponse("overflow.example", ttl: 60))
        for i in 0..<500 { cache.observe(addressResponse("other-\(i).example", ttl: 60)) }
        assert(cache.retainedRecordCount <= 8, "One shared IP must not retain an unbounded set of names")
        now += 2
        assert(cache.hostname(for: "203.0.113.9") == nil,
               "Dropping overflow names must preserve ambiguity when the retained short-lived records expire")
        now += 60
        assert(cache.hostname(for: "203.0.113.9") == "long-lived.example",
               "Attribution can resume after all overflow mappings expire")
        let manyAddresses = DomainCache(clock: { now })
        for i in 0..<8 { manyAddresses.observe(addressResponse("expired-\(i).example", ttl: 1)) }
        manyAddresses.observe(addressResponse("remaining-overflow.example", ttl: 60))
        now += 2
        for i in 0..<2100 {
            manyAddresses.observe(addressResponse("host-\(i).example", ttl: 60, ip: [198, 18, UInt8(i >> 8), UInt8(i & 255)]))
        }
        assert(manyAddresses.retainedAddressCount <= 2048, "Distinct addresses including overflow markers must remain bounded")
        assert(manyAddresses.retainedRecordCount <= 2047, "An overflow marker still consumes one address slot after its names expire")
    }
}
