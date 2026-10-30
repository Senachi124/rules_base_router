import Foundation
import Darwin

/// Bounded DNS parsing for observed replies. No HTTPS interception or SNI guessing.
enum DNSWire {
    struct Answer { let name: String; let address: String; let ttl: UInt32 }
    static func name(_ bytes: [UInt8], at cursor: inout Int) -> String? {
        var offset = cursor, labels: [String] = [], jumped = false, visited = Set<Int>()
        for _ in 0..<128 {
            guard offset < bytes.count, visited.insert(offset).inserted else { return nil }
            let size = Int(bytes[offset])
            if size & 0xc0 == 0xc0 {
                guard offset + 1 < bytes.count else { return nil }
                if !jumped { cursor = offset + 2 }; jumped = true
                offset = ((size & 0x3f) << 8) | Int(bytes[offset + 1]); continue
            }
            guard size & 0xc0 == 0, size <= 63 else { return nil }
            offset += 1
            if size == 0 { if !jumped { cursor = offset }; let value = labels.joined(separator: ".").lowercased(); return value.utf8.count <= 253 ? value : nil }
            guard offset + size <= bytes.count, let label = String(bytes: bytes[offset..<offset + size], encoding: .utf8) else { return nil }
            labels.append(label); offset += size
        }
        return nil
    }
    static func query(_ host: String, id: UInt16, ipv6: Bool = false) -> Data? {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for part in host.split(separator: ".") {
            let label = Array(part.utf8); guard !label.isEmpty, label.count <= 63 else { return nil }
            bytes.append(UInt8(label.count)); bytes.append(contentsOf: label)
        }
        bytes.append(contentsOf: [0, 0, ipv6 ? 28 : 1, 0, 1]); return Data(bytes)
    }
    static func question(_ data: Data) -> String? {
        let b = [UInt8](data); guard b.count >= 12, b[4] == 0, b[5] == 1 else { return nil }
        var p = 12; return name(b, at: &p)
    }
    static func identifier(_ data: Data) -> UInt16? { let b = [UInt8](data); return b.count >= 2 ? (UInt16(b[0]) << 8) | UInt16(b[1]) : nil }
    static func answers(_ data: Data) -> [Answer] {
        let b = [UInt8](data)
        guard b.count >= 12, b[2] & 0x80 != 0, b[2] & 0x02 == 0, b[3] & 0x0f == 0, b[4] == 0, b[5] == 1 else { return [] }
        var p = 12; guard let question = name(b, at: &p), p + 4 <= b.count else { return [] }; p += 4
        let count = (Int(b[6]) << 8) | Int(b[7]); guard count <= 256 else { return [] }
        var records: [(String, String, UInt32)] = [], aliases: [String: (target: String, ttl: UInt32)] = [:]
        for _ in 0..<count {
            guard let owner = name(b, at: &p), p + 10 <= b.count else { return [] }
            let type = (Int(b[p]) << 8) | Int(b[p+1]); let cls = (Int(b[p+2]) << 8) | Int(b[p+3])
            let ttl = (UInt32(b[p+4]) << 24) | (UInt32(b[p+5]) << 16) | (UInt32(b[p+6]) << 8) | UInt32(b[p+7])
            let size = (Int(b[p+8]) << 8) | Int(b[p+9]); p += 10
            guard p + size <= b.count else { return [] }
            if cls == 1 {
                if type == 1 && size == 4 { records.append((owner, b[p..<p+4].map(String.init).joined(separator: "."), ttl)) }
                if type == 28 && size == 16 {
                    var address = in6_addr(); withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: b[p..<p+16]) }
                    var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    if inet_ntop(AF_INET6, &address, &text, socklen_t(text.count)) != nil { records.append((owner, String(cString: text), ttl)) }
                }
                if type == 5 {
                    var offset = p
                    if let target = name(b, at: &offset), offset == p + size {
                        if let previous = aliases[owner] {
                            // Conflicting aliases make attribution unsafe. Duplicate records retain the shortest lifetime.
                            guard previous.target == target else { return [] }
                            aliases[owner] = (target, min(previous.ttl, ttl))
                        } else { aliases[owner] = (target, ttl) }
                    }
                }
            }
            p += size
        }
        var lifetimes: [String: UInt32] = [question: UInt32.max]
        var current = question, chainTTL = UInt32.max
        for _ in 0..<16 {
            guard let alias = aliases[current] else { break }
            guard lifetimes[alias.target] == nil else { return [] }
            chainTTL = min(chainTTL, alias.ttl)
            lifetimes[alias.target] = chainTTL
            current = alias.target
        }
        // A truncated alias chain is not a proven mapping to the question name.
        if aliases[current] != nil { return [] }
        return records.compactMap { owner, address, ttl in
            guard let lifetime = lifetimes[owner] else { return nil }
            return Answer(name: question, address: address, ttl: min(ttl, lifetime))
        }
    }
    static func isIP(_ host: String) -> Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return host.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }
}

final class DomainCache {
    private var records: [String: [String: Date]] = [:]
    private var overflowUntil: [String: Date] = [:]
    private let lock = NSLock()
    private let clock: () -> Date
    private let maxAddresses = 2048
    private let maxNamesPerAddress = 8

    init(clock: @escaping () -> Date = Date.init) { self.clock = clock }

    /// Useful for bounded-cache diagnostics. No hostnames or browsing data are exposed.
    var retainedRecordCount: Int {
        lock.lock(); defer { lock.unlock() }
        return records.values.reduce(0) { $0 + $1.count }
    }
    var retainedAddressCount: Int {
        lock.lock(); defer { lock.unlock() }
        return Set(records.keys).union(overflowUntil.keys).count
    }

    func observe(_ data: Data) {
        let answers = DNSWire.answers(data); lock.lock(); defer { lock.unlock() }
        let now = clock()
        records = records.mapValues { $0.filter { $0.value > now } }.filter { !$0.value.isEmpty }
        overflowUntil = overflowUntil.filter { $0.value > now }
        var retainedAddresses = Set(records.keys).union(overflowUntil.keys)
        for answer in answers where answer.ttl > 0 {
            let expiration = now.addingTimeInterval(TimeInterval(min(answer.ttl, 300)))
            if !retainedAddresses.contains(answer.address) && retainedAddresses.count >= maxAddresses { continue }
            retainedAddresses.insert(answer.address)
            var names = records[answer.address, default: [:]]
            if names[answer.name] != nil || names.count < maxNamesPerAddress {
                names[answer.name] = expiration
                records[answer.address] = names
            } else {
                // Remember ambiguity when names are dropped; otherwise expiry of retained names
                // could incorrectly make this address appear to belong to one remaining domain.
                overflowUntil[answer.address] = max(overflowUntil[answer.address] ?? expiration, expiration)
            }
        }
    }
    func hostname(for ip: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        let now = clock()
        guard overflowUntil[ip].map({ $0 <= now }) ?? true else { return nil }
        let active = records[ip, default: [:]].filter { $0.value > now }
        // Ambiguous CDN addresses must not be attributed to one arbitrary domain.
        return active.count == 1 ? active.keys.first : nil
    }
}
