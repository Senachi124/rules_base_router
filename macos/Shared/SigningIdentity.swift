import Foundation
import Security

enum SigningIdentity {
    static func fromStaticURL(_ url: URL) -> AppIdentity? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        return identity(code)
    }
    static func fromAuditToken(_ token: Data?) -> AppIdentity? {
        guard let token else { return nil }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit as String: token] as CFDictionary, [], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        return identity(staticCode)
    }
    private static func identity(_ code: SecStaticCode) -> AppIdentity? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let info = info as? [String: Any], let identifier = info[kSecCodeInfoIdentifier as String] as? String else { return nil }
        if let team = info[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty { return AppIdentity(signingID: identifier, teamID: team) }
        // Apple system apps often have no TeamIdentifier. Verify the Apple anchor first.
        var requirement: SecRequirement?
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
           SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess {
            return AppIdentity(signingID: identifier, teamID: "APPLE")
        }
        return nil
    }
    static func application(at url: URL) throws -> AppRule {
        guard let main = fromStaticURL(url) else { throw RouteBarError("暫時只支援有有效簽署嘅 App。") }
        var identities: Set<AppIdentity> = [main]
        let root = url.appendingPathComponent("Contents")
        if let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey], options: [.skipsHiddenFiles]) {
            for case let candidate as URL in files {
                guard let values = try? candidate.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]), values.isSymbolicLink != true else { continue }
                if ["app", "xpc", "appex"].contains(candidate.pathExtension) || (values.isRegularFile == true && FileManager.default.isExecutableFile(atPath: candidate.path)) {
                    if let identity = fromStaticURL(candidate), identity.teamID == main.teamID { identities.insert(identity) }
                }
            }
        }
        let name = (Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String) ?? url.deletingPathExtension().lastPathComponent
        return AppRule(name: name, path: url.path, identities: identities.sorted { $0.signingID < $1.signingID })
    }
}
