import Foundation
import Security

enum KeychainStore {
    private static func query(_ id: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.routebar.wireguard", kSecAttrAccount as String: id,
            kSecUseDataProtectionKeychain as String: Bundle.main.object(forInfoDictionaryKey: "RouteBarBuildChannel") as? String != "DevelopmentPreview"]
        if let group = Bundle.main.object(forInfoDictionaryKey: "RouteBarKeychainGroup") as? String,
           group != "com.routebar.shared", !group.contains("$("), !group.isEmpty {
            q[kSecAttrAccessGroup as String] = group
        }
        return q
    }
    static func save(_ profile: String, id: String) throws {
        let q = query(id)
        let attributes: [String: Any] = [kSecValueData as String: Data(profile.utf8), kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let update = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var insert = q; attributes.forEach { insert[$0.key] = $0.value }
            let status = SecItemAdd(insert as CFDictionary, nil)
            guard status == errSecSuccess else { throw RouteBarError("Keychain 寫入失敗（\(status)）。") }
        } else if update != errSecSuccess { throw RouteBarError("Keychain 更新失敗（\(update)）。") }
    }
    static func load(_ id: String) throws -> String {
        var q = query(id); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let value = String(data: data, encoding: .utf8) else { throw RouteBarError("無法讀取 VPN 設定檔（Keychain \(status)）。請重新匯入。") }
        return value
    }
    static func delete(_ id: String) throws {
        let status = SecItemDelete(query(id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw RouteBarError("無法刪除 Keychain 設定（\(status)）。") }
    }
}
