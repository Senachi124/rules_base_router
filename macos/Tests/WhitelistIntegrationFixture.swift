import Foundation

/// Emits engine configurations using the same import, persistence and conversion
/// APIs as the application. scripts/test-whitelist-integration.py validates the
/// results with the actual Rust controller and bundled engine schema checker.
@main
struct WhitelistIntegrationFixture {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw RouteBarError("Usage: whitelist-fixture normalized-config.json")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let imported = try JSONDecoder().decode(V2Configuration.self, from: data)
        let document = WhitelistDocument(imported: imported)
        guard document.rules.count == 3, document.profiles.count == 2 else {
            throw RouteBarError("Fixture import unexpectedly changed rule/profile counts")
        }
        // Exercise exactly the Codable representation persisted by the UI.
        let persisted = try JSONEncoder().encode(document)
        let baseline = try JSONDecoder().decode(WhitelistDocument.self, from: persisted)
        guard baseline == document else {
            throw RouteBarError("Unified whitelist persistence changed the document")
        }
        var disabledCompound = baseline
        disabledCompound.rules[1].enabled = false
        var disabledFallback = baseline
        disabledFallback.rules[2].enabled = false
        var selectedExit = baseline
        selectedExit.rules[1].via = "usa"
        var reordered = baseline
        reordered.rules.swapAt(1, 2)
        // Keychain-backed profiles use a temporary staging path at connection
        // time; explicit paths must override metadata without altering rules.
        let stagedPaths = Dictionary(uniqueKeysWithValues: baseline.profiles.map { ($0.id, $0.profilePath!) })
        var staged = baseline
        for index in staged.profiles.indices { staged.profiles[index].profilePath = "/unavailable/profile.conf" }
        let cases: [String: Any] = [
            "baseline": baseline.engineConfig(),
            "disabled_compound": disabledCompound.engineConfig(),
            "disabled_fallback": disabledFallback.engineConfig(),
            "selected_exit": selectedExit.engineConfig(),
            "reordered": reordered.engineConfig(),
            "staged_profiles": staged.engineConfig(profilePaths: stagedPaths),
        ]
        let encoded = try JSONSerialization.data(withJSONObject: cases, options: [.sortedKeys])
        FileHandle.standardOutput.write(encoded)
    }
}
