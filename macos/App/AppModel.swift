import AppKit
import Combine
import Foundation
import UniformTypeIdentifiers

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var document = WhitelistDocument()
    @Published var selectedSection = 0
    @Published var error: String?
    @Published private(set) var isBusy = false
    @Published private(set) var hasUnappliedChanges = false
    let vpn = VPNController()
    private let preferences: UserDefaults
    private let documentKey = "routebar.whitelist.document.v1"
    private let appliedKey = "routebar.whitelist.applied.v1"
    private var appliedDocument: WhitelistDocument?
    private var cancellables = Set<AnyCancellable>()

    init(preferences: UserDefaults = .standard) {
        self.preferences = preferences
        if let data = preferences.data(forKey: appliedKey) {
            appliedDocument = try? JSONDecoder().decode(WhitelistDocument.self, from: data)
        }
        if let data = preferences.data(forKey: documentKey) {
            do { document = try JSONDecoder().decode(WhitelistDocument.self, from: data) }
            catch { self.error = "已儲存嘅白名單無法讀取；原始資料仍然保留。請重新匯入設定。" }
        } else if !CommandLine.arguments.contains("--config"), let source = preferences.string(forKey: "routebar.v2.source") {
            // Migration is a one-time import into the same editable whitelist.
            isBusy = true
            Task {
                defer { isBusy = false }
                do { try await importDocument(at: URL(fileURLWithPath: source)) }
                catch { self.error = "無法搬移已儲存配置：\(error.localizedDescription)" }
            }
        } else if !CommandLine.arguments.contains("--config") {
            do {
                document = try Self.legacyDocument(preferences: preferences)
                try persist(document)
            } catch { self.error = "無法搬移已儲存白名單：\(error.localizedDescription)" }
        }
        updateDirtyState()
        vpn.$lastError.compactMap { $0 }.sink { [weak self] in self?.error = $0 }.store(in: &cancellables)
        vpn.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
    }

    var editingLocked: Bool { isBusy || vpn.isPreparing }
    var canConnect: Bool {
        guard !editingLocked, vpn.backendAvailable, vpn.hasAuthorization, !vpn.isActive, vpn.status != .unknown else { return false }
        let selected = Set(document.rules.filter(\.enabled).map(\.via) + [document.defaultVia])
        return document.profiles.contains { profile in
            selected.contains(profile.id) && (!(profile.profilePath ?? "").isEmpty || !(profile.keychainID ?? "").isEmpty)
        }
    }

    func openSettings(_ section: Int = 0) {
        selectedSection = section
        SettingsWindowPresenter.shared.show(model: self)
    }

    @discardableResult
    func saveRule(_ rule: WhitelistRule) async -> Bool {
        guard !editingLocked else { return false }
        isBusy = true
        defer { isBusy = false }
        var next = document
        if let index = next.rules.firstIndex(where: { $0.id == rule.id }) { next.rules[index] = rule }
        else { next.rules.append(rule) }
        do { try persist(try await validated(next)); return true }
        catch { self.error = error.localizedDescription; return false }
    }

    func setRuleEnabled(_ id: String, _ enabled: Bool) {
        change { value in if let i = value.rules.firstIndex(where: { $0.id == id }) { value.rules[i].enabled = enabled } }
    }
    func removeRule(_ id: String) { change { $0.rules.removeAll { $0.id == id } } }
    func moveRule(_ id: String, offset: Int) {
        change { value in
            guard let index = value.rules.firstIndex(where: { $0.id == id }) else { return }
            let target = min(max(index + offset, 0), value.rules.count - 1)
            guard target != index else { return }
            let rule = value.rules.remove(at: index)
            value.rules.insert(rule, at: target)
        }
    }
    func duplicateRule(_ id: String) {
        change { value in
            guard let index = value.rules.firstIndex(where: { $0.id == id }) else { return }
            var copy = value.rules[index]; copy.id = UUID().uuidString
            copy.name = Self.uniqueName(copy.name + " 副本", existing: value.rules.map(\.name))
            value.rules.insert(copy, at: index + 1)
        }
    }

    func addApplications() {
        guard !editingLocked else { return }
        guard let exit = document.preferredExit else { selectedSection = 1; error = "請先加入一個 VPN 出口。"; return }
        let panel = NSOpenPanel()
        panel.title = "加入白名單"
        panel.message = "選擇需要經 VPN 嘅 App；bundle 入面嘅 executable 同 helper 會一併匹配。"
        panel.allowedContentTypes = [.applicationBundle]
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = true
        panel.directoryURL = URL(fileURLWithPath: "/Applications"); panel.prompt = "加入"
        guard panel.runModal() == .OK else { return }
        let urls = panel.urls
        change { value in
            for url in urls {
                let resolved = url.resolvingSymlinksInPath()
                if value.rules.contains(where: { $0.match.apps == [resolved.path] && !$0.match.hasDestinations && $0.match.processNames.isEmpty && $0.via == exit.id }) { continue }
                let name = (Bundle(url: resolved)?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String) ?? resolved.deletingPathExtension().lastPathComponent
                value.rules.append(WhitelistRule(name: Self.uniqueName(name, existing: value.rules.map(\.name)), via: exit.id, match: WhitelistMatch(apps: [resolved.path])))
            }
        }
    }

    func chooseProfile() {
        guard !editingLocked else { return }
        let panel = NSOpenPanel()
        panel.title = "加入 VPN 出口"
        panel.message = "匯入 WireGuard .conf；私鑰會儲存喺 macOS Keychain。"
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .plainText, .plainText]
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false; panel.prompt = "加入"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importProfile(at: url)
    }

    func importProfile(at url: URL) {
        guard !editingLocked else { return }
        isBusy = true
        Task {
            defer { isBusy = false }
            var createdKey: String?
            do {
                let result = try await Task.detached(priority: .userInitiated) { () -> VPNExit in
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
                    guard let size = attrs[.size] as? NSNumber, size.intValue <= 131072 else { throw RouteBarError("設定檔上限為 128 KB。") }
                    let content = try String(contentsOf: url, encoding: .utf8)
                    let summary = try CoreBridge.inspect(content)
                    let key = UUID().uuidString
                    try KeychainStore.save(content, id: key)
                    return VPNExit(name: url.deletingPathExtension().lastPathComponent, keychainID: key, endpoint: summary.endpointHost)
                }.value
                createdKey = result.keychainID
                var next = document; next.profiles.append(result)
                if next.preferredExitID.isEmpty { next.preferredExitID = result.id }
                try persist(try await validated(next))
            } catch {
                if let createdKey { try? KeychainStore.delete(createdKey) }
                self.error = error.localizedDescription
            }
        }
    }

    func removeProfile(_ id: String) {
        guard !editingLocked, let profile = document.profiles.first(where: { $0.id == id }) else { return }
        guard !document.rules.contains(where: { $0.via == id }), document.defaultVia != id, document.dnsVia != id else {
            error = "呢個出口仍然被規則、預設出口或 DNS 使用。請先更改相關設定。"; return
        }
        isBusy = true
        Task {
            defer { isBusy = false }
            do {
                var next = document; next.profiles.removeAll { $0.id == id }
                if next.preferredExitID == id { next.preferredExitID = next.profiles.first?.id ?? "" }
                let checked = try await validated(next)
                let previous = document
                try persist(checked)
                do { if let key = profile.keychainID { try KeychainStore.delete(key) } }
                catch { try persist(previous); throw error }
            } catch { self.error = error.localizedDescription }
        }
    }
    func renameProfile(_ id: String, name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { error = "請輸入出口名稱。"; return }
        change { value in if let index = value.profiles.firstIndex(where: { $0.id == id }) { value.profiles[index].name = trimmed } }
    }
    func setPreferredExit(_ id: String) {
        guard document.profiles.contains(where: { $0.id == id }) else { return }
        change { $0.preferredExitID = id }
    }
    func updateDNS(via: String, server: String, strategy: String) {
        change { $0.dnsVia = via; $0.dnsServer = server.trimmingCharacters(in: .whitespacesAndNewlines); $0.dnsStrategy = strategy }
    }
    func setDefaultVia(_ via: String) { change { $0.defaultVia = via } }

    func importConfiguration() {
        guard !editingLocked else { return }
        let panel = NSOpenPanel()
        panel.title = "匯入分流設定"
        panel.message = "將配置匯入同一份白名單，取代目前規則同出口。原始配置檔保持不變。"
        panel.allowedContentTypes = [UTType(filenameExtension: "yaml") ?? .plainText, UTType(filenameExtension: "yml") ?? .plainText, .json, .plainText]
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await loadConfiguration(at: url) }
    }
    func loadConfiguration(at url: URL) async {
        guard !editingLocked else { return }
        isBusy = true
        defer { isBusy = false }
        do { try await importDocument(at: url); selectedSection = 0 }
        catch { self.error = error.localizedDescription }
    }

    func connect() {
        guard canConnect else { return }
        let snapshot = document
        isBusy = true
        Task {
            defer { isBusy = false }
            await vpn.connect(document: snapshot)
            if vpn.lastError == nil && vpn.serviceLoaded { markApplied(snapshot) }
        }
    }
    func applyChanges() {
        guard !editingLocked, vpn.hasAuthorization else { return }
        guard vpn.serviceLoaded else { connect(); return }
        let snapshot = document
        isBusy = true
        Task {
            defer { isBusy = false }
            await vpn.connect(document: snapshot, reload: true)
            if vpn.lastError == nil && vpn.serviceLoaded { markApplied(snapshot) }
        }
    }

    private func change(_ transform: (inout WhitelistDocument) -> Void) {
        guard !editingLocked else { return }
        var next = document; transform(&next)
        guard next != document else { return }
        isBusy = true
        Task {
            defer { isBusy = false }
            do { try persist(try await validated(next)) }
            catch { self.error = error.localizedDescription }
        }
    }
    private func persist(_ value: WhitelistDocument) throws {
        preferences.set(try JSONEncoder().encode(value), forKey: documentKey)
        document = value; updateDirtyState()
    }
    private func markApplied(_ value: WhitelistDocument) {
        do {
            preferences.set(try JSONEncoder().encode(value), forKey: appliedKey)
            appliedDocument = value; updateDirtyState()
        } catch { self.error = error.localizedDescription }
    }
    private func updateDirtyState() { hasUnappliedChanges = appliedDocument != document }

    /// Inspect the complete document including disabled rules, without loading
    /// any private key or starting the engine. Keychain profiles use placeholders.
    private func validated(_ value: WhitelistDocument) async throws -> WhitelistDocument {
        guard Set(value.profiles.map(\.id)).count == value.profiles.count else { throw RouteBarError("VPN 出口識別碼重複。") }
        guard Set(value.rules.map(\.id)).count == value.rules.count else { throw RouteBarError("規則識別碼重複。") }
        let directory = try V2Backend.secureDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var paths: [String: String] = [:]
        for profile in value.profiles {
            if profile.keychainID != nil { paths[profile.id] = directory.appendingPathComponent(profile.id + ".conf").path }
        }
        var everyRule = value
        for index in everyRule.rules.indices { everyRule.rules[index].enabled = true }
        let url = directory.appendingPathComponent("config.json")
        try V2Backend.secureWrite(try JSONSerialization.data(withJSONObject: everyRule.engineConfig(profilePaths: paths), options: [.sortedKeys]), to: url)
        let data = try await V2Backend.command(["config-inspect", "-c", url.path, "--json"])
        let parsed = try JSONDecoder().decode(V2Configuration.self, from: data)
        var result = value
        for index in result.rules.indices {
            result.rules[index].name = parsed.routing.rules[index].name
            result.rules[index].match = Self.match(from: parsed.routing.rules[index].match)
        }
        result.dnsVia = parsed.dns.via; result.dnsStrategy = parsed.dns.strategy; result.dnsServer = parsed.dns.server
        result.defaultVia = parsed.routing.default
        return result
    }

    private func importDocument(at url: URL) async throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 1_048_576 else { throw RouteBarError("配置檔案上限為 1 MB。") }
        let data = try await V2Backend.command(["config-inspect", "-c", url.path, "--json"])
        let config = try JSONDecoder().decode(V2Configuration.self, from: data)
        _ = try await V2Backend.command(["validate", "-c", url.path, "--json"])
        let next = WhitelistDocument(imported: config)
        try persist(next)
    }
    private static func match(from value: V2Configuration.Match) -> WhitelistMatch {
        WhitelistMatch(imported: value)
    }
    private static func uniqueName(_ proposed: String, existing: [String]) -> String {
        var name = proposed; var index = 2
        while existing.contains(name) { name = "\(proposed) (\(index))"; index += 1 }
        return name
    }
    static func legacyDocument(preferences: UserDefaults) throws -> WhitelistDocument {
        let profile = try preferences.data(forKey: "routebar.profile-metadata.v1").map { try JSONDecoder().decode(SavedProfile.self, from: $0) }
        let policy = try preferences.data(forKey: "routebar.policy.v1").map { try JSONDecoder().decode(RoutingPolicy.self, from: $0) } ?? RoutingPolicy()
        return WhitelistDocument.migrated(profile: profile, policy: policy,
            dnsVia: preferences.string(forKey: "routebar.dns.via") ?? "direct",
            dnsStrategy: preferences.string(forKey: "routebar.dns.strategy") ?? "auto")
    }
}
