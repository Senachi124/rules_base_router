import Combine
import Foundation

enum VPNServiceState { case disconnected, connecting, connected, disconnecting, unknown }

@MainActor
final class VPNController: ObservableObject {
    @Published private(set) var status: VPNServiceState = .disconnected
    @Published private(set) var serviceLoaded = false
    @Published private(set) var isPreparing = false
    @Published private(set) var preparationMessage = ""
    @Published private(set) var diagnosticMessage = "讀取最近服務日誌，查看程序與目的地；請留意私隱。"
    @Published private(set) var logText = ""
    @Published private(set) var statusDetail = ""
    @Published var lastError: String?
    let authorization = SessionAuthorization.shared
    private var cancellables = Set<AnyCancellable>()
    private var timer: Timer?
    private var isRefreshing = false

    var hasAuthorization: Bool { authorization.authorized }
    var isAuthorizing: Bool { authorization.isAuthorizing }
    var authorizationMessage: String { authorization.message }
    var backendAvailable: Bool { V2Backend.isAvailable }
    var isActive: Bool { serviceLoaded || [.connecting, .connected, .disconnecting].contains(status) }
    var isLocked: Bool { isPreparing || isActive || status == .unknown }
    var statusTitle: String {
        if isPreparing { return preparationMessage }
        switch status {
        case .connected: return "分流服務運行中"
        case .connecting: return "啟動服務中…"
        case .disconnecting: return "停止服務中…"
        case .unknown: return "服務狀態未能確認"
        case .disconnected: return serviceLoaded ? "服務已載入，程序未運行" : "未連線"
        }
    }
    init() {
        authorization.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &cancellables)
        Task { await refreshStatus() }
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { @MainActor in guard let self, !self.isPreparing else { return }; await self.refreshStatus() }
        }
    }
    deinit { timer?.invalidate() }

    func refreshStatus() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        guard backendAvailable else { status = .unknown; statusDetail = "缺少隨附 Rust 控制器或 sing-box 引擎。"; return }
        do {
            let data = try await hasAuthorization ? authorization.request(command: "status") : V2Backend.command(["status", "--json"])
            let reply = try JSONDecoder().decode(V2ServiceStatus.self, from: data)
            serviceLoaded = reply.loaded
            status = reply.running ? .connected : .disconnected
            statusDetail = reply.detail + (reply.pid > 0 ? " · PID \(reply.pid)" : "")
            if reply.foreground_unknown == true { statusDetail += " · 前台模式需管理員權限先能確認；啟動時會檢查操作鎖。" }
        } catch { status = .unknown; statusDetail = error.localizedDescription }
    }

    func authorizeSession() async {
        guard backendAvailable, !authorization.isAuthorizing else { return }
        do { try await authorization.authorize() }
        catch { /* Cancellation stays in the authorization banner; settings remain editable. */ }
        await refreshStatus()
    }
    func requestAuthorization() { Task { await authorizeSession() } }

    func connect(document: WhitelistDocument, reload: Bool = false) async {
        guard !isPreparing, reload ? serviceLoaded : !isActive else { return }
        guard hasAuthorization else { lastError = "請先按「授權本次開啟」；白名單仍可編輯。"; return }
        isPreparing = true
        lastError = nil
        preparationMessage = "驗證並套用白名單…"
        defer { isPreparing = false; preparationMessage = "" }
        do {
            var profiles: [String: String] = [:]
            var placeholderPaths: [String: String] = [:]
            for profile in document.profiles {
                let content: String
                if let keychainID = profile.keychainID {
                    content = try KeychainStore.load(keychainID)
                } else if let path = profile.profilePath {
                    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
                    defer { try? file.close() }
                    let data = try file.read(upToCount: 131073) ?? Data()
                    guard data.count <= 131072, let text = String(data: data, encoding: .utf8) else {
                        throw RouteBarError("VPN 設定檔過大或無法讀取，請重新匯入。")
                    }
                    content = text
                } else { throw RouteBarError("VPN 出口缺少設定檔，請重新匯入。") }
                guard content.utf8.count <= 131072 else { throw RouteBarError("VPN 設定檔上限為 128 KB。") }
                profiles[profile.id] = content
                // The helper ignores caller paths and writes these profile contents
                // into its own private directory before compiling the configuration.
                placeholderPaths[profile.id] = "/profiles/" + profile.id + ".conf"
            }
            status = .connecting
            let data = try await authorization.request(command: reload ? "reload" : "up",
                config: document.engineConfig(profilePaths: placeholderPaths), profiles: profiles)
            let reply = try JSONDecoder().decode(V2ServiceStatus.self, from: data)
            if reply.detail.contains("already running") {
                throw RouteBarError("分流服務已經運行；目前白名單尚未套用，請按「套用變更」。")
            }
            logText = ""
            diagnosticMessage = "程序狀態唔代表 WireGuard 握手或出口驗證；可讀取日誌查看實際流量。"
        } catch { lastError = error.localizedDescription }
        await refreshStatus()
    }

    func disconnect() {
        guard !isPreparing else { return }
        guard hasAuthorization else { lastError = "請先按「授權本次開啟」再停止服務。"; return }
        lastError = nil
        isPreparing = true; preparationMessage = "停止分流服務…"; status = .disconnecting
        Task {
            defer { isPreparing = false; preparationMessage = "" }
            do { _ = try await authorization.request(command: "down") }
            catch { lastError = error.localizedDescription }
            await refreshStatus()
        }
    }
    func refreshDiagnostics() {
        guard !isPreparing else { return }
        guard hasAuthorization else { diagnosticMessage = "請先完成本次 App 授權。"; return }
        diagnosticMessage = "讀取服務日誌…"
        Task {
            do {
                let data = try await authorization.request(command: "logs", lines: 100)
                struct Logs: Decodable { let logs: String }
                logText = try JSONDecoder().decode(Logs.self, from: data).logs
                diagnosticMessage = "最近 100 行服務日誌；包含程序及目的地，請留意私隱。"
            } catch { diagnosticMessage = error.localizedDescription }
        }
    }
}
