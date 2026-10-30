import AppKit
import SwiftUI

private enum Palette {
    static let accent = Color(red: 0.12, green: 0.47, blue: 0.40)
    static let canvas = Color(nsColor: .windowBackgroundColor)
    static let card = Color(nsColor: .controlBackgroundColor)
    static let muted = Color.secondary
}

struct RouteBarSettings: View {
    @ObservedObject var model: AppModel
    @State private var editingRule: WhitelistRule?
    @State private var search = ""
    private let sections = [("白名單", "line.3.horizontal.decrease.circle"), ("VPN 出口", "network"), ("連線設定", "slider.horizontal.3"), ("活動記錄", "waveform.path")]
    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                header.padding(.horizontal, 32).padding(.top, 40).padding(.bottom, 24)
                if !model.vpn.hasAuthorization {
                    authorizationBanner.padding(.horizontal, 32).padding(.bottom, 18)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        switch model.selectedSection {
                        case 1: exits
                        case 2: ConnectionSettings(model: model)
                        case 3: ActivityView(controller: model.vpn)
                        default: whitelist
                        }
                    }.padding(.horizontal, 32).padding(.bottom, 32)
                }
            }.background(Palette.canvas)
        }
        .frame(minWidth: 920, minHeight: 660)
        .tint(Palette.accent)
        .sheet(item: $editingRule) { rule in
            RuleEditor(model: model, rule: rule)
        }
        .alert("未能完成操作", isPresented: Binding(get: { model.error != nil && editingRule == nil }, set: { if !$0 { model.error = nil } })) {
            Button("知道了", role: .cancel) { model.error = nil }
        } message: { Text(model.error ?? "") }
    }
    private var authorizationBanner: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "lock.shield").font(.system(size: 20)).foregroundStyle(Palette.accent)
            VStack(alignment: .leading, spacing: 5) {
                Text(model.vpn.isAuthorizing ? "等待本次 App 授權" : "授權後即可控制 VPN")
                    .font(.system(size: 12, weight: .semibold))
                Text(model.vpn.backendAvailable ? (model.vpn.authorizationMessage.isEmpty ? "開啟 App 時授權一次；取消後仍可編輯白名單。" : model.vpn.authorizationMessage) : "網絡服務未齊備，請重新安裝 RouteBar。")
                    .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 10)
            if model.vpn.isAuthorizing { ProgressView().controlSize(.small) }
            else {
                Button("授權本次開啟") { model.vpn.requestAuthorization() }
                    .disabled(!model.vpn.backendAvailable)
            }
        }.padding(14).background(Palette.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 11))
    }
    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "arrow.triangle.branch").font(.system(size: 22, weight: .semibold)).foregroundStyle(Palette.accent)
                Text("RouteBar").font(.system(size: 21, weight: .semibold, design: .rounded))
            }.padding(.horizontal, 24).padding(.top, 49).padding(.bottom, 40)
            Text("工作空間").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary).padding(.horizontal, 25).padding(.bottom, 12)
            ForEach(sections.indices, id: \.self) { index in
                Button { model.selectedSection = index } label: {
                    HStack(spacing: 11) {
                        Image(systemName: sections[index].1).font(.system(size: 15)).frame(width: 19)
                        Text(sections[index].0).font(.system(size: 13, weight: model.selectedSection == index ? .semibold : .regular))
                        Spacer()
                        if index == 0 {
                            Text("\(model.document.rules.count)").font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                        }
                    }.foregroundStyle(model.selectedSection == index ? Palette.accent : Color.primary.opacity(0.72))
                        .padding(.horizontal, 13).padding(.vertical, 12)
                        .background(model.selectedSection == index ? Palette.accent.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 9))
                        .contentShape(Rectangle())
                }.buttonStyle(.plain).padding(.horizontal, 12).padding(.bottom, 4)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 7) {
                    Circle().fill(model.vpn.status == .connected ? Palette.accent : Color.secondary.opacity(0.45)).frame(width: 6, height: 6)
                    Text(model.vpn.status == .connected ? "分流服務運行中" : model.vpn.statusTitle).font(.system(size: 11, weight: .medium))
                }
                Text("只連接你選擇的流量。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
                .background(Palette.card.opacity(0.65), in: RoundedRectangle(cornerRadius: 10)).padding(14)
        }.frame(width: 202).background(Color.primary.opacity(0.025))
    }
    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 7) {
                Text(sections[min(max(model.selectedSection, 0), 3)].0).font(.system(size: 27, weight: .semibold))
                Text(["決定哪些 App 與網站使用 VPN。", "管理你的 WireGuard 連線出口。", "設定其餘流量與 DNS 的連線方式。", "查看分流服務的狀態與連線日誌。"][min(max(model.selectedSection, 0), 3)])
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
            if model.vpn.hasAuthorization {
                Label("本次已授權", systemImage: "lock.open").font(.system(size: 10)).foregroundStyle(.secondary).padding(.trailing, 7)
            }
            if model.isBusy || model.vpn.isPreparing { ProgressView().controlSize(.small) }
            Button {
                if model.vpn.isActive { model.vpn.disconnect() } else { model.connect() }
            } label: {
                Label(model.vpn.isActive ? "中斷連線" : "連線", systemImage: "power")
                    .font(.system(size: 13, weight: .semibold)).padding(.horizontal, 10).padding(.vertical, 6)
            }.buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(model.vpn.isPreparing || model.isBusy || !model.vpn.hasAuthorization || (!model.vpn.isActive && !model.canConnect))
        }
    }
    private var whitelist: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(alignment: .top, spacing: 18) {
                Image(systemName: "arrow.triangle.branch").font(.system(size: 26, weight: .light))
                    .foregroundStyle(Palette.accent).frame(width: 54, height: 54)
                    .background(Palette.accent.opacity(0.09), in: RoundedRectangle(cornerRadius: 15))
                VStack(alignment: .leading, spacing: 7) {
                    Text(model.document.defaultVia == "direct" ? "白名單經 VPN，其餘保持直連" : "按白名單決定每條連線的出口")
                        .font(.system(size: 16, weight: .semibold))
                    Text("\(model.document.rules.filter(\.enabled).count) 條規則已啟用  ·  \(model.document.profiles.count) 個 VPN 出口")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    Text("由上至下匹配，第一條符合的規則生效。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }.padding(22).frame(maxWidth: .infinity, alignment: .leading)
                .background(Palette.accent.opacity(0.045), in: RoundedRectangle(cornerRadius: 15))
                .overlay(RoundedRectangle(cornerRadius: 15).stroke(Palette.accent.opacity(0.12), lineWidth: 1))
            if model.hasUnappliedChanges && model.vpn.serviceLoaded {
                HStack {
                    Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(Palette.accent)
                    Text("白名單已儲存，套用後更新連線。重啟會中斷現有連線。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    Spacer()
                    Button("套用變更") { model.applyChanges() }.disabled(model.editingLocked || !model.vpn.hasAuthorization)
                }.padding(13).background(Palette.card, in: RoundedRectangle(cornerRadius: 10))
            }
            HStack(spacing: 10) {
                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.tertiary)
                    TextField("搜尋白名單", text: $search).textFieldStyle(.plain)
                }.font(.system(size: 12)).padding(9).frame(maxWidth: 220)
                    .background(Palette.card, in: RoundedRectangle(cornerRadius: 8))
                Spacer()
                Button { model.addApplications() } label: { Label("加入 App", systemImage: "plus") }
                    .disabled(model.editingLocked || model.document.profiles.isEmpty)
                Button {
                    editingRule = WhitelistRule(name: "", via: model.document.preferredExitID)
                } label: { Label("加入網站", systemImage: "globe") }
                    .disabled(model.editingLocked || model.document.profiles.isEmpty)
            }
            if model.document.profiles.isEmpty {
                emptyState(icon: "network", title: "先加入一個 VPN 出口", detail: "匯入 WireGuard 設定檔，再選擇需要使用 VPN 的 App 與網站。") {
                    model.chooseProfile()
                }
            } else if model.document.rules.isEmpty {
                emptyState(icon: "app.badge.checkmark", title: "你的白名單，由你決定", detail: "加入整個 App，或指定網站。未加入的流量預設使用原本網絡。") {
                    model.addApplications()
                }
            } else {
                VStack(spacing: 0) {
                    HStack {
                        Text("應用程式與網站"); Spacer(); Text("出口").frame(width: 125, alignment: .leading); Text("啟用").frame(width: 65)
                    }.font(.system(size: 10, weight: .medium)).foregroundStyle(.tertiary).padding(.horizontal, 18).padding(.bottom, 11)
                    let visible = model.document.rules.filter { search.isEmpty || ([$0.name] + $0.match.apps + $0.match.domains + $0.match.domainSuffixes).joined(separator: " ").localizedCaseInsensitiveContains(search) }
                    if visible.isEmpty { Text("沒有符合搜尋的規則").foregroundStyle(.secondary).padding(35) }
                    ForEach(visible) { rule in
                        RuleRow(model: model, rule: rule, edit: { editingRule = rule })
                        if rule.id != visible.last?.id { Divider().padding(.leading, 76) }
                    }
                }.padding(.vertical, 15).background(Palette.card, in: RoundedRectangle(cornerRadius: 13))
                    .overlay(RoundedRectangle(cornerRadius: 13).stroke(Color.primary.opacity(0.055), lineWidth: 1))
            }
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "info.circle")
                Text("App 規則包含其內置 helper。網站規則依賴 DNS 及連線辨識；App 自帶加密 DNS 時可能無法辨識。")
                    .fixedSize(horizontal: false, vertical: true)
            }.font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }
    private func emptyState(icon: String, title: String, detail: String, action: @escaping () -> Void) -> some View {
        VStack(spacing: 14) {
            Image(systemName: icon).font(.system(size: 30, weight: .light)).foregroundStyle(Palette.accent).padding(.bottom, 5)
            Text(title).font(.system(size: 17, weight: .semibold))
            Text(detail).font(.system(size: 12)).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 340)
            Button(model.document.profiles.isEmpty ? "匯入 VPN 出口" : "加入 App", action: action).padding(.top, 5).disabled(model.editingLocked)
        }.frame(maxWidth: .infinity).padding(.vertical, 42).background(Palette.card, in: RoundedRectangle(cornerRadius: 13))
    }
    private var exits: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("\(model.document.profiles.count) 個已儲存出口").font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button { model.chooseProfile() } label: { Label("匯入 WireGuard", systemImage: "plus") }.disabled(model.editingLocked)
            }
            ForEach(model.document.profiles) { exit in
                ExitCard(model: model, exit: exit)
            }
            if model.document.profiles.isEmpty {
                emptyState(icon: "network", title: "加入你的 VPN", detail: "選擇供應商提供的 WireGuard .conf 設定檔。") { model.chooseProfile() }
            }
            Text("預設出口用於新加入的白名單。每條規則都可以選擇不同出口。")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            Divider().padding(.top, 10)
            HStack {
                Text("已有分流設定？").font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button("匯入設定…") { model.importConfiguration() }.disabled(model.editingLocked)
            }
        }
    }
}

private struct RuleRow: View {
    @ObservedObject var model: AppModel
    let rule: WhitelistRule
    let edit: () -> Void
    private var appName: String? { rule.match.apps.first.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent } }
    private var title: String {
        if let appName, rule.match.apps.count == 1 { return appName }
        return rule.name.isEmpty ? (rule.match.domainSuffixes.first ?? rule.match.domains.first ?? "自訂規則") : rule.name
    }
    private var subtitle: String {
        let destinations = rule.match.domainSuffixes + rule.match.domains + rule.match.ipCIDRs
        let programs = rule.match.apps.count + rule.match.processNames.count
        if !destinations.isEmpty {
            let summary = destinations.prefix(2).joined(separator: "、") + (destinations.count > 2 ? " 等 \(destinations.count) 個目的地" : "")
            return programs > 0 ? "只限 \(summary)" : "所有 App · \(summary)"
        }
        return programs > 1 ? "\(programs) 個 App／程序的所有連線" : "所有網站與連線"
    }
    var body: some View {
        HStack(spacing: 13) {
            Group {
                if let path = rule.match.apps.first {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable().frame(width: 34, height: 34)
                } else {
                    Image(systemName: rule.match.processNames.isEmpty ? "globe" : "terminal").font(.system(size: 21)).foregroundStyle(Palette.accent)
                        .frame(width: 34, height: 34)
                }
            }.frame(width: 40, height: 42)
            Button(action: edit) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                    Text(subtitle).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
                }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
            }.buttonStyle(.plain)
            Picker("出口", selection: Binding(get: { rule.via }, set: { value in
                var updated = rule; updated.via = value
                Task { _ = await model.saveRule(updated) }
            })) {
                ForEach(model.document.profiles) { exit in Text(exit.name).tag(exit.id) }
                Text("直連").tag("direct")
            }.labelsHidden().frame(width: 125)
            Toggle("啟用 \(title)", isOn: Binding(get: { rule.enabled }, set: { model.setRuleEnabled(rule.id, $0) }))
                .labelsHidden().toggleStyle(.switch).controlSize(.small).frame(width: 40)
            Menu {
                Button("編輯規則", action: edit)
                Button("複製規則") { model.duplicateRule(rule.id) }
                Divider()
                Button("向上移") { model.moveRule(rule.id, offset: -1) }.disabled(model.document.rules.first?.id == rule.id)
                Button("向下移") { model.moveRule(rule.id, offset: 1) }.disabled(model.document.rules.last?.id == rule.id)
                Divider()
                Button("移除規則", role: .destructive) { model.removeRule(rule.id) }
            } label: { Image(systemName: "ellipsis").frame(width: 17, height: 25) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        }.padding(.horizontal, 16).padding(.vertical, 14).opacity(rule.enabled ? 1 : 0.55).disabled(model.editingLocked)
    }
}

private struct ExitCard: View {
    @ObservedObject var model: AppModel
    let exit: VPNExit
    @State private var renaming = false
    @State private var name = ""
    @State private var removing = false
    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: "network").font(.system(size: 24, weight: .light)).foregroundStyle(Palette.accent)
                .frame(width: 52, height: 52).background(Palette.accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(exit.name).font(.system(size: 15, weight: .semibold))
                    if model.document.preferredExitID == exit.id {
                        Text("預設").font(.system(size: 9, weight: .medium)).foregroundStyle(Palette.accent).padding(.horizontal, 7).padding(.vertical, 3)
                            .background(Palette.accent.opacity(0.08), in: Capsule())
                    }
                }
                Text(exit.endpoint.isEmpty ? "WireGuard" : exit.endpoint).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled)
                Text("\(model.document.rules.filter { $0.via == exit.id }.count) 條規則使用此出口")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer()
            if model.document.preferredExitID != exit.id {
                Button("設為預設") { model.setPreferredExit(exit.id) }
            }
            Menu {
                Button("重新命名") { name = exit.name; renaming = true }
                Button("移除出口", role: .destructive) { removing = true }
            } label: { Image(systemName: "ellipsis").frame(width: 20, height: 24) }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        }.padding(20).background(Palette.card, in: RoundedRectangle(cornerRadius: 13)).disabled(model.editingLocked)
            .alert("重新命名出口", isPresented: $renaming) {
                TextField("名稱", text: $name)
                Button("取消", role: .cancel) { }
                Button("儲存") { model.renameProfile(exit.id, name: name) }
            }
            .confirmationDialog("移除 \(exit.name)？", isPresented: $removing) {
                Button("移除出口", role: .destructive) { model.removeProfile(exit.id) }
            } message: { Text("仍被規則或 DNS 使用的出口需要先更改其設定。") }
    }
}

private struct ConnectionSettings: View {
    @ObservedObject var model: AppModel
    @State private var via = "direct"
    @State private var server = ""
    @State private var strategy = "auto"
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            settingsCard("未匹配的流量", icon: "arrow.up.right") {
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(model.document.defaultVia == "direct" ? "原本網絡 · 直連" : "使用 \(model.document.profiles.first { $0.id == model.document.defaultVia }?.name ?? model.document.defaultVia)")
                            .font(.system(size: 13, weight: .medium))
                        Text("白名單未命中時使用的出口。")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Picker("未匹配的出口", selection: Binding(get: { model.document.defaultVia }, set: model.setDefaultVia)) {
                        Text("直連").tag("direct")
                        ForEach(model.document.profiles) { Text($0.name).tag($0.id) }
                    }.labelsHidden().frame(width: 170).disabled(model.editingLocked)
                }
            }
            settingsCard("DNS", icon: "globe") {
                VStack(alignment: .leading, spacing: 17) {
                    Text("所有 App 共用此 DNS 設定，獨立於白名單的流量出口。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    Picker("查詢出口", selection: $via) {
                        Text("原本網絡").tag("direct")
                        ForEach(model.document.profiles) { Text($0.name).tag($0.id) }
                    }
                    TextField("DNS 伺服器（留空使用預設）", text: $server).textFieldStyle(.roundedBorder)
                    Picker("地址策略", selection: $strategy) {
                        Text("自動").tag("auto")
                        Text("只用 IPv4").tag("ipv4_only")
                        Text("只用 IPv6").tag("ipv6_only")
                        Text("優先 IPv4").tag("prefer_ipv4")
                        Text("優先 IPv6").tag("prefer_ipv6")
                    }
                    HStack { Spacer(); Button("儲存 DNS 設定") { model.updateDNS(via: via, server: server, strategy: strategy) }
                        .disabled(model.editingLocked || (via == model.document.dnsVia && server == model.document.dnsServer && strategy == model.document.dnsStrategy)) }
                }
            }
            settingsCard("本次 App 授權", icon: "lock.shield") {
                Text("開啟 App 時向 macOS 要求一次管理員授權，不會自動啟動 VPN。授權後連線、斷線、套用規則及讀取日誌不再重複要求密碼。完全結束 App 會結束本次授權；關閉視窗仍會保留選單列 App。")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            settingsCard("背景連線", icon: "power") {
                Text("關閉視窗或結束 App 後，背景分流服務會繼續運行並於開機載入。要停止 VPN，請按「中斷連線」。停止或服務崩潰時，流量可能恢復直連。")
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }.onAppear { via = model.document.dnsVia; server = model.document.dnsServer; strategy = model.document.dnsStrategy }
    }
}

private func settingsCard<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
    VStack(alignment: .leading, spacing: 20) {
        Label(title, systemImage: icon).font(.system(size: 14, weight: .semibold))
        content()
    }.padding(22).frame(maxWidth: .infinity, alignment: .leading).background(Palette.card, in: RoundedRectangle(cornerRadius: 13))
}

private struct ActivityView: View {
    @ObservedObject var controller: VPNController
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            settingsCard("連線狀態", icon: "waveform.path") {
                VStack(alignment: .leading, spacing: 9) {
                    Text(controller.statusTitle).font(.system(size: 14, weight: .medium))
                    Text(controller.statusDetail).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled)
                    Text("服務運行不代表 VPN 出口已通過驗證。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                    Button("重新整理狀態") { Task { await controller.refreshStatus() } }
                }
            }
            HStack {
                Text("最近日誌").font(.system(size: 14, weight: .semibold))
                Spacer()
                Button("讀取日誌…") { controller.refreshDiagnostics() }.disabled(controller.isPreparing || !controller.hasAuthorization)
            }
            Text(controller.diagnosticMessage).font(.system(size: 11)).foregroundStyle(.secondary)
            ScrollView([.vertical, .horizontal]) {
                Text(controller.logText.isEmpty ? "連線後可在這裡查看分流記錄。" : controller.logText)
                    .font(.system(size: 11, design: .monospaced)).textSelection(.enabled).padding(17).frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 220).background(Palette.card, in: RoundedRectangle(cornerRadius: 11))
        }
    }
}

private struct RuleEditor: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State var rule: WhitelistRule
    @State private var appPaths = ""
    @State private var processNames = ""
    @State private var suffixes = ""
    @State private var domains = ""
    @State private var cidrs = ""
    @State private var saving = false
    @State private var saveError: String?
    private func values(_ text: String) -> [String] { text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                VStack(alignment: .leading, spacing: 6) {
                    Text(model.document.rules.contains { $0.id == rule.id } ? "編輯白名單" : "加入白名單").font(.system(size: 22, weight: .semibold))
                    Text("選擇 App、網站，以及它們使用的出口。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark").foregroundStyle(.secondary) }.buttonStyle(.plain)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 19) {
                    TextField("規則名稱", text: $rule.name).textFieldStyle(.roundedBorder)
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("應用程式").font(.system(size: 12, weight: .semibold))
                            Spacer()
                            Button("選擇 App…") { chooseApps() }
                        }
                        if appPaths.isEmpty { Text("所有 App；選擇 App 可限定網站規則的適用範圍。")
                            .font(.system(size: 11)).foregroundStyle(.secondary) }
                        else { ForEach(values(appPaths), id: \.self) { path in
                            HStack {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable().frame(width: 24, height: 24)
                                Text(URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent).font(.system(size: 12))
                                Spacer()
                                Button { appPaths = values(appPaths).filter { $0 != path }.joined(separator: "\n") } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }.buttonStyle(.plain)
                            }.padding(8).background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 7))
                        } }
                    }
                    VStack(alignment: .leading, spacing: 7) {
                        Text("網站與子網域").font(.system(size: 12, weight: .semibold))
                        Text("每行一個，例如 chatgpt.com。留空則包含所選 App 的所有網站。")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                        TextEditor(text: $suffixes).font(.system(size: 12, design: .monospaced)).frame(height: 68)
                            .padding(5).background(Palette.card).overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2)))
                    }
                    DisclosureGroup("精確網站、程序與 IP 網段") {
                        VStack(alignment: .leading, spacing: 10) {
                            editorField("精確網站（不含子網域）", text: $domains)
                            editorField("程序名稱", text: $processNames)
                            editorField("目的 IP 網段（CIDR）", text: $cidrs)
                            editorField("App／Executable 路徑", text: $appPaths)
                        }.padding(.top, 10)
                    }.font(.system(size: 12))
                    Picker("使用出口", selection: $rule.via) {
                        ForEach(model.document.profiles) { Text($0.name).tag($0.id) }
                        Text("直連（例外規則）").tag("direct")
                    }
                    HStack(alignment: .top, spacing: 7) {
                        Image(systemName: "info.circle")
                        Text("同時選擇 App 與網站時，只有該 App 連接指定網站才會匹配。其他連線繼續按下一條規則處理。")
                    }.font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            Divider()
            HStack {
                Toggle("啟用規則", isOn: $rule.enabled).toggleStyle(.switch).controlSize(.small)
                Spacer()
                if saving { ProgressView().controlSize(.small) }
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("儲存規則") { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(saving || model.editingLocked)
            }
        }.padding(28).frame(width: 550, height: 660).tint(Palette.accent).disabled(saving)
            .alert("無法儲存規則", isPresented: Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })) {
                Button("知道了", role: .cancel) { saveError = nil }
            } message: { Text(saveError ?? "") }
            .onAppear {
                appPaths = rule.match.apps.joined(separator: "\n")
                processNames = rule.match.processNames.joined(separator: "\n")
                suffixes = rule.match.domainSuffixes.joined(separator: "\n")
                domains = rule.match.domains.joined(separator: "\n")
                cidrs = rule.match.ipCIDRs.joined(separator: "\n")
            }
    }
    private func editorField(_ title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 11)).foregroundStyle(.secondary)
            TextEditor(text: text).font(.system(size: 11, design: .monospaced)).frame(height: 45).padding(4)
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.secondary.opacity(0.2)))
        }
    }
    private func chooseApps() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.applicationBundle]; panel.allowsMultipleSelection = true
        panel.directoryURL = URL(fileURLWithPath: "/Applications"); panel.prompt = "加入"
        if panel.runModal() == .OK {
            var paths = values(appPaths)
            for url in panel.urls { let path = url.resolvingSymlinksInPath().path; if !paths.contains(path) { paths.append(path) } }
            appPaths = paths.joined(separator: "\n")
        }
    }
    private func save() {
        rule.match.apps = values(appPaths); rule.match.processNames = values(processNames)
        rule.match.domainSuffixes = values(suffixes); rule.match.domains = values(domains); rule.match.ipCIDRs = values(cidrs)
        if rule.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            rule.name = values(appPaths).first.map { URL(fileURLWithPath: $0).deletingPathExtension().lastPathComponent } ?? values(suffixes).first ?? values(domains).first ?? "自訂規則"
        }
        saving = true
        Task { let success = await model.saveRule(rule); saving = false; if success { dismiss() } else { saveError = model.error; model.error = nil } }
    }
}
