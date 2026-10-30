import AppKit
import SwiftUI

@main
struct RouteBarApp: App {
    @NSApplicationDelegateAdaptor(RouteBarAppDelegate.self) private var delegate
    var body: some Scene {
        MenuBarExtra {
            RouteBarMenu(model: delegate.model)
        } label: {
            Image(systemName: delegate.model.vpn.status == .connected ? "shield.lefthalf.filled" : "shield")
                .accessibilityLabel("RouteBar")
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor
final class RouteBarAppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private var endingSession = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        if let index = CommandLine.arguments.firstIndex(of: "--config"), CommandLine.arguments.indices.contains(index + 1) {
            let url = URL(fileURLWithPath: CommandLine.arguments[index + 1])
            Task { await model.loadConfiguration(at: url); model.openSettings() }
        } else { model.openSettings() }
        Task { await model.vpn.authorizeSession() }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !endingSession else { return .terminateLater }
        endingSession = true
        Task {
            await SessionAuthorization.shared.endSession()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

struct RouteBarMenu: View {
    @ObservedObject var model: AppModel
    var body: some View {
        Text(model.vpn.statusTitle)
        Text("\(model.document.rules.filter(\.enabled).count) 條白名單規則已啟用")
        Divider()
        if !model.vpn.hasAuthorization {
            Button(model.vpn.isAuthorizing ? "等待管理員授權…" : "授權本次開啟…") { model.vpn.requestAuthorization() }
                .disabled(model.vpn.isAuthorizing || !model.vpn.backendAvailable)
        }
        if model.vpn.isActive {
            if model.hasUnappliedChanges {
                Button("套用白名單變更") { model.applyChanges() }.disabled(model.editingLocked || !model.vpn.hasAuthorization)
            }
            Button("中斷連線") { model.vpn.disconnect() }.disabled(model.vpn.isPreparing || !model.vpn.hasAuthorization)
        } else {
            Button("連線") { model.connect() }.disabled(!model.canConnect)
        }
        Divider()
        Button("開啟白名單…") { model.openSettings() }.keyboardShortcut(",")
        Button("VPN 出口…") { model.openSettings(1) }
        Button("活動記錄…") { model.openSettings(3) }
        Divider()
        Button("結束 RouteBar") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

@MainActor
final class SettingsWindowPresenter: NSObject, NSWindowDelegate {
    static let shared = SettingsWindowPresenter()
    private var window: NSWindow?
    func show(model: AppModel) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let window = NSWindow(contentViewController: NSHostingController(rootView: RouteBarSettings(model: model)))
        window.title = "RouteBar"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
        window.setContentSize(NSSize(width: 1000, height: 720))
        window.minSize = NSSize(width: 920, height: 660)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    func windowWillClose(_ notification: Notification) { window = nil }
}
