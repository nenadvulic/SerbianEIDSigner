import AppKit
import ServiceManagement
import SignerCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let config = AppConfig.default
    private var server: WebSocketServer?
    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "eID"
        statusItem = item

        let menu = NSMenu()
        let status = NSMenuItem(title: "Starting…", action: nil, keyEquivalent: "")
        menu.addItem(status)
        menu.addItem(.separator())
        let login = NSMenuItem(title: "Launch at Login", action: #selector(toggleLogin(_:)), keyEquivalent: "")
        login.target = self
        menu.addItem(login)
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = menu

        do {
            let srv = WebSocketServer(ports: config.ports, originAllowlist: config.originAllowlist,
                                      handler: Dispatcher(card: TKCardService()))
            let port = try srv.start()
            server = srv
            status.title = "Listening on 127.0.0.1:\(port)"
        } catch {
            status.title = "Server failed: \(error)"
            item.button?.title = "eID !"
        }

        registerLoginItem()
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    func applicationWillTerminate(_ notification: Notification) { server?.stop() }

    private func registerLoginItem() {
        guard SMAppService.mainApp.status == .notRegistered else { return }
        do { try SMAppService.mainApp.register() } catch {
            NSLog("SignerApp: login item registration failed: \(error)")
        }
    }

    @objc private func toggleLogin(_ sender: NSMenuItem) {
        do {
            if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() }
            else { try SMAppService.mainApp.register() }
        } catch { NSLog("SignerApp: login item toggle failed: \(error)") }
        sender.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }
}

let app = NSApplication.shared
let delegate = MainActor.assumeIsolated { AppDelegate() }
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
