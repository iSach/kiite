import AppKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var controller: StatusController?
    private var openedBeforeLaunch: [URL] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = StatusController()
        controller.install()
        self.controller = controller
        installMenu()
        AppLog.write("log path \(AppLog.path)")
        if !openedBeforeLaunch.isEmpty {
            controller.importURLs(openedBeforeLaunch)
            openedBeforeLaunch = []
        }
    }

    // Files opened with the app (Open With or a menu-bar drop target)
    // go through the same import as a drop on the status item.
    func application(_ application: NSApplication, open urls: [URL]) {
        AppLog.write("open urls=\(urls.count)")
        guard let controller else {
            openedBeforeLaunch += urls
            return
        }
        controller.importURLs(urls)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        controller?.refreshLaunchAtLogin()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        controller?.showHistory()
        return true
    }

    @objc private func showSettings() { controller?.showSettings() }
    @objc private func showUploads() { controller?.showHistory() }

    private func installMenu() {
        let bar = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "Kiite")
        let settings = NSMenuItem(title: "Settings…", action: #selector(showSettings), keyEquivalent: ",")
        settings.target = self
        appMenu.addItem(settings)
        let uploads = NSMenuItem(title: "Show All Uploads", action: #selector(showUploads), keyEquivalent: "1")
        uploads.target = self
        appMenu.addItem(uploads)
        appMenu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Kiite", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApp
        appMenu.addItem(quit)
        appItem.submenu = appMenu
        bar.addItem(appItem)

        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        for (title, selector, key) in [("Undo", "undo:", "z"), ("Cut", "cut:", "x"), ("Copy", "copy:", "c"), ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a")] {
            edit.addItem(NSMenuItem(title: title, action: NSSelectorFromString(selector), keyEquivalent: key))
        }
        editItem.submenu = edit
        bar.addItem(editItem)
        NSApp.mainMenu = bar
    }
}

@main
enum KiiteMain {
    static func main() {
        #if KIITE_TESTING
        if CommandLine.arguments.contains("--self-test") {
            exit(LocalProofs.run())
        }
        #endif
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) {
            app.run()
        }
    }
}
