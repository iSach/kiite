import AppKit
import SwiftUI

@MainActor
final class AppWindows: NSObject, NSWindowDelegate {
    private var settings: NSWindow?
    private var history: NSWindow?
    var settingsWindow: NSWindow? { settings }
    var historyWindow: NSWindow? { history }

    func showSettings<Content: View>(@ViewBuilder content: () -> Content) {
        show(&settings, title: "Settings", size: NSSize(width: 640, height: 760), content: content)
    }

    func showHistory<Content: View>(@ViewBuilder content: () -> Content) {
        show(&history, title: "Uploads", size: NSSize(width: 760, height: 520), content: content)
    }

    private func show<Content: View>(_ slot: inout NSWindow?, title: String, size: NSSize, @ViewBuilder content: () -> Content) {
        if let window = slot {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.contentViewController = NSHostingController(rootView: content())
        window.isReleasedWhenClosed = false
        window.collectionBehavior = [.moveToActiveSpace]
        window.minSize = NSSize(width: 520, height: 380)
        window.delegate = self
        window.center()
        slot = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }
}
