import AppKit
import Carbon.HIToolbox

struct Shortcut: Codable, Equatable {
    var keyCode: UInt32
    var modifiers: UInt
    var key: String

    private static let defaultsKey = "screenshotShortcut"

    var label: String {
        let flags = NSEvent.ModifierFlags(rawValue: modifiers)
        return [(NSEvent.ModifierFlags.control, "⌃"), (.option, "⌥"), (.shift, "⇧"), (.command, "⌘")]
            .filter { flags.contains($0.0) }.map(\.1).joined() + key
    }

    var carbonModifiers: UInt32 {
        let flags = NSEvent.ModifierFlags(rawValue: modifiers)
        return (flags.contains(.command) ? UInt32(cmdKey) : 0) | (flags.contains(.shift) ? UInt32(shiftKey) : 0)
            | (flags.contains(.option) ? UInt32(optionKey) : 0) | (flags.contains(.control) ? UInt32(controlKey) : 0)
    }

    /// Nil for keys that need a ⌘, ⌃, or ⌥ modifier but were pressed without one.
    init?(event: NSEvent) {
        let flags = event.modifierFlags.intersection([.command, .shift, .option, .control])
        // Name the key by its letter or digit, from whichever layer has one,
        // so AZERTY's 3 key reads "3" rather than its unshifted quote.
        let plain = event.characters(byApplyingModifiers: []) ?? ""
        let shifted = event.characters(byApplyingModifiers: .shift) ?? ""
        let raw = plain.unicodeScalars.allSatisfy(CharacterSet.alphanumerics.contains) || !shifted.unicodeScalars.allSatisfy(CharacterSet.alphanumerics.contains) ? plain : shifted
        let scalar = raw.unicodeScalars.first?.value ?? 0
        let isFunctionKey = (0xF704...0xF70F).contains(scalar)
        guard isFunctionKey || !flags.intersection([.command, .option, .control]).isEmpty else { return nil }
        keyCode = UInt32(event.keyCode)
        modifiers = flags.rawValue
        if isFunctionKey {
            key = "F\(scalar - 0xF703)"
        } else if event.keyCode == UInt16(kVK_Space) {
            key = "Space"
        } else if let printable = raw.unicodeScalars.first, !CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains(printable) {
            key = raw.uppercased()
        } else {
            key = "Key \(event.keyCode)"
        }
    }

    static var saved: Shortcut? {
        get { UserDefaults.standard.data(forKey: defaultsKey).flatMap { try? JSONDecoder().decode(Shortcut.self, from: $0) } }
        set { UserDefaults.standard.set(newValue.flatMap { try? JSONEncoder().encode($0) }, forKey: defaultsKey) }
    }
}

/// One global hotkey through Carbon, which needs no Accessibility permission.
@MainActor
final class HotKey {
    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private let action: () -> Void

    init(action: @escaping () -> Void) {
        self.action = action
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, _, data in
            guard let data else { return noErr }
            let hotKey = Unmanaged<HotKey>.fromOpaque(data).takeUnretainedValue()
            MainActor.assumeIsolated { hotKey.action() }
            return noErr
        }, 1, &spec, Unmanaged.passUnretained(self).toOpaque(), &handler)
    }

    /// Returns false when macOS or another app already owns the combination.
    @discardableResult
    func register(_ shortcut: Shortcut?) -> Bool {
        unregister()
        guard let shortcut else { return true }
        let id = EventHotKeyID(signature: OSType(0x4B494954), id: 1)
        return RegisterEventHotKey(shortcut.keyCode, shortcut.carbonModifiers, id, GetApplicationEventTarget(), 0, &ref) == noErr
    }

    func unregister() {
        if let ref { UnregisterEventHotKey(ref) }
        ref = nil
    }
}

enum ScreenCapture {
    static let directory = FileManager.default.temporaryDirectory.appendingPathComponent("kiite-captures", isDirectory: true)

    /// Runs the system's interactive capture (drag a region, Space for a window).
    /// Calls back on the main queue with the file, or nil when cancelled.
    static func interactive(completion: @escaping @Sendable (URL?) -> Void) {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd 'at' HH.mm.ss"
        let url = directory.appendingPathComponent("Screenshot \(formatter.string(from: Date())).png")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            process.arguments = ["-i", url.path]
            process.terminationHandler = { _ in
                let made = FileManager.default.fileExists(atPath: url.path)
                DispatchQueue.main.async { completion(made ? url : nil) }
            }
            try process.run()
        } catch {
            AppLog.write("screencapture failed \(error.localizedDescription)")
            DispatchQueue.main.async { completion(nil) }
        }
    }
}
