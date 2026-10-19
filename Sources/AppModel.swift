import Foundation
import Observation

enum IconState: Equatable {
    case ready
    case hover
    case uploading(CGFloat)
    case success
    case attention
}

@MainActor
@Observable
final class AppModel {
    var history: [HistoryRecord] = []
    var recent: [HistoryRecord] = []
    var icon: IconState = .attention
    var queuedCount = 0
    var banner = "Set the destination in Settings and trust its host key. A drop before that waits as Needs setup."
    var phaseNote: String?
    var progressText = ""
    var progressFraction: Double?
    var destinationReady = false
    var savedDraft: DestinationDraft?
    var copyFeedbackID: String?
    var activeID: String?
    var testLines: [String] = []
    var testRunning = false
    var hostKeyOffer: HostKeyOffer?
    var saveGeneration = 0
    var keyPickGeneration = 0
    var keyPickBookmark: Data?
    var keyPickFilename = ""
    var keyPickError = ""
    var launchAtLogin = false
    var loginNeedsApproval = false
    var loginError = ""
    var screenshotShortcut: Shortcut?
    var recordingShortcut = false
    var shortcutError = ""

    var stateLabel: String {
        if let phaseNote { return phaseNote }
        switch icon {
        case .ready: return destinationReady ? "Ready" : "Needs setup"
        case .hover: return "Drop to upload"
        case .uploading: return progressText.isEmpty ? "Uploading" : progressText
        case .success: return "Uploaded"
        case .attention: return "Needs attention"
        }
    }

    var accessibilityLabel: String {
        switch icon {
        case .ready: return destinationReady ? "Kiite, ready." : "Kiite, needs setup."
        case .hover: return "Kiite, drop to upload."
        case .uploading: return "Kiite, \(phaseNote?.lowercased() ?? "uploading")."
        case .success: return "Kiite, upload complete."
        case .attention: return "Kiite, needs attention."
        }
    }

    func record(_ message: String) {
        AppLog.write(message)
    }
}
