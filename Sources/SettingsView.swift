import SwiftUI

struct SettingsView: View {
    var model: AppModel
    var onSave: (DestinationDraft, String, String, Bool, Bool) -> String?
    var onProbe: (DestinationDraft) -> Void
    var onTrust: (HostKeyOffer) -> String?
    var onTest: (DestinationDraft, String, String, Bool) -> Void
    var onChooseKey: () -> Void
    var onShowUploads: () -> Void
    var onSetLaunchAtLogin: (Bool) -> Void
    var onRecordShortcut: () -> Void
    var onClearShortcut: () -> Void

    @State private var draft = DestinationDraft()
    @State private var baseline = DestinationDraft()
    @State private var password = ""
    @State private var passphrase = ""
    @State private var dropPassword = false
    @State private var dropPassphrase = false
    @State private var didLoad = false
    @State private var errorText = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                Form {
                    Section("Connection") {
                        TextField("Name", text: $draft.profileName, prompt: Text("Destination"))
                        TextField("Host", text: $draft.host, prompt: Text("ssh.example.com"))
                        TextField("Port", text: $draft.port)
                            .frame(maxWidth: 120)
                        TextField("Username", text: $draft.username)
                        Picker("Authentication", selection: $draft.authMethod) {
                            Text("Private key").tag("publicKey")
                            Text("Password").tag("password")
                        }
                        if draft.authMethod == "password" {
                            SecureField(passwordPrompt, text: $password)
                            if draft.hasPassword {
                                Toggle("Remove saved password", isOn: $dropPassword)
                            }
                            Text("The password is stored in the Keychain on this Mac.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            Button(draft.keyFilename.isEmpty ? "Choose Private Key…" : "Change Key…") {
                                onChooseKey()
                            }
                            .buttonStyle(.bordered)
                            .help("Opens your .ssh folder and shows hidden files. Kiite does not copy the key.")
                            Text(draft.keyFilename.isEmpty ? "No key chosen" : draft.keyFilename)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            SecureField(passphrasePrompt, text: $passphrase)
                            if draft.hasPassphrase {
                                Toggle("Remove saved passphrase", isOn: $dropPassphrase)
                            }
                            Text("The key stays in the file you choose. Kiite stores a bookmark, not a copy. The chooser opens in your .ssh folder and shows hidden files.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        hostKeyBlock
                    }
                    Section("Publishing") {
                        TextField("Public root", text: $draft.remoteRoot, prompt: Text("/srv/kiite/public"))
                        TextField("Staging root", text: $draft.stagingRoot, prompt: Text("/srv/kiite/staging"))
                        TextField("Public base URL", text: $draft.publicBase, prompt: Text("https://cdn.example.com/shared/"))
                        Text("Paths are the server’s SFTP paths. Kiite does not expand ~ or shell variables. The https base is separate from the SSH host. Links are public.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Section("General") {
                        Toggle("Start at login", isOn: Binding(
                            get: { model.launchAtLogin },
                            set: onSetLaunchAtLogin
                        ))
                        if model.loginNeedsApproval {
                            Text("Allow Kiite in System Settings → General → Login Items.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Button("Open Login Items") { LoginItem.openSettings() }
                        }
                        if !model.loginError.isEmpty {
                            Text(model.loginError)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                        Toggle("Short URLs", isOn: $draft.shortURLs)
                            .help("Use a 16-character random name plus the file extension for new uploads. Original filenames stay in Kiite; downloads use the short name.")
                        Text(draft.shortURLs ? "Downloads use a short random name, keeping the file extension." : "Links include the date and original filename.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Stepper("Recent uploads in the menu: \(draft.recentCount)", value: $draft.recentCount, in: 1...20)
                        Toggle("Copy a verified link automatically", isOn: $draft.autoCopy)
                    }
                    Section("Screenshot") {
                        LabeledContent("Capture and upload") {
                            HStack {
                                Button(model.recordingShortcut ? "Press a shortcut…" : model.screenshotShortcut?.label ?? "Record Shortcut") {
                                    onRecordShortcut()
                                }
                                .disabled(model.recordingShortcut)
                                if model.screenshotShortcut != nil && !model.recordingShortcut {
                                    Button("Clear") { onClearShortcut() }
                                }
                            }
                        }
                        Text(model.recordingShortcut ? "Press the keys with ⌘, ⌃, or ⌥. Esc cancels." : "Drag a region, or press Space to pick a window. Kiite uploads the screenshot and copies its link. A shortcut macOS already uses, such as ⇧⌘3, must be turned off in System Settings → Keyboard → Keyboard Shortcuts → Screenshots first.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if !model.shortcutError.isEmpty {
                            Text(model.shortcutError)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                    if !model.testLines.isEmpty || model.testRunning {
                        Section("Test Connection") {
                            if model.testRunning {
                                Text("Running the publishing test…")
                                    .font(.caption)
                            }
                            ForEach(Array(model.testLines.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.caption)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
                .formStyle(.grouped)
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                if !errorText.isEmpty {
                    Text(errorText)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Text(unsaved ? "Unsaved changes" : "Saved")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Show Uploads") { onShowUploads() }
                    Button("Test Connection") { test() }
                        .disabled(model.testRunning)
                    Button("Save") { save() }
                        .keyboardShortcut("s", modifiers: .command)
                        .disabled(model.testRunning)
                }
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 520)
        .onAppear(perform: loadIfNeeded)
        .onChange(of: model.saveGeneration) { _, _ in
            guard let saved = model.savedDraft else { return }
            draft = saved
            baseline = saved
            password = ""
            passphrase = ""
            dropPassword = false
            dropPassphrase = false
            errorText = ""
        }
        .onChange(of: model.keyPickGeneration) { _, _ in
            if model.keyPickError.isEmpty, let data = model.keyPickBookmark {
                draft.keyBookmark = data
                draft.keyFilename = model.keyPickFilename
                errorText = ""
            } else if !model.keyPickError.isEmpty {
                errorText = model.keyPickError
            }
        }
    }

    private var hostKeyBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(trustSummary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Button("Check Host Key") { onProbe(draft) }
                    .disabled(model.testRunning)
                if let offer = matchingOffer {
                    Button(trustButtonTitle(offer), action: { trust(offer) })
                        .disabled(model.testRunning || alreadyTrusted(offer))
                }
            }
        }
    }

    private var matchingOffer: HostKeyOffer? {
        guard let offer = model.hostKeyOffer else { return nil }
        guard offer.host == PublicMapping.normalizeHost(draft.host), offer.port == (PublicMapping.portValue(draft.port) ?? -1) else {
            return nil
        }
        return offer
    }

    private var trustSummary: String {
        if let offer = matchingOffer {
            let state = alreadyTrusted(offer) ? "This matches the trusted key." : trustButtonTitle(offer) == "Update Trusted Key" ? "This is different from the trusted key. Transfers stay blocked until you update trust." : "Compare this fingerprint, then trust it. Kiite sends credentials only after that."
            return "\(offer.host) port \(offer.port) · \(offer.algorithm) · \(offer.openssh). \(state)"
        }
        if draft.trustedSHA256.count == 64, draft.trustedHost == PublicMapping.normalizeHost(draft.host), draft.trustedPort == (PublicMapping.portValue(draft.port) ?? -1) {
            return "Trusted \(draft.trustedAlgorithm) \(PublicMapping.opensshFingerprint(hex: draft.trustedSHA256)). Check the host key again to compare it with the server."
        }
        return "The host key is not trusted for this host and port. Check it before Test Connection will sign in."
    }

    private func alreadyTrusted(_ offer: HostKeyOffer) -> Bool {
        draft.trustedHost == offer.host && draft.trustedPort == offer.port && draft.trustedSHA256.lowercased() == offer.sha256.lowercased()
    }

    private func trustButtonTitle(_ offer: HostKeyOffer) -> String {
        if draft.trustedSHA256.count == 64 && draft.trustedHost == offer.host && draft.trustedPort == offer.port && !alreadyTrusted(offer) {
            return "Update Trusted Key"
        }
        return "Trust This Key"
    }

    private var passwordPrompt: String {
        draft.hasPassword && !dropPassword ? "New password" : "Password"
    }

    private var passphrasePrompt: String {
        draft.hasPassphrase && !dropPassphrase ? "New key passphrase" : "Key passphrase, if the key has one"
    }

    private var unsaved: Bool {
        draft != baseline || !password.isEmpty || !passphrase.isEmpty || dropPassword || dropPassphrase
    }

    private func loadIfNeeded() {
        guard !didLoad else { return }
        didLoad = true
        let saved = model.savedDraft ?? DestinationDraft()
        draft = saved
        baseline = saved
    }

    private func save() {
        errorText = ""
        if let error = onSave(draft, password, passphrase, dropPassword, dropPassphrase) {
            errorText = error
        }
    }

    private func test() {
        errorText = ""
        onTest(draft, password, passphrase, dropPassword)
    }

    private func trust(_ offer: HostKeyOffer) {
        errorText = ""
        if let error = onTrust(offer) {
            errorText = error
            return
        }
        draft.trustedHost = offer.host
        draft.trustedPort = offer.port
        draft.trustedAlgorithm = offer.algorithm
        draft.trustedSHA256 = offer.sha256
        baseline.trustedHost = offer.host
        baseline.trustedPort = offer.port
        baseline.trustedAlgorithm = offer.algorithm
        baseline.trustedSHA256 = offer.sha256
    }
}
