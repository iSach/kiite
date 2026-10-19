import AppKit
import SwiftUI

struct QueuedUpload {
    var id: String
    var name: String
    var snapshot: URL
    var bytes: Int64
    var batchID: String
    var host: String
    var port: Int32
    var user: String
    var keyBookmark: Data?
    var passphrase: String?
    var password: String?
    var pin: String
    var stagingPath: String
    var finalPath: String
    var publicURL: String
    var expectedSHA256: String?
}

private struct KeyPickOutcome: Sendable {
    var bookmark: Data?
    var filename: String = ""
    var error: String = ""
    var domain: String = ""
    var code: Int = 0
}

private func keyPickOutcome(response: NSApplication.ModalResponse, url: URL?, failed: String?) -> KeyPickOutcome {
    if let failed {
        return KeyPickOutcome(error: failed)
    }
    guard response == .OK, let url else { return KeyPickOutcome() }
    let accessing = url.startAccessingSecurityScopedResource()
    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
    do {
        let data = try KeyBookmark.make(for: url)
        let name = url.lastPathComponent
        guard !name.isEmpty, name != "/", name != "." else {
            return KeyPickOutcome(error: "Choose a private key file. Kiite did not copy anything.")
        }
        return KeyPickOutcome(bookmark: data, filename: name)
    } catch {
        let ns = error as NSError
        var message = "Kiite could not keep access to that key file. \(ns.localizedDescription) (\(ns.domain) \(ns.code)). The key was not copied."
        if ns.domain == NSCocoaErrorDomain && (ns.code == 257 || ns.code == 256 || ns.code == 513) {
            message += " macOS refused a bookmark for that file."
        }
        return KeyPickOutcome(error: message, domain: ns.domain, code: ns.code)
    }
}

private struct UploadBatch {
    var id: String
    var order: [String] = []
    var bytes: [String: Int64] = [:]
    var urls: [String: String] = [:]
    var failed: Set<String> = []
    var unverified: Set<String> = []
    var finished: Set<String> = []
    var autoCopy: Bool
}

private struct ImportItem: Sendable {
    var id: String
    var url: URL
    var original: HistoryRecord?
}

private struct PendingImport: Sendable {
    var id: String
    var items: [ImportItem]
    var draft: DestinationDraft?
    var cancellation = PreparationCancellation()
}

private enum PreparedItem: Sendable {
    case ready(String, UploadJob)
    case failed(String, String)
}

@MainActor
final class StatusController: NSObject, NSPopoverDelegate {
    let model: AppModel
    private let store = Store()
    private let windows = AppWindows()
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private var dropView: DropReceivingView?
    private var windowBridge: WindowDragBridge?
    private let popover = NSPopover()
    private var timer: Timer?
    private var jobs: [QueuedUpload] = []
    private var imports: [PendingImport] = []
    private var activeImport: PendingImport?
    private let preparationQueue = DispatchQueue(label: "com.isach.kiite.preparation", qos: .userInitiated)
    private var batches: [UploadBatch] = []
    private var active: QueuedUpload?
    private var uploadProgress: ProgressGate?
    private var checkHandle = CheckHandle()
    private var uploading = false
    private var checking = false
    private var successUntil: Date?
    private var attentionUntil: Date?
    private var hoverLogged = false
    private var acceptedSequence: Int?
    private var transferETA = TransferETA()
    private var keyPanelOpen = false
    private var retryPanelOpen = false
    private lazy var contextMenu: NSMenu = {
        let menu = NSMenu()
        for (title, action) in [("Show All", #selector(menuShowAll)), ("Settings", #selector(menuSettings))] {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.target = self
            menu.addItem(item)
        }
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Kiite", action: #selector(menuQuit), keyEquivalent: "")
        quit.target = self
        menu.addItem(quit)
        return menu
    }()

    override init() {
        self.model = AppModel()
        super.init()
    }

    func install() {
        guard let button = statusItem.button else {
            model.record("status button missing")
            return
        }
        store.launchMaintenance()
        reloadLists()
        refreshIdle()
        let view = DropReceivingView(frame: button.bounds)
        view.autoresizingMask = [.width, .height]
        view.controller = self
        view.registersForDrags = true
        button.addSubview(view)
        dropView = view
        button.imagePosition = .imageOnly
        button.setAccessibilityElement(true)
        button.setAccessibilityRole(.button)
        applyAccessibility()
        button.postsFrameChangedNotifications = true
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(buttonFrameChanged),
            name: NSView.frameDidChangeNotification,
            object: button
        )
        scheduleLayoutLog(attempt: 0)

        popover.behavior = .transient
        popover.delegate = self
        let popoverHost = NSHostingController(rootView: PopoverRoot(
            model: model,
            onShowAll: { [weak self] in self?.showHistory() },
            onSettings: { [weak self] in self?.showSettings() },
            onQuit: { NSApp.terminate(nil) },
            onCopy: { [weak self] id in self?.copyLink(id) },
            onOpen: { [weak self] id in self?.openLink(id) },
            onRetry: { [weak self] id in self?.retry(id) },
            onCheck: { [weak self] id in self?.checkAgain(id) },
            onCancel: { [weak self] in self?.cancelActive() }
        ))
        // Keep progress rows inside the scrolling list instead of resizing the
        // popover while it is anchored to the menu bar.
        popoverHost.sizingOptions = []
        popover.contentViewController = popoverHost
        popover.contentSize = PopoverRoot.contentSize
        model.record("installed sandbox=\(isSandboxed)")
        render()
        if !model.destinationReady {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
                guard let self, !self.model.destinationReady else { return }
                self.showSettings()
            }
        }
    }

    func showSettings() {
        refreshLaunchAtLogin()
        windows.showSettings {
            SettingsView(
                model: model,
                onSave: { [weak self] draft, password, passphrase, dropPassword, dropPassphrase in
                    self?.save(draft, password: password, passphrase: passphrase, dropPassword: dropPassword, dropPassphrase: dropPassphrase)
                },
                onProbe: { [weak self] draft in self?.probe(draft) },
                onTrust: { [weak self] offer in self?.trust(offer) },
                onTest: { [weak self] draft, password, passphrase, dropPassword in
                    self?.test(draft, password: password, passphrase: passphrase, dropPassword: dropPassword)
                },
                onChooseKey: { [weak self] in
                    guard let self else { return }
                    self.chooseKey()
                },
                onShowUploads: { [weak self] in self?.showHistory() },
                onSetLaunchAtLogin: { [weak self] enabled in self?.setLaunchAtLogin(enabled) }
            )
        }
    }

    func refreshLaunchAtLogin() {
        model.launchAtLogin = LoginItem.enabled
        model.loginNeedsApproval = LoginItem.needsApproval
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        model.loginError = ""
        do {
            try LoginItem.setEnabled(enabled)
        } catch {
            model.loginError = "Could not change Start at login. \(error.localizedDescription)"
        }
        refreshLaunchAtLogin()
    }

    func showHistory() {
        windows.showHistory {
            HistoryView(
                model: model,
                onImport: { [weak self] urls in self?.receive(urls) },
                onSettings: { [weak self] in self?.showSettings() },
                onCopy: { [weak self] id in self?.copyLink(id) },
                onOpen: { [weak self] id in self?.openLink(id) },
                onRetry: { [weak self] id in self?.retry(id) },
                onCheck: { [weak self] id in self?.checkAgain(id) },
                onCancel: { [weak self] in self?.cancelActive() },
                onRemove: { [weak self] id in self?.removeHistory(id) }
            )
        }
    }

    func importURLs(_ urls: [URL]) {
        receive(urls)
    }

    @objc private func buttonFrameChanged() {
        guard let button = statusItem.button else { return }
        dropView?.frame = button.bounds
        installWindowTargetIfNeeded()
    }

    private func scheduleLayoutLog(attempt: Int) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            guard let self, let button = self.statusItem.button else { return }
            self.dropView?.frame = button.bounds
            let window = button.window
            let windowFrame = window?.frame ?? .zero
            let screenRect = window.map { $0.convertToScreen(button.convert(button.bounds, to: nil)) } ?? .zero
            let placed = windowFrame.height > 1 && screenRect.minY > 100
            if placed || attempt == 6 {
                let screen = window?.screen
                self.model.record(
                    "layout t=\(attempt) visible=\(self.statusItem.isVisible) thickness=\(NSStatusBar.system.thickness) window=\(window?.windowNumber ?? -1) button=\(self.describe(button.bounds)) windowFrame=\(self.describe(windowFrame)) screen=\(self.describe(screenRect)) display=\(screen.map { self.describe($0.frame) } ?? "nil") class=\(window.map { String(describing: type(of: $0)) } ?? "nil")"
                )
            }
            if windowFrame.height > 1 {
                self.installWindowTargetIfNeeded()
            }
            if !placed && attempt < 6 {
                self.scheduleLayoutLog(attempt: attempt + 1)
            }
        }
    }

    func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(nil)
            model.record("popover closed")
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        model.record("popover opened")
    }

    func showContextMenu(with event: NSEvent, from view: NSView) {
        popover.performClose(nil)
        setHighlighted(false)
        NSMenu.popUpContextMenu(contextMenu, with: event, for: view)
    }

    @objc private func menuShowAll() { showHistory() }
    @objc private func menuSettings() { showSettings() }
    @objc private func menuQuit() { NSApp.terminate(nil) }

    func setHighlighted(_ highlighted: Bool) {
        statusItem.button?.isHighlighted = highlighted
    }

    func dragEntered(receiver: String, info: NSDraggingInfo) -> NSDragOperation {
        let decision = decision(for: info)
        if !hoverLogged {
            model.record("draggingEntered receiver=\(receiver) sequence=\(info.draggingSequenceNumber) \(decision.summary)")
            hoverLogged = true
        }
        guard decision.acceptsAny else { return [] }
        if active == nil && activeImport == nil && !checking {
            model.icon = .hover
            render()
        }
        return .copy
    }

    func dragUpdated(receiver: String, info: NSDraggingInfo) -> NSDragOperation {
        decision(for: info).acceptsAny ? .copy : []
    }

    func dragExited(receiver: String) {
        hoverLogged = false
        model.record("draggingExited receiver=\(receiver)")
        if case .hover = model.icon {
            restoreIdleIcon()
        }
    }

    func prepareDrag(receiver: String, info: NSDraggingInfo) -> Bool {
        let ok = decision(for: info).acceptsAny
        model.record("prepareForDragOperation receiver=\(receiver) sequence=\(info.draggingSequenceNumber) accept=\(ok)")
        return ok
    }

    func performDrag(receiver: String, info: NSDraggingInfo) -> Bool {
        hoverLogged = false
        if acceptedSequence == info.draggingSequenceNumber {
            model.record("duplicate perform ignored sequence=\(info.draggingSequenceNumber) receiver=\(receiver)")
            return true
        }
        acceptedSequence = info.draggingSequenceNumber
        let decision = decision(for: info)
        model.record("performDragOperation receiver=\(receiver) sequence=\(info.draggingSequenceNumber) \(decision.summary)")
        receive(decision.urls)
        if !decision.acceptsAny {
            attentionPulse()
            return false
        }
        return true
    }

    private func receive(_ urls: [URL]) {
        if urls.isEmpty {
            model.record("rejected payload: no regular files")
            attentionPulse()
            return
        }
        let request = PendingImport(id: UUID().uuidString, items: urls.map { ImportItem(id: UUID().uuidString, url: $0, original: nil) }, draft: store.loadDraft())
        for item in request.items {
            store.insertPreparing(id: item.id, filename: item.url.lastPathComponent, batchID: request.id)
        }
        imports.append(request)
        model.queuedCount = queuedCount
        reloadLists()
        pump()
    }

    private var queuedCount: Int {
        jobs.count + imports.reduce(0) { $0 + $1.items.count }
    }

    private func prepare(_ request: PendingImport) {
        activeImport = request
        successUntil = nil
        attentionUntil = nil
        model.progressFraction = nil
        model.progressText = ""
        model.phaseNote = "Preparing files"
        model.progressText = ""
        model.icon = .uploading(0)
        model.queuedCount = queuedCount
        render()
        preparationQueue.async {
            var results: [PreparedItem] = []
            for item in request.items {
                DispatchQueue.main.sync {
                    MainActor.assumeIsolated {
                        self.model.activeID = item.id
                        self.model.phaseNote = "Preparing \(item.url.lastPathComponent)"
                        self.store.setStatus(id: item.id, status: UploadStatus.preparing, detail: "Preparing a stable copy…", completed: false)
                        self.reloadLists()
                    }
                }
                do {
                    let snapshot = try FileSnapshot.prepare(url: item.url, cancellation: request.cancellation)
                    if let original = item.original,
                       ((original.bytes > 0 || !original.sha256.isEmpty) && snapshot.bytes != original.bytes
                        || original.sha256.isEmpty && snapshot.name != original.filename) {
                        try? FileManager.default.removeItem(at: snapshot.snapshot)
                        throw PreparationError(message: "Choose the original file with the same name and size, or drop the changed file as a new upload.")
                    }
                    results.append(.ready(item.id, snapshot))
                } catch {
                    let detail = (error as? LocalizedError)?.errorDescription ?? "The file could not be prepared. Check access and free disk space."
                    results.append(.failed(item.id, detail))
                }
            }
            let prepared = results
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self.finishPreparing(request, results: prepared) }
            }
        }
    }

    private func finishPreparing(_ request: PendingImport, results: [PreparedItem]) {
        activeImport = nil
        model.activeID = nil
        model.phaseNote = nil
        if request.cancellation.isCancelled {
            for result in results {
                if case .ready(_, let snapshot) = result { try? FileManager.default.removeItem(at: snapshot.snapshot) }
            }
            for item in request.items {
                store.setStatus(id: item.id, status: UploadStatus.cancelled, detail: "File preparation cancelled. Drop the file again to upload it.", completed: true)
            }
            model.banner = "File preparation cancelled."
            reloadLists()
            pump()
            return
        }
        let draft = store.canUpload(draft: request.draft) ? request.draft : store.loadDraft()
        let ready = store.canUpload(draft: draft)
        var batch = UploadBatch(id: request.id, autoCopy: draft?.autoCopy ?? false)
        var queued: [QueuedUpload] = []
        var needsSettings = false
        for result in results {
            switch result {
            case .failed(let id, let reason):
                store.setStatus(id: id, status: UploadStatus.failed, detail: reason, completed: true)
                batch.order.append(id)
                batch.failed.insert(id)
                batch.finished.insert(id)
                model.banner = reason
                model.record("preparation failed \(id)")
                model.icon = .attention
                attentionUntil = Date().addingTimeInterval(3)
                ensureTimer()
            case .ready(let id, let snap):
                store.setSnapshot(id: id, snapshot: snap)
                store.setStatus(id: id, status: UploadStatus.needsSetup, detail: "Needs setup. Save a destination and trust its host key.", completed: false)
                if ready, let draft, let upload = makeQueued(
                    id: id,
                    name: snap.name,
                    snapshot: snap.snapshot,
                    bytes: snap.bytes,
                    batchID: batch.id,
                    draft: draft,
                    existing: request.items.first(where: { $0.id == id })?.original
                ) {
                    queued.append(upload)
                    batch.order.append(id)
                    batch.bytes[id] = snap.bytes
                } else {
                    needsSettings = true
                }
                model.record("enqueued \(id) bytes=\(snap.bytes)")
            }
        }
        if !queued.isEmpty {
            jobs.append(contentsOf: queued)
            batches.append(batch)
        }
        model.queuedCount = queuedCount
        reloadLists()
        if needsSettings {
            model.banner = "Needs setup. Kiite kept the files and will not upload until the destination is saved and the host key is trusted."
            model.icon = .attention
            render()
            DispatchQueue.main.async { [weak self] in self?.showSettings() }
        }
        pump()
    }

    private func makeQueued(
        id: String,
        name: String,
        snapshot: URL,
        bytes: Int64,
        batchID: String,
        draft: DestinationDraft,
        existing: HistoryRecord?
    ) -> QueuedUpload? {
        let key = (existing?.objectKey.isEmpty == false ? existing?.objectKey : nil) ?? PublicMapping.allocateKey(filename: name, shortURLs: draft.shortURLs)
        let host = (existing?.snapshotHost.isEmpty == false ? existing?.snapshotHost : nil) ?? draft.normalizedHost
        let port = (existing?.snapshotPort ?? 0) > 0 ? existing!.snapshotPort : (PublicMapping.portValue(draft.port) ?? 22)
        let user = (existing?.snapshotUser.isEmpty == false ? existing?.snapshotUser : nil) ?? draft.username.trimmingCharacters(in: .whitespacesAndNewlines)
        let root = (existing?.snapshotRoot.isEmpty == false ? existing?.snapshotRoot : nil) ?? draft.remoteRoot
        let stagingRoot = (existing?.snapshotStaging.isEmpty == false ? existing?.snapshotStaging : nil) ?? draft.stagingRoot
        let preservedURL = existing?.publicURL ?? ""
        let base = preservedURL.isEmpty ? draft.publicBase : (existing?.snapshotBase ?? draft.publicBase)
        guard draft.trustedHost == host, draft.trustedPort == port, draft.trustedSHA256.count == 64 else {
            store.setStatus(id: id, status: UploadStatus.needsSetup, detail: "Trust the host key for \(host) port \(port) before this upload can start.", completed: false)
            return nil
        }
        guard let stagingPath = PublicMapping.join(root: stagingRoot, objectKey: key),
              let finalPath = PublicMapping.join(root: root, objectKey: key)
        else {
            store.setStatus(id: id, status: UploadStatus.failed, detail: "The remote path was rejected.", completed: true)
            return nil
        }
        let publicURL = preservedURL.isEmpty ? (PublicMapping.publicURL(base: base, objectKey: key) ?? "") : preservedURL
        var snap = draft
        snap.host = host
        snap.port = String(port)
        snap.username = user
        snap.remoteRoot = root
        snap.stagingRoot = stagingRoot
        snap.publicBase = base
        let creds = store.credential(for: snap, typedPassword: "", typedPassphrase: "")
        if snap.authMethod == "password" && (creds.password ?? "").isEmpty {
            store.setStatus(id: id, status: UploadStatus.failed, detail: "The password is not available. The Keychain may be locked.", completed: true)
            return nil
        }
        if snap.authMethod != "password" && snap.keyBookmark == nil {
            store.setStatus(id: id, status: UploadStatus.failed, detail: "Choose the private key again in Settings.", completed: true)
            return nil
        }
        store.prepareUpload(id: id, draft: snap, objectKey: key, remotePath: finalPath, publicURL: publicURL)
        return QueuedUpload(
            id: id,
            name: name,
            snapshot: snapshot,
            bytes: bytes,
            batchID: batchID,
            host: host,
            port: Int32(port),
            user: user,
            keyBookmark: snap.authMethod == "password" ? nil : snap.keyBookmark,
            passphrase: snap.authMethod == "password" ? nil : creds.passphrase,
            password: snap.authMethod == "password" ? creds.password : nil,
            pin: draft.trustedSHA256,
            stagingPath: stagingPath,
            finalPath: finalPath,
            publicURL: publicURL,
            expectedSHA256: existing?.sha256.isEmpty == false ? existing?.sha256 : nil
        )
    }

    private func retry(_ id: String) {
        guard let draft = store.loadDraft(), store.canUpload(draft: draft) else {
            model.banner = "Save a trusted destination before retrying."
            showSettings()
            return
        }
        guard active?.id != id, !jobs.contains(where: { $0.id == id }) else { return }
        guard let record = store.record(id: id) else { return }
        guard FileManager.default.fileExists(atPath: record.snapshotPath) else {
            chooseRetrySource(record)
            return
        }
        guard let upload = makeQueued(
            id: id,
            name: record.filename,
            snapshot: URL(fileURLWithPath: record.snapshotPath),
            bytes: record.bytes,
            batchID: UUID().uuidString,
            draft: draft,
            existing: record
        ) else {
            reloadLists()
            showSettings()
            return
        }
        var batch = UploadBatch(id: upload.batchID, autoCopy: draft.autoCopy && !record.clipboardDone)
        batch.order = [id]
        batch.bytes[id] = record.bytes
        jobs.append(upload)
        batches.append(batch)
        model.queuedCount = queuedCount
        reloadLists()
        pump()
    }

    private func chooseRetrySource(_ record: HistoryRecord) {
        guard !retryPanelOpen else { return }
        retryPanelOpen = true
        popover.performClose(nil)
        showHistory()
        guard let window = windows.historyWindow else {
            retryPanelOpen = false
            return
        }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Retry Upload"
        panel.message = "Choose \(record.filename) again. Kiite checks it against the original upload and keeps the same public URL."
        panel.beginSheetModal(for: window) { [weak self] response in
            let url = response == .OK ? panel.url : nil
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.retryPanelOpen = false
                    guard let url else { return }
                    let request = PendingImport(id: UUID().uuidString,
                                                items: [ImportItem(id: record.id, url: url, original: record)],
                                                draft: self.store.loadDraft())
                    self.store.setStatus(id: record.id, status: UploadStatus.preparing, detail: "Preparing the file for retry…", completed: false)
                    self.imports.append(request)
                    self.reloadLists()
                    self.pump()
                }
            }
        }
    }

    private func pump() {
        guard active == nil, activeImport == nil, !checking else { return }
        guard !jobs.isEmpty else {
            if !imports.isEmpty {
                prepare(imports.removeFirst())
                return
            }
            model.queuedCount = 0
            if successUntil == nil && attentionUntil == nil {
                restoreIdleIcon()
            }
            return
        }
        let job = jobs.removeFirst()
        active = job
        successUntil = nil
        attentionUntil = nil
        model.activeID = job.id
        uploading = true
        checking = false
        transferETA = TransferETA()
        model.queuedCount = queuedCount
        model.phaseNote = "Preparing upload"
        model.progressFraction = 0
        model.progressText = "Preparing…"
        model.icon = .uploading(batchFraction(current: job, written: 0))
        let gate = ProgressGate(total: job.bytes)
        uploadProgress = gate
        checkHandle = CheckHandle()
        render()
        ensureTimer()
        let handle = checkHandle
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = UploadWork.run(job: job, progress: gate, check: handle, onDigest: { hex, sample, refreshed in
                DispatchQueue.main.sync {
                    MainActor.assumeIsolated {
                        self.store.setDigest(id: job.id, sha256: hex, sample: sample)
                        if let refreshed {
                            self.store.replaceBookmark(refreshed)
                        }
                        self.reloadLists()
                    }
                }
            }, onChecking: {
                DispatchQueue.main.sync {
                    MainActor.assumeIsolated {
                        self.uploading = false
                        self.checking = true
                        self.model.phaseNote = "Checking public link"
                        self.model.progressFraction = 0.99
                        self.model.progressText = "99% · Checking link…"
                        self.model.icon = .uploading(self.batchFraction(current: job, written: Int64(Double(job.bytes) * 0.99)))
                        self.store.setStatus(id: job.id, status: UploadStatus.checking, detail: "Checking public link.", completed: false)
                        self.reloadLists()
                        self.render()
                    }
                }
            })
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.finish(job, outcome)
                }
            }
        }
    }

    private func finish(_ job: QueuedUpload, _ outcome: TransferOutcome) {
        uploadProgress?.close()
        uploadProgress = nil
        uploading = false
        checking = false
        active = nil
        model.activeID = nil
        model.phaseNote = nil
        model.progressText = ""
        model.progressFraction = nil
        switch outcome {
        case .verified:
            store.setStatus(id: job.id, status: UploadStatus.verified, detail: "Public link verified.", completed: true)
            store.clearSnapshot(id: job.id)
            note(job, kind: .verified)
            model.icon = .uploading(1)
            model.banner = "Public link verified for \(job.name)."
            model.record("verified \(job.id) bytes=\(job.bytes)")
        case .publishedUnverified(let detail):
            store.setStatus(id: job.id, status: UploadStatus.publishedUnverified, detail: detail, completed: true)
            store.clearSnapshot(id: job.id)
            note(job, kind: .unverified)
            model.banner = "\(job.name) was published. \(detail)"
            model.record("published-unverified \(job.id)")
            restoreIdleIcon()
        case .failed(let code, let message):
            store.setStatus(id: job.id, status: UploadStatus.failed, detail: message, completed: true)
            if code == UploadWork.sourceChangedCode { store.clearSnapshot(id: job.id) }
            note(job, kind: .failed)
            model.banner = message
            model.icon = .attention
            attentionUntil = Date().addingTimeInterval(3)
            model.record("upload failed \(job.id) code=\(code)")
        case .cancelled:
            store.setStatus(id: job.id, status: UploadStatus.cancelled, detail: "Cancelled.", completed: true)
            store.clearSnapshot(id: job.id)
            note(job, kind: .failed)
            model.banner = "Cancelled \(job.name)."
            model.record("cancelled \(job.id)")
            restoreIdleIcon()
        }
        model.queuedCount = queuedCount
        reloadLists()
        settleBatches()
        render()
        if successUntil != nil && (!jobs.isEmpty || !imports.isEmpty) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.pump() }
        } else {
            pump()
        }
    }

    private enum BatchKind { case verified, unverified, failed }

    private func note(_ job: QueuedUpload, kind: BatchKind) {
        guard let index = batches.firstIndex(where: { $0.id == job.batchID }) else { return }
        batches[index].finished.insert(job.id)
        switch kind {
        case .verified:
            batches[index].urls[job.id] = job.publicURL
        case .unverified:
            batches[index].unverified.insert(job.id)
        case .failed:
            batches[index].failed.insert(job.id)
        }
    }

    private func settleBatches() {
        var keep: [UploadBatch] = []
        for batch in batches {
            let done = batch.order.allSatisfy { batch.finished.contains($0) }
            let stillQueued = active?.batchID == batch.id || jobs.contains { $0.batchID == batch.id }
            guard done && !stillQueued else {
                keep.append(batch)
                continue
            }
            let urls = batch.order.compactMap { batch.urls[$0] }.filter { !$0.isEmpty }
            if batch.failed.isEmpty && batch.unverified.isEmpty && !urls.isEmpty {
                model.icon = .success
                successUntil = Date().addingTimeInterval(2)
                ensureTimer()
            } else {
                successUntil = nil
                model.icon = .attention
                attentionUntil = Date().addingTimeInterval(3)
                ensureTimer()
            }
            guard batch.autoCopy else {
                store.setClipboardDone(ids: batch.order.filter { batch.urls[$0] != nil })
                continue
            }
            guard !urls.isEmpty else { continue }
            let ids = batch.order.filter { batch.urls[$0] != nil }
            store.setClipboardIntent(ids: ids)
            if paste(urls.joined(separator: "\n")) {
                store.setClipboardDone(ids: ids)
                let failed = batch.failed.count
                if failed == 0 && batch.unverified.isEmpty {
                    model.banner = urls.count == 1 ? "Link copied." : "\(urls.count) links copied."
                } else if failed > 0 {
                    model.banner = "\(urls.count) links copied; \(failed) upload failed."
                } else {
                    model.banner = "\(urls.count) links copied. \(batch.unverified.count) published file still needs a public check."
                }
            } else {
                model.banner = "Uploaded; could not copy link."
            }
        }
        batches = keep
    }

    private func checkAgain(_ id: String) {
        guard active == nil, activeImport == nil, !checking else {
            model.banner = "Wait for the current upload to finish."
            return
        }
        guard let record = store.record(id: id), let url = URL(string: record.publicURL), url.scheme?.lowercased() == "https" else {
            model.banner = "This upload has no stored public URL."
            return
        }
        guard let sample = store.sample(id: id), !sample.isEmpty || record.bytes == 0 else {
            model.banner = "The sample for this upload is gone, so Kiite cannot check the link again."
            return
        }
        checking = true
        successUntil = nil
        model.activeID = id
        model.phaseNote = "Checking public link"
        model.progressFraction = 1
        model.progressText = "100% · Checking link…"
        model.icon = .uploading(1)
        let handle = CheckHandle()
        checkHandle = handle
        let bytes = record.bytes
        let copied = record.clipboardDone
        let autoCopy = store.loadDraft()?.autoCopy ?? false
        render()
        ensureTimer()
        DispatchQueue.global(qos: .userInitiated).async {
            let detail = PublicCheck.fetch(url: url, sample: sample, expectedBytes: bytes, handle: handle)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.finishCheck(id: id, detail: detail, autoCopy: autoCopy && !copied, url: record.publicURL)
                }
            }
        }
    }

    private func finishCheck(id: String, detail: String?, autoCopy: Bool, url: String) {
        checking = false
        model.activeID = nil
        model.phaseNote = nil
        model.progressFraction = nil
        model.progressText = ""
        if detail == nil {
            store.setStatus(id: id, status: UploadStatus.verified, detail: "Public link verified.", completed: true)
            if autoCopy && !url.isEmpty {
                store.setClipboardIntent(ids: [id])
                if paste(url) {
                    store.setClipboardDone(ids: [id])
                    model.banner = "Link copied."
                } else {
                    model.banner = "Uploaded; could not copy link."
                }
            } else {
                model.banner = "Public link verified."
            }
            model.icon = .success
            successUntil = Date().addingTimeInterval(2)
            ensureTimer()
            model.record("verified \(id)")
        } else {
            store.setStatus(id: id, status: UploadStatus.publishedUnverified, detail: detail ?? "", completed: true)
            model.banner = detail ?? "The public link was not verified."
            restoreIdleIcon()
        }
        reloadLists()
        render()
        pump()
    }

    private func cancelActive() {
        activeImport?.cancellation.cancel()
        if uploading {
            uploadProgress?.requestCancel()
        }
        if checking {
            checkHandle.cancel()
        }
    }

    private func copyLink(_ id: String) {
        guard let record = store.record(id: id), let url = URL(string: record.publicURL), url.scheme?.lowercased() == "https" else { return }
        if paste(record.publicURL) {
            store.setClipboardDone(ids: [id])
            model.copyFeedbackID = id
            model.banner = "Copied."
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                if self?.model.copyFeedbackID == id { self?.model.copyFeedbackID = nil }
            }
        } else {
            model.banner = "Uploaded; could not copy link."
        }
    }

    private func openLink(_ id: String) {
        guard let record = store.record(id: id), let url = URL(string: record.publicURL), url.scheme?.lowercased() == "https" else { return }
        NSWorkspace.shared.open(url)
    }

    private func removeHistory(_ id: String) {
        guard active?.id != id, activeImport?.items.contains(where: { $0.id == id }) != true,
              !jobs.contains(where: { $0.id == id }), !imports.contains(where: { $0.items.contains(where: { $0.id == id }) }) else {
            model.banner = "Finish or cancel the upload before removing it from history."
            return
        }
        store.removeHistory(id: id)
        reloadLists()
    }

    private func paste(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        let board = NSPasteboard.general
        board.clearContents()
        return board.setString(text, forType: .string)
    }

    private func save(_ draft: DestinationDraft, password: String, passphrase: String, dropPassword: Bool, dropPassphrase: Bool) -> String? {
        if let error = store.save(draft: draft, password: password, passphrase: passphrase, dropPassword: dropPassword, dropPassphrase: dropPassphrase) {
            return error
        }
        reloadLists()
        model.saveGeneration += 1
        if !resumeNeedsSetup() {
            refreshIdle()
        }
        model.record("destination saved")
        return nil
    }

    private func trust(_ offer: HostKeyOffer) -> String? {
        if let error = store.saveTrust(host: offer.host, port: offer.port, algorithm: offer.algorithm, sha256: offer.sha256) {
            return error
        }
        reloadLists()
        model.record("host trust updated \(offer.host) port \(offer.port) \(offer.algorithm)")
        if !resumeNeedsSetup() {
            refreshIdle()
        }
        return nil
    }

    private func probe(_ draft: DestinationDraft) {
        guard PublicMapping.hostError(draft.host) == nil, let port = PublicMapping.portValue(draft.port) else {
            model.testLines = ["Enter a host and a port before checking the host key."]
            return
        }
        let host = draft.normalizedHost
        model.testRunning = true
        model.testLines = ["Checking the host key. Credentials are not sent."]
        DispatchQueue.global(qos: .userInitiated).async {
            var probe = KiiteProbeResult()
            let code = host.withCString { kiite_probe_hostkey($0, Int32(port), &probe) }
            let hex = CBridge.probeHex(probe)
            let algorithm = CBridge.probeAlgorithm(probe)
            let message = CBridge.probeMessage(probe)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.model.testRunning = false
                    guard code == 0, hex.count == 64 else {
                        self.model.hostKeyOffer = nil
                        self.model.testLines = ["Reachability: \(message).", "Result: stopped before authentication."]
                        return
                    }
                    let offer = HostKeyOffer(
                        host: host,
                        port: port,
                        algorithm: algorithm,
                        sha256: hex,
                        openssh: PublicMapping.opensshFingerprint(hex: hex)
                    )
                    self.model.hostKeyOffer = offer
                    self.model.testLines = ["Host key: \(algorithm) \(offer.openssh).", "Kiite did not send credentials."]
                }
            }
        }
    }

    private func test(_ draft: DestinationDraft, password: String, passphrase: String, dropPassword: Bool) {
        model.testRunning = true
        model.testLines = ["Starting the publishing test."]
        DispatchQueue.global(qos: .userInitiated).async {
            let report = ConnectionTest.run(draft: draft, password: password, passphrase: passphrase, dropPassword: dropPassword)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self.model.testRunning = false
                    self.model.testLines = report.lines
                    if let offer = report.offer {
                        self.model.hostKeyOffer = offer
                    }
                    self.model.record("connection test finished")
                }
            }
        }
    }

    private func chooseKey() {
        guard !keyPanelOpen else { return }
        keyPanelOpen = true
        DispatchQueue.main.async { [weak self] in
            self?.presentKeyPanel()
        }
    }

    private func presentKeyPanel() {
        guard let window = windows.settingsWindow else {
            keyPanelOpen = false
            publishKeyOutcome(keyPickOutcome(response: .abort, url: nil, failed: "Settings is not open. Open Settings, then choose the key again."))
            return
        }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.canCreateDirectories = false
        panel.prompt = "Choose"
        panel.message = "Choose the private key file. Hidden files are shown. Kiite keeps the key where it is and stores only a bookmark."
        // The sandbox home is the container. Do not stat this path from the app.
        if let ssh = realSSHDirectory() {
            panel.directoryURL = ssh
        }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        panel.beginSheetModal(for: window) { [weak self] response in
            let outcome = keyPickOutcome(response: response, url: response == .OK ? panel.url : nil, failed: nil)
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self?.keyPanelOpen = false
                    self?.publishKeyOutcome(outcome)
                }
            }
        }
    }

    private func publishKeyOutcome(_ outcome: KeyPickOutcome) {
        guard let bookmark = outcome.bookmark else {
            guard !outcome.error.isEmpty else { return }
            model.keyPickBookmark = nil
            model.keyPickFilename = ""
            model.keyPickError = outcome.error
            model.keyPickGeneration += 1
            if !outcome.domain.isEmpty {
                model.record("key bookmark failed domain=\(outcome.domain) code=\(outcome.code)")
            }
            return
        }
        model.keyPickBookmark = bookmark
        model.keyPickFilename = outcome.filename
        model.keyPickError = ""
        model.keyPickGeneration += 1
        model.record("key bookmark stored bytes=\(bookmark.count)")
    }

    /// Real home from the passwd database. `FileManager` home is the sandbox container.
    private func realSSHDirectory() -> URL? {
        guard let entry = getpwuid(getuid()), let dir = entry.pointee.pw_dir else { return nil }
        let home = String(cString: dir)
        guard home.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: home, isDirectory: true).appendingPathComponent(".ssh", isDirectory: true)
    }

    @discardableResult
    private func resumeNeedsSetup() -> Bool {
        guard let draft = store.loadDraft(), store.canUpload(draft: draft) else { return false }
        let waiting = store.allRecords().filter { $0.status == UploadStatus.needsSetup }.reversed()
        var batch = UploadBatch(id: UUID().uuidString, autoCopy: draft.autoCopy)
        var queued: [QueuedUpload] = []
        for record in waiting {
            guard active?.id != record.id, !jobs.contains(where: { $0.id == record.id }) else { continue }
            guard FileManager.default.fileExists(atPath: record.snapshotPath) else {
                store.setStatus(id: record.id, status: UploadStatus.failed, detail: "The prepared file is gone. Drop the file again.", completed: true)
                continue
            }
            guard let upload = makeQueued(
                id: record.id,
                name: record.filename,
                snapshot: URL(fileURLWithPath: record.snapshotPath),
                bytes: record.bytes,
                batchID: batch.id,
                draft: draft,
                existing: record
            ) else { continue }
            queued.append(upload)
            batch.order.append(record.id)
            batch.bytes[record.id] = record.bytes
        }
        guard !queued.isEmpty else { return false }
        jobs.append(contentsOf: queued)
        batches.append(batch)
        model.queuedCount = queuedCount
        model.banner = "Starting uploads that were waiting for setup."
        reloadLists()
        pump()
        return true
    }

    private func reloadLists() {
        let draft = store.loadDraft()
        model.savedDraft = draft
        model.destinationReady = store.canUpload(draft: draft)
        model.history = store.allRecords()
        let limit = min(20, max(1, draft?.recentCount ?? 5))
        model.recent = Array(model.history.prefix(limit))
        if let error = store.openError {
            model.banner = error
        }
    }

    private func refreshIdle() {
        guard !uploading, !checking, active == nil, activeImport == nil else { return }
        let draft = model.savedDraft
        if let error = store.openError {
            model.banner = error
        } else if !model.destinationReady {
            model.banner = "Set the destination in Settings and trust its host key. A drop before that waits as Needs setup."
        } else if draft?.publicBase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
            model.banner = "Uploads publish to \(draft?.normalizedHost ?? "the saved server"). Add an https base before a finished upload can turn the kite blue."
        } else {
            model.banner = "Uploads publish to \(draft?.normalizedHost ?? "the saved server"). The kite turns blue after the public link checks out."
        }
        restoreIdleIcon()
    }

    private func restoreIdleIcon() {
        if uploading || checking || activeImport != nil { return }
        if successUntil != nil {
            model.icon = .success
        } else if attentionUntil != nil || !model.destinationReady {
            model.icon = .attention
        } else {
            model.icon = .ready
        }
        if !uploading && !checking {
            model.phaseNote = nil
        }
        render()
    }

    private func attentionPulse() {
        attentionUntil = Date().addingTimeInterval(2)
        model.icon = .attention
        render()
        ensureTimer()
    }

    private func ensureTimer() {
        guard timer == nil else { return }
        let timer = Timer(timeInterval: 1.0 / 15.0, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.tick()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    private func tick() {
        let now = Date()
        if let until = successUntil, now >= until {
            successUntil = nil
            if active == nil { restoreIdleIcon() }
        }
        if let until = attentionUntil, now >= until {
            attentionUntil = nil
            if active == nil { restoreIdleIcon() }
        }
        if uploading, let progress = uploadProgress?.current, let job = active {
            // Both network passes count toward progress. Reserve completion for
            // successful publication and the public-link check.
            let done = min(progress.total, max(0, progress.written)) + min(progress.total, max(0, progress.verified))
            let work = progress.total * 2
            let fileFraction = progress.total == 0 ? (progress.phase >= KIITE_PHASE_PUBLISHING ? 0.99 : 0) : min(0.99, Double(done) / Double(work) * 0.99)
            model.icon = .uploading(batchFraction(current: job, written: Int64(Double(job.bytes) * fileFraction)))
            let remaining = transferETA.remaining(written: done, total: work, now: ProcessInfo.processInfo.systemUptime)
            model.progressFraction = fileFraction
            switch progress.phase {
            case KIITE_PHASE_HASHING:
                model.phaseNote = "Preparing upload"
                model.progressText = "Preparing…"
            case KIITE_PHASE_CONNECTING:
                model.phaseNote = "Connecting"
                model.progressText = "Connecting…"
            case KIITE_PHASE_DIRECTORIES:
                model.phaseNote = "Preparing upload"
                model.progressText = "Preparing upload…"
            case KIITE_PHASE_VERIFYING:
                model.phaseNote = "Verifying upload"
                model.progressText = DisplayFormat.progress(fraction: fileFraction, secondsRemaining: remaining) + " · Verifying…"
            case KIITE_PHASE_PUBLISHING:
                model.phaseNote = "Publishing"
                model.progressText = "99% · Publishing…"
            default:
                model.phaseNote = "Uploading"
                model.progressText = DisplayFormat.progress(fraction: fileFraction, secondsRemaining: remaining)
            }
            if let row = model.history.firstIndex(where: { $0.id == job.id }) {
                model.history[row].detail = model.progressText
            }
            if let row = model.recent.firstIndex(where: { $0.id == job.id }) {
                model.recent[row].detail = model.progressText
            }
        }
        model.queuedCount = queuedCount
        render()
        if active == nil && activeImport == nil && !checking && successUntil == nil && attentionUntil == nil && jobs.isEmpty && imports.isEmpty {
            timer?.invalidate()
            timer = nil
        }
    }

    private func batchFraction(current: QueuedUpload, written: Int64) -> CGFloat {
        guard let batch = batches.first(where: { $0.id == current.batchID }) else {
            return current.bytes == 0 ? CGFloat(model.progressFraction ?? 0) : min(1, CGFloat(written) / CGFloat(max(current.bytes, 1)))
        }
        let total = batch.bytes.values.reduce(Int64(0), +)
        if total == 0 { return CGFloat(model.progressFraction ?? 0) }
        var done: Int64 = 0
        for id in batch.order {
            if batch.finished.contains(id) {
                done += batch.bytes[id] ?? 0
            } else if id == current.id {
                done += min(written, batch.bytes[id] ?? written)
            }
        }
        return min(1, CGFloat(done) / CGFloat(total))
    }

    private func render() {
        applyAccessibility()
        guard let button = statusItem.button else { return }
        dropView?.frame = button.bounds
        let appearance = kiteAppearance
        button.contentTintColor = nil
        button.image = KiteDrawing.templateImage(hover: appearance == .hover)
        dropView?.fillImage = KiteDrawing.fillImage(appearance: appearance)
    }

    private func applyAccessibility() {
        let label = model.accessibilityLabel
        statusItem.button?.setAccessibilityLabel(label)
        dropView?.setAccessibilityLabel(label)
    }

    private func decision(for info: NSDraggingInfo) -> DragDecision {
        let pasteboard = info.draggingPasteboard
        let types = pasteboard.types ?? []
        let hasFileURL = types.contains(.fileURL)
        let hasPromise = types.contains(Self.promiseType)
        if hasPromise && !hasFileURL {
            return DragDecision(urls: [], verdicts: [.reject(name: "promise", reason: "file promises are not supported")])
        }
        guard hasFileURL, let items = pasteboard.pasteboardItems else {
            return DragDecision(urls: [], verdicts: [])
        }
        var urls: [URL] = []
        for item in items {
            guard let raw = item.string(forType: .fileURL), let url = URL(string: raw) else { continue }
            urls.append(url)
        }
        if urls.isEmpty {
            return DragDecision(urls: [], verdicts: [.reject(name: "payload", reason: "no file URL")])
        }
        return DragDecision(urls: urls, verdicts: urls.map(DropClassifier.classify(url:)))
    }

    private var isSandboxed: Bool {
        ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
    }

    private func installWindowTargetIfNeeded() {
        guard windowBridge == nil, let window = statusItem.button?.window, window.frame.height > 1 else { return }
        let bridge = WindowDragBridge(controller: self)
        bridge.install(on: window)
        windowBridge = bridge
    }

    private func describe(_ rect: NSRect) -> String {
        String(format: "%.0f,%.0f %.0fx%.0f", rect.origin.x, rect.origin.y, rect.size.width, rect.size.height)
    }

    static let promiseType = NSPasteboard.PasteboardType("com.apple.pasteboard.promised-file-url")

    var kiteAppearance: KiteAppearance {
        switch model.icon {
        case .ready: return .ready
        case .hover: return .hover
        case .uploading(let progress): return .uploading(progress)
        case .success: return .success
        case .attention: return .attention
        }
    }
}

private struct DragDecision {
    var urls: [URL]
    var verdicts: [DropVerdict]
    var acceptsAny: Bool {
        verdicts.contains { if case .accept = $0 { return true }; return false }
    }
    var summary: String {
        let accepted = verdicts.filter { if case .accept = $0 { return true }; return false }.count
        let rejected = verdicts.count - accepted
        return "items=\(verdicts.count) accept=\(accepted) reject=\(rejected)"
    }
}

@MainActor
final class DropReceivingView: NSView {
    weak var controller: StatusController?
    var registersForDrags = true
    var fillImage: NSImage? {
        didSet { needsDisplay = true }
    }
    private var performedSequence: Int?
    private var contextClick = false

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        registerForDraggedTypes([.fileURL, StatusController.promiseType])
    }

    required init?(coder: NSCoder) { nil }

    override var isOpaque: Bool { false }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let fillImage else { return }
        let imageRect = NSRect(x: bounds.midX - 9, y: bounds.midY - 9, width: 18, height: 18)
        fillImage.draw(in: imageRect, from: .zero, operation: .sourceOver, fraction: 1,
                       respectFlipped: true, hints: nil)
    }

    override func mouseDown(with event: NSEvent) {
        contextClick = event.modifierFlags.contains(.control)
        if contextClick {
            controller?.showContextMenu(with: event, from: self)
            return
        }
        controller?.setHighlighted(true)
    }

    override func mouseUp(with event: NSEvent) {
        controller?.setHighlighted(false)
        guard !contextClick else { return }
        controller?.togglePopover()
    }

    override func rightMouseDown(with event: NSEvent) {
        controller?.showContextMenu(with: event, from: self)
    }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        guard registersForDrags else { return [] }
        return controller?.dragEntered(receiver: "DropReceivingView", info: sender) ?? []
    }

    override func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation {
        guard registersForDrags else { return [] }
        return controller?.dragUpdated(receiver: "DropReceivingView", info: sender) ?? []
    }

    override func draggingExited(_ sender: NSDraggingInfo?) {
        guard registersForDrags else { return }
        controller?.dragExited(receiver: "DropReceivingView")
    }

    override func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard registersForDrags else { return false }
        return controller?.prepareDrag(receiver: "DropReceivingView", info: sender) ?? false
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard registersForDrags else { return false }
        if performedSequence == sender.draggingSequenceNumber {
            AppLog.write("duplicate perform ignored sequence=\(sender.draggingSequenceNumber) receiver=DropReceivingView")
            return true
        }
        performedSequence = sender.draggingSequenceNumber
        return controller?.performDrag(receiver: "DropReceivingView", info: sender) ?? false
    }
}

@MainActor
final class WindowDragBridge: NSObject, NSWindowDelegate, NSDraggingDestination {
    private weak var controller: StatusController?
    private weak var original: NSWindowDelegate?
    private var performedSequence: Int?

    init(controller: StatusController) {
        self.controller = controller
    }

    func install(on window: NSWindow) {
        original = window.delegate
        window.registerForDraggedTypes([.fileURL, StatusController.promiseType])
        window.delegate = self
        AppLog.write("window drag registration installed originalDelegate=\(original.map { String(describing: type(of: $0)) } ?? "nil")")
    }

    override func responds(to aSelector: Selector!) -> Bool {
        if super.responds(to: aSelector) { return true }
        return original?.responds(to: aSelector) ?? false
    }

    override func forwardingTarget(for aSelector: Selector!) -> Any? {
        if original?.responds(to: aSelector) == true { return original }
        return super.forwardingTarget(for: aSelector)
    }

    func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        controller?.dragEntered(receiver: "StatusWindow", info: sender) ?? []
    }

    func draggingUpdated(_ sender: NSDraggingInfo) -> NSDragOperation {
        controller?.dragUpdated(receiver: "StatusWindow", info: sender) ?? []
    }

    func draggingExited(_ sender: NSDraggingInfo?) {
        controller?.dragExited(receiver: "StatusWindow")
    }

    func prepareForDragOperation(_ sender: NSDraggingInfo) -> Bool {
        controller?.prepareDrag(receiver: "StatusWindow", info: sender) ?? false
    }

    func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        if performedSequence == sender.draggingSequenceNumber {
            AppLog.write("duplicate perform ignored sequence=\(sender.draggingSequenceNumber) receiver=StatusWindow")
            return true
        }
        performedSequence = sender.draggingSequenceNumber
        return controller?.performDrag(receiver: "StatusWindow", info: sender) ?? false
    }
}
