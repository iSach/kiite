import AppKit
import SwiftUI

struct HistoryView: View {
    var model: AppModel
    var onImport: ([URL]) -> Void
    var onSettings: () -> Void
    var onCopy: (String) -> Void
    var onOpen: (String) -> Void
    var onRetry: (String) -> Void
    var onCheck: (String) -> Void
    var onCancel: () -> Void
    var onRemove: (String) -> Void

    @State private var query = ""
    @State private var filter = "All"
    @State private var targeted = false
    @State private var pendingRemoval: HistoryRecord?

    private let filters = ["All", "Needs setup", "In progress", "Published", "Verified", "Failed"]

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Search filenames", text: $query)
                Picker("Status", selection: $filter) {
                    ForEach(filters, id: \.self) { Text($0) }
                }
                .pickerStyle(.menu)
                .frame(width: 160)
                Button("Upload File…") { pickFiles() }
                Button("Settings") { onSettings() }
            }
            .padding(12)

            if targeted {
                Text("Drop to upload")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 8)
            }

            Divider()

            if visible.isEmpty {
                ContentUnavailableView("No uploads", systemImage: "tray", description: Text(emptyDescription))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(visible) { record in
                            UploadRow(
                                record: record,
                                copied: model.copyFeedbackID == record.id,
                                canCancel: model.activeID == record.id,
                                progress: model.activeID == record.id ? model.progressFraction : nil,
                                progressText: model.activeID == record.id ? model.progressText : "",
                                onCopy: { onCopy(record.id) },
                                onOpen: { onOpen(record.id) },
                                onRetry: { onRetry(record.id) },
                                onCheck: { onCheck(record.id) },
                                onCancel: onCancel,
                                onRemove: { pendingRemoval = record }
                            )
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                            Divider()
                        }
                    }
                    .padding(.vertical, 8)
                }
            }
        }
        .frame(minWidth: 640, minHeight: 420)
        .onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
            Task { @MainActor in
                var urls: [URL] = []
                for provider in providers {
                    let url: URL? = await withCheckedContinuation { continuation in
                        _ = provider.loadObject(ofClass: URL.self) { object, _ in
                            continuation.resume(returning: object)
                        }
                    }
                    if let url { urls.append(url) }
                }
                onImport(urls)
            }
            return !providers.isEmpty
        }
        .alert("Remove from history?", isPresented: removalPresented) {
            Button("Remove from History", role: .destructive) {
                if let pendingRemoval { onRemove(pendingRemoval.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the entry on this Mac. The file stays on the server.")
        }
    }

    private var removalPresented: Binding<Bool> {
        Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })
    }

    private var visible: [HistoryRecord] {
        model.history.filter { record in
            let matchesQuery = query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                || record.filename.localizedCaseInsensitiveContains(query)
            return matchesQuery && matchesFilter(record)
        }
    }

    private var emptyDescription: String {
        query.isEmpty && filter == "All"
            ? "Uploads you drop on the kite show up here."
            : "Nothing matches this search."
    }

    private func matchesFilter(_ record: HistoryRecord) -> Bool {
        switch filter {
        case "Needs setup": return record.status == UploadStatus.needsSetup
        case "In progress":
            return record.status == UploadStatus.preparing || record.status == UploadStatus.queued || record.status == UploadStatus.uploading || record.status == UploadStatus.checking
        case "Published": return record.status == UploadStatus.publishedUnverified
        case "Verified": return record.status == UploadStatus.verified
        case "Failed":
            return record.status == UploadStatus.failed || record.status == UploadStatus.cancelled || record.status == UploadStatus.interrupted
        default: return true
        }
    }

    private func pickFiles() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.message = "Choose files to upload."
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK else { return }
        onImport(panel.urls)
    }
}
