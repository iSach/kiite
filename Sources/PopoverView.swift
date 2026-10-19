import SwiftUI

struct PopoverRoot: View {
    static let contentSize = CGSize(width: 360, height: 330)

    var model: AppModel
    var onShowAll: () -> Void
    var onSettings: () -> Void
    var onQuit: () -> Void
    var onCopy: (String) -> Void
    var onOpen: (String) -> Void
    var onRetry: (String) -> Void
    var onCheck: (String) -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    if model.recent.isEmpty {
                        Text("No uploads yet.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(model.recent) { record in
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
                                onCancel: onCancel
                            )
                        }
                    }
                }
                .padding(12)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            HStack {
                Button("Show All") { onShowAll() }
                    .accessibilityLabel("Show All")
                Button("Settings") { onSettings() }
                    .keyboardShortcut(",")
                Spacer()
                Button("Quit Kiite") { onQuit() }
                    .keyboardShortcut("q")
            }
            .padding(12)
        }
        .frame(width: Self.contentSize.width, height: Self.contentSize.height)
    }
}

struct UploadRow: View {
    var record: HistoryRecord
    var copied: Bool
    var canCancel: Bool
    var progress: Double?
    var progressText: String
    var onCopy: () -> Void
    var onOpen: () -> Void
    var onRetry: () -> Void
    var onCheck: () -> Void
    var onCancel: () -> Void
    var onRemove: (() -> Void)? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.filename)
                        .font(.callout)
                        .truncationMode(.middle)
                        .help(record.filename)
                    Text("\((record.completedAt ?? record.createdAt).formatted(date: .abbreviated, time: .shortened)) · \(DisplayFormat.fileSize(record.bytes))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)

                HStack(spacing: 6) {
                    Button("Open", action: onOpen)
                        .disabled(!showsLink)
                        .accessibilityLabel("Open \(record.filename)")
                    Button(copied ? "Copied" : "Copy Link", action: onCopy)
                        .disabled(!showsLink || copied)
                        .accessibilityLabel("Copy link for \(record.filename)")
                }
                .buttonStyle(UploadActionButtonStyle())
                .fixedSize()
            }

            if canCancel || showsRetry || needsCheck {
                HStack(spacing: 10) {
                    if canCancel {
                        Text(progressText.isEmpty ? "Preparing…" : progressText)
                            .monospacedDigit()
                        Spacer()
                        Button("Cancel", action: onCancel)
                    } else if record.status == UploadStatus.cancelled {
                        Text("Cancelled")
                    }
                    if showsRetry { Button("Retry", action: onRetry) }
                    if needsCheck { Button("Check Again", action: onCheck) }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .buttonStyle(.borderless)
            }
            if let progress, canCancel {
                ProgressView(value: progress)
                    .tint(.green)
                    .accessibilityLabel("Upload progress")
                    .accessibilityValue("\(Int(progress * 100)) percent")
            }
            if showsProblem && !record.detail.isEmpty {
                Text(record.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contextMenu {
            if let onRemove {
                Button("Remove from History", role: .destructive, action: onRemove)
                    .disabled(isBusy)
            }
        }
    }

    private var showsLink: Bool {
        !record.publicURL.isEmpty && (record.status == UploadStatus.verified || record.status == UploadStatus.publishedUnverified)
    }

    private var showsRetry: Bool {
        [UploadStatus.needsSetup, UploadStatus.failed, UploadStatus.interrupted, UploadStatus.cancelled].contains(record.status)
    }

    private var showsProblem: Bool {
        [UploadStatus.needsSetup, UploadStatus.failed, UploadStatus.interrupted, UploadStatus.publishedUnverified].contains(record.status)
    }

    private var needsCheck: Bool {
        record.status == UploadStatus.publishedUnverified && !record.publicURL.isEmpty
    }

    private var isBusy: Bool {
        canCancel || [UploadStatus.preparing, UploadStatus.queued, UploadStatus.uploading, UploadStatus.checking].contains(record.status)
    }
}

private struct UploadActionButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption)
            .foregroundStyle(.primary)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(.primary.opacity(configuration.isPressed ? 0.16 : 0.08), in: RoundedRectangle(cornerRadius: 5))
            .contentShape(RoundedRectangle(cornerRadius: 5))
            .opacity(isEnabled ? 1 : 0.4)
    }
}
