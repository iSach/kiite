import Foundation

final class ProgressGate: @unchecked Sendable {
    let pointer: UnsafeMutablePointer<KiiteProgress>

    init(total: Int64) {
        pointer = .allocate(capacity: 1)
        pointer.initialize(to: KiiteProgress(written: 0, total: total, cancel: 0, phase: KIITE_PHASE_HASHING, verified: 0))
    }

    func requestCancel() {
        kiite_progress_cancel(pointer)
    }

    var current: KiiteProgress { kiite_progress_snapshot(pointer) }

    func close() {
        pointer.deinitialize(count: 1)
        pointer.deallocate()
    }
}

struct UploadJob: Sendable {
    var name: String
    var snapshot: URL
    var bytes: Int64
}

struct PreparationError: LocalizedError {
    var message: String
    var errorDescription: String? { message }
}
