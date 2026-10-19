import Darwin
import Foundation

final class PreparationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func check() throws {
        if isCancelled { throw CancellationError() }
    }
}

enum FileSnapshot {
    static func prepare(url: URL, cancellation: PreparationCancellation = PreparationCancellation(), allowClone: Bool = true) throws -> UploadJob {
        try cancellation.check()
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        guard case .accept(let name, _) = DropClassifier.classify(url: url) else {
            throw PreparationError(message: "Choose a readable regular file. Folders, packages, aliases, and symbolic links are not uploaded.")
        }

        // Open without following a link, then validate the descriptor to cover a
        // source replaced between drag classification and preparation.
        let source = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) } ?? -1
        }
        guard source >= 0 else { throw PreparationError(message: "The source file could not be opened.") }
        defer { Darwin.close(source) }
        var before = stat()
        guard fstat(source, &before) == 0, before.st_mode & S_IFMT == S_IFREG else {
            throw PreparationError(message: "The source is no longer a regular file.")
        }
        guard before.st_size <= PublicMapping.stagingQuota else {
            throw PreparationError(message: "This file exceeds the 10 GiB preparation limit.")
        }

        let fm = FileManager.default
        let directory = fm.temporaryDirectory.appendingPathComponent("kiite-snapshots", isDirectory: true)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let staged = try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.fileSizeKey])
            .reduce(Int64(0)) { $0 + Int64((try? $1.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) }
        guard before.st_size <= PublicMapping.stagingQuota - min(staged, PublicMapping.stagingQuota) else {
            throw PreparationError(message: "The 10 GiB preparation space is full. Finish or cancel queued uploads before adding more files.")
        }
        let destination = directory.appendingPathComponent(UUID().uuidString)
        var keep = false
        defer { if !keep { try? fm.removeItem(at: destination) } }

        let cloned = allowClone && destination.withUnsafeFileSystemRepresentation { path in
            path.map { fclonefileat(source, AT_FDCWD, $0, 0) == 0 } ?? false
        }
        if !cloned {
            let output = destination.withUnsafeFileSystemRepresentation { path in
                path.map { Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600) } ?? -1
            }
            guard output >= 0 else { throw PreparationError(message: "Could not create a prepared file. Check free disk space.") }
            defer { Darwin.close(output) }
            let inputHandle = FileHandle(fileDescriptor: source, closeOnDealloc: false)
            let outputHandle = FileHandle(fileDescriptor: output, closeOnDealloc: false)
            var copied: Int64 = 0
            while true {
                try cancellation.check()
                let chunk = try inputHandle.read(upToCount: 1024 * 1024) ?? Data()
                if chunk.isEmpty { break }
                copied += Int64(chunk.count)
                guard copied <= before.st_size else { throw PreparationError(message: "The source changed while preparing it. Try again once it has finished saving.") }
                try outputHandle.write(contentsOf: chunk)
            }
            guard copied == before.st_size else { throw PreparationError(message: "The source changed while preparing it. Try again once it has finished saving.") }
        }
        try cancellation.check()
        var after = stat()
        guard fstat(source, &after) == 0,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw PreparationError(message: "The source changed while preparing it. Try again once it has finished saving.")
        }
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        keep = true
        return UploadJob(name: name, snapshot: destination, bytes: Int64(before.st_size))
    }
}
