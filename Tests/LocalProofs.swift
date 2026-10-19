import CryptoKit
import Darwin
import Foundation
import Security

enum LocalProofs {
    /// Exit status for `--self-test`. Prints one line per check. Does not print secret values.
    static func run() -> Int32 {
        var failed = false
        if !classify() { failed = true }
        if !snapshot() { failed = true }
        if !keychain() { failed = true }
        if !PublicMapping.runTests() { failed = true }
        if !storeRoundTrip() { failed = true }
        return failed ? 1 : 0
    }

    @MainActor
    static func summary() -> String {
        let code = run()
        return code == 0 ? "Local proofs passed." : "Local proofs failed. See the log."
    }

    private static func classify() -> Bool {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("kiite-spike-classify-\(UUID().uuidString)", isDirectory: true)
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? fm.removeItem(at: root) }
            let file = root.appendingPathComponent("note.txt")
            try Data().write(to: file)
            let folder = root.appendingPathComponent("folder", isDirectory: true)
            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
            let link = root.appendingPathComponent("link")
            try fm.createSymbolicLink(at: link, withDestinationURL: file)
            let package = root.appendingPathComponent("Sample.app", isDirectory: true)
            try fm.createDirectory(at: package, withIntermediateDirectories: true)
            let fifo = root.appendingPathComponent("pipe")
            guard mkfifo(fifo.path, 0o600) == 0 else {
                report("CLASSIFY fail fifo-create")
                return false
            }

            let cases: [(URL, String)] = [
                (file, "accept"),
                (folder, "reject"),
                (link, "reject"),
                (package, "reject"),
                (fifo, "reject"),
            ]
            for (url, expect) in cases {
                let verdict = DropClassifier.classify(url: url)
                let got = verdict.accepts ? "accept" : "reject"
                if got != expect {
                    report("CLASSIFY fail \(url.lastPathComponent) expected \(expect) got \(got)")
                    return false
                }
            }
            if case .accept(_, let bytes) = DropClassifier.classify(url: file), bytes != 0 {
                report("CLASSIFY fail empty-file size")
                return false
            }
            report("CLASSIFY ok")
            return true
        } catch {
            report("CLASSIFY fail \(error.localizedDescription)")
            return false
        }
    }

    private static func snapshot() -> Bool {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("kiite-preparation-test-\(UUID().uuidString)")
        var snapshots: [URL] = []
        defer {
            for url in snapshots { try? fm.removeItem(at: url) }
            try? fm.removeItem(at: root)
        }
        do {
            try fm.createDirectory(at: root, withIntermediateDirectories: true)
            let source = root.appendingPathComponent("source.bin")
            let bytes = Data((0..<(3 * 1024 * 1024)).map { UInt8($0 % 251) })
            for allowClone in [true, false] {
                try bytes.write(to: source)
                let job = try FileSnapshot.prepare(url: source, allowClone: allowClone)
                snapshots.append(job.snapshot)
                try Data("changed source".utf8).write(to: source)
                guard job.bytes == bytes.count, try Data(contentsOf: job.snapshot) == bytes,
                      (try fm.attributesOfItem(atPath: job.snapshot.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600 else {
                    report("SNAPSHOT fail stable copy or permissions")
                    return false
                }
            }
            let link = root.appendingPathComponent("link")
            try fm.createSymbolicLink(at: link, withDestinationURL: source)
            for url in [root, link] {
                do {
                    let unexpected = try FileSnapshot.prepare(url: url)
                    snapshots.append(unexpected.snapshot)
                    report("SNAPSHOT fail accepted unsupported source")
                    return false
                } catch { }
            }
            let cancellation = PreparationCancellation()
            cancellation.cancel()
            do {
                let unexpected = try FileSnapshot.prepare(url: source, cancellation: cancellation, allowClone: false)
                snapshots.append(unexpected.snapshot)
                report("SNAPSHOT fail ignored cancellation")
                return false
            } catch is CancellationError { }
            let huge = root.appendingPathComponent("over-limit")
            let descriptor = Darwin.open(huge.path, O_CREAT | O_RDWR, 0o600)
            guard descriptor >= 0 else { return false }
            let sized = ftruncate(descriptor, PublicMapping.stagingQuota + 1)
            Darwin.close(descriptor)
            guard sized == 0 else { return false }
            do {
                let unexpected = try FileSnapshot.prepare(url: huge)
                snapshots.append(unexpected.snapshot)
                report("SNAPSHOT fail ignored size limit")
                return false
            } catch { }
            try bytes.write(to: source)
            var chunks = 0
            do {
                _ = try FileDigest.hashAndSample(source, isCancelled: { chunks += 1; return chunks > 1 })
                report("SNAPSHOT fail hash ignored cancellation")
                return false
            } catch is CancellationError { }
            report("SNAPSHOT ok clone/copy, stable bytes, permissions, rejection, quota, cancellation")
            return true
        } catch {
            report("SNAPSHOT fail \(error.localizedDescription)")
            return false
        }
    }

    private static func keychain() -> Bool {
        let service = "com.isach.kiite.spike.proof"
        let account = "synthetic"
        let secret = Data("kiite-spike-synthetic".utf8)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = secret
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else {
            report("KEYCHAIN fail add status=\(added)")
            return false
        }
        var query = base
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let read = SecItemCopyMatching(query as CFDictionary, &item)
        SecItemDelete(base as CFDictionary)
        guard read == errSecSuccess, let data = item as? Data, data == secret else {
            report("KEYCHAIN fail read status=\(read) match=\(false)")
            return false
        }
        report("KEYCHAIN ok")
        return true
    }

    private static func storeRoundTrip() -> Bool {
        let path = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("kiite-store-\(UUID().uuidString).sqlite")
            .path
        let store = Store(databasePath: path)
        let ok = store.runRoundTripTest()
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.removeItem(atPath: path + "-wal")
        try? FileManager.default.removeItem(atPath: path + "-shm")
        return ok
    }

    private static func report(_ line: String) {
        AppLog.write(line)
    }
}

private extension DropVerdict {
    var accepts: Bool {
        if case .accept = self { return true }
        return false
    }
}
