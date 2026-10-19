import Foundation
import Security
import SQLite3

enum UploadStatus {
    static let preparing = "preparing"
    static let needsSetup = "needsSetup"
    static let queued = "queued"
    static let uploading = "uploading"
    static let checking = "checking"
    static let publishedUnverified = "publishedUnverified"
    static let verified = "verified"
    static let failed = "failed"
    static let cancelled = "cancelled"
    static let interrupted = "interrupted"

    static func label(_ status: String) -> String {
        switch status {
        case preparing: return "Preparing file"
        case needsSetup: return "Needs setup"
        case queued: return "Queued"
        case uploading: return "Uploading"
        case checking: return "Checking public link"
        case publishedUnverified: return "Published, public link not verified"
        case verified: return "Public link verified"
        case failed: return "Failed"
        case cancelled: return "Cancelled"
        case interrupted: return "Interrupted"
        default: return status
        }
    }
}

struct DestinationDraft: Equatable, Sendable {
    var profileName: String = ""
    var host: String = ""
    var port: String = "22"
    var username: String = ""
    var authMethod: String = "publicKey"
    var keyBookmark: Data?
    var keyFilename: String = ""
    var remoteRoot: String = ""
    var stagingRoot: String = ""
    var publicBase: String = ""
    var recentCount: Int = 5
    var autoCopy: Bool = true
    var shortURLs: Bool = true
    var trustedSHA256: String = ""
    var trustedAlgorithm: String = ""
    var trustedHost: String = ""
    var trustedPort: Int = 0
    var hasPassword: Bool = false
    var hasPassphrase: Bool = false

    var normalizedHost: String { PublicMapping.normalizeHost(host) }
}

struct HistoryRecord: Identifiable, Equatable, Sendable {
    var id: String
    var createdAt: Date
    var completedAt: Date?
    var filename: String
    var bytes: Int64
    var status: String
    var detail: String
    var publicURL: String
    var remotePath: String
    var objectKey: String
    var sha256: String
    var snapshotPath: String
    var batchID: String
    var snapshotHost: String
    var snapshotPort: Int
    var snapshotUser: String
    var snapshotRoot: String
    var snapshotStaging: String
    var snapshotBase: String
    var clipboardDone: Bool
}

enum DestinationRules {
    static func errors(draft: DestinationDraft, password: String, dropPassword: Bool) -> [String] {
        var errors: [String] = []
        if let host = PublicMapping.hostError(draft.host) {
            errors.append(host)
        }
        if PublicMapping.portValue(draft.port) == nil {
            errors.append("Enter a port from 1 to 65535.")
        }
        if draft.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            errors.append("Enter the SSH username.")
        }
        if draft.authMethod == "password" {
            let available = !dropPassword && (draft.hasPassword || !password.isEmpty)
            if !available {
                errors.append("Enter the password. Kiite stores it in the Keychain.")
            }
            if password.contains("\n") || password.contains("\0") || password.utf8.count > 1024 {
                errors.append("The password cannot contain a newline, and it has to stay under 1024 bytes.")
            }
        } else if draft.keyBookmark == nil || draft.keyFilename.isEmpty {
            errors.append("Choose the private key file. Kiite keeps the file where it is.")
        }
        if let root = PublicMapping.remoteRootError(draft.remoteRoot) {
            errors.append("Public root: \(root)")
        }
        if let staging = PublicMapping.remoteRootError(draft.stagingRoot) {
            errors.append("Staging root: \(staging)")
        }
        if PublicMapping.remoteRootError(draft.remoteRoot) == nil,
           PublicMapping.remoteRootError(draft.stagingRoot) == nil,
           PublicMapping.pathsOverlap(draft.remoteRoot, draft.stagingRoot) {
            errors.append("The staging root and the public root have to be different directories, and neither can sit inside the other.")
        }
        if let base = PublicMapping.publicBaseError(draft.publicBase) {
            errors.append(base)
        }
        if !(1...20).contains(draft.recentCount) {
            errors.append("Recent uploads must be from 1 to 20.")
        }
        return errors
    }
}

enum SecretStore {
    static let destinationService = "com.isach.kiite.spike.destination"
    static let passwordAccount = "password"
    static let passphraseAccount = "passphrase"

    static func write(service: String = destinationService, account: String, secret: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = Data(secret.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil)
    }

    static func read(service: String = destinationService, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecReturnData as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        return text
    }

    static func exists(service: String = destinationService, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    static func delete(service: String = destinationService, account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }
}

enum KeyBookmark {
    static func make(for url: URL) throws -> Data {
        try url.bookmarkData(options: [.withSecurityScope, .securityScopeAllowOnlyReadAccess], includingResourceValuesForKeys: nil, relativeTo: nil)
    }

    static func data(for url: URL) -> Data? {
        try? make(for: url)
    }

    static func resolve(_ data: Data) -> (url: URL, refreshed: Data?)? {
        var stale = false
        guard let url = try? URL(
            resolvingBookmarkData: data,
            options: [.withSecurityScope],
            relativeTo: nil,
            bookmarkDataIsStale: &stale
        ) else { return nil }
        let refreshed = stale ? KeyBookmark.data(for: url) : nil
        return (url, refreshed)
    }
}

final class Store {
    private var db: OpaquePointer?
    private(set) var openError: String?
    private let transient: sqlite3_destructor_type = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    init(databasePath: String? = nil) {
        let path = databasePath ?? Store.defaultPath
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(path, &handle, flags, nil) == SQLITE_OK else {
            if handle != nil { sqlite3_close(handle) }
            db = nil
            openError = "Kiite could not open its settings database."
            return
        }
        db = handle
        openError = nil
        sqlite3_busy_timeout(db, 2000)
        _ = exec("PRAGMA journal_mode=WAL;")
        _ = exec("PRAGMA foreign_keys=ON;")
        if !migrate() {
            openError = "Kiite could not update its settings database. Your existing data was kept."
        }
    }

    deinit {
        if db != nil { sqlite3_close(db) }
    }

    static var defaultPath: String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("KiiteSpike", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("kiite.sqlite").path
    }

    func loadDraft() -> DestinationDraft? {
        guard db != nil else { return nil }
        let sql = """
        SELECT profile_name, host, port, username, auth_method, key_bookmark, key_filename,
               remote_root, staging_root, public_base, recent_count, auto_copy,
               trusted_sha256, trusted_algorithm, trusted_host, trusted_port, short_urls
        FROM destination WHERE id = 1
        """
        guard let stmt = prepare(sql) else { return nil }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        var draft = DestinationDraft()
        draft.profileName = columnText(stmt, 0)
        draft.host = columnText(stmt, 1)
        draft.port = String(sqlite3_column_int(stmt, 2))
        draft.username = columnText(stmt, 3)
        draft.authMethod = columnText(stmt, 4)
        draft.keyBookmark = columnBlob(stmt, 5)
        draft.keyFilename = columnText(stmt, 6)
        draft.remoteRoot = columnText(stmt, 7)
        draft.stagingRoot = columnText(stmt, 8)
        draft.publicBase = columnText(stmt, 9)
        draft.recentCount = Int(sqlite3_column_int(stmt, 10))
        draft.autoCopy = sqlite3_column_int(stmt, 11) != 0
        draft.trustedSHA256 = columnText(stmt, 12)
        draft.trustedAlgorithm = columnText(stmt, 13)
        draft.trustedHost = columnText(stmt, 14)
        draft.trustedPort = Int(sqlite3_column_int(stmt, 15))
        draft.shortURLs = sqlite3_column_int(stmt, 16) != 0
        draft.hasPassword = SecretStore.exists(account: SecretStore.passwordAccount)
        draft.hasPassphrase = SecretStore.exists(account: SecretStore.passphraseAccount)
        if draft.port == "0" { draft.port = "22" }
        return draft
    }

    func canUpload(draft: DestinationDraft?) -> Bool {
        guard let draft else { return false }
        guard DestinationRules.errors(draft: draft, password: "", dropPassword: false).isEmpty else { return false }
        guard let port = PublicMapping.portValue(draft.port) else { return false }
        return draft.trustedHost == draft.normalizedHost && draft.trustedPort == port && draft.trustedSHA256.count == 64
    }

    func save(draft: DestinationDraft, password: String, passphrase: String, dropPassword: Bool, dropPassphrase: Bool) -> String? {
        guard db != nil else { return openError }
        var next = draft
        next.host = draft.normalizedHost
        guard let port = PublicMapping.portValue(draft.port),
              let remote = PublicMapping.normalizedRoot(draft.remoteRoot),
              let staging = PublicMapping.normalizedRoot(draft.stagingRoot)
        else {
            let errors = DestinationRules.errors(draft: draft, password: password, dropPassword: dropPassword)
            return errors.first ?? "Check the destination fields."
        }
        let errors = DestinationRules.errors(draft: draft, password: password, dropPassword: dropPassword)
        if let error = errors.first { return error }
        next.remoteRoot = remote
        next.stagingRoot = staging
        next.publicBase = draft.publicBase.trimmingCharacters(in: .whitespacesAndNewlines)
        next.username = draft.username.trimmingCharacters(in: .whitespacesAndNewlines)
        if next.profileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            next.profileName = "Destination"
        }
        let sql = """
        INSERT INTO destination (
            id, profile_name, host, port, username, auth_method, key_bookmark, key_filename,
            remote_root, staging_root, public_base, recent_count, auto_copy, short_urls,
            trusted_sha256, trusted_algorithm, trusted_host, trusted_port
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', 0)
        ON CONFLICT(id) DO UPDATE SET
            profile_name = excluded.profile_name,
            host = excluded.host,
            port = excluded.port,
            username = excluded.username,
            auth_method = excluded.auth_method,
            key_bookmark = excluded.key_bookmark,
            key_filename = excluded.key_filename,
            remote_root = excluded.remote_root,
            staging_root = excluded.staging_root,
            public_base = excluded.public_base,
            recent_count = excluded.recent_count,
            auto_copy = excluded.auto_copy,
            short_urls = excluded.short_urls
        """
        guard let stmt = prepare(sql) else { return "Could not save the destination." }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, next.profileName)
        bindText(stmt, 2, next.host)
        sqlite3_bind_int(stmt, 3, Int32(port))
        bindText(stmt, 4, next.username)
        bindText(stmt, 5, next.authMethod == "password" ? "password" : "publicKey")
        bindBlob(stmt, 6, next.keyBookmark)
        bindText(stmt, 7, next.keyFilename)
        bindText(stmt, 8, next.remoteRoot)
        bindText(stmt, 9, next.stagingRoot)
        bindText(stmt, 10, next.publicBase)
        sqlite3_bind_int(stmt, 11, Int32(min(20, max(1, next.recentCount))))
        sqlite3_bind_int(stmt, 12, next.autoCopy ? 1 : 0)
        sqlite3_bind_int(stmt, 13, next.shortURLs ? 1 : 0)
        guard sqlite3_step(stmt) == SQLITE_DONE else { return "Could not save the destination." }
        if next.authMethod == "password" {
            if dropPassword {
                let status = SecretStore.delete(account: SecretStore.passwordAccount)
                if status != errSecSuccess { return "Settings saved, but the Keychain password could not be removed." }
            } else if !password.isEmpty {
                let status = SecretStore.write(account: SecretStore.passwordAccount, secret: password)
                if status != errSecSuccess { return "Settings saved, but the password could not be stored in the Keychain." }
            }
        }
        if dropPassphrase {
            let status = SecretStore.delete(account: SecretStore.passphraseAccount)
            if status != errSecSuccess { return "Settings saved, but the Keychain passphrase could not be removed." }
        } else if !passphrase.isEmpty {
            let status = SecretStore.write(account: SecretStore.passphraseAccount, secret: passphrase)
            if status != errSecSuccess { return "Settings saved, but the key passphrase could not be stored in the Keychain." }
        }
        return nil
    }

    func saveTrust(host: String, port: Int, algorithm: String, sha256: String) -> String? {
        guard db != nil else { return openError }
        guard sha256.count == 64, (1...65535).contains(port) else { return "Check the host key again before trusting it." }
        let sql = """
        INSERT INTO destination (
            id, profile_name, host, port, username, auth_method, key_filename,
            remote_root, staging_root, public_base, recent_count, auto_copy,
            trusted_sha256, trusted_algorithm, trusted_host, trusted_port
        ) VALUES (1, '', '', 22, '', 'publicKey', '', '', '', '', 5, 1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            trusted_sha256 = excluded.trusted_sha256,
            trusted_algorithm = excluded.trusted_algorithm,
            trusted_host = excluded.trusted_host,
            trusted_port = excluded.trusted_port
        """
        guard let stmt = prepare(sql) else { return "Could not store the trusted host key." }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, sha256.lowercased())
        bindText(stmt, 2, algorithm)
        bindText(stmt, 3, host)
        sqlite3_bind_int(stmt, 4, Int32(port))
        return sqlite3_step(stmt) == SQLITE_DONE ? nil : "Could not store the trusted host key."
    }

    func replaceBookmark(_ data: Data) {
        guard let stmt = prepare("UPDATE destination SET key_bookmark = ? WHERE id = 1") else { return }
        defer { sqlite3_finalize(stmt) }
        bindBlob(stmt, 1, data)
        _ = sqlite3_step(stmt)
    }

    func credential(for draft: DestinationDraft, typedPassword: String, typedPassphrase: String) -> (password: String?, passphrase: String?) {
        let password = typedPassword.isEmpty ? SecretStore.read(account: SecretStore.passwordAccount) : typedPassword
        let passphrase = typedPassphrase.isEmpty ? SecretStore.read(account: SecretStore.passphraseAccount) : typedPassphrase
        if draft.authMethod == "password" {
            return (password, nil)
        }
        return (nil, passphrase)
    }

    func insertNeedsSetup(id: String, filename: String, bytes: Int64, snapshotPath: String, batchID: String) {
        insert(
            id: id,
            filename: filename,
            bytes: bytes,
            status: UploadStatus.needsSetup,
            detail: "Needs setup. Save a destination and trust its host key.",
            snapshotPath: snapshotPath,
            batchID: batchID
        )
    }

    func insertPreparing(id: String, filename: String, batchID: String) {
        insert(id: id, filename: filename, bytes: 0, status: UploadStatus.preparing,
               detail: "Waiting to prepare the file.", snapshotPath: "", batchID: batchID)
    }

    func setSnapshot(id: String, snapshot: UploadJob) {
        guard let stmt = prepare("UPDATE upload SET snapshot_path = ?, bytes = ?, completed_at = NULL WHERE id = ?") else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, snapshot.snapshot.path)
        sqlite3_bind_int64(stmt, 2, snapshot.bytes)
        bindText(stmt, 3, id)
        _ = sqlite3_step(stmt)
    }

    func prepareUpload(id: String, draft: DestinationDraft, objectKey: String, remotePath: String, publicURL: String) {
        let sql = """
        UPDATE upload SET
            status = ?, detail = '', completed_at = NULL, object_key = ?, remote_path = ?, public_url = ?,
            snapshot_host = ?, snapshot_port = ?, snapshot_user = ?,
            snapshot_root = ?, snapshot_staging = ?, snapshot_base = ?
        WHERE id = ?
        """
        guard let stmt = prepare(sql) else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, UploadStatus.queued)
        bindText(stmt, 2, objectKey)
        bindText(stmt, 3, remotePath)
        bindText(stmt, 4, publicURL)
        bindText(stmt, 5, draft.normalizedHost)
        sqlite3_bind_int(stmt, 6, Int32(PublicMapping.portValue(draft.port) ?? 0))
        bindText(stmt, 7, draft.username.trimmingCharacters(in: .whitespacesAndNewlines))
        bindText(stmt, 8, draft.remoteRoot)
        bindText(stmt, 9, draft.stagingRoot)
        bindText(stmt, 10, draft.publicBase.trimmingCharacters(in: .whitespacesAndNewlines))
        bindText(stmt, 11, id)
        _ = sqlite3_step(stmt)
    }

    func setDigest(id: String, sha256: String, sample: Data) {
        guard let stmt = prepare("UPDATE upload SET sha256 = ?, sample = ?, status = ? WHERE id = ?") else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, sha256)
        bindBlob(stmt, 2, sample)
        bindText(stmt, 3, UploadStatus.uploading)
        bindText(stmt, 4, id)
        _ = sqlite3_step(stmt)
    }

    func setStatus(id: String, status: String, detail: String, completed: Bool) {
        let sql = completed
            ? "UPDATE upload SET status = ?, detail = ?, completed_at = ? WHERE id = ?"
            : "UPDATE upload SET status = ?, detail = ? WHERE id = ?"
        guard let stmt = prepare(sql) else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, status)
        bindText(stmt, 2, detail)
        if completed {
            sqlite3_bind_double(stmt, 3, Date().timeIntervalSince1970)
            bindText(stmt, 4, id)
        } else {
            bindText(stmt, 3, id)
        }
        _ = sqlite3_step(stmt)
    }

    func setClipboardIntent(ids: [String]) {
        for id in ids {
            guard let stmt = prepare("UPDATE upload SET clipboard_intent = 1 WHERE id = ? AND clipboard_done = 0") else { continue }
            bindText(stmt, 1, id)
            _ = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
    }

    func setClipboardDone(ids: [String]) {
        for id in ids {
            guard let stmt = prepare("UPDATE upload SET clipboard_done = 1 WHERE id = ?") else { continue }
            bindText(stmt, 1, id)
            _ = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
    }

    func clearSnapshot(id: String) {
        guard let record = record(id: id) else { return }
        removeSnapshotFile(record.snapshotPath)
        guard let stmt = prepare("UPDATE upload SET snapshot_path = '' WHERE id = ?") else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        _ = sqlite3_step(stmt)
    }

    func sample(id: String) -> Data? {
        guard let stmt = prepare("SELECT sample FROM upload WHERE id = ?") else { return nil }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return columnBlob(stmt, 0)
    }

    func record(id: String) -> HistoryRecord? {
        allRecords().first { $0.id == id }
    }

    func allRecords() -> [HistoryRecord] {
        let sql = """
        SELECT id, created_at, completed_at, filename, bytes, status, detail, public_url, remote_path,
               object_key, sha256, snapshot_path, batch_id, snapshot_host, snapshot_port, snapshot_user,
               snapshot_root, snapshot_staging, snapshot_base, clipboard_done
        FROM upload ORDER BY created_at DESC
        """
        guard let stmt = prepare(sql) else { return [] }
        defer { sqlite3_finalize(stmt) }
        var rows: [HistoryRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let completed = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? nil : Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
            rows.append(HistoryRecord(
                id: columnText(stmt, 0),
                createdAt: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
                completedAt: completed,
                filename: columnText(stmt, 3),
                bytes: sqlite3_column_int64(stmt, 4),
                status: columnText(stmt, 5),
                detail: columnText(stmt, 6),
                publicURL: columnText(stmt, 7),
                remotePath: columnText(stmt, 8),
                objectKey: columnText(stmt, 9),
                sha256: columnText(stmt, 10),
                snapshotPath: columnText(stmt, 11),
                batchID: columnText(stmt, 12),
                snapshotHost: columnText(stmt, 13),
                snapshotPort: Int(sqlite3_column_int(stmt, 14)),
                snapshotUser: columnText(stmt, 15),
                snapshotRoot: columnText(stmt, 16),
                snapshotStaging: columnText(stmt, 17),
                snapshotBase: columnText(stmt, 18),
                clipboardDone: sqlite3_column_int(stmt, 19) != 0
            ))
        }
        return rows
    }

    func removeHistory(id: String) {
        if let record = record(id: id) {
            removeSnapshotFile(record.snapshotPath)
        }
        guard let stmt = prepare("DELETE FROM upload WHERE id = ?") else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        _ = sqlite3_step(stmt)
    }

    func launchMaintenance() {
        guard let stmt = prepare("""
        UPDATE upload SET status = ?, detail = ?
        WHERE status IN (?, ?, ?, ?)
        """) else { return }
        bindText(stmt, 1, UploadStatus.interrupted)
        bindText(stmt, 2, "Upload interrupted. Retry to send it again.")
        bindText(stmt, 3, UploadStatus.uploading)
        bindText(stmt, 4, UploadStatus.checking)
        bindText(stmt, 5, UploadStatus.queued)
        bindText(stmt, 6, UploadStatus.preparing)
        _ = sqlite3_step(stmt)
        sqlite3_finalize(stmt)
        let cutoff = Date().timeIntervalSince1970 - (24 * 60 * 60)
        for record in allRecords() where !record.snapshotPath.isEmpty && record.createdAt.timeIntervalSince1970 < cutoff {
            clearSnapshot(id: record.id)
        }
    }

    #if KIITE_TESTING
    func runRoundTripTest() -> Bool {
        let kept = publicURLStability()
        let secret = "roundtrip-secret"
        let service = "com.isach.kiite.spike.proof"
        let account = "settings-roundtrip"
        _ = SecretStore.delete(service: service, account: account)
        let wrote = SecretStore.write(service: service, account: account, secret: secret)
        let read = SecretStore.read(service: service, account: account)
        _ = SecretStore.delete(service: service, account: account)
        let gone = SecretStore.read(service: service, account: account) == nil
        let ok = kept && wrote == errSecSuccess && read == secret && gone
        AppLog.write(ok ? "STORE ok" : "STORE fail kept=\(kept) keychain=\(wrote == errSecSuccess && gone)")
        return ok
    }

    private func publicURLStability() -> Bool {
        let id = UUID().uuidString
        insert(id: id, filename: "note.txt", bytes: 4, status: UploadStatus.verified, detail: "", snapshotPath: "", batchID: "batch")
        guard let stmt = prepare("UPDATE upload SET public_url = ?, object_key = ? WHERE id = ?") else { return false }
        bindText(stmt, 1, "https://cdn.example.com/shared/2026/10/ab/note.txt")
        bindText(stmt, 2, "2026/10/ab/note.txt")
        bindText(stmt, 3, id)
        _ = sqlite3_step(stmt)
        sqlite3_finalize(stmt)
        var draft = DestinationDraft()
        draft.host = "ssh.example.com"
        draft.port = "22"
        draft.username = "uploader"
        draft.authMethod = "publicKey"
        draft.keyBookmark = Data([1, 2, 3])
        draft.keyFilename = "id_ed25519"
        draft.remoteRoot = "/srv/kiite/public"
        draft.stagingRoot = "/srv/kiite/staging"
        draft.publicBase = "https://cdn.example.com/other/"
        guard let db, let filename = sqlite3_db_filename(db, "main") else { return false }
        let path = String(cString: filename)
        for enabled in [false, true] {
            draft.shortURLs = enabled
            guard save(draft: draft, password: "", passphrase: "", dropPassword: false, dropPassphrase: false) == nil else { return false }
            let reopened = Store(databasePath: path)
            guard reopened.openError == nil, reopened.loadDraft()?.shortURLs == enabled else { return false }
        }
        // This method runs only on the disposable self-test database. Recreate
        // its previous schema to exercise migration with real saved data.
        guard exec("ALTER TABLE destination DROP COLUMN short_urls") else { return false }
        setMeta("schema_version", "1")
        guard migrate(), loadDraft()?.shortURLs == true,
              loadDraft()?.host == draft.host, loadDraft()?.keyBookmark == draft.keyBookmark,
              meta("schema_version") == "2" else { return false }
        let record = allRecords().first { $0.id == id }
        return record?.publicURL == "https://cdn.example.com/shared/2026/10/ab/note.txt"
            && record?.objectKey == "2026/10/ab/note.txt"
    }

    #endif

    private func insert(id: String, filename: String, bytes: Int64, status: String, detail: String, snapshotPath: String, batchID: String) {
        let sql = """
        INSERT INTO upload (
            id, created_at, filename, bytes, status, detail, snapshot_path, batch_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        guard let stmt = prepare(sql) else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, id)
        sqlite3_bind_double(stmt, 2, Date().timeIntervalSince1970)
        bindText(stmt, 3, filename)
        sqlite3_bind_int64(stmt, 4, bytes)
        bindText(stmt, 5, status)
        bindText(stmt, 6, detail)
        bindText(stmt, 7, snapshotPath)
        bindText(stmt, 8, batchID)
        _ = sqlite3_step(stmt)
    }

    private func migrate() -> Bool {
        guard exec("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS destination (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            profile_name TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL DEFAULT '',
            auth_method TEXT NOT NULL DEFAULT 'publicKey',
            key_bookmark BLOB,
            key_filename TEXT NOT NULL DEFAULT '',
            remote_root TEXT NOT NULL DEFAULT '',
            staging_root TEXT NOT NULL DEFAULT '',
            public_base TEXT NOT NULL DEFAULT '',
            recent_count INTEGER NOT NULL DEFAULT 5,
            auto_copy INTEGER NOT NULL DEFAULT 1,
            short_urls INTEGER NOT NULL DEFAULT 1,
            trusted_sha256 TEXT NOT NULL DEFAULT '',
            trusted_algorithm TEXT NOT NULL DEFAULT '',
            trusted_host TEXT NOT NULL DEFAULT '',
            trusted_port INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS upload (
            id TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            completed_at REAL,
            filename TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            status TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            public_url TEXT NOT NULL DEFAULT '',
            remote_path TEXT NOT NULL DEFAULT '',
            object_key TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL DEFAULT '',
            snapshot_path TEXT NOT NULL DEFAULT '',
            batch_id TEXT NOT NULL DEFAULT '',
            snapshot_host TEXT NOT NULL DEFAULT '',
            snapshot_port INTEGER NOT NULL DEFAULT 0,
            snapshot_user TEXT NOT NULL DEFAULT '',
            snapshot_root TEXT NOT NULL DEFAULT '',
            snapshot_staging TEXT NOT NULL DEFAULT '',
            snapshot_base TEXT NOT NULL DEFAULT '',
            clipboard_intent INTEGER NOT NULL DEFAULT 0,
            clipboard_done INTEGER NOT NULL DEFAULT 0,
            sample BLOB
        );
        CREATE INDEX IF NOT EXISTS upload_created ON upload(created_at DESC);
        """) else { return false }
        if !hasShortURLColumn(), !exec("ALTER TABLE destination ADD COLUMN short_urls INTEGER NOT NULL DEFAULT 1") {
            return false
        }
        if (Int(meta("schema_version") ?? "0") ?? 0) < 2 { setMeta("schema_version", "2") }
        return true
    }

    private func hasShortURLColumn() -> Bool {
        guard let stmt = prepare("PRAGMA table_info(destination)") else { return false }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if columnText(stmt, 1) == "short_urls" { return true }
        }
        return false
    }

    private func meta(_ key: String) -> String? {
        guard let stmt = prepare("SELECT value FROM meta WHERE key = ?") else { return nil }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return columnText(stmt, 0)
    }

    private func setMeta(_ key: String, _ value: String) {
        guard let stmt = prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value") else { return }
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, 1, key)
        bindText(stmt, 2, value)
        _ = sqlite3_step(stmt)
    }

    private func removeSnapshotFile(_ path: String) {
        guard snapshotOwned(path) else { return }
        try? FileManager.default.removeItem(atPath: path)
    }

    private func snapshotOwned(_ path: String) -> Bool {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("kiite-snapshots", isDirectory: true)
            .standardizedFileURL.path
        let file = URL(fileURLWithPath: path).standardizedFileURL.path
        return file.hasPrefix(root + "/")
    }

    private func exec(_ sql: String) -> Bool {
        sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK
    }

    private func prepare(_ sql: String) -> OpaquePointer? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        return stmt
    }

    private func bindText(_ stmt: OpaquePointer?, _ index: Int32, _ value: String) {
        _ = value.withCString { sqlite3_bind_text(stmt, index, $0, -1, transient) }
    }

    private func bindBlob(_ stmt: OpaquePointer?, _ index: Int32, _ value: Data?) {
        guard let value, !value.isEmpty else {
            sqlite3_bind_null(stmt, index)
            return
        }
        _ = value.withUnsafeBytes { raw in
            sqlite3_bind_blob(stmt, index, raw.baseAddress, Int32(value.count), transient)
        }
    }

    private func columnText(_ stmt: OpaquePointer?, _ index: Int32) -> String {
        guard let bytes = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: bytes)
    }

    private func columnBlob(_ stmt: OpaquePointer?, _ index: Int32) -> Data? {
        guard sqlite3_column_type(stmt, index) != SQLITE_NULL, let bytes = sqlite3_column_blob(stmt, index) else { return nil }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, index)))
    }
}
