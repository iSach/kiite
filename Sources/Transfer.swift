import CryptoKit
import Darwin
import Foundation

struct HostKeyOffer: Equatable, Sendable {
    var host: String
    var port: Int
    var algorithm: String
    var sha256: String
    var openssh: String
}

enum TransferOutcome: Sendable {
    case verified
    case publishedUnverified(String)
    case failed(Int32, String)
    case cancelled
}

struct TransferJob: @unchecked Sendable {
    var host: String
    var port: Int32
    var user: String
    var keyPath: String?
    var passphrase: String?
    var password: String?
    var hostSHA256: String
    var localPath: String
    var sha256: String
    var stagingPath: String
    var finalPath: String
    var publicURL: String
    var bytes: Int64
    var sample: Data
    var progress: ProgressGate?
    var check: CheckHandle
}

final class CheckHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionTask?
    private var flag = false

    func attach(_ task: URLSessionTask) {
        lock.lock()
        self.task = task
        let cancelNow = flag
        lock.unlock()
        if cancelNow { task.cancel() }
    }

    func cancel() {
        lock.lock()
        flag = true
        let current = task
        lock.unlock()
        current?.cancel()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }
}

enum FileDigest {
    static func hashAndSample(_ url: URL, isCancelled: () -> Bool = { false }) throws -> (hex: String, sample: Data) {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        var sample = Data()
        while true {
            if isCancelled() { throw CancellationError() }
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
            if sample.count < PublicMapping.sampleLimit {
                sample.append(chunk.prefix(PublicMapping.sampleLimit - sample.count))
            }
        }
        return (hasher.finalize().map { String(format: "%02x", $0) }.joined(), sample)
    }
}

enum UploadWork {
    static let sourceChangedCode: Int32 = 12

    static func run(job: QueuedUpload, progress: ProgressGate, check: CheckHandle, onDigest: (String, Data, Data?) -> Void, onChecking: () -> Void) -> TransferOutcome {
        let started = ProcessInfo.processInfo.systemUptime
        let access = KeyAccess.open(bookmark: job.keyBookmark)
        defer { access.stop() }
        if job.keyBookmark != nil && access.path == nil {
            return .failed(5, "The private key file is unavailable. Choose it again in Settings.")
        }
        let hashed: (hex: String, sample: Data)
        do {
            hashed = try FileDigest.hashAndSample(job.snapshot, isCancelled: { progress.current.cancel != 0 })
        } catch is CancellationError {
            return .cancelled
        } catch {
            return .failed(3, "could not hash snapshot")
        }
        if let expected = job.expectedSHA256, expected != hashed.hex {
            return .failed(sourceChangedCode, "This file differs from the original upload. Drop it as a new upload to share the changed file.")
        }
        onDigest(hashed.hex, hashed.sample, access.refreshed)
        let prepared = ProcessInfo.processInfo.systemUptime - started
        var result = KiiteUploadResult()
        let code = Transfer.invoke(
            host: job.host,
            port: job.port,
            user: job.user,
            keyPath: access.path,
            passphrase: job.passphrase,
            password: job.password,
            pin: job.pin,
            local: job.snapshot.path,
            digest: hashed.hex,
            staging: job.stagingPath,
            final: job.finalPath,
            progress: progress.pointer,
            result: &result
        )
        AppLog.write(String(format: "transfer timings %@ prepare=%.3fs connect=%.3fs directories=%.3fs send=%.3fs verify=%.3fs publish=%.3fs close=%.3fs code=%d",
                              job.id, prepared, result.connect_seconds, result.directory_seconds,
                              result.write_seconds, result.verify_seconds, result.publish_seconds, result.close_seconds, code))
        if code == 11 { return .cancelled }
        if code != 0 { return .failed(code, CBridge.text(result)) }
        if job.publicURL.isEmpty {
            return .publishedUnverified("No public HTTPS base is set for this upload.")
        }
        guard let url = URL(string: job.publicURL), url.scheme?.lowercased() == "https" else {
            return .publishedUnverified("The stored public URL is not an https URL.")
        }
        onChecking()
        if check.isCancelled {
            return .publishedUnverified("Published. The public check was cancelled.")
        }
        let checkStarted = ProcessInfo.processInfo.systemUptime
        let detail = PublicCheck.fetch(url: url, sample: hashed.sample, expectedBytes: job.bytes, handle: check)
        AppLog.write(String(format: "public check timing %@ %.3fs", job.id, ProcessInfo.processInfo.systemUptime - checkStarted))
        if let detail {
            if check.isCancelled {
                return .publishedUnverified("Published. The public check was cancelled.")
            }
            return .publishedUnverified(detail)
        }
        return .verified
    }
}

enum Transfer {
    static func run(_ job: TransferJob) -> TransferOutcome {
        var result = KiiteUploadResult()
        let code = invoke(
            host: job.host,
            port: job.port,
            user: job.user,
            keyPath: job.keyPath,
            passphrase: job.passphrase,
            password: job.password,
            pin: job.hostSHA256,
            local: job.localPath,
            digest: job.sha256,
            staging: job.stagingPath,
            final: job.finalPath,
            progress: job.progress?.pointer,
            result: &result
        )
        let message = CBridge.text(result)
        if code == 11 { return .cancelled }
        if code != 0 { return .failed(code, message) }
        if job.publicURL.isEmpty {
            return .publishedUnverified("No public HTTPS base is set for this upload.")
        }
        guard let url = URL(string: job.publicURL), url.scheme?.lowercased() == "https" else {
            return .publishedUnverified("The stored public URL is not an https URL.")
        }
        if job.check.isCancelled {
            return .publishedUnverified("Published. The public check was cancelled.")
        }
        if let detail = PublicCheck.fetch(url: url, sample: job.sample, expectedBytes: job.bytes, handle: job.check) {
            if job.check.isCancelled {
                return .publishedUnverified("Published. The public check was cancelled.")
            }
            return .publishedUnverified(detail)
        }
        return .verified
    }

    static func invoke(
        host: String,
        port: Int32,
        user: String,
        keyPath: String?,
        passphrase: String?,
        password: String?,
        pin: String,
        local: String,
        digest: String,
        staging: String,
        final: String,
        progress: UnsafeMutablePointer<KiiteProgress>?,
        result: inout KiiteUploadResult
    ) -> Int32 {
        let hostBox = CString(host)
        let userBox = CString(user)
        let keyBox = CString(keyPath)
        let phraseBox = CString(passphrase)
        let passwordBox = CString(password)
        let pinBox = CString(pin)
        let localBox = CString(local)
        let digestBox = CString(digest)
        let stagingBox = CString(staging)
        let finalBox = CString(final)
        guard let hostPtr = hostBox.const, let userPtr = userBox.const, let pinPtr = pinBox.const,
              let localPtr = localBox.const, let digestPtr = digestBox.const,
              let stagingPtr = stagingBox.const, let finalPtr = finalBox.const
        else {
            result.code = 3
            return 3
        }
        return kiite_upload_file(
            hostPtr, port, userPtr, keyBox.const, phraseBox.const, passwordBox.const, pinPtr,
            localPtr, digestPtr, stagingPtr, finalPtr, progress, &result
        )
    }
}

enum PublicCheck {
    static func fetch(url: URL, sample: Data, expectedBytes: Int64, handle: CheckHandle?) -> String? {
        guard let host = url.host, url.scheme?.lowercased() == "https" else {
            return "The public URL is not https."
        }
        let fetcher = BoundedFetch(host: host, limit: PublicMapping.sampleLimit, handle: handle)
        fetcher.fetch(url: url)
        if let error = fetcher.error as NSError? {
            if error.code == NSURLErrorCancelled { return "The public check was cancelled." }
            if error.domain == NSURLErrorDomain && (error.code == NSURLErrorSecureConnectionFailed || error.code == NSURLErrorServerCertificateUntrusted || error.code == NSURLErrorServerCertificateHasBadDate || error.code == NSURLErrorCannotLoadFromNetwork) {
                return "The public link failed TLS verification."
            }
            return "The public link could not be fetched."
        }
        guard let response = fetcher.response else {
            return "The public link could not be fetched."
        }
        return evaluate(sample: sample, expectedBytes: expectedBytes, response: response, body: fetcher.body, stoppedEarly: fetcher.stoppedEarly)
    }

    static func evaluate(sample: Data, expectedBytes: Int64, response: HTTPURLResponse, body: Data, stoppedEarly: Bool) -> String? {
        let status = response.statusCode
        if expectedBytes == 0 {
            if (status == 200 && body.isEmpty) || status == 416 { return nil }
            return "The public server returned \(status) for an empty file."
        }
        if status == 404 { return "The public link returned 404." }
        if status == 403 { return "The public link returned 403." }
        if (300..<400).contains(status) { return "The public check refused a redirect." }
        let length = response.value(forHTTPHeaderField: "Content-Length").flatMap(Int64.init)
        let total = rangeTotal(response)
        if let total, total != expectedBytes {
            return "The public length does not match the uploaded file."
        }
        let want = Int(min(Int64(PublicMapping.sampleLimit), expectedBytes))
        let matches = body.count == want && body.elementsEqual(sample.prefix(want))
        if status == 206 && matches { return nil }
        if status == 200 && Int64(body.count) == expectedBytes && body.elementsEqual(sample.prefix(body.count)) {
            return nil
        }
        if status == 200 && stoppedEarly && matches && length == expectedBytes { return nil }
        if status == 200 && stoppedEarly && length == nil && total == nil {
            return "The public response had no length metadata."
        }
        if status == 200 || status == 206 {
            return "The public bytes do not match the uploaded file."
        }
        return "The public link returned \(status)."
    }

    private static func rangeTotal(_ response: HTTPURLResponse) -> Int64? {
        guard let header = response.value(forHTTPHeaderField: "Content-Range"),
              let slash = header.lastIndex(of: "/")
        else { return nil }
        let total = header[header.index(after: slash)...]
        if total == "*" { return nil }
        return Int64(total)
    }
}

final class BoundedFetch: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let allowedHost: String
    let limit: Int
    let handle: CheckHandle?
    private(set) var body = Data()
    private(set) var response: HTTPURLResponse?
    private(set) var error: Error?
    private(set) var stoppedEarly = false
    private let done = DispatchSemaphore(value: 0)

    init(host: String, limit: Int, handle: CheckHandle?) {
        allowedHost = host.lowercased()
        self.limit = limit
        self.handle = handle
    }

    func fetch(url: URL) {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 30
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("bytes=0-\(max(0, PublicMapping.sampleLimit - 1))", forHTTPHeaderField: "Range")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.httpShouldHandleCookies = false
        let task = session.dataTask(with: request)
        handle?.attach(task)
        task.resume()
        done.wait()
        session.finishTasksAndInvalidate()
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let room = limit - body.count
        if data.count <= room {
            body.append(data)
            return
        }
        if room > 0 { body.append(data.prefix(room)) }
        stoppedEarly = true
        dataTask.cancel()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if stoppedEarly, let error, (error as NSError).code == NSURLErrorCancelled {
            self.error = nil
        } else {
            self.error = error
        }
        done.signal()
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let host = request.url?.host?.lowercased(), host == allowedHost, request.url?.scheme?.lowercased() == "https" else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}

struct ConnectionTestReport: Sendable {
    var lines: [String]
    var offer: HostKeyOffer?
}

enum ConnectionTest {
    static func run(draft: DestinationDraft, password: String, passphrase: String, dropPassword: Bool) -> ConnectionTestReport {
        let errors = DestinationRules.errors(draft: draft, password: password, dropPassword: dropPassword)
        if let error = errors.first {
            return ConnectionTestReport(lines: ["Result: \(error)"], offer: nil)
        }
        let host = draft.normalizedHost
        let port = PublicMapping.portValue(draft.port) ?? 22
        var probe = KiiteProbeResult()
        let probeCode = host.withCString { kiite_probe_hostkey($0, Int32(port), &probe) }
        if probeCode != 0 {
            let message = CBridge.probeMessage(probe)
            return ConnectionTestReport(lines: [
                "Reachability: \(message).",
                "Result: stopped before authentication.",
            ], offer: nil)
        }
        let hex = CBridge.probeHex(probe)
        let algorithm = CBridge.probeAlgorithm(probe)
        let offer = HostKeyOffer(
            host: host,
            port: port,
            algorithm: algorithm,
            sha256: hex,
            openssh: PublicMapping.opensshFingerprint(hex: hex)
        )
        var lines = ["Reachability: connected to \(host) port \(port)."]
        let trusted = draft.trustedHost == host && draft.trustedPort == port && draft.trustedSHA256.lowercased() == hex.lowercased() && hex.count == 64
        let changed = draft.trustedSHA256.count == 64 && draft.trustedHost == host && draft.trustedPort == port && draft.trustedSHA256.lowercased() != hex.lowercased()
        if !trusted {
            let reason = changed
                ? "the key changed. Kiite did not send credentials."
                : "this key is not trusted yet. Kiite did not send credentials."
            lines.append("Host trust: \(algorithm) \(offer.openssh). \(reason)")
            lines.append("Result: stopped before authentication.")
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        lines.append("Host trust: \(algorithm) \(offer.openssh). This matches the trusted key.")

        let access = KeyAccess.open(bookmark: draft.authMethod == "password" ? nil : draft.keyBookmark)
        defer { access.stop() }
        if draft.authMethod != "password" && access.path == nil {
            lines.append("Authentication: the private key file is unavailable. Choose it again.")
            lines.append("Result: stopped before a successful authentication.")
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        let storedPassword = (!dropPassword && password.isEmpty) ? SecretStore.read(account: SecretStore.passwordAccount) : password
        let storedPhrase = passphrase.isEmpty ? SecretStore.read(account: SecretStore.passphraseAccount) : passphrase
        let secret = draft.authMethod == "password" ? storedPassword : nil
        let phrase = draft.authMethod == "password" ? nil : storedPhrase
        var directory = KiiteUploadResult()
        let directoryCode = directoryCheck(
            host: host, port: Int32(port), user: draft.username.trimmingCharacters(in: .whitespacesAndNewlines),
            keyPath: access.path, passphrase: phrase, password: secret, pin: hex,
            remote: PublicMapping.normalizedRoot(draft.remoteRoot) ?? "",
            staging: PublicMapping.normalizedRoot(draft.stagingRoot) ?? "",
            result: &directory
        )
        if directoryCode != 0 {
            lines.append("SFTP: \(CBridge.text(directory)).")
            lines.append("Result: the publishing test did not start.")
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        lines.append("SFTP: authenticated, and both roots are directories.")

        let identifier = PublicMapping.randomIdentifier()
        let objectKey = PublicMapping.allocateKey(filename: "kiite-connection-test.bin", shortURLs: draft.shortURLs)
        guard let remoteRoot = PublicMapping.normalizedRoot(draft.remoteRoot),
              let stagingRoot = PublicMapping.normalizedRoot(draft.stagingRoot),
              let stagingPath = PublicMapping.join(root: stagingRoot, objectKey: objectKey),
              let finalPath = PublicMapping.join(root: remoteRoot, objectKey: objectKey)
        else {
            lines.append("Result: the remote path was rejected.")
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        let bytes = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("kiite-connection-test-\(identifier)")
        do {
            try bytes.write(to: temp, options: .atomic)
        } catch {
            lines.append("Result: could not write the local test file.")
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        defer { try? FileManager.default.removeItem(at: temp) }
        let digest = (try? FileDigest.hashAndSample(temp).hex) ?? ""
        var uploaded = KiiteUploadResult()
        let uploadCode = Transfer.invoke(
            host: host, port: Int32(port), user: draft.username.trimmingCharacters(in: .whitespacesAndNewlines),
            keyPath: access.path, passphrase: phrase, password: secret, pin: hex,
            local: temp.path, digest: digest, staging: stagingPath, final: finalPath,
            progress: nil, result: &uploaded
        )
        if uploadCode != 0 {
            lines.append("Publish: \(CBridge.text(uploaded)).")
            lines.append("Result: atomic publish did not succeed. Kiite will not pretend a login is enough.")
            _ = remove(host: host, port: Int32(port), user: draft.username, keyPath: access.path, passphrase: phrase, password: secret, pin: hex, path: stagingPath)
            return ConnectionTestReport(lines: lines, offer: offer)
        }
        lines.append("Publish: posix-rename published the test file.")
        let base = draft.publicBase.trimmingCharacters(in: .whitespacesAndNewlines)
        var publicOK = false
        if base.isEmpty {
            lines.append("Public link: no public base is set, so the link was not checked.")
        } else if let urlText = PublicMapping.publicURL(base: base, objectKey: objectKey), let url = URL(string: urlText) {
            if let detail = PublicCheck.fetch(url: url, sample: bytes, expectedBytes: Int64(bytes.count), handle: nil) {
                lines.append("Public link: \(detail)")
            } else {
                publicOK = true
                lines.append("Public link: the anonymous fetch matched the test file.")
            }
        } else {
            lines.append("Public link: the public base did not produce a URL.")
        }
        let removed = remove(host: host, port: Int32(port), user: draft.username, keyPath: access.path, passphrase: phrase, password: secret, pin: hex, path: finalPath)
        lines.append(removed ? "Cleanup: removed the test file." : "Cleanup: the test file is still on the server.")
        lines.append("Kiite does not certify that the web server hides the staging directory. Keep staging off the public site.")
        if base.isEmpty {
            lines.append("Result: publish works. The public link was not checked.")
        } else if publicOK {
            lines.append("Result: publish works, and the public file matched.")
        } else {
            lines.append("Result: publish works, but the public link did not check out.")
        }
        return ConnectionTestReport(lines: lines, offer: offer)
    }

    private static func directoryCheck(
        host: String, port: Int32, user: String, keyPath: String?, passphrase: String?, password: String?, pin: String,
        remote: String, staging: String, result: inout KiiteUploadResult
    ) -> Int32 {
        let hostBox = CString(host)
        let userBox = CString(user)
        let keyBox = CString(keyPath)
        let phraseBox = CString(passphrase)
        let passwordBox = CString(password)
        let pinBox = CString(pin)
        let remoteBox = CString(remote)
        let stagingBox = CString(staging)
        guard let hostPtr = hostBox.const, let userPtr = userBox.const, let pinPtr = pinBox.const,
              let remotePtr = remoteBox.const, let stagingPtr = stagingBox.const
        else { return 3 }
        return kiite_check_directories(hostPtr, port, userPtr, keyBox.const, phraseBox.const, passwordBox.const, pinPtr, remotePtr, stagingPtr, &result)
    }

    private static func remove(
        host: String, port: Int32, user: String, keyPath: String?, passphrase: String?, password: String?, pin: String, path: String
    ) -> Bool {
        var result = KiiteUploadResult()
        let hostBox = CString(host)
        let userBox = CString(user.trimmingCharacters(in: .whitespacesAndNewlines))
        let keyBox = CString(keyPath)
        let phraseBox = CString(passphrase)
        let passwordBox = CString(password)
        let pinBox = CString(pin)
        let pathBox = CString(path)
        guard let hostPtr = hostBox.const, let userPtr = userBox.const, let pinPtr = pinBox.const, let pathPtr = pathBox.const else {
            return false
        }
        let code = kiite_remove_file(hostPtr, port, userPtr, keyBox.const, phraseBox.const, passwordBox.const, pinPtr, pathPtr, &result)
        return code == 0
    }
}

struct KeyAccess {
    var path: String?
    var refreshed: Data?
    var stop: () -> Void

    static func open(bookmark: Data?) -> KeyAccess {
        guard let bookmark, let resolved = KeyBookmark.resolve(bookmark) else {
            return KeyAccess(path: nil, refreshed: nil, stop: {})
        }
        let started = resolved.url.startAccessingSecurityScopedResource()
        return KeyAccess(
            path: resolved.url.path,
            refreshed: resolved.refreshed,
            stop: { if started { resolved.url.stopAccessingSecurityScopedResource() } }
        )
    }
}

final class CString {
    private let pointer: UnsafeMutablePointer<CChar>?
    init(_ value: String?) {
        if let value, !value.isEmpty {
            pointer = strdup(value)
        } else {
            pointer = nil
        }
    }
    var const: UnsafePointer<CChar>? { pointer.map { UnsafePointer($0) } }
    deinit {
        if let pointer {
            memset(pointer, 0, strlen(pointer))
            free(pointer)
        }
    }
}

enum CBridge {
    static func text(_ result: KiiteUploadResult) -> String {
        var copy = result
        return withUnsafePointer(to: &copy.message) {
            $0.withMemoryRebound(to: CChar.self, capacity: 240) { String(cString: $0) }
        }
    }

    static func probeMessage(_ result: KiiteProbeResult) -> String {
        var copy = result
        return withUnsafePointer(to: &copy.message) {
            $0.withMemoryRebound(to: CChar.self, capacity: 240) { String(cString: $0) }
        }
    }

    static func probeHex(_ result: KiiteProbeResult) -> String {
        var copy = result
        return withUnsafePointer(to: &copy.sha256_hex) {
            $0.withMemoryRebound(to: CChar.self, capacity: 65) { String(cString: $0) }
        }
    }

    static func probeAlgorithm(_ result: KiiteProbeResult) -> String {
        var copy = result
        return withUnsafePointer(to: &copy.algorithm) {
            $0.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
        }
    }
}
