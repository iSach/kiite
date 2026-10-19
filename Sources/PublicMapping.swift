import Darwin
import Foundation
import Security

enum PublicMapping {
    static let sampleLimit = 64 * 1024
    static let stagingQuota: Int64 = 10 * 1024 * 1024 * 1024

    static func normalizeHost(_ raw: String) -> String {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("["), host.hasSuffix("]"), host.count > 2 {
            host = String(host.dropFirst().dropLast())
        }
        return host
    }

    static func hostError(_ raw: String) -> String? {
        let host = normalizeHost(raw)
        if host.isEmpty {
            return "Enter the SSH host."
        }
        if host.contains("@") || host.contains("/") || host.contains(" ") || host.contains("\\") {
            return "Enter the host on its own. Put the user and port in their own fields."
        }
        if host.contains(":") && !isIPv6(host) {
            return "Enter the port in the port field."
        }
        if !host.contains(":") && !isIPv4(host) && !isDNSName(host) {
            return "Enter a hostname or an IP address."
        }
        return nil
    }

    static func portValue(_ raw: String) -> Int? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(text), port >= 1, port <= 65535 else { return nil }
        return port
    }

    static func remoteRootError(_ raw: String) -> String? {
        let path = stripSlash(raw.trimmingCharacters(in: .whitespacesAndNewlines))
        if path.isEmpty {
            return "Enter an absolute SFTP path."
        }
        if path.hasPrefix("~") || path.contains("$") {
            return "Kiite does not expand ~ or shell variables. Enter the absolute SFTP path."
        }
        if !path.hasPrefix("/") || path.contains("//") {
            return "Enter one absolute SFTP path, without a repeated slash."
        }
        if path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
            return "The path cannot contain . or .. ."
        }
        if path.utf8.count >= 4000 {
            return "That path is too long."
        }
        return nil
    }

    static func normalizedRoot(_ raw: String) -> String? {
        guard remoteRootError(raw) == nil else { return nil }
        return stripSlash(raw.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    static func pathsOverlap(_ leftRaw: String, _ rightRaw: String) -> Bool {
        guard let left = normalizedRoot(leftRaw), let right = normalizedRoot(rightRaw) else { return false }
        if left == right { return true }
        return right.hasPrefix(left + "/") || left.hasPrefix(right + "/")
    }

    static func publicBaseError(_ raw: String) -> String? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }
        guard let components = URLComponents(string: text) else {
            return "Enter an https URL."
        }
        if components.scheme?.lowercased() != "https" || (components.host ?? "").isEmpty {
            return "The public base has to be an https URL with a host."
        }
        if components.user != nil || components.password != nil {
            return "The public base cannot include a username or password."
        }
        if components.query != nil || components.fragment != nil || text.contains("?") || text.contains("#") {
            return "The public base cannot include a query or a fragment."
        }
        if text.contains("\\") {
            return "The public base cannot include a backslash."
        }
        let pieces = components.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if pieces.contains(where: { $0 == "." || $0 == ".." || $0 == "%2e" || $0 == "%2E" || $0 == "%2e%2e" || $0.lowercased() == "%2e%2e" }) {
            return "The public base path cannot contain . or .. ."
        }
        return nil
    }

    static func sanitizedBasename(_ name: String) -> String {
        var text = name.precomposedStringWithCanonicalMapping
        text = text.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "\\", with: "_")
        let controls = CharacterSet.controlCharacters
        text = String(String.UnicodeScalarView(text.unicodeScalars.filter { !controls.contains($0) }))
        text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty || text == "." || text == ".." {
            text = "file"
        }
        text = limitUTF8(text, bytes: 200)
        if text.isEmpty || text == "." || text == ".." {
            return "file"
        }
        return text
    }

    static func allocateKey(filename: String, identifier: String? = nil, shortURLs: Bool = false, now: Date = Date()) -> String {
        let identifier = identifier ?? (shortURLs ? randomShortIdentifier() : randomIdentifier())
        let name = sanitizedBasename(filename)
        if shortURLs {
            let compoundExtensions = ["tar.gz", "tar.bz2", "tar.xz", "tar.zst"]
            let compound = compoundExtensions.first { name.lowercased().hasSuffix("." + $0) }
            let ext = compound.map { String(name.suffix($0.count)) } ?? (name as NSString).pathExtension
            return identifier + (ext.isEmpty ? "" : "." + ext)
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0)!
        let year = calendar.component(.year, from: now)
        let month = calendar.component(.month, from: now)
        return String(format: "%04d/%02d/%@/%@", year, month, identifier, name)
    }

    static func randomIdentifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            bytes = (0..<16).map { _ in UInt8.random(in: 0...255) }
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    static func randomShortIdentifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 12)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            bytes = (0..<12).map { _ in UInt8.random(in: 0...255) }
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    static func join(root: String, objectKey: String) -> String? {
        guard let base = normalizedRoot(root) else { return nil }
        if objectKey.hasPrefix("/") || objectKey.contains("//") { return nil }
        let segments = objectKey.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if segments.isEmpty || segments.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
            return nil
        }
        return base + "/" + segments.joined(separator: "/")
    }

    static func publicURL(base: String, objectKey: String) -> String? {
        let text = base.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return nil }
        guard publicBaseError(text) == nil, var components = URLComponents(string: text) else { return nil }
        var path = components.percentEncodedPath
        if path.isEmpty { path = "/" }
        if !path.hasSuffix("/") { path += "/" }
        let encoded = objectKey.split(separator: "/").map { encodeSegment(String($0)) }.joined(separator: "/")
        if encoded.isEmpty { return nil }
        components.percentEncodedPath = path + encoded
        components.query = nil
        components.fragment = nil
        return components.string
    }

    static func encodeSegment(_ segment: String) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        var encoded = ""
        for byte in segment.utf8 {
            let scalar = Unicode.Scalar(byte)
            if allowed.contains(scalar) {
                encoded.append(Character(scalar))
            } else {
                encoded += String(format: "%%%02X", byte)
            }
        }
        return encoded
    }

    static func opensshFingerprint(hex: String) -> String {
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            guard let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex), next > index else { return "" }
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return "" }
            bytes.append(byte)
            index = next
        }
        guard bytes.count == 32 else { return "" }
        let encoded = Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(encoded)"
    }

    #if KIITE_TESTING
    static func runTests() -> Bool {
        let shortID = "AbCdEf0123-_xyZ9"
        let shortCases = ["Budget #1.pdf": shortID + ".pdf", "photo.JPG": shortID + ".JPG",
                          "archive.tar.gz": shortID + ".tar.gz", "README": shortID,
                          ".env": shortID, "name.": shortID, "\u{65e5}\u{672c}.png": shortID + ".png"]
        for (name, expected) in shortCases {
            let key = allocateKey(filename: name, identifier: shortID, shortURLs: true)
            guard key == expected, !key.contains("/"),
                  publicURL(base: "https://cdn.example.com", objectKey: key) == "https://cdn.example.com/" + expected else {
                report("MAPPING fail short URL for \(name)")
                return false
            }
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let identifiers = (0..<1000).map { _ in randomShortIdentifier() }
        guard Set(identifiers).count == identifiers.count,
              identifiers.allSatisfy({ $0.count == 16 && $0.unicodeScalars.allSatisfy(allowed.contains) }),
              allocateKey(filename: "note.txt", identifier: "legacy", shortURLs: false, now: Date(timeIntervalSince1970: 0)) == "1970/01/legacy/note.txt" else {
            report("MAPPING fail random short identifiers or legacy format")
            return false
        }
        let key = "2026/10/0123456789abcdef0123456789abcdef/Budget #1 (final) 100%.pdf"
        let remote = join(root: "/srv/kiite/public", objectKey: key)
        let url = publicURL(base: "https://cdn.example.com/shared/", objectKey: key)
        let expectedURL = "https://cdn.example.com/shared/2026/10/0123456789abcdef0123456789abcdef/Budget%20%231%20%28final%29%20100%25.pdf"
        guard remote == "/srv/kiite/public/2026/10/0123456789abcdef0123456789abcdef/Budget #1 (final) 100%.pdf",
              url == expectedURL
        else {
            report("MAPPING fail example remote=\(remote ?? "nil") url=\(url ?? "nil")")
            return false
        }
        guard publicURL(base: "https://cdn.example.com/shared", objectKey: "2026/10/ab/a+b.txt")?.contains("%2B") == true else {
            report("MAPPING fail plus")
            return false
        }
        guard publicURL(base: "https://cdn.example.com/shared/", objectKey: "2026/10/ab/100% sure?.txt")?.contains("%25") == true,
              publicURL(base: "https://cdn.example.com/shared/", objectKey: "2026/10/ab/100% sure?.txt")?.contains("%3F") == true,
              publicURL(base: "https://cdn.example.com/shared/", objectKey: "2026/10/ab/say \"hi\".txt")?.contains("%22") == true
        else {
            report("MAPPING fail reserved")
            return false
        }
        let emoji = publicURL(base: "https://cdn.example.com/", objectKey: "2026/10/ab/\u{1F389}.png")
        guard emoji == "https://cdn.example.com/2026/10/ab/\(encodeSegment("\u{1F389}")).png" else {
            report("MAPPING fail emoji")
            return false
        }
        let accent = sanitizedBasename("cafe\u{0301}.txt")
        guard accent == "caf\u{00e9}.txt" else {
            report("MAPPING fail nfc")
            return false
        }
        guard sanitizedBasename(".env") == ".env" else {
            report("MAPPING fail leading-dot")
            return false
        }
        guard sanitizedBasename("../secret") == ".._secret" else {
            report("MAPPING fail traversal-name")
            return false
        }
        guard join(root: "/srv/public", objectKey: "2026/10/ab/../../etc/passwd") == nil else {
            report("MAPPING fail traversal-key")
            return false
        }
        let long = sanitizedBasename(String(repeating: "a", count: 300))
        guard long.utf8.count == 200 else {
            report("MAPPING fail long \(long.utf8.count)")
            return false
        }
        guard remoteRootError("/srv//public") != nil,
              remoteRootError("~/uploads") != nil,
              remoteRootError("/srv/../public") != nil,
              publicBaseError("http://cdn.example.com/shared") != nil,
              publicBaseError("https://user:pw@cdn.example.com/shared") != nil,
              publicBaseError("https://cdn.example.com/shared?x=1") != nil,
              publicBaseError("https://cdn.example.com/shared#frag") != nil,
              publicBaseError("") == nil
        else {
            report("MAPPING fail rejection")
            return false
        }
        let literal = publicURL(base: "https://cdn.example.com/files/", objectKey: "2026/10/ab/%2Fname")
        guard literal?.contains("%252Fname") == true else {
            report("MAPPING fail encoded-separator \(literal ?? "nil")")
            return false
        }
        guard publicURL(base: "https://cdn.example.com/shared/", objectKey: "2026/10/ab/\u{65e5}\u{672c}\u{8a9e}.txt") != nil else {
            report("MAPPING fail non-latin")
            return false
        }
        report("MAPPING ok")
        return true
    }

    #endif

    private static func stripSlash(_ path: String) -> String {
        var text = path
        while text.count > 1 && text.hasSuffix("/") {
            text.removeLast()
        }
        return text
    }

    private static func limitUTF8(_ text: String, bytes limit: Int) -> String {
        var out = ""
        var count = 0
        for scalar in text.unicodeScalars {
            let add = String(scalar).utf8.count
            if count + add > limit { break }
            out.unicodeScalars.append(scalar)
            count += add
        }
        return out
    }

    private static func isIPv4(_ host: String) -> Bool {
        var address = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ host: String) -> Bool {
        var address = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func isDNSName(_ host: String) -> Bool {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.isEmpty || labels.contains(where: { $0.isEmpty || $0.count > 63 || $0.utf8.count > 63 }) {
            return false
        }
        return labels.allSatisfy { label in
            if label.hasPrefix("-") || label.hasSuffix("-") { return false }
            return label.unicodeScalars.allSatisfy { scalar in
                scalar == "-" || CharacterSet.alphanumerics.contains(scalar)
            }
        }
    }

    private static func report(_ line: String) {
        AppLog.write(line)
    }
}
