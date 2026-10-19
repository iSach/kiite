import Foundation

enum DropVerdict: Equatable {
    case accept(name: String, bytes: Int64)
    case reject(name: String, reason: String)
}

enum DropClassifier {
    /// Stat the URL. Do not read file bytes and do not follow links.
    static func classify(url: URL) -> DropVerdict {
        let name = url.lastPathComponent.isEmpty ? "(unnamed)" : url.lastPathComponent
        let keys: Set<URLResourceKey> = [
            .isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey,
            .isPackageKey, .isAliasFileKey, .fileSizeKey,
        ]
        let values: URLResourceValues
        do {
            values = try url.resourceValues(forKeys: keys)
        } catch {
            return .reject(name: name, reason: "unreadable")
        }
        if values.isSymbolicLink == true {
            return .reject(name: name, reason: "symlink is not followed")
        }
        if values.isAliasFile == true {
            return .reject(name: name, reason: "alias is not followed")
        }
        if values.isPackage == true {
            return .reject(name: name, reason: "packages are not uploaded")
        }
        if values.isDirectory == true {
            return .reject(name: name, reason: "folders are not uploaded")
        }
        guard values.isRegularFile == true else {
            return .reject(name: name, reason: "not a regular file")
        }
        return .accept(name: name, bytes: Int64(values.fileSize ?? 0))
    }
}
