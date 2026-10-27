import Foundation

/// 只读的模型目录扫描器。
///
/// 复刻 UnfairPlay `internal/fairplay/model_files.go` 的硬校验：
/// 目录必须 0700、每个 `.bin` 必须 0600、禁止符号链接、最多 256 个，
/// 任一文件不合格时 CLI 会让**整个目录**读取失败，所以这里也要给出同样结论。
public struct UnfairPlayModelStore: Sendable {
    public static let maximumModels = 256

    public let directoryURL: URL

    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }

    public func scan() -> UnfairPlayModelDirectoryReport {
        let fileManager = FileManager.default
        let path = directoryURL.path

        guard let attributes = try? fileManager.attributesOfItem(atPath: path) else {
            return .missing(path: path)
        }
        let fileType = attributes[.type] as? FileAttributeType ?? .typeUnknown
        guard fileType == .typeDirectory else {
            return UnfairPlayModelDirectoryReport(
                path: path,
                exists: true,
                isDirectory: false,
                permissions: "-",
                isPrivate: false,
                models: [],
                issues: ["模型路径不是目录"],
                isUsable: false
            )
        }

        let directoryMode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        let directoryPrivate = directoryMode & 0o077 == 0

        let entries = (try? fileManager.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: [.fileSizeKey, .isSymbolicLinkKey, .isRegularFileKey],
            options: []
        )) ?? []

        var models: [UnfairPlayModelSummary] = []
        var issues: [String] = []

        if !directoryPrivate {
            issues.append("目录权限为 \(Self.modeText(directoryMode))，UnfairPlay 要求 0700：chmod 700 \(path)")
        }

        let keys: Set<URLResourceKey> = [.fileSizeKey, .isSymbolicLinkKey, .isRegularFileKey]
        for entry in entries where entry.pathExtension.lowercased() == "bin" {
            let values = try? entry.resourceValues(forKeys: keys)
            let isSymlink = values?.isSymbolicLink ?? false
            let isRegularFile = values?.isRegularFile ?? false
            let entryAttributes = try? fileManager.attributesOfItem(atPath: entry.path)
            var mode = 0
            if let number = entryAttributes?[.posixPermissions] as? NSNumber {
                mode = number.intValue
            }
            let parsed = Self.parseFileName(entry.lastPathComponent)

            models.append(
                UnfairPlayModelSummary(
                    fileName: entry.lastPathComponent,
                    selector: parsed.selector,
                    sha256: parsed.sha256,
                    bytes: Int64(values?.fileSize ?? 0),
                    permissions: Self.modeText(mode),
                    isPrivate: mode & 0o077 == 0,
                    isSymlink: isSymlink,
                    isRegularFile: isRegularFile
                )
            )

            if isSymlink {
                issues.append("\(entry.lastPathComponent)：模型目录不能包含符号链接")
            }
            if !isRegularFile {
                issues.append("\(entry.lastPathComponent)：不是普通文件")
            }
            if mode & 0o077 != 0 {
                issues.append("\(entry.lastPathComponent)：权限为 \(Self.modeText(mode))，要求 0600")
            }
        }

        if models.count > Self.maximumModels {
            issues.append("模型数量 \(models.count) 超过 \(Self.maximumModels)")
        }
        if models.isEmpty {
            issues.append("目录中没有 .bin 模型文件")
        }

        models.sort { $0.fileName.localizedStandardCompare($1.fileName) == .orderedAscending }

        return UnfairPlayModelDirectoryReport(
            path: path,
            exists: true,
            isDirectory: true,
            permissions: Self.modeText(directoryMode),
            isPrivate: directoryPrivate,
            models: models,
            issues: issues,
            isUsable: issues.isEmpty
        )
    }

    /// 目录内可用的 selector（来自文件名，去重排序）
    public func selectors() -> [String] {
        let values = scan().models.compactMap(\.selector)
        return Array(Set(values)).sorted()
    }

    /// 仅删除目录内的 `.bin` 文件，其他文件与目录本身保持不动
    @discardableResult
    public func clearModels() throws -> [String] {
        let fileManager = FileManager.default
        let entries = (try? fileManager.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: nil,
            options: []
        )) ?? []
        var removed: [String] = []
        for entry in entries where entry.pathExtension.lowercased() == "bin" {
            try fileManager.removeItem(at: entry)
            removed.append(entry.lastPathComponent)
        }
        return removed
    }

    /// 解析 `<8hex>-<8hex>-<sha256>.bin`
    static func parseFileName(_ fileName: String) -> (selector: String?, sha256: String?) {
        let stem = (fileName as NSString).deletingPathExtension
        let parts = stem.split(separator: "-", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              isHex(parts[0], length: 8),
              isHex(parts[1], length: 8),
              isHex(parts[2], length: 64) else {
            return (nil, nil)
        }
        return ("\(parts[0]):\(parts[1])", parts[2])
    }

    private static func isHex(_ value: String, length: Int) -> Bool {
        value.count == length && value.allSatisfy { $0.isHexDigit }
    }

    private static func modeText(_ mode: Int) -> String {
        String(format: "%04o", mode & 0o7777)
    }
}
