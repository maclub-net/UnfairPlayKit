import Foundation

/// UnfairPlay 相关设置。
///
/// 模型目录留空表示使用上游默认目录（`~/Library/Application Support/unfairplay/models`），
/// 这样老用户升级后无需任何配置即可被发现已有模型。
public struct UnfairPlaySettings: Codable, Sendable, Equatable {
    /// 模型目录；空串表示使用默认目录
    public var modelDirectory: String

    public init(modelDirectory: String = "") {
        self.modelDirectory = modelDirectory
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(modelDirectory: try container.decodeIfPresent(String.self, forKey: .modelDirectory) ?? "")
    }

    /// 上游默认模型目录（`defaultModelDirectory()` 的非 root 分支）
    public static func defaultDirectoryPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/unfairplay/models", isDirectory: true)
            .path
    }

    /// 解析后的模型目录绝对路径
    public func resolvedDirectoryPath() -> String {
        let trimmed = modelDirectory.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return Self.defaultDirectoryPath()
        }
        return (trimmed as NSString).expandingTildeInPath
    }

    public func resolvedDirectoryURL() -> URL {
        URL(fileURLWithPath: resolvedDirectoryPath(), isDirectory: true)
    }
}

/// 单个模型文件的只读摘要（不读取模型字节）
public struct UnfairPlayModelSummary: Codable, Sendable, Identifiable, Equatable {
    public var fileName: String
    /// 从文件名 `<8hex>-<8hex>-<sha256>.bin` 解析出的 selector，解析失败为 nil
    public var selector: String?
    /// 从文件名第三段解析出的模型哈希
    public var sha256: String?
    public var bytes: Int64
    /// 权限位的八进制文本，例如 `0600`
    public var permissions: String
    /// 是否满足 CLI 要求的私有权限（不含 group/other 位）
    public var isPrivate: Bool
    public var isSymlink: Bool
    public var isRegularFile: Bool

    public var id: String { fileName }

    public init(
        fileName: String,
        selector: String?,
        sha256: String?,
        bytes: Int64,
        permissions: String,
        isPrivate: Bool,
        isSymlink: Bool,
        isRegularFile: Bool
    ) {
        self.fileName = fileName
        self.selector = selector
        self.sha256 = sha256
        self.bytes = bytes
        self.permissions = permissions
        self.isPrivate = isPrivate
        self.isSymlink = isSymlink
        self.isRegularFile = isRegularFile
    }
}

/// 模型目录的只读诊断结果
public struct UnfairPlayModelDirectoryReport: Codable, Sendable, Equatable {
    public var path: String
    public var exists: Bool
    public var isDirectory: Bool
    /// 目录权限位的八进制文本
    public var permissions: String
    /// 目录是否满足 0700
    public var isPrivate: Bool
    public var models: [UnfairPlayModelSummary]
    /// 与 CLI 硬校验（0700 / 0600 / 无符号链接 / ≤256 / 至少一个 .bin）不一致的问题
    public var issues: [String]
    /// 是否可被 UnfairPlay 正常读取
    public var isUsable: Bool

    public init(
        path: String,
        exists: Bool,
        isDirectory: Bool,
        permissions: String,
        isPrivate: Bool,
        models: [UnfairPlayModelSummary],
        issues: [String],
        isUsable: Bool
    ) {
        self.path = path
        self.exists = exists
        self.isDirectory = isDirectory
        self.permissions = permissions
        self.isPrivate = isPrivate
        self.models = models
        self.issues = issues
        self.isUsable = isUsable
    }

    public static func missing(path: String) -> UnfairPlayModelDirectoryReport {
        UnfairPlayModelDirectoryReport(
            path: path,
            exists: false,
            isDirectory: false,
            permissions: "-",
            isPrivate: false,
            models: [],
            issues: ["未找到模型目录，请先执行一次 unfairplay setup"],
            isUsable: false
        )
    }
}

// MARK: - doctor 报告

public struct UnfairPlaySINFDiagnostic: Codable, Sendable, Equatable {
    public var path: String
    public var selectorId: String
    public var currentLayout: Bool
    public var sha256: String?

    public init(path: String, selectorId: String, currentLayout: Bool, sha256: String?) {
        self.path = path
        self.selectorId = selectorId
        self.currentLayout = currentLayout
        self.sha256 = sha256
    }

    enum CodingKeys: String, CodingKey {
        case path
        case selectorId = "selector_id"
        case currentLayout = "current_layout"
        case sha256
    }
}

public struct UnfairPlayDoctorModel: Codable, Sendable, Equatable {
    public var path: String
    public var selectorId: String?
    public var sha256: String?
    public var bytes: Int?

    public init(path: String, selectorId: String?, sha256: String?, bytes: Int?) {
        self.path = path
        self.selectorId = selectorId
        self.sha256 = sha256
        self.bytes = bytes
    }

    enum CodingKeys: String, CodingKey {
        case path
        case selectorId = "selector_id"
        case sha256
        case bytes
    }
}

/// `unfairplay doctor --ipa` 的 stdout JSON（`unfairplay-doctor-v1`）。
///
/// 注意：CLI 在存在 errors 时退出码仍为 1，因此**不能**用退出码判定，只看 `decryptReady`。
public struct UnfairPlayDoctorReport: Codable, Sendable, Equatable {
    public var schema: String
    public var ready: Bool
    public var decryptReady: Bool
    public var checks: [String: Bool]
    public var errors: [String]
    public var warnings: [String]
    public var nextActions: [String]
    public var sinf: [UnfairPlaySINFDiagnostic]
    public var models: [UnfairPlayDoctorModel]
    public var compatibleModelsBySINF: [String: String]
    public var compatibleModel: String?

    public init(
        schema: String = "",
        ready: Bool = false,
        decryptReady: Bool = false,
        checks: [String: Bool] = [:],
        errors: [String] = [],
        warnings: [String] = [],
        nextActions: [String] = [],
        sinf: [UnfairPlaySINFDiagnostic] = [],
        models: [UnfairPlayDoctorModel] = [],
        compatibleModelsBySINF: [String: String] = [:],
        compatibleModel: String? = nil
    ) {
        self.schema = schema
        self.ready = ready
        self.decryptReady = decryptReady
        self.checks = checks
        self.errors = errors
        self.warnings = warnings
        self.nextActions = nextActions
        self.sinf = sinf
        self.models = models
        self.compatibleModelsBySINF = compatibleModelsBySINF
        self.compatibleModel = compatibleModel
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            schema: try container.decodeIfPresent(String.self, forKey: .schema) ?? "",
            ready: try container.decodeIfPresent(Bool.self, forKey: .ready) ?? false,
            decryptReady: try container.decodeIfPresent(Bool.self, forKey: .decryptReady) ?? false,
            checks: try container.decodeIfPresent([String: Bool].self, forKey: .checks) ?? [:],
            errors: try container.decodeIfPresent([String].self, forKey: .errors) ?? [],
            warnings: try container.decodeIfPresent([String].self, forKey: .warnings) ?? [],
            nextActions: try container.decodeIfPresent([String].self, forKey: .nextActions) ?? [],
            sinf: try container.decodeIfPresent([UnfairPlaySINFDiagnostic].self, forKey: .sinf) ?? [],
            models: try container.decodeIfPresent([UnfairPlayDoctorModel].self, forKey: .models) ?? [],
            compatibleModelsBySINF: try container.decodeIfPresent([String: String].self, forKey: .compatibleModelsBySINF) ?? [:],
            compatibleModel: try container.decodeIfPresent(String.self, forKey: .compatibleModel)
        )
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case ready
        case decryptReady = "decrypt_ready"
        case checks
        case errors
        case warnings
        case nextActions = "next_actions"
        case sinf
        case models
        case compatibleModelsBySINF = "compatible_models_by_sinf"
        case compatibleModel = "compatible_model"
    }
}

// MARK: - decrypt 报告

public struct UnfairPlayImageDiagnostic: Codable, Sendable, Equatable {
    public var member: String
    public var cryptidBefore: UInt32
    public var cryptidAfter: UInt32

    public init(member: String, cryptidBefore: UInt32, cryptidAfter: UInt32) {
        self.member = member
        self.cryptidBefore = cryptidBefore
        self.cryptidAfter = cryptidAfter
    }

    enum CodingKeys: String, CodingKey {
        case member
        case cryptidBefore = "cryptid_before"
        case cryptidAfter = "cryptid_after"
    }
}

/// `unfairplay decrypt` 落盘的报告（`unfairplay-decryption-v1`）。
///
/// 只映射安全字段：`oracle`、`licenses` 等敏感内容不进入本类型。
public struct UnfairPlayDecryptReport: Codable, Sendable, Equatable {
    public var schema: String
    public var complete: Bool
    public var plaintextVerified: Bool
    public var signatureVerified: Bool
    public var encryptedImageCount: Int
    public var decryptedPageCount: Int
    public var modelBuild: String
    public var warnings: [String]
    public var images: [UnfairPlayImageDiagnostic]

    public init(
        schema: String = "",
        complete: Bool = false,
        plaintextVerified: Bool = false,
        signatureVerified: Bool = false,
        encryptedImageCount: Int = 0,
        decryptedPageCount: Int = 0,
        modelBuild: String = "",
        warnings: [String] = [],
        images: [UnfairPlayImageDiagnostic] = []
    ) {
        self.schema = schema
        self.complete = complete
        self.plaintextVerified = plaintextVerified
        self.signatureVerified = signatureVerified
        self.encryptedImageCount = encryptedImageCount
        self.decryptedPageCount = decryptedPageCount
        self.modelBuild = modelBuild
        self.warnings = warnings
        self.images = images
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            schema: try container.decodeIfPresent(String.self, forKey: .schema) ?? "",
            complete: try container.decodeIfPresent(Bool.self, forKey: .complete) ?? false,
            plaintextVerified: try container.decodeIfPresent(Bool.self, forKey: .plaintextVerified) ?? false,
            signatureVerified: try container.decodeIfPresent(Bool.self, forKey: .signatureVerified) ?? false,
            encryptedImageCount: try container.decodeIfPresent(Int.self, forKey: .encryptedImageCount) ?? 0,
            decryptedPageCount: try container.decodeIfPresent(Int.self, forKey: .decryptedPageCount) ?? 0,
            modelBuild: try container.decodeIfPresent(String.self, forKey: .modelBuild) ?? "",
            warnings: try container.decodeIfPresent([String].self, forKey: .warnings) ?? [],
            images: try container.decodeIfPresent([UnfairPlayImageDiagnostic].self, forKey: .images) ?? []
        )
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case complete
        case plaintextVerified = "plaintext_verified"
        case signatureVerified = "signature_verified"
        case encryptedImageCount = "encrypted_image_count"
        case decryptedPageCount = "decrypted_page_count"
        case modelBuild = "model_build"
        case warnings
        case images
    }
}

public struct UnfairPlayDecryptResult: Sendable, Equatable {
    public var outputURL: URL
    public var outputSHA256: String?
    public var report: UnfairPlayDecryptReport

    public init(outputURL: URL, outputSHA256: String?, report: UnfairPlayDecryptReport) {
        self.outputURL = outputURL
        self.outputSHA256 = outputSHA256
        self.report = report
    }
}

// MARK: - 预检结果

public struct UnfairPlayProbeResult: Sendable, Equatable {
    public var report: UnfairPlayDoctorReport
    /// 每个 SINF 都配到了可用模型
    public var isReady: Bool
    /// IPA 内是否存在加密 Mach-O（false 表示无需解密）
    public var hasEncryptedPayload: Bool
    /// IPA 中的 SINF selector（去重）
    public var sinfSelectors: [String]
    /// 本机模型可用的 selector（去重）
    public var availableSelectors: [String]

    public init(
        report: UnfairPlayDoctorReport,
        isReady: Bool,
        hasEncryptedPayload: Bool,
        sinfSelectors: [String],
        availableSelectors: [String]
    ) {
        self.report = report
        self.isReady = isReady
        self.hasEncryptedPayload = hasEncryptedPayload
        self.sinfSelectors = sinfSelectors
        self.availableSelectors = availableSelectors
    }
}

// MARK: - 错误

public enum UnfairPlayError: Error, LocalizedError, Equatable, Sendable {
    case binaryNotFound
    case missingSourceIPA
    case modelDirectoryMissing(String)
    case noEncryptedPayload
    case modelNotProvided(selectors: [String], available: [String])
    case notReady(errors: [String])
    case processFailure(String)
    case invalidReport(String)
    case decryptionIncomplete(errors: [String])

    public var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            return "未找到 unfairplay 可执行文件，请在设置 → 工具路径填写路径，或使用内置版本"
        case .missingSourceIPA:
            return "内部错误：UnfairPlay 引擎缺少下载产物 IPA 路径"
        case .modelDirectoryMissing(let path):
            return "未找到模型目录 \(path)，请先执行一次 unfairplay setup 采集模型"
        case .noEncryptedPayload:
            return "该 IPA 不含加密 Mach-O（可能已是解密包），无需 UnfairPlay"
        case .modelNotProvided(let selectors, let available):
            let sinf = selectors.isEmpty ? "未知" : selectors.joined(separator: "、")
            let models = available.isEmpty ? "无" : available.joined(separator: "、")
            return "该 IPA 属于 selector \(sinf)，本机没有对应模型（已有：\(models)）。请在 Mac App Store 登录该账号后执行一次 sudo unfairplay setup --app <已装App> --ipa <同账号IPA>"
        case .notReady(let errors):
            return errors.isEmpty ? "UnfairPlay 预检未通过" : Self.text(forCLIFailure: errors.joined(separator: "；"))
        case .processFailure(let message):
            return Self.text(forCLIFailure: message)
        case .invalidReport(let message):
            return "无法解析 UnfairPlay 输出：\(message)"
        case .decryptionIncomplete(let errors):
            let detail = errors.isEmpty ? "" : "（\(errors.joined(separator: "；"))）"
            return "UnfairPlay 解密未完整完成\(detail)"
        }
    }

    /// 把 CLI 原文映射成可操作的结论（施工方案 §6.5）
    public static func text(forCLIFailure message: String) -> String {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "UnfairPlay 执行失败"
        }
        if trimmed.contains("no supported encrypted Mach-O images") {
            return "该 IPA 不含加密 Mach-O（可能已是解密包），无需 UnfairPlay"
        }
        if trimmed.contains("no enrollment model matches SINF") {
            return "本机没有与 IPA 匹配的模型：\(trimmed)。请登录对应账号后执行一次 unfairplay setup 采集模型"
        }
        if trimmed.contains("IPA member not found") {
            return "采集时 --app 与 --ipa 不是同一个 App"
        }
        if trimmed.contains("must not be accessible by group or other users") {
            return "模型目录/文件权限过宽（需 0700/0600）：chmod 700 <目录>、chmod 600 <目录>/*.bin"
        }
        if trimmed.contains("registry contains a symlink") {
            return "模型目录含符号链接，UnfairPlay 拒绝读取"
        }
        if trimmed.contains("contains more than 256 models") {
            return "模型数量超过 256"
        }
        if trimmed.contains("no saved enrollment models") {
            return "未找到模型目录，先在设置中填入正确路径"
        }
        return trimmed
    }
}
