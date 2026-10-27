import CUnfairPlay
import CryptoKit
import Darwin
import Foundation

/// Setup stages, in execution order. Recovery is the stage that emulates
/// `fairplayd`; it is not ported yet, so a full run stops there today.
public enum UnfairPlaySetupStage: String, Sendable {
    case validation
    case capture
    case recovery
    case install
    case decryptionValidation
}

public enum UnfairPlaySetupError: Error, LocalizedError, Equatable, Sendable {
    case notAnApplication(String)
    case infoPlistUnreadable(String)
    case appSINFCount(Int)
    case sinfSelectorUnreadable(String)
    case ipaHasNoMatchingSINF(selector: String)
    case ipaMissingMember(String)
    case stateDirectoryUnreadable(String)
    case fairplaydUnavailable(String)
    case captureDirectoryExists(String)
    case recoveryUnavailable(selector: String)
    case recoveryFailed(String)
    case fileOperation(String)

    public var errorDescription: String? {
        switch self {
        case let .notAnApplication(path):
            return "已装 App 不是 .app 目录：\(path)"
        case let .infoPlistUnreadable(path):
            return "无法读取 App 的 Info.plist：\(path)"
        case let .appSINFCount(count):
            return "已装 App 的 SC_Info 必须恰好包含一个根 SINF，实际 \(count) 个"
        case let .sinfSelectorUnreadable(path):
            return "无法解析 SINF 的 selector：\(path)"
        case let .ipaHasNoMatchingSINF(selector):
            return "IPA 内没有 selector 为 \(selector) 的 SINF，请确认 IPA 与已装 App 使用同一账号"
        case let .ipaMissingMember(member):
            return "IPA 缺少成员：\(member)"
        case let .stateDirectoryUnreadable(path):
            return "无法读取 FairPlay 系统状态 \(path)，需要管理员权限（root）"
        case let .fairplaydUnavailable(reason):
            return "无法读取 fairplayd：\(reason)"
        case let .captureDirectoryExists(path):
            return "采集目录已存在，请换一个空目录：\(path)"
        case let .recoveryUnavailable(selector):
            return "已完成采集与校验（selector \(selector)），但本机引擎尚未包含 recovery 阶段，暂时无法生成模型"
        case let .recoveryFailed(reason):
            return "recovery 执行失败：\(reason)"
        case let .fileOperation(reason):
            return reason
        }
    }
}

/// Owner to restore after a root capture, so the capture can be read (and later
/// processed) by the invoking user.
public struct UnfairPlaySetupOwner: Sendable, Equatable {
    public let uid: uid_t
    public let gid: gid_t

    public init(uid: uid_t, gid: gid_t) {
        self.uid = uid
        self.gid = gid
    }
}

public struct UnfairPlaySetupOptions: Sendable {
    public var appURL: URL
    public var ipaURL: URL
    public var modelDirectoryURL: URL
    /// Built-in IORegistry interface whose parent controller carries the MAC.
    public var hardwareInterface: String

    public init(
        appURL: URL,
        ipaURL: URL,
        modelDirectoryURL: URL,
        hardwareInterface: String = "en0"
    ) {
        self.appURL = appURL
        self.ipaURL = ipaURL
        self.modelDirectoryURL = modelDirectoryURL
        self.hardwareInterface = hardwareInterface
    }
}

public struct UnfairPlaySetupValidation: Sendable, Equatable {
    public let appDirectory: URL
    public let bundleIdentifier: String
    public let executable: String
    public let selector: String
    public let installedSINF: URL
    /// Root inside the IPA that carries the matching SINF, e.g. `Payload/Foo.app`.
    public let ipaRoot: String
    public let ipaTargetSINFMember: String
    public let hasModel: Bool
    public let warnings: [String]
}

public struct UnfairPlaySetupCaptureResult: Sendable {
    public let directory: URL
    public let manifestURL: URL
    public let validation: UnfairPlaySetupValidation
}

/// Native enrollment setup.
///
/// `validate` needs no privileges. `capture` reads `/private/var/db/fpsd`, so it
/// must run as root; pass `owner` and the whole capture tree is handed back to
/// that account. `installModel` is the last stage and needs no privileges when
/// the model directory is owned by the invoking user.
public enum UnfairPlaySetup {
    public static let captureSchema = "unfairplay-native-enrollment-capture-v1"
    public static let defaultFairPlaydPath =
        "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd"
    public static let systemStatePath = "/private/var/db/fpsd/SC Info"
    public static let sharedStatePath = "/Users/Shared/SC Info"
    public static let adiPath = "/private/var/db/fpsd/adi"

    // MARK: - Validation

    public static func validate(options: UnfairPlaySetupOptions) throws -> UnfairPlaySetupValidation {
        let app = try normalizeInstalledApp(options.appURL)
        let info = try readAppInfo(app)
        let sinf = try selectAppSINF(app)
        let selector = sinf.selector

        let sinfEntries = try listIPASINFs(options.ipaURL)
        let roots = sinfEntries
            .filter { $0.selector == selector }
            .map { root(of: $0.member) }
        guard let ipaRoot = roots.min(by: { $0.count < $1.count }) else {
            throw UnfairPlaySetupError.ipaHasNoMatchingSINF(selector: selector)
        }
        let targetMember = "\(ipaRoot)/SC_Info/\(info.executable).sinf"
        guard sinfEntries.contains(where: { $0.member == targetMember }) else {
            throw UnfairPlaySetupError.ipaMissingMember(targetMember)
        }
        let targetSelector = try readIPASINFSelector(options.ipaURL, member: targetMember)
        guard targetSelector == selector else {
            throw UnfairPlaySetupError.ipaHasNoMatchingSINF(selector: selector)
        }

        var warnings: [String] = []
        let store = UnfairPlayModelStore(directoryURL: options.modelDirectoryURL)
        let hasModel = store.selectors().contains(selector)
        if !hasModel {
            warnings.append("本机还没有 selector \(selector) 的模型")
        }
        let support = resolveFairPlaySupport(
            hash: try fileSHA256(URL(fileURLWithPath: defaultFairPlaydPath)).sha256,
            build: (try? systemVersion("-buildVersion")) ?? ""
        )
        if support.status != "supported" {
            warnings.append("fairplayd 版本 \(support.build) 的状态为 \(support.status)")
        }

        return UnfairPlaySetupValidation(
            appDirectory: app,
            bundleIdentifier: info.identifier,
            executable: info.executable,
            selector: selector,
            installedSINF: sinf.url,
            ipaRoot: ipaRoot,
            ipaTargetSINFMember: targetMember,
            hasModel: hasModel,
            warnings: warnings
        )
    }

    // MARK: - Capture

    public static func capture(
        options: UnfairPlaySetupOptions,
        captureDirectory: URL,
        owner: UnfairPlaySetupOwner? = nil
    ) throws -> UnfairPlaySetupCaptureResult {
        let validation = try validate(options: options)
        let app = validation.appDirectory
        let fileManager = FileManager.default

        let capture = captureDirectory
        if fileManager.fileExists(atPath: capture.path) {
            throw UnfairPlaySetupError.captureDirectoryExists(capture.path)
        }
        do {
            try fileManager.createDirectory(
                at: capture,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw UnfairPlaySetupError.fileOperation("创建采集目录失败：\(capture.path)：\(error.localizedDescription)")
        }

        let isRoot = geteuid() == 0
        var files: [UnfairPlayEnrollmentManifest.File] = []
        do {
            let fairplayd = URL(fileURLWithPath: defaultFairPlaydPath)
            guard fileManager.isReadableFile(atPath: fairplayd.path) else {
                throw UnfairPlaySetupError.fairplaydUnavailable(fairplayd.path)
            }
            let fairplaydRelative = "fairplayd/fairplayd.arm64e"
            let fairplaydResult = try thinFairPlayd(
                source: fairplayd,
                destination: capture.appendingPathComponent(fairplaydRelative)
            )
            let fairplaydFile = UnfairPlayEnrollmentManifest.File(
                path: fairplaydRelative,
                bytes: fairplaydResult.bytes,
                sha256: fairplaydResult.sha256,
                mode: "0600"
            )
            files.append(fairplaydFile)

            let mac = try hardwareMAC(interface: options.hardwareInterface)
            let macRelative = "hardware/iomac.bin"
            let macFile = try writePrivate(mac, to: capture.appendingPathComponent(macRelative), relative: macRelative)
            files.append(macFile)

            let infoData = try Data(contentsOf: app.appendingPathComponent("Info.plist"))
            let infoRelative = "app/Info.plist"
            files.append(try writePrivate(infoData, to: capture.appendingPathComponent(infoRelative), relative: infoRelative))

            let executableRelative = "app/executable"
            files.append(try copyPrivate(
                app.appendingPathComponent(validation.executable),
                to: capture.appendingPathComponent(executableRelative),
                relative: executableRelative
            ))

            let licenseFiles = try copyDirectoryFiles(
                app.appendingPathComponent("SC_Info"),
                to: capture.appendingPathComponent("app/SC_Info"),
                captureRoot: capture
            )
            files.append(contentsOf: licenseFiles)

            var stateFiles: [UnfairPlayEnrollmentManifest.File] = []
            for (source, relativeRoot) in [
                (systemStatePath, "state/fpsd-sc-info"),
                (sharedStatePath, "state/shared-sc-info"),
                (adiPath, "state/adi")
            ] {
                let captured = try copyDirectoryFiles(
                    URL(fileURLWithPath: source),
                    to: capture.appendingPathComponent(relativeRoot),
                    captureRoot: capture
                )
                stateFiles.append(contentsOf: captured)
            }
            files.append(contentsOf: stateFiles)

            let ipaRelative = "ipa/App.ipa"
            files.append(try copyPrivate(
                options.ipaURL,
                to: capture.appendingPathComponent(ipaRelative),
                relative: ipaRelative
            ))

            let targetMember = validation.ipaTargetSINFMember
            let targetSINF = try readIPAMember(options.ipaURL, member: targetMember)
            let targetSelector = try readIPASINFSelector(options.ipaURL, member: targetMember)
            guard targetSelector == validation.selector else {
                throw UnfairPlaySetupError.ipaHasNoMatchingSINF(selector: validation.selector)
            }
            let targetRelative = "ipa/App.sinf"
            files.append(try writePrivate(targetSINF, to: capture.appendingPathComponent(targetRelative), relative: targetRelative))

            guard !stateFiles.isEmpty else {
                throw UnfairPlaySetupError.stateDirectoryUnreadable(systemStatePath)
            }
            if !isRoot {
                throw UnfairPlaySetupError.stateDirectoryUnreadable(systemStatePath)
            }

            let manifest = UnfairPlayEnrollmentManifest(
                schema: captureSchema,
                createdAt: iso8601Now(),
                productVersion: (try? systemVersion("-productVersion")) ?? "",
                buildVersion: (try? systemVersion("-buildVersion")) ?? "",
                fairplayd: fairplaydFile,
                enrollmentSupport: resolveFairPlaySupport(
                    hash: fairplaydFile.sha256,
                    build: (try? systemVersion("-buildVersion")) ?? ""
                ),
                hardwareMAC: macFile,
                app: .init(
                    bundleIdentifier: validation.bundleIdentifier,
                    executable: validation.executable,
                    executablePath: app.appendingPathComponent(validation.executable).path,
                    selector: UnfairPlayEnrollmentManifest.Selector(identifier: validation.selector)
                        ?? .init(user: 0, key: 0),
                    selectorID: validation.selector,
                    sinfPath: "app/SC_Info/\(validation.installedSINF.lastPathComponent)",
                    targetSINFPath: targetRelative,
                    ipaMemberRoot: validation.ipaRoot
                ),
                ipa: files.first(where: { $0.path == ipaRelative }),
                files: files,
                warnings: validation.warnings + (isRoot ? [] : [
                    "capture must run as root to read /private/var/db/fpsd"
                ])
            )
            let manifestURL = capture.appendingPathComponent("manifest.json")
            let data = try JSONEncoder.pretty.encode(manifest)
            try data.write(to: manifestURL, options: .withoutOverwriting)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)

            if let owner {
                try restoreOwnership(capture, owner: owner)
            }
            return UnfairPlaySetupCaptureResult(
                directory: capture,
                manifestURL: manifestURL,
                validation: validation
            )
        } catch {
            try? fileManager.removeItem(at: capture)
            throw error
        }
    }

    // MARK: - Install

    /// Port of `installEnrollmentModel`: `<selector>-<sha256>.bin`, directory
    /// 0700, file 0600, and an identical existing file is reused.
    @discardableResult
    public static func installModel(
        directory: URL,
        selector: String,
        model: Data,
        owner: UnfairPlaySetupOwner? = nil
    ) throws -> (url: URL, sha256: String, reused: Bool) {
        guard isValidSelector(selector) else {
            throw UnfairPlaySetupError.fileOperation("selector 格式无效：\(selector)")
        }
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        } catch {
            throw UnfairPlaySetupError.fileOperation("创建模型目录失败：\(directory.path)：\(error.localizedDescription)")
        }
        let digest = SHA256.hex(model)
        let name = selector.replacingOccurrences(of: ":", with: "-") + "-" + digest + ".bin"
        let url = directory.appendingPathComponent(name)
        var reused = false
        if fileManager.fileExists(atPath: url.path) {
            let existing = try Data(contentsOf: url)
            reused = existing == model
            guard reused else {
                throw UnfairPlaySetupError.fileOperation("模型哈希冲突：\(url.path)")
            }
        } else {
            do {
                try model.write(to: url, options: .withoutOverwriting)
                try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            } catch {
                throw UnfairPlaySetupError.fileOperation("写入模型失败：\(url.path)：\(error.localizedDescription)")
            }
        }
        if let owner, geteuid() == 0 {
            _ = chown(directory.path, owner.uid, owner.gid)
            _ = chown(url.path, owner.uid, owner.gid)
        }
        return (url, digest, reused)
    }

    // MARK: - Pipeline

    /// Installs the enrollment model generated from an existing capture.
    @discardableResult
    public static func recoverAndInstall(
        options: UnfairPlaySetupOptions,
        capture: UnfairPlaySetupCaptureResult,
        owner: UnfairPlaySetupOwner? = nil
    ) throws -> (recovery: UnfairPlaySetupRecovery, url: URL, sha256: String, reused: Bool) {
        let recovery = try recover(capture: capture, options: options)
        let installed = try installModel(
            directory: options.modelDirectoryURL,
            selector: capture.validation.selector,
            model: recovery.model,
            owner: owner
        )
        return (recovery, installed.url, installed.sha256, installed.reused)
    }

    /// Runs validation, capture, recovery and install in one call. The caller
    /// still owns the decryption gate, which needs a user-context CLI run.
    public static func run(
        options: UnfairPlaySetupOptions,
        captureDirectory: URL,
        owner: UnfairPlaySetupOwner? = nil
    ) throws -> UnfairPlaySetupCaptureResult {
        let capture = try capture(options: options, captureDirectory: captureDirectory, owner: owner)
        _ = try recoverAndInstall(options: options, capture: capture, owner: owner)
        return capture
    }
}

// MARK: - App inspection

extension UnfairPlaySetup {
    struct AppInfo {
        let identifier: String
        let executable: String
    }

    struct AppSINF {
        let url: URL
        let selector: String
    }

    static func normalizeInstalledApp(_ url: URL) throws -> URL {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory),
              isDirectory.boolValue,
              url.pathExtension.lowercased() == "app" else {
            throw UnfairPlaySetupError.notAnApplication(url.path)
        }
        let wrapper = url.appendingPathComponent("Wrapper")
        var wrapperIsDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: wrapper.path, isDirectory: &wrapperIsDirectory),
              wrapperIsDirectory.boolValue else {
            return url
        }
        let entries = (try? fileManager.contentsOfDirectory(
            at: wrapper,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        )) ?? []
        for entry in entries where entry.pathExtension.lowercased() == "app" {
            return entry
        }
        throw UnfairPlaySetupError.notAnApplication(url.path)
    }

    static func readAppInfo(_ app: URL) throws -> AppInfo {
        let url = app.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dictionary = plist as? [String: Any],
              let identifier = dictionary["CFBundleIdentifier"] as? String,
              let executable = dictionary["CFBundleExecutable"] as? String,
              !identifier.isEmpty,
              !executable.isEmpty else {
            throw UnfairPlaySetupError.infoPlistUnreadable(url.path)
        }
        return AppInfo(identifier: identifier, executable: executable)
    }

    static func selectAppSINF(_ app: URL) throws -> AppSINF {
        let directory = app.appendingPathComponent("SC_Info")
        let entries = (try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        )) ?? []
        let sinfs = entries.filter { $0.pathExtension.lowercased() == "sinf" }
        guard sinfs.count == 1 else {
            throw UnfairPlaySetupError.appSINFCount(sinfs.count)
        }
        let url = sinfs[0]
        let data = try Data(contentsOf: url)
        guard let selector = sinfSelector(data), !selector.isEmpty else {
            throw UnfairPlaySetupError.sinfSelectorUnreadable(url.path)
        }
        return AppSINF(url: url, selector: selector)
    }

    static func sinfSelector(_ data: Data) -> String? {
        try? withContext { context in
            var selector = [CChar](repeating: 0, count: 18)
            let status: Int32 = data.withUnsafeBytes { raw in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                    return 0
                }
                return up_setup_sinf_selector(context, base, data.count, &selector)
            }
            guard status == 1 else {
                return nil
            }
            return String(cString: selector)
        }
    }
}

// MARK: - IPA inspection

extension UnfairPlaySetup {
    struct IPASINF {
        let member: String
        let selector: String
    }

    static func root(of member: String) -> String {
        guard let range = member.range(of: "/SC_Info/", options: .backwards) else {
            return ""
        }
        return String(member[member.startIndex..<range.lowerBound])
    }

    static func listIPASINFs(_ ipa: URL) throws -> [IPASINF] {
        try withContext { context in
            var entries: UnsafeMutablePointer<up_setup_sinf>?
            var count = 0
            guard up_setup_list_ipa_sinfs(context, ipa.path, &entries, &count) == 1,
                  let entries else {
                throw UnfairPlaySetupError.ipaMissingMember(errorText(context))
            }
            defer { up_setup_free_ipa_sinfs(entries, count) }
            var result: [IPASINF] = []
            for index in 0..<count {
                let item = entries[index]
                guard let member = item.member else {
                    continue
                }
                let selector = withUnsafeBytes(of: item.selector) { raw in
                    String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
                }
                result.append(IPASINF(member: String(cString: member), selector: selector))
            }
            return result
        }
    }

    static func readIPAMember(_ ipa: URL, member: String) throws -> Data {
        try withContext { context in
            var bytes: UnsafeMutablePointer<UInt8>?
            var length = 0
            guard up_setup_read_ipa_member(context, ipa.path, member, &bytes, &length) == 1,
                  let bytes else {
                throw UnfairPlaySetupError.ipaMissingMember(member)
            }
            defer { up_setup_free_bytes(bytes) }
            return Data(bytes: bytes, count: length)
        }
    }

    static func readIPASINFSelector(_ ipa: URL, member: String) throws -> String {
        let data = try readIPAMember(ipa, member: member)
        guard let selector = sinfSelector(data), !selector.isEmpty else {
            throw UnfairPlaySetupError.sinfSelectorUnreadable(member)
        }
        return selector
    }
}

// MARK: - Files

extension UnfairPlaySetup {
    static func withContext<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        guard let context = up_context_create(nil) else {
            throw UnfairPlaySetupError.fileOperation("UnfairPlay 上下文初始化失败")
        }
        defer { up_context_free(context) }
        return try body(context)
    }

    static func errorText(_ context: OpaquePointer) -> String {
        let text = String(cString: up_last_error(context)).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? "UnfairPlay 原生调用失败" : text
    }

    struct FileDigest {
        let sha256: String
        let bytes: Int64
    }

    static func fileSHA256(_ url: URL) throws -> FileDigest {
        try withContext { context in
            var sha = [CChar](repeating: 0, count: 65)
            var bytes: Int64 = 0
            guard up_setup_file_sha256(context, url.path, &sha, &bytes) == 1 else {
                throw UnfairPlaySetupError.fileOperation(errorText(context))
            }
            return FileDigest(sha256: String(cString: sha), bytes: bytes)
        }
    }

    static func thinFairPlayd(source: URL, destination: URL) throws -> FileDigest {
        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: destination.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return try withContext { context in
            var sha = [CChar](repeating: 0, count: 65)
            var bytes: Int64 = 0
            guard up_setup_thin_fairplayd(context, source.path, destination.path, &sha, &bytes) == 1 else {
                throw UnfairPlaySetupError.fairplaydUnavailable(errorText(context))
            }
            return FileDigest(sha256: String(cString: sha), bytes: bytes)
        }
    }

    static func writePrivate(_ data: Data, to url: URL, relative: String) throws -> UnfairPlayEnrollmentManifest.File {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try data.write(to: url, options: .withoutOverwriting)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw UnfairPlaySetupError.fileOperation("写入 \(url.path) 失败：\(error.localizedDescription)")
        }
        return .init(path: relative, bytes: Int64(data.count), sha256: SHA256.hex(data), mode: "0600")
    }

    static func copyPrivate(_ source: URL, to url: URL, relative: String) throws -> UnfairPlayEnrollmentManifest.File {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fileManager.copyItem(at: source, to: url)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw UnfairPlaySetupError.fileOperation("复制 \(source.path) 失败：\(error.localizedDescription)")
        }
        let digest = try fileSHA256(url)
        return .init(path: relative, bytes: digest.bytes, sha256: digest.sha256, mode: "0600")
    }

    static func copyDirectoryFiles(_ source: URL, to destination: URL, captureRoot: URL) throws -> [UnfairPlayEnrollmentManifest.File] {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: source.path, isDirectory: &isDirectory) else {
            return []
        }
        guard isDirectory.boolValue else {
            throw UnfairPlaySetupError.fileOperation("采集状态路径不是目录：\(source.path)")
        }
        guard let enumerator = fileManager.enumerator(
            at: source,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: []
        ) else {
            return []
        }
        var result: [UnfairPlayEnrollmentManifest.File] = []
        for case let entry as URL in enumerator {
            let values = try entry.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true {
                throw UnfairPlaySetupError.fileOperation("采集状态包含符号链接：\(entry.path)")
            }
            if values.isDirectory == true {
                continue
            }
            let relativeToSource = entry.path.dropFirst(source.path.count + 1)
            let target = destination.appendingPathComponent(String(relativeToSource))
            let relative = target.path.dropFirst(captureRoot.path.count + 1)
            result.append(try copyPrivate(entry, to: target, relative: String(relative)))
        }
        return result
    }

    static func restoreOwnership(_ root: URL, owner: UnfairPlaySetupOwner) throws {
        _ = chown(root.path, owner.uid, owner.gid)
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isSymbolicLinkKey],
            options: []
        ) else {
            return
        }
        for case let entry as URL in enumerator {
            if try entry.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true {
                continue
            }
            _ = chown(entry.path, owner.uid, owner.gid)
        }
    }

    static func isValidSelector(_ selector: String) -> Bool {
        let parts = selector.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return false }
        return parts.allSatisfy { $0.count == 8 && $0.allSatisfy(\.isHexDigit) }
    }

    static func iso8601Now() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date())
    }

    static func systemVersion(_ flag: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sw_vers")
        process.arguments = [flag]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func hardwareMAC(interface: String) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/ioreg")
        process.arguments = ["-a", "-l", "-p", "IOService"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let root = plist as? [String: Any] else {
            throw UnfairPlaySetupError.fileOperation("无法解析 IORegistry")
        }
        func visit(_ node: [String: Any], _ parent: [String: Any]) -> Data? {
            if node["BSD Name"] as? String == interface, node["IOBuiltin"] as? Bool == true,
               let mac = parent["IOMACAddress"] as? Data, mac.count == 6 {
                return mac
            }
            for child in (node["IORegistryEntryChildren"] as? [Any]) ?? [] {
                if let childMap = child as? [String: Any], let found = visit(childMap, node) {
                    return found
                }
            }
            return nil
        }
        guard let mac = visit(root, [:]) else {
            throw UnfairPlaySetupError.fileOperation("内置接口 \(interface) 没有 6 字节 IOMACAddress")
        }
        return mac
    }
}

// MARK: - FairPlay build support

extension UnfairPlaySetup {
    /// Builds whose `fairplayd` hash is validated by the upstream project.
    static func resolveFairPlaySupport(hash: String, build: String) -> UnfairPlayFairPlaySupport {
        let normalized = hash.lowercased()
        switch normalized {
        case "93b8db9c7140cedbd04a3bbbce297b68ba9060e8a4f39ef52a1017964f3da4c5":
            return .init(
                profile: "portable-current-sinf", build: "25G83",
                status: "portable-semantic-verified",
                validationBasis: "canonical-contract-with-portable-semantic-evaluator",
                recovery: true, decrypt: true,
                evaluatorProfile: "macos26a428",
                evaluatorSHA256: "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
            )
        case "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784":
            return .init(
                profile: "macos26a428", build: "26A428",
                status: "supported",
                validationBasis: "exact-binary-profile-and-canonical-contract",
                recovery: true, decrypt: true,
                evaluatorProfile: "macos26a428",
                evaluatorSHA256: "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
            )
        case "f68e4407e90af5466d2766e1b1c4637260d08cb0518f991e1797ac6c4964439d":
            return .init(
                profile: "portable-current-sinf", build: "26B118",
                status: "portable-semantic-verified",
                validationBasis: "canonical-contract-with-portable-semantic-evaluator",
                recovery: true, decrypt: true,
                evaluatorProfile: "macos26a428",
                evaluatorSHA256: "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
            )
        default:
            let valid = normalized.count == 64 && normalized.allSatisfy(\.isHexDigit)
            return .init(
                profile: "portable-current-sinf", build: build,
                status: valid ? "portable-semantic-validation-required" : "invalid-fairplayd-identity",
                validationBasis: valid
                    ? "portable-semantic-evaluator-plus-complete-ipa-promotion-gate"
                    : nil,
                recovery: valid, decrypt: false,
                evaluatorProfile: "macos26a428",
                evaluatorSHA256: "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784"
            )
        }
    }
}

// MARK: - SHA-256

enum SHA256 {
    static func hex(_ data: Data) -> String {
        CryptoKit.SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
