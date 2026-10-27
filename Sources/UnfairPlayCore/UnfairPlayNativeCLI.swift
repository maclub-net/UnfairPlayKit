import CUnfairPlay
import Foundation

/// 进程内 UnfairPlay 封装：直接调用 C 核心，不启动子进程。
///
/// 与 `UnfairPlayCLI` 共享同一套方法签名、JSON 契约与错误映射，调用方可在两者之间切换；
/// 区别只在于 `decrypt` 的模型目录解析：这里自行复刻上游 CLI 的默认目录回落。
public actor UnfairPlayNativeCLI: UnfairPlayClient {
    public init() {}

    /// 读取核心版本号
    public func version() async -> String? {
        let text = String(cString: up_version()).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    /// 预检。显式传入的模型目录必须存在；传 `nil` 表示本次不加载模型（与 CLI 省略 `--model` 等价）。
    public func doctor(ipa: URL, modelDirectory: URL?) async throws -> UnfairPlayDoctorReport {
        try Self.requireExistingDirectory(modelDirectory)
        let context = try Self.makeContext(modelDirectory)
        defer { up_context_free(context) }

        var json: UnsafeMutablePointer<CChar>?
        let status = up_doctor(context, ipa.path, &json)
        defer {
            if let json {
                up_string_free(json)
            }
        }
        guard status == 1, let json else {
            throw UnfairPlayError.processFailure(Self.errorText(context, status: status))
        }
        guard let data = String(cString: json).data(using: .utf8),
              let report = try? JSONDecoder().decode(UnfairPlayDoctorReport.self, from: data) else {
            throw UnfairPlayError.invalidReport("doctor 报告无法解析")
        }
        return report
    }

    /// 解密。模型目录为空时按上游 CLI 规则回落到默认目录，并保留同一失败文案。
    public func decrypt(
        input: URL,
        output: URL,
        report: URL,
        modelDirectory: URL?
    ) async throws -> UnfairPlayDecryptResult {
        guard input.pathExtension.lowercased() == "ipa" else {
            throw UnfairPlayError.processFailure("input must be an IPA")
        }
        let resolved = try Self.resolvedModelDirectory(modelDirectory)
        let context = try Self.makeContext(resolved)
        defer { up_context_free(context) }

        var json: UnsafeMutablePointer<CChar>?
        let status = up_decrypt(context, input.path, output.path, report.path, 0, &json)
        let stdout = json.map { String(cString: $0) } ?? ""
        if let json {
            up_string_free(json)
        }

        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: output.path), fileManager.fileExists(atPath: report.path) else {
            throw UnfairPlayError.processFailure(Self.errorText(context, status: status))
        }
        guard let data = try? Data(contentsOf: report),
              let decoded = try? JSONDecoder().decode(UnfairPlayDecryptReport.self, from: data) else {
            throw UnfairPlayError.invalidReport("decrypt 报告无法解析")
        }
        return UnfairPlayDecryptResult(
            outputURL: output,
            outputSHA256: Self.readOutputSHA256(from: stdout),
            report: decoded
        )
    }

    // MARK: - 内部

    private static func makeContext(_ modelDirectory: URL?) throws -> OpaquePointer {
        let created: OpaquePointer?
        if let path = modelDirectory?.path {
            created = path.withCString { up_context_create($0) }
        } else {
            created = up_context_create(nil)
        }
        guard let created else {
            throw UnfairPlayError.processFailure("UnfairPlay 进程内上下文初始化失败")
        }
        return created
    }

    private static func errorText(_ context: OpaquePointer, status: Int32) -> String {
        let text = String(cString: up_last_error(context)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            return "UnfairPlay 进程内调用失败（状态 \(status)）"
        }
        return text
    }

    private static func isExistingDirectory(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    private static func requireExistingDirectory(_ url: URL?) throws {
        if let url, !isExistingDirectory(url) {
            throw UnfairPlayError.modelDirectoryMissing(url.path)
        }
    }

    /// 复刻 `selectedModelPath`：显式目录原样使用，否则读取 `UNFAIRPLAY_MODEL_DIR`
    /// 或默认目录，并在默认目录缺失时报出与 CLI 相同的结论。
    private static func resolvedModelDirectory(_ explicit: URL?) throws -> URL {
        if let explicit {
            try requireExistingDirectory(explicit)
            return explicit
        }
        let configured = ProcessInfo.processInfo.environment["UNFAIRPLAY_MODEL_DIR"] ?? ""
        let path = configured.isEmpty
            ? UnfairPlaySettings.defaultDirectoryPath()
            : (configured as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: path, isDirectory: true)
        guard isExistingDirectory(url) else {
            throw UnfairPlayError.processFailure("no saved enrollment models; run unfairplay setup or pass --model")
        }
        return url
    }

    /// 从 decrypt 结果 JSON 中只取产物哈希；其余字段（含逻辑密钥指纹）一律丢弃
    private static func readOutputSHA256(from stdout: String) -> String? {
        guard let data = stdout.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return object["OutputSHA256"] as? String
    }
}
