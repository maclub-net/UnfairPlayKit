import Foundation

public struct UnfairPlayProcessResult: Sendable, Equatable {
    public var stdout: String
    public var stderr: String
    public var status: Int32

    public init(stdout: String, stderr: String, status: Int32) {
        self.stdout = stdout
        self.stderr = stderr
        self.status = status
    }
}

/// 进程执行注入点。
///
/// APParse 会注入自己的 `CommandExecutor`，让任务取消能直接终止 UnfairPlay 子进程；
/// 默认实现用 Foundation `Process`，便于在测试或独立工具中直接使用。
public struct UnfairPlayProcessRunner: Sendable {
    public typealias Handler = @Sendable (_ executable: String, _ arguments: [String], _ workingDirectory: URL?) async -> UnfairPlayProcessResult

    private let handler: Handler

    public init(_ handler: @escaping Handler) {
        self.handler = handler
    }

    public func run(executable: String, arguments: [String], workingDirectory: URL?) async -> UnfairPlayProcessResult {
        await handler(executable, arguments, workingDirectory)
    }

    public static let process = UnfairPlayProcessRunner { executable, arguments, workingDirectory in
        await UnfairPlayCLI.runProcess(executable: executable, arguments: arguments, workingDirectory: workingDirectory)
    }
}

/// 进程执行的 UnfairPlay CLI 封装，沿用 `UnfairPlayCLI` 作为兼容名。
public typealias UnfairPlayProcessCLI = UnfairPlayCLI

/// UnfairPlay CLI 的类型安全封装：只暴露 `doctor` / `decrypt` / `--version`。
///
/// 约定（见施工方案 §6.3）：
/// - `doctor` 有 errors 时退出码仍为 1，但 stdout 的 JSON 完整，因此**不看退出码**。
/// - `decrypt` 的 stdout 含逻辑密钥指纹，绝不写入日志，只读落盘报告。
public actor UnfairPlayCLI {
    public let binaryPath: String
    private let runner: UnfairPlayProcessRunner

    public init(binaryPath: String, runner: UnfairPlayProcessRunner = .process) {
        self.binaryPath = binaryPath
        self.runner = runner
    }

    /// 读取 `unfairplay --version` 输出中的版本号
    public func version() async -> String? {
        let result = await runner.run(executable: binaryPath, arguments: ["--version"], workingDirectory: nil)
        let text = (result.stdout + "\n" + result.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
        guard result.status == 0, !text.isEmpty else {
            return nil
        }
        return text.split(whereSeparator: \.isNewline).last.map(String.init)
    }

    public func doctor(ipa: URL, modelDirectory: URL?) async throws -> UnfairPlayDoctorReport {
        var arguments = ["doctor", "--ipa", ipa.path]
        if let modelDirectory {
            try Self.appendModelDirectory(modelDirectory, to: &arguments)
        }
        let result = await runner.run(executable: binaryPath, arguments: arguments, workingDirectory: nil)
        guard let data = result.stdout.data(using: .utf8),
              let report = try? JSONDecoder().decode(UnfairPlayDoctorReport.self, from: data) else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw UnfairPlayError.processFailure(
                detail.isEmpty ? "unfairplay doctor 未返回可解析的 JSON（退出码 \(result.status)）" : detail
            )
        }
        return report
    }

    public func decrypt(
        input: URL,
        output: URL,
        report: URL,
        modelDirectory: URL?
    ) async throws -> UnfairPlayDecryptResult {
        var arguments = ["decrypt", "--input", input.path, "--output", output.path, "--report", report.path]
        if let modelDirectory {
            try Self.appendModelDirectory(modelDirectory, to: &arguments)
        }

        let result = await runner.run(executable: binaryPath, arguments: arguments, workingDirectory: nil)

        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: output.path), fileManager.fileExists(atPath: report.path) else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw UnfairPlayError.processFailure(
                detail.isEmpty ? "unfairplay decrypt 失败（退出码 \(result.status)）" : detail
            )
        }
        guard let data = try? Data(contentsOf: report),
              let decoded = try? JSONDecoder().decode(UnfairPlayDecryptReport.self, from: data) else {
            throw UnfairPlayError.invalidReport("decrypt 报告无法解析")
        }

        let outputSHA256 = Self.readOutputSHA256(from: result.stdout)
        return UnfairPlayDecryptResult(outputURL: output, outputSHA256: outputSHA256, report: decoded)
    }

    // MARK: - 内部

    private static func isExistingDirectory(_ url: URL) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) && isDirectory.boolValue
    }

    /// 显式配置的模型目录必须真实存在，否则 CLI 会静默回落到默认目录，导致「在错误的目录上判定可解密」
    private static func appendModelDirectory(_ url: URL, to arguments: inout [String]) throws {
        guard isExistingDirectory(url) else {
            throw UnfairPlayError.modelDirectoryMissing(url.path)
        }
        arguments.append(contentsOf: ["--model", url.path])
    }

    /// 从 decrypt 的 stdout JSON 中只取产物哈希；其余字段（含逻辑密钥指纹）一律丢弃
    private static func readOutputSHA256(from stdout: String) -> String? {
        guard let data = stdout.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return object["OutputSHA256"] as? String
    }

    private final class OutputBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private var stdout = ""
        private var stderr = ""

        func append(_ data: Data, isStdErr: Bool) {
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            lock.lock()
            if isStdErr {
                stderr += text
            } else {
                stdout += text
            }
            lock.unlock()
        }

        func result(status: Int32) -> UnfairPlayProcessResult {
            lock.lock()
            defer { lock.unlock() }
            return UnfairPlayProcessResult(stdout: stdout, stderr: stderr, status: status)
        }
    }

    static func runProcess(
        executable: String,
        arguments: [String],
        workingDirectory: URL?
    ) async -> UnfairPlayProcessResult {
        await withCheckedContinuation { continuation in
            let process = Process()
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            let buffer = OutputBuffer()

            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.currentDirectoryURL = workingDirectory
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
                buffer.append(handle.availableData, isStdErr: false)
            }
            stderrPipe.fileHandleForReading.readabilityHandler = { handle in
                buffer.append(handle.availableData, isStdErr: true)
            }

            process.terminationHandler = { finished in
                stdoutPipe.fileHandleForReading.readabilityHandler = nil
                stderrPipe.fileHandleForReading.readabilityHandler = nil
                buffer.append(stdoutPipe.fileHandleForReading.readDataToEndOfFile(), isStdErr: false)
                buffer.append(stderrPipe.fileHandleForReading.readDataToEndOfFile(), isStdErr: true)
                continuation.resume(returning: buffer.result(status: finished.terminationStatus))
            }

            do {
                try process.run()
            } catch {
                stdoutPipe.fileHandleForReading.readabilityHandler = nil
                stderrPipe.fileHandleForReading.readabilityHandler = nil
                continuation.resume(
                    returning: UnfairPlayProcessResult(stdout: "", stderr: error.localizedDescription, status: 127)
                )
            }
        }
    }
}

extension UnfairPlayCLI: UnfairPlayClient {}
