import Foundation

/// UnfairPlay 引擎的统一入口。
///
/// 进程内（`UnfairPlayNativeCLI`）与子进程（`UnfairPlayCLI`）实现共享同一套
/// `doctor` / `decrypt` JSON 契约与错误映射，调用方只依赖此协议即可切换实现。
public protocol UnfairPlayClient: Sendable {
    /// 读取核心版本号
    func version() async -> String?

    /// 预检。显式传入的模型目录必须存在；传 `nil` 表示本次不加载模型。
    func doctor(ipa: URL, modelDirectory: URL?) async throws -> UnfairPlayDoctorReport

    /// 解密，并在 `report` 处写入报告。
    func decrypt(
        input: URL,
        output: URL,
        report: URL,
        modelDirectory: URL?
    ) async throws -> UnfairPlayDecryptResult
}
