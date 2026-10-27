import Foundation

/// `doctor` 结果的判定层。
///
/// 关键点：CLI 在存在 errors 时退出码为 1 但 JSON 完整，因此这里**只**依据
/// `decrypt_ready` 与错误文案判定，不依赖退出码。
public enum UnfairPlayProbe {
    public static func run(
        cli: UnfairPlayCLI,
        ipa: URL,
        modelDirectory: URL?
    ) async throws -> UnfairPlayProbeResult {
        let report = try await cli.doctor(ipa: ipa, modelDirectory: modelDirectory)
        return summarize(report)
    }

    public static func summarize(_ report: UnfairPlayDoctorReport) -> UnfairPlayProbeResult {
        let noPayload = report.errors.contains {
            $0.localizedCaseInsensitiveContains("no supported encrypted Mach-O images")
        }
        let sinfSelectors = Array(Set(report.sinf.map(\.selectorId))).sorted()
        let availableSelectors = Array(Set(report.models.compactMap(\.selectorId))).sorted()

        // `compatible_models_by_sinf` 的键是 SINF 路径，值是模型路径；全部覆盖时同样视为可解密
        let compatibilityCovered = !report.sinf.isEmpty && report.sinf.allSatisfy {
            report.compatibleModelsBySINF[$0.path] != nil
        }

        return UnfairPlayProbeResult(
            report: report,
            isReady: report.decryptReady || compatibilityCovered,
            hasEncryptedPayload: !noPayload,
            sinfSelectors: sinfSelectors,
            availableSelectors: availableSelectors
        )
    }
}

public extension UnfairPlayProbeResult {
    /// 把预检结论转换成可操作的错误；优先暴露权限/目录类问题，其次才报「无匹配模型」
    func validateForDecryption() throws {
        if let inventoryError = report.errors.first(where: { $0.hasPrefix("ipa inventory:") }),
           hasEncryptedPayload {
            throw UnfairPlayError.processFailure(inventoryError)
        }
        guard hasEncryptedPayload else {
            throw UnfairPlayError.noEncryptedPayload
        }
        guard !isReady else { return }

        // 模型目录权限/符号链接/数量超限等问题会掩盖「无匹配模型」，先报真正的原因
        if let actionable = actionableModelError {
            throw UnfairPlayError.processFailure(actionable)
        }
        throw UnfairPlayError.modelNotProvided(selectors: sinfSelectors, available: availableSelectors)
    }

    /// 除「没有匹配模型」之外的模型侧错误（权限、符号链接、数量上限、目录缺失）
    var actionableModelError: String? {
        report.errors.first { error in
            !error.localizedCaseInsensitiveContains("no enrollment model matches SINF")
                && !error.hasPrefix("ipa inventory:")
        }
    }
}
