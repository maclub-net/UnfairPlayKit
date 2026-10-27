import Foundation
import Testing
@testable import UnfairPlayCore

@Suite("进程内 CLI 封装")
struct UnfairPlayNativeCLITests {
    @Test("版本号非空")
    func reportsVersion() async {
        let version = await UnfairPlayNativeCLI().version()
        #expect(version?.isEmpty == false)
    }

    @Test("缺失 IPA 仍返回可解析的预检报告")
    func reportsMissingIPA() async throws {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-missing-\(UUID().uuidString).ipa")
        let report = try await UnfairPlayNativeCLI().doctor(ipa: missing, modelDirectory: nil)
        #expect(report.schema == "unfairplay-doctor-v1")
        #expect(report.decryptReady == false)
        #expect(report.errors.isEmpty == false)
    }

    @Test("显式模型目录不存在时立即失败")
    func rejectsMissingModelDirectory() async {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-missing-\(UUID().uuidString)", isDirectory: true)
        do {
            _ = try await UnfairPlayNativeCLI().doctor(
                ipa: URL(fileURLWithPath: "/tmp/unfairplay-missing.ipa"),
                modelDirectory: directory
            )
            Issue.record("缺失模型目录应失败")
        } catch let error as UnfairPlayError {
            #expect(error == .modelDirectoryMissing(directory.path))
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test("非 IPA 输入按上游文案失败")
    func rejectsNonIPAInput() async {
        do {
            _ = try await UnfairPlayNativeCLI().decrypt(
                input: URL(fileURLWithPath: "/tmp/unfairplay-input.zip"),
                output: URL(fileURLWithPath: "/tmp/unfairplay-output.ipa"),
                report: URL(fileURLWithPath: "/tmp/unfairplay-report.json"),
                modelDirectory: nil
            )
            Issue.record("非 IPA 应失败")
        } catch let error as UnfairPlayError {
            #expect(error == .processFailure("input must be an IPA"))
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }
}
