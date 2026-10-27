import Foundation
import Testing
@testable import UnfairPlayCore

@Suite("UnfairPlay 模型目录")
struct UnfairPlayModelStoreTests {
    @Test("解析规范文件名")
    func parsesCanonicalFileName() {
        let parsed = UnfairPlayModelStore.parseFileName("e03fe290-00000011-\(String(repeating: "a", count: 64)).bin")
        #expect(parsed.selector == "e03fe290:00000011")
        #expect(parsed.sha256?.count == 64)
    }

    @Test("非规范文件名不误判")
    func rejectsMalformedFileName() {
        #expect(UnfairPlayModelStore.parseFileName("model.bin").selector == nil)
        #expect(UnfairPlayModelStore.parseFileName("e03fe290-0000001-\(String(repeating: "a", count: 64)).bin").selector == nil)
        #expect(UnfairPlayModelStore.parseFileName("e03fe290-00000011-zzzz.bin").selector == nil)
    }

    @Test("缺失目录给出确定结论")
    func reportsMissingDirectory() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-missing-\(UUID().uuidString)", isDirectory: true)
        let report = UnfairPlayModelStore(directoryURL: url).scan()
        #expect(report.exists == false)
        #expect(report.isUsable == false)
        #expect(report.issues.isEmpty == false)
    }

    @Test("权限正确时目录可用，并列出模型")
    func reportsHealthyDirectory() throws {
        let directory = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeModel(named: "e03fe290-00000011-\(String(repeating: "b", count: 64)).bin", in: directory, mode: 0o600)

        let report = UnfairPlayModelStore(directoryURL: directory).scan()
        #expect(report.isUsable)
        #expect(report.models.count == 1)
        #expect(report.models.first?.selector == "e03fe290:00000011")
    }

    @Test("文件权限过宽会整体判定不可用")
    func reportsTooOpenFile() throws {
        let directory = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeModel(named: "e03fe290-00000011-\(String(repeating: "c", count: 64)).bin", in: directory, mode: 0o644)

        let report = UnfairPlayModelStore(directoryURL: directory).scan()
        #expect(report.isUsable == false)
        #expect(report.issues.contains { $0.contains("0600") })
    }

    @Test("清空模型只删除 .bin")
    func clearOnlyRemovesBinFiles() throws {
        let directory = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeModel(named: "e03fe290-00000011-\(String(repeating: "d", count: 64)).bin", in: directory, mode: 0o600)
        let note = directory.appendingPathComponent("report.json")
        try Data("{}".utf8).write(to: note)

        let removed = try UnfairPlayModelStore(directoryURL: directory).clearModels()
        #expect(removed.count == 1)
        #expect(FileManager.default.fileExists(atPath: note.path))
    }

    // MARK: 辅助

    private func makePrivateDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return url
    }

    private func writeModel(named name: String, in directory: URL, mode: Int) throws {
        let url = directory.appendingPathComponent(name)
        try Data([0x00, 0x01]).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }
}

@Suite("UnfairPlay JSON 契约")
struct UnfairPlayReportDecodingTests {
    @Test("doctor 报告按 snake_case 解码")
    func decodesDoctorReport() throws {
        let json = """
        {
          "schema": "unfairplay-doctor-v1",
          "ready": false,
          "decrypt_ready": false,
          "checks": {"ipa_inventory": true, "ipa_sinf": true, "selector_match": false},
          "sinf": [{"path": "Payload/App.app/SC_Info/App.sinf", "selector_id": "cb152649:00000007", "current_layout": true}],
          "models": [{"path": "/tmp/models/a.bin", "selector_id": "e03fe290:00000011", "sha256": "abc", "bytes": 1024}],
          "compatible_models_by_sinf": {},
          "errors": ["no enrollment model matches SINF Payload/App.app/SC_Info/App.sinf"],
          "warnings": ["w"],
          "next_actions": ["collect native enrollment"]
        }
        """
        let report = try JSONDecoder().decode(UnfairPlayDoctorReport.self, from: Data(json.utf8))
        #expect(report.decryptReady == false)
        #expect(report.checks["ipa_inventory"] == true)
        #expect(report.sinf.first?.selectorId == "cb152649:00000007")
        #expect(report.sinf.first?.currentLayout == true)
        #expect(report.models.first?.selectorId == "e03fe290:00000011")
        #expect(report.nextActions == ["collect native enrollment"])
    }

    @Test("doctor 无 errors 时缺省字段有默认值")
    func decodesSparseDoctorReport() throws {
        let json = #"{"schema":"unfairplay-doctor-v1","ready":true,"decrypt_ready":true}"#
        let report = try JSONDecoder().decode(UnfairPlayDoctorReport.self, from: Data(json.utf8))
        #expect(report.checks.isEmpty)
        #expect(report.errors.isEmpty)
        #expect(report.sinf.isEmpty)
    }

    @Test("decrypt 报告解码并忽略敏感字段")
    func decodesDecryptReport() throws {
        let json = """
        {
          "schema": "unfairplay-decryption-v1",
          "model_build": "macos26a428",
          "oracle": {"logical_key_sha256": "SECRET"},
          "encrypted_image_count": 7,
          "decrypted_page_count": 23516,
          "images": [{"member": "Payload/App.app/App", "cryptid_before": 1, "cryptid_after": 0}],
          "complete": true,
          "plaintext_verified": true,
          "signature_verified": false,
          "warnings": []
        }
        """
        let report = try JSONDecoder().decode(UnfairPlayDecryptReport.self, from: Data(json.utf8))
        #expect(report.complete)
        #expect(report.encryptedImageCount == 7)
        #expect(report.decryptedPageCount == 23516)
        #expect(report.images.first?.cryptidAfter == 0)
        #expect(report.modelBuild == "macos26a428")
    }

    @Test("预检汇总按文案识别已解密包")
    func summarizesAlreadyDecryptedIPA() {
        let errors = ["ipa inventory: IPA contains no supported encrypted Mach-O images"]
        let report = UnfairPlayDoctorReport(errors: errors)
        let probe = UnfairPlayProbe.summarize(report)
        #expect(probe.hasEncryptedPayload == false)
        #expect(probe.isReady == false)
        #expect(throws: UnfairPlayError.noEncryptedPayload) {
            try probe.validateForDecryption()
        }
    }

    @Test("compatible_models_by_sinf 全覆盖时视为可解密")
    func treatsFullCompatibilityAsReady() {
        let report = UnfairPlayDoctorReport(
            decryptReady: false,
            checks: ["ipa_inventory": true],
            sinf: [.init(path: "Payload/App.app/App", selectorId: "cb152649:00000007", currentLayout: true, sha256: nil)],
            compatibleModelsBySINF: ["Payload/App.app/App": "/models/a.bin"]
        )
        let probe = UnfairPlayProbe.summarize(report)
        #expect(probe.isReady)
        #expect(probe.hasEncryptedPayload)
        #expect(throws: Never.self) {
            try probe.validateForDecryption()
        }
    }

    @Test("权限问题优先于 selector 差异报出")
    func surfacesPermissionErrorBeforeSelectorMismatch() {
        let report = UnfairPlayDoctorReport(
            checks: ["ipa_inventory": true],
            errors: [
                "no enrollment model matches SINF a",
                "model entry /models/x.bin must not be accessible by group or other users"
            ],
            sinf: [.init(path: "a", selectorId: "cb152649:00000007", currentLayout: true, sha256: nil)]
        )
        let probe = UnfairPlayProbe.summarize(report)
        #expect(probe.actionableModelError?.contains("must not be accessible") == true)

        var thrown: Error?
        do {
            try probe.validateForDecryption()
        } catch {
            thrown = error
        }
        #expect(thrown?.localizedDescription.contains("0700/0600") == true)
    }

    @Test("预检未命中模型时给出 selector 差异")
    func summarizesMissingModel() {
        let report = UnfairPlayDoctorReport(
            checks: ["ipa_inventory": true, "ipa_sinf": true],
            errors: ["no enrollment model matches SINF a"],
            sinf: [.init(path: "a", selectorId: "cb152649:00000007", currentLayout: true, sha256: nil)],
            models: [.init(path: "b", selectorId: "e03fe290:00000011", sha256: nil, bytes: nil)]
        )
        let probe = UnfairPlayProbe.summarize(report)
        #expect(probe.sinfSelectors == ["cb152649:00000007"])
        #expect(probe.availableSelectors == ["e03fe290:00000011"])
        #expect(throws: UnfairPlayError.self) {
            try probe.validateForDecryption()
        }
    }
}
