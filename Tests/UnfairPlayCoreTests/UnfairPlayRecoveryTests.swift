import CUnfairPlay
import Foundation
import Testing

@testable import UnfairPlayCore

@Suite("Native recovery assets")
struct UnfairPlayRecoveryAssetsTests {
    @Test("Every generated interpreter asset is present and shaped like the Go assets")
    func assetsLoad() throws {
        let assets = try UnfairPlayRecoveryAssets.load()
        #expect(assets.model.starts(with: [0x1f, 0x8b]))
        #expect(assets.compactProfile.starts(with: [0x1f, 0x8b]))
        #expect(assets.safeExtracted.starts(with: [0x1f, 0x8b]))
        #expect(assets.frame.starts(with: [0x1f, 0x8b]))
        #expect(assets.kernels.starts(with: Array("UPKR1".utf8)))
        #expect(assets.compactProfile.count > 1_000_000)
        #expect(assets.safeExtracted.count > 100_000)
    }

    @Test("A run without capture mappings loads every asset and fails with a real diagnostic")
    func runWithoutMappings() throws {
        let assets = try UnfairPlayRecoveryAssets.load()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-recovery-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let hardware = directory.appendingPathComponent("iomac.bin")
        try Data([0x02, 0x00, 0x5a, 0x00, 0x00, 0x01]).write(to: hardware)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: hardware.path)

        let context = up_context_create(nil)
        let contextValue = try #require(context)
        defer { up_context_free(contextValue) }

        var status: Int32 = 0
        try assets.model.withUnsafeBytes { model in
            try assets.compactProfile.withUnsafeBytes { compact in
                try assets.safeExtracted.withUnsafeBytes { extracted in
                    try assets.frame.withUnsafeBytes { frame in
                        try assets.kernels.withUnsafeBytes { kernels in
                            try hardware.path.withCString { hardwarePath in
                                "/Applications/Synthetic.app/Synthetic".withCString { executable in
                                    var value = up_recovery_assets()
                                    value.model_gz = model.bindMemory(to: UInt8.self).baseAddress
                                    value.model_gz_length = model.count
                                    value.compact_cfg_gz = compact.bindMemory(to: UInt8.self).baseAddress
                                    value.compact_cfg_gz_length = compact.count
                                    value.safe_extracted_gz = extracted.bindMemory(to: UInt8.self).baseAddress
                                    value.safe_extracted_gz_length = extracted.count
                                    value.frame_gz = frame.bindMemory(to: UInt8.self).baseAddress
                                    value.frame_gz_length = frame.count
                                    value.kernels = kernels.bindMemory(to: UInt8.self).baseAddress
                                    value.kernels_length = kernels.count
                                    var options = up_recovery_options()
                                    options.hardware_path = hardwarePath
                                    options.executable_path = executable
                                    var result = up_recovery_result()
                                    defer { up_recovery_result_free(&result) }
                                    status = up_recovery_run(contextValue, &value, &options, &result)
                                }
                            }
                        }
                    }
                }
            }
        }
        #expect(status == 0)
        let detail = up_last_error(contextValue).map { String(cString: $0) } ?? ""
        #expect(!detail.isEmpty)
        // Loading stops after the assets are already validated, so the failure
        // must come from the CFG walk rather than a corrupt asset.
        #expect(!detail.contains("gunzip") && !detail.contains("magic"))
    }

    @Test("Capture mappings reject inputs that are not mode-0600 regular files")
    func rejectsReadableMapping() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("unfairplay-recovery-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let hardware = directory.appendingPathComponent("iomac.bin")
        try Data([0x02, 0x00, 0x5a, 0x00, 0x00, 0x01]).write(to: hardware)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: hardware.path)

        let mappings = ["SC Info.sinf=\(hardware.path)"]
        let pointers = mappings.map { strdup($0) }
        defer { pointers.forEach { free($0) } }
        let context = up_context_create(nil)
        let contextValue = try #require(context)
        defer { up_context_free(contextValue) }
        var list = pointers.map { UnsafePointer<CChar>($0) }
        let status: Int32 = list.withUnsafeMutableBufferPointer { buffer in
            hardware.path.withCString { hardwarePath in
                "/Applications/Synthetic.app/Synthetic".withCString { executable in
                    var options = up_recovery_options()
                    options.file_mappings = UnsafePointer(buffer.baseAddress)
                    options.file_mapping_count = mappings.count
                    options.hardware_path = hardwarePath
                    options.executable_path = executable
                    var assets = up_recovery_assets()
                    var result = up_recovery_result()
                    defer { up_recovery_result_free(&result) }
                    return up_recovery_run(contextValue, &assets, &options, &result)
                }
            }
        }
        #expect(status == 0)
        let detail = up_last_error(contextValue).map { String(cString: $0) } ?? ""
        #expect(detail.contains("recovery asset is empty"))
    }
}

@Suite("Recovery mapping layout")
struct UnfairPlayRecoveryMappingTests {
    private func manifest(files: [UnfairPlayEnrollmentManifest.File]) -> UnfairPlayEnrollmentManifest {
        func file(_ path: String) -> UnfairPlayEnrollmentManifest.File {
            .init(path: path, bytes: 0, sha256: "", mode: "0600")
        }
        return UnfairPlayEnrollmentManifest(
            schema: "unfairplay-native-enrollment-capture-v1",
            createdAt: "2026-01-01T00:00:00Z",
            productVersion: "26A428",
            buildVersion: "26A428",
            fairplayd: file("fairplayd/fairplayd.arm64e"),
            enrollmentSupport: UnfairPlayFairPlaySupport(
                profile: "macos-26A428",
                build: "26A428",
                status: "supported",
                validationBasis: "fixture",
                recovery: true,
                decrypt: true,
                evaluatorProfile: nil,
                evaluatorSHA256: nil
            ),
            hardwareMAC: file("hardware/iomac.bin"),
            app: .init(
                bundleIdentifier: "com.example.synthetic",
                executable: "Synthetic",
                executablePath: "Synthetic.app/Synthetic",
                selector: .init(user: 0, key: 0),
                selectorID: "00000000:00000000",
                sinfPath: "app/SC_Info/Synthetic.sinf",
                targetSINFPath: "Synthetic.sinf",
                ipaMemberRoot: "Payload/Synthetic.app"
            ),
            ipa: nil,
            files: files,
            warnings: []
        )
    }

    @Test("The minimal profile keeps the installed SINF, its SUPF and the fpsd state")
    func minimalMappings() throws {
        let files: [UnfairPlayEnrollmentManifest.File] = [
            .init(path: "app/SC_Info/Synthetic.sinf", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "app/SC_Info/Synthetic.supf", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "app/SC_Info/Other.supf", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/fpsd-sc-info/SC Info.sidb", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/fpsd-sc-info/SC Info.state", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/shared-sc-info/SC Info.shared", bytes: 0, sha256: "", mode: "0600"),
        ]
        let mappings = try UnfairPlaySetup.recoveryMappings(
            capture: URL(fileURLWithPath: "/tmp/capture"),
            manifest: manifest(files: files),
            expanded: false
        )
        let suffixes = mappings.specifications.compactMap { $0.split(separator: "=", maxSplits: 1).first.map(String.init) }
        #expect(suffixes.contains("/Synthetic"))
        #expect(suffixes.contains("Synthetic.sinf"))
        #expect(suffixes.contains("Synthetic.supf"))
        #expect(!suffixes.contains("Other.supf"))
        #expect(suffixes.contains("/var/db/fpsd/SC Info/SC Info.sidb"))
        #expect(suffixes.contains("/var/db/fpsd/SC Info/SC Info.state"))
        #expect(!suffixes.contains("/Users/Shared/SC Info/SC Info.shared"))
        #expect(mappings.stateFileCount == 2)
    }

    @Test("The expanded profile adds every auxiliary license and state file")
    func expandedMappings() throws {
        let files: [UnfairPlayEnrollmentManifest.File] = [
            .init(path: "app/SC_Info/Synthetic.supf", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "app/SC_Info/Other.supf", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/fpsd-sc-info/SC Info.state", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/shared-sc-info/SC Info.shared", bytes: 0, sha256: "", mode: "0600"),
            .init(path: "state/adi/SC Info.adi", bytes: 0, sha256: "", mode: "0600"),
        ]
        let mappings = try UnfairPlaySetup.recoveryMappings(
            capture: URL(fileURLWithPath: "/tmp/capture"),
            manifest: manifest(files: files),
            expanded: true
        )
        let suffixes = mappings.specifications.compactMap { $0.split(separator: "=", maxSplits: 1).first.map(String.init) }
        #expect(suffixes.contains("Other.supf"))
        #expect(suffixes.contains("/Users/Shared/SC Info/SC Info.shared"))
        #expect(suffixes.contains("/var/db/fpsd/adi/SC Info.adi"))
        #expect(mappings.stateFileCount == 3)
    }
}
