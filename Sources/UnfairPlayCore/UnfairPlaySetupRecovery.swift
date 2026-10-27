import CUnfairPlay
import Foundation

/// One bounded recovery attempt: the generated `FPSENR2` enrollment model and
/// the diagnostics the reference implementation reports.
public struct UnfairPlaySetupRecovery: Sendable {
    public let model: Data
    public let stateSHA256: String
    public let iterations: Int
    public let extractedBlockHits: Int
    /// `minimal-current-sinf` or `expanded-capture`, matching the Go runner.
    public let profile: String

    public init(
        model: Data,
        stateSHA256: String,
        iterations: Int,
        extractedBlockHits: Int,
        profile: String
    ) {
        self.model = model
        self.stateSHA256 = stateSHA256
        self.iterations = iterations
        self.extractedBlockHits = extractedBlockHits
        self.profile = profile
    }
}

/// Generated interpreter assets shipped inside `UnfairPlayCore`.
enum UnfairPlayRecoveryAssets {
    struct Assets: Sendable {
        let model: Data
        let compactProfile: Data
        let safeExtracted: Data
        let frame: Data
        let kernels: Data
    }

    static func load() throws -> Assets {
        func asset(_ name: String, _ extension: String) throws -> Data {
            guard let url = Self.url(name: name, extension: `extension`) else {
                throw UnfairPlaySetupError.fileOperation("缺少 recovery 资源：\(name).\(`extension`)")
            }
            return try Data(contentsOf: url)
        }
        return Assets(
            model: try asset("recovery-model", "gz"),
            compactProfile: try asset("recovery-compact-cfg", "gz"),
            safeExtracted: try asset("recovery-safe-extracted", "gz"),
            frame: try asset("recovery-frame-semantic", "gz"),
            kernels: try asset("recovery-kernels", "bin")
        )
    }

    private static func url(name: String, extension: String) -> URL? {
        Bundle.module.url(forResource: name, withExtension: `extension`, subdirectory: "Resources")
            ?? Bundle.module.url(forResource: name, withExtension: `extension`)
    }
}

// MARK: - Capture mapping

extension UnfairPlaySetup {
    /// Mirrors `canonical.RuntimeFileMappings` for one capture manifest.
    struct RecoveryMappings {
        let specifications: [String]
        let stateFileCount: Int
    }

    static func recoveryMappings(
        capture: URL,
        manifest: UnfairPlayEnrollmentManifest,
        expanded: Bool
    ) throws -> RecoveryMappings {
        var supfs: [(virtual: String, path: String)] = []
        var sidbs: [(virtual: String, path: String)] = []
        var state: [(virtual: String, path: String, role: String)] = []
        var auxiliary: [(virtual: String, path: String)] = []

        for file in manifest.files {
            let path = file.path
            let virtual: String
            let role: String
            if path.hasPrefix("app/SC_Info/") {
                if path == manifest.app.sinfPath {
                    continue
                }
                virtual = String(path.dropFirst("app/SC_Info/".count))
                role = "license-auxiliary"
            } else if path.hasPrefix("state/fpsd-sc-info/") {
                virtual = "/var/db/fpsd/SC Info/" + path.dropFirst("state/fpsd-sc-info/".count)
                role = "fpsd-state"
            } else if path.hasPrefix("state/shared-sc-info/") {
                virtual = "/Users/Shared/SC Info/" + path.dropFirst("state/shared-sc-info/".count)
                role = "shared-state"
            } else if path.hasPrefix("state/adi/") {
                virtual = "/var/db/fpsd/adi/" + path.dropFirst("state/adi/".count)
                role = "adi-state"
            } else {
                continue
            }
            let lower = (path as NSString).lastPathComponent.lowercased()
            if lower.hasSuffix(".supf") {
                supfs.append((virtual, path))
            } else if lower == "sc info.sidb" {
                sidbs.append((virtual, path))
            } else if role == "license-auxiliary" {
                auxiliary.append((virtual, path))
            } else {
                state.append((virtual, path, role))
            }
        }

        let executableName = manifest.app.executable
        var specifications = ["/" + executableName + "=" + capture.appendingPathComponent("app/executable").path]
        specifications.append(
            (manifest.app.sinfPath as NSString).lastPathComponent
                + "=" + capture.appendingPathComponent(manifest.app.sinfPath).path
        )
        for supf in supfs {
            let name = (supf.virtual as NSString).lastPathComponent
            if expanded || name == executableName + ".supf" || name == executableName + ".v5.supf" {
                specifications.append(supf.virtual + "=" + capture.appendingPathComponent(supf.path).path)
            }
        }
        if expanded {
            for file in auxiliary {
                specifications.append(file.virtual + "=" + capture.appendingPathComponent(file.path).path)
            }
        }
        var stateFiles = 0
        for sidb in sidbs {
            specifications.append(sidb.virtual + "=" + capture.appendingPathComponent(sidb.path).path)
            stateFiles += 1
        }
        for file in state {
            let name = (file.virtual as NSString).lastPathComponent
            if expanded || (file.role == "fpsd-state" && name.hasPrefix("SC Info.")) {
                specifications.append(file.virtual + "=" + capture.appendingPathComponent(file.path).path)
                stateFiles += 1
            }
        }
        return RecoveryMappings(specifications: specifications.sorted(), stateFileCount: stateFiles)
    }

    /// Verifies every mapped capture file against its manifest descriptor the
    /// way `canonicalFile` does, then returns the absolute paths.
    static func verifyRecoveryInputs(
        capture: URL,
        manifest: UnfairPlayEnrollmentManifest,
        mappings: RecoveryMappings
    ) throws {
        var descriptors: [String: UnfairPlayEnrollmentManifest.File] = [:]
        for file in manifest.files {
            descriptors[file.path] = file
        }
        for specification in mappings.specifications {
            guard let separator = specification.firstIndex(of: "=") else {
                continue
            }
            let path = String(specification[specification.index(after: separator)...])
            guard let relative = path.hasPrefix(capture.path + "/")
                ? String(path.dropFirst(capture.path.count + 1))
                : nil,
                let descriptor = descriptors[relative] else {
                throw UnfairPlaySetupError.fileOperation("采集清单缺少映射文件：\(path)")
            }
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard data.count == descriptor.bytes, SHA256.hex(data) == descriptor.sha256 else {
                throw UnfairPlaySetupError.fileOperation("采集文件与清单不一致：\(path)")
            }
        }
    }
}

// MARK: - Recovery

extension UnfairPlaySetup {
    /// Generates the selector-bound enrollment model for an existing capture.
    /// The caller decides whether to install it and run the decryption gate.
    public static func recover(
        capture: UnfairPlaySetupCaptureResult,
        options: UnfairPlaySetupOptions
    ) throws -> UnfairPlaySetupRecovery {
        let manifestData = try Data(contentsOf: capture.manifestURL)
        let manifest = try JSONDecoder().decode(UnfairPlayEnrollmentManifest.self, from: manifestData)
        let bundle = try UnfairPlayRecoveryAssets.load()
        let hardware = capture.directory.appendingPathComponent("hardware/iomac.bin")
        let reference = capture.directory.appendingPathComponent("fairplayd/fairplayd.arm64e")

        var failures: [String] = []
        for attempt in [
            (name: "minimal-current-sinf", expanded: false),
            (name: "expanded-capture", expanded: true),
        ] {
            let mappings = try recoveryMappings(capture: capture.directory, manifest: manifest, expanded: attempt.expanded)
            guard mappings.stateFileCount > 0 else {
                failures.append("\(attempt.name): 采集不包含 FairPlay state")
                continue
            }
            try verifyRecoveryInputs(capture: capture.directory, manifest: manifest, mappings: mappings)
            do {
                let recovered = try runRecovery(
                    bundle: bundle,
                    mappings: mappings.specifications,
                    hardwarePath: hardware.path,
                    executablePath: manifest.app.executablePath,
                    referencePath: reference.path
                )
                return UnfairPlaySetupRecovery(
                    model: recovered.model,
                    stateSHA256: recovered.stateSHA256,
                    iterations: recovered.iterations,
                    extractedBlockHits: recovered.extractedBlockHits,
                    profile: attempt.name
                )
            } catch {
                failures.append("\(attempt.name): \(error.localizedDescription)")
            }
        }
        throw UnfairPlaySetupError.recoveryFailed(failures.joined(separator: "；"))
    }

    private struct RecoveryOutput {
        let model: Data
        let stateSHA256: String
        let iterations: Int
        let extractedBlockHits: Int
    }

    private static func runRecovery(
        bundle: UnfairPlayRecoveryAssets.Assets,
        mappings: [String],
        hardwarePath: String,
        executablePath: String,
        referencePath: String
    ) throws -> RecoveryOutput {
        let context = up_context_create(nil)
        guard let context else {
            throw UnfairPlaySetupError.recoveryFailed("无法创建 recovery 上下文")
        }
        defer { up_context_free(context) }

        let duplicated = mappings.map { strdup($0) }
        defer { duplicated.forEach { free($0) } }
        var pointers = duplicated.map { UnsafePointer<CChar>($0) }

        return try bundle.model.withUnsafeBytes { model in
            try bundle.compactProfile.withUnsafeBytes { compact in
                try bundle.safeExtracted.withUnsafeBytes { extracted in
                    try bundle.frame.withUnsafeBytes { frame in
                        try bundle.kernels.withUnsafeBytes { kernels in
                            try hardwarePath.withCString { hardware in
                                try executablePath.withCString { executable in
                                    try referencePath.withCString { reference in
                                        try pointers.withUnsafeMutableBufferPointer { list in
                                            var assets = up_recovery_assets()
                                            assets.model_gz = model.bindMemory(to: UInt8.self).baseAddress
                                            assets.model_gz_length = model.count
                                            assets.compact_cfg_gz = compact.bindMemory(to: UInt8.self).baseAddress
                                            assets.compact_cfg_gz_length = compact.count
                                            assets.safe_extracted_gz = extracted.bindMemory(to: UInt8.self).baseAddress
                                            assets.safe_extracted_gz_length = extracted.count
                                            assets.frame_gz = frame.bindMemory(to: UInt8.self).baseAddress
                                            assets.frame_gz_length = frame.count
                                            assets.kernels = kernels.bindMemory(to: UInt8.self).baseAddress
                                            assets.kernels_length = kernels.count
                                            var options = up_recovery_options()
                                            options.file_mappings = UnsafePointer(list.baseAddress)
                                            options.file_mapping_count = mappings.count
                                            options.hardware_path = hardware
                                            options.executable_path = executable
                                            options.reference_path = reference
                                            options.selection_max_blocks = 0
                                            var result = up_recovery_result()
                                            let status = up_recovery_run(context, &assets, &options, &result)
                                            defer { up_recovery_result_free(&result) }
                                            guard status == 1, let bytes = result.model else {
                                                let detail = up_last_error(context).map { String(cString: $0) } ?? ""
                                                throw UnfairPlaySetupError.recoveryFailed(
                                                    detail.isEmpty ? "recovery 执行失败" : detail
                                                )
                                            }
                                            let modelData = Data(bytes: bytes, count: result.model_length)
                                            return RecoveryOutput(
                                                model: modelData,
                                                stateSHA256: withUnsafeBytes(of: result.state_sha256) { bytes in
                                                    String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
                                                },
                                                iterations: Int(result.iterations),
                                                extractedBlockHits: Int(result.extracted_block_hits)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
