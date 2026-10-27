import Foundation
import Testing

@testable import UnfairPlayCore

/// 原生 setup 第一阶段的回归测试：App/IPA selector 校验、模型安装与 manifest 契约。
/// 全部使用合成夹具，不读取任何私有 FairPlay 数据。
@Suite("setup：校验与安装")
struct UnfairPlaySetupTests {
    @Test("selector 相同即通过校验")
    func validationAcceptsMatchingSelector() throws {
        let root = try Self.makeWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = try Self.makeApp(root: root, selector: Self.selector)
        let ipa = try Self.makeIPA(root: root, member: "Sample.sinf", selector: Self.selector)

        let options = UnfairPlaySetupOptions(
            appURL: app,
            ipaURL: ipa,
            modelDirectoryURL: root.appendingPathComponent("models")
        )
        let result = try UnfairPlaySetup.validate(options: options)
        #expect(result.selector == "a94fdb7a:00000006")
        #expect(result.bundleIdentifier == "com.example.sample")
        #expect(result.executable == "Sample")
        #expect(result.ipaRoot == "Payload/Sample.app")
        #expect(result.ipaTargetSINFMember == "Payload/Sample.app/SC_Info/Sample.sinf")
        #expect(result.hasModel == false)
    }

    @Test("selector 不同时指出 IPA 与账号不匹配")
    func validationRejectsDifferentSelector() throws {
        let root = try Self.makeWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = try Self.makeApp(root: root, selector: Self.selector)
        let ipa = try Self.makeIPA(
            root: root,
            member: "Sample.sinf",
            selector: (user: 0xe03f_e290, key: 0x11)
        )
        let options = UnfairPlaySetupOptions(
            appURL: app,
            ipaURL: ipa,
            modelDirectoryURL: root.appendingPathComponent("models")
        )
        #expect(throws: UnfairPlaySetupError.ipaHasNoMatchingSINF(selector: "a94fdb7a:00000006")) {
            _ = try UnfairPlaySetup.validate(options: options)
        }
    }

    @Test("已装 App 必须恰好一个根 SINF")
    func validationRejectsMultipleSINFs() throws {
        let root = try Self.makeWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        var app = try Self.makeApp(root: root, selector: Self.selector)
        let extra = app.appendingPathComponent("SC_Info/Extra.sinf")
        try Data(Self.sinf(user: Self.selector.user, key: Self.selector.key)).write(to: extra)
        _ = app
        app = root.appendingPathComponent("Sample.app")

        let ipa = try Self.makeIPA(root: root, member: "Sample.sinf", selector: Self.selector)
        let options = UnfairPlaySetupOptions(
            appURL: app,
            ipaURL: ipa,
            modelDirectoryURL: root.appendingPathComponent("models")
        )
        #expect(throws: UnfairPlaySetupError.appSINFCount(2)) {
            _ = try UnfairPlaySetup.validate(options: options)
        }
    }

    @Test("IPA 缺少与可执行文件同名的 SINF 时报告缺失成员")
    func validationReportsMissingTargetMember() throws {
        let root = try Self.makeWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = try Self.makeApp(root: root, selector: Self.selector)
        let ipa = try Self.makeIPA(root: root, member: "Other.sinf", selector: Self.selector)
        let options = UnfairPlaySetupOptions(
            appURL: app,
            ipaURL: ipa,
            modelDirectoryURL: root.appendingPathComponent("models")
        )
        #expect(throws: UnfairPlaySetupError.ipaMissingMember("Payload/Sample.app/SC_Info/Sample.sinf")) {
            _ = try UnfairPlaySetup.validate(options: options)
        }
    }

    @Test("安装模型沿用 selector-哈希.bin 命名并复用相同内容")
    func installsModelWithExpectedName() throws {
        let root = try Self.makeWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("models")
        let model = Data((0..<4184).map { UInt8(truncatingIfNeeded: $0) })

        let first = try UnfairPlaySetup.installModel(
            directory: directory,
            selector: "a94fdb7a:00000006",
            model: model
        )
        #expect(first.reused == false)
        #expect(first.url.lastPathComponent == "a94fdb7a-00000006-\(first.sha256).bin")
        let attributes = try FileManager.default.attributesOfItem(atPath: first.url.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)

        let second = try UnfairPlaySetup.installModel(
            directory: directory,
            selector: "a94fdb7a:00000006",
            model: model
        )
        #expect(second.reused == true)
        #expect(second.url == first.url)

        let store = UnfairPlayModelStore(directoryURL: directory)
        #expect(store.selectors() == ["a94fdb7a:00000006"])
    }

    @Test("manifest 使用 Go 的 snake_case 字段")
    func manifestEncodesGoFieldNames() throws {
        let file = UnfairPlayEnrollmentManifest.File(
            path: "fairplayd/fairplayd.arm64e", bytes: 1, sha256: String(repeating: "0", count: 64), mode: "0600"
        )
        let manifest = UnfairPlayEnrollmentManifest(
            schema: UnfairPlaySetup.captureSchema,
            createdAt: "2026-10-28T00:00:00Z",
            productVersion: "26.0",
            buildVersion: "25G83",
            fairplayd: file,
            enrollmentSupport: .init(
                profile: "portable-current-sinf", build: "25G83", status: "supported",
                validationBasis: nil, recovery: true, decrypt: true,
                evaluatorProfile: nil, evaluatorSHA256: nil
            ),
            hardwareMAC: file,
            app: .init(
                bundleIdentifier: "com.example.sample", executable: "Sample",
                executablePath: "/Applications/Sample.app/Sample",
                selector: .init(user: 0xa94f_db7a, key: 6),
                selectorID: "a94fdb7a:00000006",
                sinfPath: "app/SC_Info/Sample.sinf",
                targetSINFPath: "ipa/App.sinf",
                ipaMemberRoot: "Payload/Sample.app"
            ),
            ipa: nil,
            files: [file],
            warnings: []
        )
        let text = String(decoding: try JSONEncoder.pretty.encode(manifest), as: UTF8.self)
        for key in [
            "\"created_at\"", "\"product_version\"", "\"build_version\"", "\"enrollment_support\"",
            "\"end_to_end_decryption\"", "\"hardware_iomac\"", "\"selector_id\"",
            "\"target_sinf_path\"", "\"ipa_member_root\""
        ] {
            #expect(text.contains(key), "缺少字段 \(key)")
        }
    }
}

// MARK: - 夹具

extension UnfairPlaySetupTests {
    static let selector: (user: UInt32, key: UInt32) = (0xa94f_db7a, 6)

    static func makeWorkspace() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("UnfairPlaySetup-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    @discardableResult
    static func makeApp(root: URL, selector: (user: UInt32, key: UInt32)) throws -> URL {
        let app = root.appendingPathComponent("Sample.app", isDirectory: true)
        try FileManager.default.createDirectory(
            at: app.appendingPathComponent("SC_Info", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data(infoPlist.utf8).write(to: app.appendingPathComponent("Info.plist"))
        try Data().write(to: app.appendingPathComponent("Sample"))
        try Data(sinf(user: selector.user, key: selector.key))
            .write(to: app.appendingPathComponent("SC_Info/Sample.sinf"))
        return app
    }

    static func makeIPA(root: URL, member: String, selector: (user: UInt32, key: UInt32)) throws -> URL {
        let ipa = root.appendingPathComponent("Sample.ipa")
        let data = zip([
            ("Payload/Sample.app/Info.plist", Array(infoPlist.utf8)),
            ("Payload/Sample.app/SC_Info/\(member)", sinf(user: selector.user, key: selector.key)),
        ])
        try data.write(to: ipa)
        return ipa
    }

    static let infoPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
    <key>CFBundleIdentifier</key><string>com.example.sample</string>
    <key>CFBundleExecutable</key><string>Sample</string>
    </dict>
    </plist>
    """

    static func sinf(user: UInt32, key: UInt32) -> [UInt8] {
        var children: [UInt8] = []
        children += atom(type: "user", payload: bigEndian(user))
        children += atom(type: "key ", payload: bigEndian(key))
        children += atom(type: "priv", payload: [0x11, 0x22, 0x33, 0x44])
        return atom(type: "sinf", payload: atom(type: "schi", payload: children))
    }

    static func atom(type: String, payload: [UInt8]) -> [UInt8] {
        bigEndian(UInt32(8 + payload.count)) + Array(type.utf8) + payload
    }

    static func bigEndian(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    // MARK: 仅存储（method 0）的最小 ZIP 写入器

    static func zip(_ entries: [(String, [UInt8])]) -> Data {
        var output: [UInt8] = []
        var central: [UInt8] = []
        for (name, payload) in entries {
            let nameBytes = Array(name.utf8)
            let crc = crc32(payload)
            let offset = UInt32(output.count)

            output += le32(0x0403_4b50)
            output += le16(20)
            output += le16(0)
            output += le16(0)
            output += le16(0)
            output += le16(0)
            output += le32(crc)
            output += le32(UInt32(payload.count))
            output += le32(UInt32(payload.count))
            output += le16(UInt16(nameBytes.count))
            output += le16(0)
            output += nameBytes
            output += payload

            central += le32(0x0201_4b50)
            central += le16(20)
            central += le16(20)
            central += le16(0)
            central += le16(0)
            central += le16(0)
            central += le16(0)
            central += le32(crc)
            central += le32(UInt32(payload.count))
            central += le32(UInt32(payload.count))
            central += le16(UInt16(nameBytes.count))
            central += le16(0)
            central += le16(0)
            central += le16(0)
            central += le16(0)
            central += le32(0)
            central += le32(offset)
            central += nameBytes
        }
        let centralOffset = UInt32(output.count)
        output += central
        output += le32(0x0605_4b50)
        output += le16(0)
        output += le16(0)
        output += le16(UInt16(entries.count))
        output += le16(UInt16(entries.count))
        output += le32(UInt32(central.count))
        output += le32(centralOffset)
        output += le16(0)
        return Data(output)
    }

    static func le16(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]
    }

    static func le32(_ value: UInt32) -> [UInt8] {
        [0, 8, 16, 24].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var table: [UInt32] = []
        for index in 0..<256 {
            var value = UInt32(index)
            for _ in 0..<8 {
                value = (value & 1) == 1 ? (value >> 1) ^ 0xEDB8_8320 : value >> 1
            }
            table.append(value)
        }
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc = (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 0xFF)]
        }
        return crc ^ 0xFFFF_FFFF
    }
}
