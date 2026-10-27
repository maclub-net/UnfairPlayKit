import Foundation
import Testing

@testable import CUnfairPlay

/// 与 Go 上游 `internal/fairplay/pagekey.go` 对齐的固定向量。
/// 向量由 `go test -run TestZZNativeCrosscheck` 打印，作为逐位一致的基线。
@Suite("C 核心：页密钥派生")
struct NativePageKeyTests {
    private static let logicalKeys: [String] = [
        "000102030405060708090a0b0c0d0e0f",
        "ffeeddccbbaa99887766554433221100",
        "9f3c710a5512ee80316d02f7ab44c95e",
    ]

    private static let masks: [String] = [
        "79891eea60ad2e7ea75fe7ff291bc082",
        "a05530ebe311c4c59e0a428e1e1cbd5d",
        "66f9e34beac53d2fd3675bd4795498e5",
    ]

    private static let wrappedValues: [String] = [
        "112233445566778899aabbccddeeff00",
        "00000000000000000000000000000000",
        "a55a0ff03cc369968778d22d14e14224",
    ]

    private static let offsets: [UInt64] = [0, 4096, 0x3f041000, 0x1ffffffff, 0xdeadbeefcafebabe]

    /// 每个 (logicalIndex, wrappedIndex, offsetIndex) 对应的 key。
    private static let keys: [String] = [
        "e25be05e7586a50a04d3ce5c29303d3f",
        "8d448087a87d2e52d2b42f4dae794a4e",
        "f9cd4ccf0807ea5b08b2f1534cd627ab",
        "2c2263856acec7524d65f07b60646603",
        "3ca89ec2c144869f65db182b32288fde",
        "02e194863d02106bd0d3e5023aca48fb",
        "aa48824bf75bbc3ae42ce40efe18a8d6",
        "275d3a8b03185aab49b0d23eab176782",
        "1c3d71635c95cf0845cac379cc7ac08b",
        "dca1053312bc4c5269fe8eb62bbff9eb",
        "1866ccf999eaed76b0a61af876f2935b",
        "1ed4f8ce7cfd9e0848a8587891b87047",
        "90bc788ba54649d8c9c8b5680a2f0fd6",
        "f76878667a1da997c065a0d4b1287073",
        "284905f55a36a41ec065d425a24286f1",
        "517a51dca85a780581e8de24b24f4456",
        "9db8f91f8aa925d6661b9688c58bf665",
        "dfc24847481670f574eb7999a4237983",
        "a4ef1e277a3e696f11ce8d9bd66df227",
        "f0526037a116dcd867d51707105c3bcb",
        "666dd03a52af580a63ff21e1be26b60d",
        "f7b11f279182b3d44b611baded01f0b9",
        "53bb8f43c93a00677eb0462cb0dd60a7",
        "e6752a0aa6ebdfdf60e4f0a08bf5eacd",
        "4ea88d6104b6def260c4a6b5adf344df",
        "451a82eb168e52301ca9ac4e86d85612",
        "5b3d0d7ed5d4a04bd8743c34845813cc",
        "e9b64b4470f5eab66944fd63382e1c6f",
        "73f016ce9c47bd2cd485ef000077cdd0",
        "b4ab503d0750adfeb61510df6197a802",
        "515aa8377d91ef88f5832c96b5fda991",
        "35aaf6ce1056c514db89763703460c3e",
        "706f163d3b0f4fead2a0f732af0beff1",
        "63d756a1f66c1670635894d45ff752d8",
        "5a1fade4b1c590739f54888bd274fc25",
        "a7e635fe05ac1f4d600b19964d05f6a4",
        "7c210d91738e4a2dd2e36f2eb0bd5335",
        "bfabe412546468fde79380feafa25f42",
        "488211183f838add0c5e5f4559bb7291",
        "f0ba23c042b031b875e6b23315dae6c0",
        "cc68977bf6dafc6a1a53bc886e32351d",
        "6f55b1260c4d666fd804913c762e0251",
        "baead383039eb9b849bcc78167597cff",
        "e45de1ec9efe86fdace50d31586da6f4",
        "6958ad6c1267516bd1385ddb87e8df0d",
    ]

    @Test("应用掩码与 Go 一致")
    func derivesApplicationMask() {
        for (index, hex) in Self.masks.enumerated() {
            let logical = Self.bytes(Self.logicalKeys[index])
            var mask = [UInt8](repeating: 0, count: 16)
            up_test_app_mask(logical, &mask)
            #expect(Self.hex(mask) == hex)
        }
    }

    @Test("页密钥与 Go 一致")
    func derivesPageKey() {
        var cursor = 0
        for logicalIndex in 0..<Self.masks.count {
            let mask = Self.bytes(Self.masks[logicalIndex])
            for wrapped in Self.wrappedValues {
                let wrappedBytes = Self.bytes(wrapped)
                for offset in Self.offsets {
                    var key = [UInt8](repeating: 0, count: 16)
                    up_test_page_key(mask, wrappedBytes, offset, 0, &key)
                    #expect(
                        Self.hex(key) == Self.keys[cursor],
                        "logical \(logicalIndex) wrapped \(wrapped) offset \(offset)"
                    )
                    cursor += 1
                }
            }
        }
        #expect(cursor == Self.keys.count)
    }

    // MARK: 辅助

    private static func bytes(_ hex: String) -> [UInt8] {
        var result: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            result.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// 模型包与 SINF 布局解析，字段含义与 Go 版严格一致。
@Suite("C 核心：模型与 SINF")
struct NativeModelTests {
    @Test("解析 v1 模型")
    func parsesVersionOnePack() {
        let pack = Self.makePack(version: 1)
        var version: UInt32 = 0
        var selectorUser: UInt32 = 0
        var selectorKey: UInt32 = 0
        var hasSelector: Int32 = 0
        var error: UnsafeMutablePointer<CChar>?
        let status = up_test_parse_model(
            pack, pack.count, &version, &hasSelector, &selectorUser, &selectorKey, &error
        )
        #expect(status == 1)
        #expect(version == 1)
        #expect(hasSelector == 0)
        #expect(error == nil)
    }

    @Test("解析 v2/v3 模型并读出 selector")
    func parsesSelector() {
        for version: UInt32 in [2, 3] {
            let pack = Self.makePack(version: version)
            var parsedVersion: UInt32 = 0
            var selectorUser: UInt32 = 0
            var selectorKey: UInt32 = 0
            var hasSelector: Int32 = 0
            var error: UnsafeMutablePointer<CChar>?
            let status = up_test_parse_model(
                pack, pack.count, &parsedVersion, &hasSelector, &selectorUser, &selectorKey, &error
            )
            #expect(status == 1)
            #expect(parsedVersion == version)
            #expect(hasSelector == 1)
            #expect(selectorUser == 0xe03fe290)
            #expect(selectorKey == 0x11)
        }
    }

    @Test("长度不符时失败闭合")
    func rejectsBadEnvelope() {
        var pack = Self.makePack(version: 2)
        pack.removeLast()
        var version: UInt32 = 0
        var hasSelector: Int32 = 0
        var error: UnsafeMutablePointer<CChar>?
        let status = up_test_parse_model(
            pack, pack.count, &version, &hasSelector, nil, nil, &error
        )
        #expect(status == 0)
        let message = error.map { String(cString: $0) } ?? ""
        #expect(message == "invalid current SINF model envelope")
        if let error {
            up_string_free(error)
        }
    }

    @Test("SINF 选择器按大端读取")
    func parsesSinfSelector() {
        let sinf = Self.makeSINF(user: 0xcb152649, key: 0x07)
        var user: UInt32 = 0
        var key: UInt32 = 0
        var error: UnsafeMutablePointer<CChar>?
        let status = up_test_sinf_selector(sinf, sinf.count, &user, &key, &error)
        #expect(status == 1)
        #expect(user == 0xcb152649)
        #expect(key == 0x07)
    }

    @Test("缺少 user 原子时报确切错误")
    func reportsMissingAtom() {
        let sinf = Self.makeSINF(user: nil, key: 0x07)
        var error: UnsafeMutablePointer<CChar>?
        let status = up_test_sinf_selector(sinf, sinf.count, nil, nil, &error)
        #expect(status == 0)
        let message = error.map { String(cString: $0) } ?? ""
        #expect(message == "SINF requires one \"user\" atom, found 0")
        if let error {
            up_string_free(error)
        }
    }

    // MARK: 构造

    private static func makePack(version: UInt32) -> [UInt8] {
        let length: Int
        switch version {
        case 1: length = 8 + 4 + 4 + 32 + 16 + 16 + 16 * 256
        case 2: length = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256
        default: length = 8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + 16 * 256 + 27 * 16 + 16 * 256
        }
        var pack = [UInt8](repeating: 0, count: length)
        let magic: [UInt8] = version == 1 ? [0x46, 0x50, 0x53, 0x32, 0x36, 0x41, 0x34, 0x00]
            : version == 2 ? [0x46, 0x50, 0x53, 0x45, 0x4e, 0x52, 0x32, 0x00]
            : [0x46, 0x50, 0x53, 0x45, 0x4e, 0x52, 0x33, 0x00]
        pack.replaceSubrange(0..<8, with: magic)
        pack.replaceSubrange(8..<12, with: littleEndian(version))
        pack.replaceSubrange(12..<16, with: littleEndian(UInt32(length)))
        for index in 16..<48 {
            pack[index] = UInt8(index)
        }
        if version >= 2 {
            pack.replaceSubrange(48..<52, with: littleEndian(0xe03fe290))
            pack.replaceSubrange(52..<56, with: littleEndian(0x11))
        }
        let payload = version == 1 ? 48 : version == 2 ? 56 : 68
        if version == 3 {
            pack.replaceSubrange(56..<60, with: littleEndian(0))
            pack.replaceSubrange(60..<64, with: littleEndian(27 * 16))
            pack[64] = 0x5a
        }
        for index in 0..<16 {
            pack[payload + index] = UInt8(0xa0 + index)
        }
        // 每张表都写成恒等置换，满足 Go 版的逐表校验。
        let tableStarts: [Int] = version == 1
            ? [payload + 32]
            : version == 2 ? [payload + 32] : [payload + 16, payload + 16 + 4096 + 432]
        for start in tableStarts {
            for block in 0..<16 {
                for value in 0..<256 {
                    pack[start + block * 256 + value] = UInt8(value)
                }
            }
        }
        return pack
    }

    private static func makeSINF(user: UInt32?, key: UInt32) -> [UInt8] {
        var children: [UInt8] = []
        if let user {
            children += atom(type: "user", payload: bigEndian(user))
        }
        children += atom(type: "key ", payload: bigEndian(key))
        children += atom(type: "priv", payload: [0x11, 0x22, 0x33, 0x44])
        let schi = atom(type: "schi", payload: children)
        return atom(type: "sinf", payload: schi)
    }

    private static func atom(type: String, payload: [UInt8]) -> [UInt8] {
        let size = UInt32(8 + payload.count)
        return bigEndian(size) + Array(type.utf8) + payload
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    private static func littleEndian(_ value: UInt32) -> [UInt8] {
        [0, 8, 16, 24].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }
}
