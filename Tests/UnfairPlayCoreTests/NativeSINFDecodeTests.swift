import CommonCrypto
import Foundation
import Testing

@testable import CUnfairPlay

/// SINF 解码的合成夹具，逐行对照 Go 的 `current_sinf_test.go`。
/// 这些夹具同时覆盖 v1/v2 白盒路径与 v3 变换路径，并断言失败闭合标记。
@Suite("C 核心：SINF 解码")
struct NativeSINFDecodeTests {
    private static let legacyKey: [UInt8] = [
        0x61, 0x19, 0xe4, 0x72, 0x0b, 0xce, 0x35, 0xa8,
        0xd7, 0x43, 0x9a, 0xf0, 0x26, 0x58, 0xbd, 0x8c,
    ]
    private static let whitening: [UInt8] = [
        0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f,
        0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x0e,
    ]
    private static let innerKey: [UInt8] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    ]
    private static let iv: [UInt8] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]

    @Test("v1 模型解开 SINF 并得到逻辑密钥")
    func decodesLegacyPack() {
        let (sinf, pack) = Self.legacyFixture(user: 0x10203040, key: 2, righBytes: 88, version: 1)
        let result = Self.resolve(sinf: sinf, pack: pack)
        #expect(result.status == 1)
        #expect(result.mismatch == 0)
        #expect(result.version == 1)
        #expect(result.logical == Self.logicalFromInnerKey(Self.innerKey))
    }

    @Test("v2 模型要求 selector 绑定匹配")
    func decodesSelectorBoundPack() {
        let (sinf, pack) = Self.legacyFixture(user: 0x10203040, key: 2, righBytes: 96)
        let result = Self.resolve(sinf: sinf, pack: pack)
        #expect(result.status == 1)
        #expect(result.logical == Self.logicalFromInnerKey(Self.innerKey))
    }

    @Test("selector 不匹配时明确拒绝")
    func rejectsSelectorMismatch() {
        let (sinf, _) = Self.legacyFixture(user: 0x10203040, key: 2, righBytes: 88)
        let pack = Self.legacyPack(version: 2, selector: (0x50607080, 2))
        let result = Self.resolve(sinf: sinf, pack: pack)
        #expect(result.status == 0)
        #expect(result.mismatch == 0)
        #expect(result.error.contains("enrollment model is bound to selector"))
    }

    @Test("被篡改的 priv 载荷标记为模型不匹配")
    func flagsTamperedPayload() {
        let (sinf, pack) = Self.legacyFixture(user: 0x90a0b0c0, key: 7, righBytes: 96)
        var mutated = sinf
        let privateStart = Self.privatePayloadOffset(mutated)
        mutated[privateStart + 31] ^= 1
        let result = Self.resolve(sinf: mutated, pack: pack)
        #expect(result.status == 0)
        #expect(result.mismatch == 1)
        #expect(result.error.hasPrefix("SINF does not match the selected FairPlay model"))
    }

    @Test("v3 模型解开 432 字节工作缓冲区")
    func decodesVersionThree() {
        let fixture = Self.versionThreeFixture(selector: (0x11223344, 2), innerKey: Self.innerKey)
        let result = Self.resolve(sinf: fixture.sinf, pack: fixture.pack)
        #expect(result.status == 1)
        #expect(result.mismatch == 0)
        #expect(result.version == 3)
        #expect(result.logical == Self.logicalFromInnerKey(Self.innerKey))
    }

    @Test("v3 载荷被篡改时标记为模型不匹配")
    func flagsTamperedVersionThree() {
        let fixture = Self.versionThreeFixture(selector: (0x11223344, 2), innerKey: Self.innerKey)
        var sinf = fixture.sinf
        let privateStart = Self.privatePayloadOffset(sinf)
        sinf[privateStart + 24] ^= 1
        let result = Self.resolve(sinf: sinf, pack: fixture.pack)
        #expect(result.status == 0)
        #expect(result.mismatch == 1)
    }

    // MARK: - 夹具构造

    private struct Resolution {
        let status: Int32
        let mismatch: Int32
        let version: UInt32
        let logical: [UInt8]
        let error: String
    }

    private static func resolve(sinf: [UInt8], pack: [UInt8]) -> Resolution {
        var logical = [UInt8](repeating: 0, count: 16)
        var version: UInt32 = 0
        var mismatch: Int32 = 0
        var error: UnsafeMutablePointer<CChar>?
        let status = up_test_resolve_logical_key(
            sinf, sinf.count, pack, pack.count, &logical, &version, &mismatch, &error
        )
        let message = error.map { String(cString: $0) } ?? ""
        if let error {
            up_string_free(error)
        }
        return Resolution(
            status: status, mismatch: mismatch, version: version, logical: logical, error: message
        )
    }

    private static func legacyFixture(
        user: UInt32, key: UInt32, righBytes: Int, version: UInt32 = 2
    ) -> (sinf: [UInt8], pack: [UInt8]) {
        let plaintext = Self.legacyPlaintext(righBytes: righBytes, innerKey: Self.innerKey)
        let trailerBytes = plaintext.count % 16
        let ciphertextBytes = plaintext.count - trailerBytes
        let ciphertext = Self.cbcEncrypt(
            Array(plaintext[0..<ciphertextBytes]), key: Self.legacyKey, iv: Self.iv
        )
        let logicalPayload = Self.iv + ciphertext
        var protected = [UInt8](repeating: 0, count: logicalPayload.count + trailerBytes)
        for (index, value) in logicalPayload.enumerated() {
            let position = index % 16
            let external = value ^ UInt8(truncatingIfNeeded: position &* 17)
            protected[index] = external ^ Self.whitening[position]
        }
        let sinf = Self.sinf(
            user: user, key: key, privatePayload: protected
        )
        let pack = Self.legacyPack(version: version, selector: (user, key))
        return (sinf, pack)
    }

    private static func legacyPlaintext(righBytes: Int, innerKey: [UInt8]) -> [UInt8] {
        let types = ["key ", "iviv", "tmpr", "righ", "name"]
        let sizes = [24, 24, 24, righBytes, 264]
        var plaintext: [UInt8] = []
        for (index, type) in types.enumerated() {
            var payload = [UInt8](repeating: 0, count: sizes[index] - 8)
            if index == 0 {
                payload.replaceSubrange(0..<16, with: innerKey)
            }
            plaintext += Self.atom(type: type, payload: payload)
        }
        return plaintext
    }

    private static func legacyPack(version: UInt32, selector: (UInt32, UInt32)) -> [UInt8] {
        let length = version == 1
            ? 8 + 4 + 4 + 32 + 16 + 16 + 16 * 256
            : 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256
        var pack = [UInt8](repeating: 0, count: length)
        let magic = version == 1
            ? Array("FPSENR1\0".utf8)
            : Array("FPSENR2\0".utf8)
        pack.replaceSubrange(0..<8, with: magic)
        pack.replaceSubrange(8..<12, with: littleEndian(version))
        pack.replaceSubrange(12..<16, with: littleEndian(UInt32(length)))
        for index in 0..<32 {
            pack[16 + index] = UInt8(index + 1)
        }
        var cursor = 48
        if version == 2 {
            pack.replaceSubrange(48..<52, with: littleEndian(selector.0))
            pack.replaceSubrange(52..<56, with: littleEndian(selector.1))
            cursor = 56
        }
        pack.replaceSubrange(cursor..<(cursor + 16), with: legacyKey)
        cursor += 16
        pack.replaceSubrange(cursor..<(cursor + 16), with: whitening)
        cursor += 16
        for position in 0..<16 {
            for value in 0..<256 {
                pack[cursor + position * 256 + value] =
                    UInt8(truncatingIfNeeded: value ^ (position * 17))
            }
        }
        return pack
    }

    private static func sinf(user: UInt32, key: UInt32, privatePayload: [UInt8]) -> [UInt8] {
        var fields: [UInt8] = []
        fields += atom(type: "user", payload: bigEndian(user))
        fields += atom(type: "key ", payload: bigEndian(key))
        fields += atom(type: "priv", payload: privatePayload)
        return atom(type: "sinf", payload: atom(type: "schi", payload: fields))
    }

    private struct VersionThreeFixture {
        let sinf: [UInt8]
        let pack: [UInt8]
    }

    private static func versionThreeFixture(
        selector: (UInt32, UInt32), innerKey: [UInt8]
    ) -> VersionThreeFixture {
        var privatePayload = [UInt8](repeating: 0, count: 440)
        for index in 0..<privatePayload.count {
            privatePayload[index] = UInt8(truncatingIfNeeded: index * 29 + 7)
        }
        var fields: [UInt8] = []
        fields += atom(type: "user", payload: bigEndian(selector.0))
        fields += atom(type: "key ", payload: bigEndian(selector.1))
        fields += atom(type: "iviv", payload: [UInt8](repeating: 0, count: 16))
        fields += atom(type: "righ", payload: [UInt8](repeating: 0, count: 80))
        fields += atom(type: "name", payload: [UInt8](repeating: 0, count: 256))
        fields += atom(type: "priv", payload: privatePayload)
        var children: [UInt8] = []
        children += atom(type: "frma", payload: Array("game".utf8))
        children += atom(type: "schm", payload: [UInt8](repeating: 0, count: 12))
        children += atom(type: "schi", payload: fields)
        children += atom(type: "sign", payload: [UInt8](repeating: 0, count: 128))
        let sinf = atom(type: "sinf", payload: children)

        var plaintext = [UInt8](repeating: 0, count: 432)
        plaintext.replaceSubrange(0..<4, with: Array("itun".utf8))
        plaintext.replaceSubrange(4..<8, with: bigEndian(12))
        plaintext.replaceSubrange(8..<12, with: Array("vers".utf8))
        plaintext.replaceSubrange(12..<16, with: bigEndian(1))
        let layout: [(offset: Int, size: UInt32, type: String)] = [
            (16, 24, "key "), (40, 24, "iviv"), (64, 24, "tmpr"), (88, 88, "righ"),
            (176, 264, "name"),
        ]
        for field in layout {
            plaintext.replaceSubrange(
                field.offset..<(field.offset + 4), with: bigEndian(field.size)
            )
            plaintext.replaceSubrange(
                (field.offset + 4)..<(field.offset + 8), with: Array(field.type.utf8)
            )
        }
        plaintext.replaceSubrange(24..<40, with: innerKey)

        var pack = [UInt8](repeating: 0, count: 8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16
            + 16 * 256 + 432 + 16 * 256)
        pack.replaceSubrange(0..<8, with: Array("FPSENR3\0".utf8))
        pack.replaceSubrange(8..<12, with: littleEndian(3))
        pack.replaceSubrange(12..<16, with: littleEndian(UInt32(pack.count)))
        for index in 16..<48 {
            pack[index] = UInt8(index)
        }
        pack.replaceSubrange(48..<52, with: littleEndian(selector.0))
        pack.replaceSubrange(52..<56, with: littleEndian(selector.1))
        pack.replaceSubrange(60..<64, with: littleEndian(432))
        pack[64] = 0x98
        pack.replaceSubrange(68..<84, with: legacyKey)

        var cursor = 84
        for position in 0..<16 {
            for value in 0..<256 {
                pack[cursor + position * 256 + value] = UInt8(truncatingIfNeeded: value)
            }
        }
        cursor += 16 * 256

        let privateStart = privatePayloadOffset(sinf)
        let sourceOffset = privateStart + 24
        pack.replaceSubrange(56..<60, with: littleEndian(UInt32(sourceOffset)))
        let source = Array(sinf[sourceOffset..<sourceOffset + 432])
        let internalState = cbcDecryptBlocks(source, key: legacyKey)
        for index in 0..<432 {
            pack[cursor + index] = internalState[index] ^ plaintext[index] ^ pack[64]
        }
        cursor += 432
        for position in 0..<16 {
            for value in 0..<256 {
                pack[cursor + position * 256 + value] = UInt8(truncatingIfNeeded: value)
            }
        }
        return VersionThreeFixture(sinf: sinf, pack: pack)
    }

    /// 返回 `priv` 原子载荷的起始偏移，与 C 侧解析结果等价。
    private static func privatePayloadOffset(_ sinf: [UInt8]) -> Int {
        let rootSize = Int(be32(sinf, 0))
        precondition(rootSize == sinf.count)
        var cursor = 8
        while cursor + 8 <= rootSize {
            let size = Int(be32(sinf, cursor))
            let type = String(decoding: sinf[(cursor + 4)..<(cursor + 8)], as: UTF8.self)
            if type == "schi" {
                var field = cursor + 8
                while field + 8 <= cursor + size {
                    let fieldSize = Int(be32(sinf, field))
                    let fieldType = String(
                        decoding: sinf[(field + 4)..<(field + 8)], as: UTF8.self
                    )
                    if fieldType == "priv" {
                        return field + 8
                    }
                    field += fieldSize
                }
            }
            cursor += size
        }
        preconditionFailure("priv atom not found")
    }

    private static func be32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }

    private static func logicalFromInnerKey(_ inner: [UInt8]) -> [UInt8] {
        var logical = [UInt8](repeating: 0, count: 16)
        for word in 0..<4 {
            let base = word * 4
            let decoded = UInt32(inner[base]) << 24 | UInt32(inner[base + 1]) << 16
                | UInt32(inner[base + 2]) << 8 | UInt32(inner[base + 3])
            let mixed = decoded &+ UInt32(13 + word) &* 0xa6b13d89
            logical[base] = UInt8(truncatingIfNeeded: mixed)
            logical[base + 1] = UInt8(truncatingIfNeeded: mixed >> 8)
            logical[base + 2] = UInt8(truncatingIfNeeded: mixed >> 16)
            logical[base + 3] = UInt8(truncatingIfNeeded: mixed >> 24)
        }
        return logical
    }

    private static func atom(type: String, payload: [UInt8]) -> [UInt8] {
        bigEndian(UInt32(8 + payload.count)) + Array(type.utf8) + payload
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    private static func littleEndian(_ value: UInt32) -> [UInt8] {
        [0, 8, 16, 24].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    // MARK: - AES

    private static func cbcEncrypt(_ plaintext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        aes(operation: kCCEncrypt, input: plaintext, key: key, iv: iv)
    }

    private static func cbcDecryptBlocks(_ ciphertext: [UInt8], key: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        var index = 0
        while index < ciphertext.count {
            let block = Array(ciphertext[index..<(index + 16)])
            let zeroIV = [UInt8](repeating: 0, count: 16)
            output += aes(operation: kCCDecrypt, input: block, key: key, iv: zeroIV)
            index += 16
        }
        return output
    }

    private static func aes(
        operation: Int, input: [UInt8], key: [UInt8], iv: [UInt8]
    ) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: input.count)
        var moved = 0
        let status: CCCryptorStatus = input.withUnsafeBytes { inputBytes in
            iv.withUnsafeBytes { ivBytes in
                key.withUnsafeBytes { keyBytes in
                    output.withUnsafeMutableBytes { outputBytes in
                        CCCrypt(
                            CCOperation(operation),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBytes.baseAddress,
                            16,
                            ivBytes.baseAddress,
                            inputBytes.baseAddress,
                            input.count,
                            outputBytes.baseAddress,
                            input.count,
                            &moved
                        )
                    }
                }
            }
        }
        precondition(status == CCCryptorStatus(kCCSuccess) && moved == input.count)
        return output
    }
}
