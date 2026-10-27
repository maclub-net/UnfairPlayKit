import Foundation
import Testing

@testable import CUnfairPlay

/// ZIP 读写与 SUPF 页 key 表的回归测试。
/// ZIP 侧同时覆盖 store/deflate、整段读取、前缀读取与 `add_raw` 复制；
/// SUPF 侧的几何校验逐条对照 `internal/fairplay/supf.go`。
@Suite("C 核心：ZIP 与 SUPF")
struct NativeArchiveTests {
    // MARK: - ZIP

    @Test("写入、读取并原样复制成员")
    func roundTripsArchive() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("UnfairPlayKitZip-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = directory.appendingPathComponent("first.zip")
        let copy = directory.appendingPathComponent("copy.zip")

        var payload: [UInt8] = []
        for index in 0..<8192 {
            payload.append(UInt8(truncatingIfNeeded: index &* 31 &+ (index >> 3)))
        }

        var error: UnsafeMutablePointer<CChar>?
        let status: Int32 = first.path.withCString { firstPath in
            copy.path.withCString { copyPath in
                payload.withUnsafeBufferPointer { buffer in
                    up_test_zip_round_trip(
                        firstPath, copyPath, buffer.baseAddress, buffer.count, &error
                    )
                }
            }
        }
        let message = error.map { String(cString: $0) } ?? ""
        if let error {
            up_string_free(error)
        }
        #expect(status == 1, "\(message)")
        #expect(Self.fileSize(first) > 0)
        #expect(Self.fileSize(copy) > 0)
    }

    // MARK: - SUPF

    @Test("variant 5 读出两个架构的页 key")
    func readsVersionFiveArchitectures() {
        let arm64 = Self.records(count: 3, seed: 0x10)
        let arm64e = Self.records(count: 2, seed: 0x90)
        let blob = Self.supf(variant: 5, architectures: [
            (0x0100_000c, 0, arm64),
            (0x0100_000c, 0x8000_0002, arm64e),
        ])

        let first = Self.lookup(blob: blob, cpuType: 0x0100_000c, cpuSubtype: 0)
        #expect(first.status == 1)
        #expect(first.architectureCount == 2)
        #expect(first.recordCount == 3)
        #expect(first.payload == arm64.flatMap { $0 })

        let second = Self.lookup(blob: blob, cpuType: 0x0100_000c, cpuSubtype: 0x8000_0002)
        #expect(second.status == 1)
        #expect(second.recordCount == 2)
        #expect(second.payload == arm64e.flatMap { $0 })
    }

    @Test("variant 3 跳过 20 字节扩展区")
    func readsVersionThreeArchitectures() {
        let table = Self.records(count: 1, seed: 0x40)
        let blob = Self.supf(variant: 3, architectures: [(0x0100_000c, 0, table)])
        let lookup = Self.lookup(blob: blob, cpuType: 0x0100_000c, cpuSubtype: 0)
        #expect(lookup.status == 1)
        #expect(lookup.payload == table.flatMap { $0 })
    }

    @Test("缺少架构时报告与 Go 相同的文案")
    func reportsMissingArchitecture() {
        let blob = Self.supf(variant: 5, architectures: [(0x0100_000c, 0, [])])
        let lookup = Self.lookup(blob: blob, cpuType: 0x0200_000c, cpuSubtype: 0)
        #expect(lookup.status == 0)
        #expect(lookup.error == "SUPF has no matching architecture 0x200000c/0x0")
    }

    @Test("几何异常逐条失败闭合")
    func rejectsMalformedGeometry() {
        let truncated = Self.lookup(blob: [0, 0, 0], cpuType: 0, cpuSubtype: 0)
        #expect(truncated.status == 0)
        #expect(truncated.error == "SUPF is truncated")

        var unsupported = [UInt8](repeating: 0, count: 12)
        unsupported[0] = 4
        unsupported.replaceSubrange(4..<8, with: Self.bigEndian(4))
        unsupported.replaceSubrange(8..<12, with: Self.bigEndian(1))
        #expect(Self.lookup(blob: unsupported, cpuType: 0, cpuSubtype: 0).error
            == "unsupported SUPF variant 4")

        let emptyCount = Self.lookup(blob: Self.supf(variant: 5, architectures: []), cpuType: 0, cpuSubtype: 0)
        #expect(emptyCount.error == "SUPF architecture count is invalid")

        var oversized = [UInt8](repeating: 0, count: 12)
        oversized[0] = 5
        oversized.replaceSubrange(4..<8, with: Self.bigEndian(4096))
        oversized.replaceSubrange(8..<12, with: Self.bigEndian(1))
        #expect(Self.lookup(blob: oversized, cpuType: 0, cpuSubtype: 0).error
            == "SUPF outer payload exceeds file")

        var shortLength = [UInt8](repeating: 0, count: 12)
        shortLength[0] = 5
        shortLength.replaceSubrange(4..<8, with: Self.bigEndian(4))
        shortLength.replaceSubrange(8..<12, with: Self.bigEndian(1))
        #expect(Self.lookup(blob: shortLength, cpuType: 0, cpuSubtype: 0).error
            == "SUPF architecture length is truncated")

        let geometry = Self.supfEntry(
            variant: 5, cpuType: 0x0100_000c, cpuSubtype: 0, pages: 1, records: Self.records(count: 1, seed: 0),
            declaredLength: 4
        )
        #expect(Self.lookup(blob: Self.wrap(variant: 5, entries: [geometry], declaredCount: 1),
                            cpuType: 0, cpuSubtype: 0).error
            == "SUPF architecture has invalid geometry")

        let truncatedPages = Self.supfEntry(
            variant: 3, cpuType: 0x0100_000c, cpuSubtype: 0, pages: 0, records: [],
            declaredLength: 28
        )
        #expect(Self.lookup(blob: Self.wrap(variant: 3, entries: [truncatedPages], declaredCount: 1),
                            cpuType: 0, cpuSubtype: 0).error
            == "SUPF page count is truncated")

        let inconsistent = Self.supfEntry(
            variant: 5, cpuType: 0x0100_000c, cpuSubtype: 0, pages: 2,
            records: Self.records(count: 1, seed: 0), declaredLength: nil
        )
        #expect(Self.lookup(blob: Self.wrap(variant: 5, entries: [inconsistent], declaredCount: 1),
                            cpuType: 0, cpuSubtype: 0).error
            == "SUPF page-key table has inconsistent length")

        let leftover = Self.supfEntry(
            variant: 5, cpuType: 0x0100_000c, cpuSubtype: 0, pages: 1,
            records: Self.records(count: 1, seed: 0), declaredLength: nil
        )
        let padded = Self.withTrailing(
            Self.wrap(variant: 5, entries: [leftover], declaredCount: 1), bytes: [0, 0, 0, 0]
        )
        #expect(Self.lookup(blob: padded, cpuType: 0, cpuSubtype: 0).error
            == "SUPF records do not fill outer payload")
    }

    // MARK: - 构造与读取

    private struct Lookup {
        let status: Int32
        let payload: [UInt8]
        let recordCount: Int
        let architectureCount: Int
        let error: String
    }

    private static func lookup(
        blob: [UInt8], cpuType: UInt32, cpuSubtype: UInt32
    ) -> Lookup {
        var output = [UInt8](repeating: 0, count: 4096)
        var recordCount = 0
        var architectureCount = 0
        var error: UnsafeMutablePointer<CChar>?
        let status: Int32 = blob.withUnsafeBufferPointer { blobBuffer in
            output.withUnsafeMutableBufferPointer { outputBuffer in
                up_test_supf_records(
                    blobBuffer.baseAddress, blob.count, cpuType, cpuSubtype,
                    outputBuffer.baseAddress, outputBuffer.count,
                    &recordCount, &architectureCount, &error
                )
            }
        }
        let message = error.map { String(cString: $0) } ?? ""
        if let error {
            up_string_free(error)
        }
        let used = status == 1 ? Array(output[0..<(recordCount * 32)]) : []
        return Lookup(
            status: status,
            payload: used,
            recordCount: recordCount,
            architectureCount: architectureCount,
            error: message
        )
    }

    private static func records(count: Int, seed: Int) -> [[UInt8]] {
        (0..<count).map { page in
            (0..<32).map { offset in
                UInt8(truncatingIfNeeded: seed + page * 7 + offset * 3)
            }
        }
    }

    private static func supf(
        variant: UInt8,
        architectures: [(UInt32, UInt32, [[UInt8]])]
    ) -> [UInt8] {
        let entries = architectures.map { architecture in
            supfEntry(
                variant: variant, cpuType: architecture.0, cpuSubtype: architecture.1,
                pages: UInt32(architecture.2.count), records: architecture.2,
                declaredLength: nil
            )
        }
        return wrap(
            variant: variant, entries: entries,
            declaredCount: UInt32(architectures.count)
        )
    }

    /// 构造单条架构记录。`declaredLength` 允许写入与内容不符的长度字段。
    private static func supfEntry(
        variant: UInt8,
        cpuType: UInt32,
        cpuSubtype: UInt32,
        pages: UInt32,
        records: [[UInt8]],
        declaredLength: UInt32?
    ) -> [UInt8] {
        var body = bigEndian(cpuType) + bigEndian(cpuSubtype)
        if variant == 3 {
            body += [UInt8](repeating: 0x5a, count: 20)
        }
        body += bigEndian(pages)
        for record in records {
            precondition(record.count == 32)
            body += record
        }
        return bigEndian(declaredLength ?? UInt32(body.count)) + body
    }

    private static func wrap(variant: UInt8, entries: [[UInt8]], declaredCount: UInt32) -> [UInt8] {
        var body = bigEndian(declaredCount)
        for entry in entries {
            body += entry
        }
        var blob = [UInt8](repeating: 0, count: 8)
        blob[0] = variant
        blob.replaceSubrange(4..<8, with: bigEndian(UInt32(body.count)))
        return blob + body
    }

    /// 追加未声明的尾部字节，并同步外层长度字段。
    private static func withTrailing(_ blob: [UInt8], bytes: [UInt8]) -> [UInt8] {
        var result = blob + bytes
        result.replaceSubrange(4..<8, with: bigEndian(UInt32(result.count - 8)))
        return result
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> UInt32($0)) }
    }

    private static func fileSize(_ url: URL) -> Int {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.size] as? Int) ?? 0
    }
}
