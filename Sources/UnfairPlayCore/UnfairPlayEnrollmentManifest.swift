import Foundation

/// Validation metadata for the captured `fairplayd` build. Field names and
/// values mirror `FairPlayBuildSupport` in the Go capture so a capture can be
/// compared side by side with the reference implementation.
public struct UnfairPlayFairPlaySupport: Codable, Sendable, Equatable {
    public var profile: String
    public var build: String
    public var status: String
    public var validationBasis: String?
    public var recovery: Bool
    public var decrypt: Bool
    public var evaluatorProfile: String?
    public var evaluatorSHA256: String?

    public init(
        profile: String,
        build: String,
        status: String,
        validationBasis: String?,
        recovery: Bool,
        decrypt: Bool,
        evaluatorProfile: String?,
        evaluatorSHA256: String?
    ) {
        self.profile = profile
        self.build = build
        self.status = status
        self.validationBasis = validationBasis
        self.recovery = recovery
        self.decrypt = decrypt
        self.evaluatorProfile = evaluatorProfile
        self.evaluatorSHA256 = evaluatorSHA256
    }

    enum CodingKeys: String, CodingKey {
        case profile
        case build
        case status
        case validationBasis = "validation_basis"
        case recovery
        case decrypt = "end_to_end_decryption"
        case evaluatorProfile = "evaluator_profile"
        case evaluatorSHA256 = "evaluator_source_sha256"
    }
}

/// `unfairplay-native-enrollment-capture-v1` manifest, field-compatible with
/// `EnrollmentCaptureManifest` in `internal/fairplay/enrollment_capture.go`.
public struct UnfairPlayEnrollmentManifest: Codable, Sendable {
    public struct File: Codable, Sendable, Equatable {
        public let path: String
        public let bytes: Int64
        public let sha256: String
        public let mode: String

        public init(path: String, bytes: Int64, sha256: String, mode: String) {
            self.path = path
            self.bytes = bytes
            self.sha256 = sha256
            self.mode = mode
        }
    }

    public struct Selector: Codable, Sendable, Equatable {
        public let user: UInt32
        public let key: UInt32

        public init(user: UInt32, key: UInt32) {
            self.user = user
            self.key = key
        }

        /// Parses `%08x:%08x`, returning nil for anything else.
        public init?(identifier: String) {
            let parts = identifier.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let user = UInt32(parts[0], radix: 16),
                  let key = UInt32(parts[1], radix: 16) else {
                return nil
            }
            self.user = user
            self.key = key
        }

        public var identifier: String {
            String(format: "%08x:%08x", user, key)
        }
    }

    public struct App: Codable, Sendable, Equatable {
        public let bundleIdentifier: String
        public let executable: String
        public let executablePath: String
        public let selector: Selector
        public let selectorID: String
        public let sinfPath: String
        public let targetSINFPath: String
        public let ipaMemberRoot: String

        public init(
            bundleIdentifier: String,
            executable: String,
            executablePath: String,
            selector: Selector,
            selectorID: String,
            sinfPath: String,
            targetSINFPath: String,
            ipaMemberRoot: String
        ) {
            self.bundleIdentifier = bundleIdentifier
            self.executable = executable
            self.executablePath = executablePath
            self.selector = selector
            self.selectorID = selectorID
            self.sinfPath = sinfPath
            self.targetSINFPath = targetSINFPath
            self.ipaMemberRoot = ipaMemberRoot
        }

        enum CodingKeys: String, CodingKey {
            case bundleIdentifier = "bundle_identifier"
            case executable
            case executablePath = "executable_path"
            case selector
            case selectorID = "selector_id"
            case sinfPath = "sinf_path"
            case targetSINFPath = "target_sinf_path"
            case ipaMemberRoot = "ipa_member_root"
        }
    }

    public let schema: String
    public let createdAt: String
    public let productVersion: String
    public let buildVersion: String
    public let fairplayd: File
    public let enrollmentSupport: UnfairPlayFairPlaySupport
    public let hardwareMAC: File
    public let app: App
    public let ipa: File?
    public let files: [File]
    public let warnings: [String]

    public init(
        schema: String,
        createdAt: String,
        productVersion: String,
        buildVersion: String,
        fairplayd: File,
        enrollmentSupport: UnfairPlayFairPlaySupport,
        hardwareMAC: File,
        app: App,
        ipa: File?,
        files: [File],
        warnings: [String]
    ) {
        self.schema = schema
        self.createdAt = createdAt
        self.productVersion = productVersion
        self.buildVersion = buildVersion
        self.fairplayd = fairplayd
        self.enrollmentSupport = enrollmentSupport
        self.hardwareMAC = hardwareMAC
        self.app = app
        self.ipa = ipa
        self.files = files
        self.warnings = warnings
    }

    enum CodingKeys: String, CodingKey {
        case schema
        case createdAt = "created_at"
        case productVersion = "product_version"
        case buildVersion = "build_version"
        case fairplayd
        case enrollmentSupport = "enrollment_support"
        case hardwareMAC = "hardware_iomac"
        case app
        case ipa
        case files
        case warnings
    }
}

extension JSONEncoder {
    /// Two-space indentation like `json.MarshalIndent`, without escaping slashes
    /// so member paths stay readable.
    static var pretty: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        return encoder
    }
}
