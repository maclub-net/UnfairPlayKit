# UnfairPlayKit

**English** · [简体中文](README.zh-CN.md)

A FairPlay toolkit for macOS. Its API mirrors the upstream Go `unfairplay` CLI.
The core lives in `CUnfairPlay` (plain C, no dependencies beyond `libz`), and
`UnfairPlayCore` provides the Swift wrappers, model-directory handling, and the
native enrollment pipeline.

- In-process engine: no external `unfairplay` binary and no child processes.
- One set of method signatures and JSON contracts: `UnfairPlayCLI` (subprocess)
  and `UnfairPlayNativeCLI` (in-process) both implement `UnfairPlayClient`, so
  they are interchangeable.

## Requirements

- macOS 14 or later
- Swift 6.0 toolchain

## Installation

```swift
.package(url: "https://github.com/maclub-net/UnfairPlayKit.git", from: "0.2.0")
```

Import `UnfairPlayCore` for the Swift layer (including resources) or
`CUnfairPlay` for the C API.

## Usage

### IPA validation and decryption

```swift
import UnfairPlayCore

let cli = UnfairPlayNativeCLI()

// Validation: an explicit directory must exist; nil skips model loading.
let report = try await cli.doctor(ipa: ipaURL, modelDirectory: modelDirectory)

// Decryption: a nil modelDirectory falls back to the upstream CLI default.
let result = try await cli.decrypt(
    input: ipaURL,
    output: outputURL,
    report: reportURL,
    modelDirectory: modelDirectory
)
```

Use `UnfairPlayCLI(binaryPath:)` when you need the old subprocess behavior; the
calls are identical.

### Obtaining IPAs

Decrypted (砸壳) IPA packages can be downloaded from the Mac Club website:
<https://www.maclub.net>. The decryption path above accepts the encrypted IPAs
you already own, so you can also decrypt them locally.

### Enrollment models

`UnfairPlaySetup` has four stages that map one-to-one onto the Go
`validate → capture → recovery → install` pipeline:

| Stage | Method | Privileges |
| --- | --- | --- |
| Validate | `validate(options:)` | User |
| Capture | `capture(options:captureDirectory:owner:)` | root |
| Recover | `recover(capture:options:)` | User |
| Install | `installModel(directory:selector:model:owner:)` | User |

Run the whole pipeline at once (decryption validation excluded):

```swift
let options = UnfairPlaySetupOptions(
    appURL: URL(fileURLWithPath: "/Applications/Foo.app"),
    ipaURL: ipaURL,
    modelDirectoryURL: modelDirectory
)

let capture = try UnfairPlaySetup.run(
    options: options,
    captureDirectory: captureURL
)
```

Capture reads `/private/var/db/fpsd`, so it must run as root. Pass `owner` to
hand the whole capture tree back to that account. The model is written to
`UnfairPlaySetupOptions.modelDirectoryURL`.

#### Model naming

```
<selector>-<sha256>.bin
```

Colons in the selector become dashes. The directory is 0700 and each file is
0600; an existing identical model is reused.

#### Capture layout

```
capture/
  manifest.json            # schema: unfairplay-native-enrollment-capture-v1
  app/                     # SINF / SUPF from the installed bundle
  state/                   # state files under /private/var/db/fpsd
  hardware/iomac.bin       # MAC read via IORegistry (hardwareInterface, en0)
  fairplayd/fairplayd.arm64e
  ipa/                     # the matching SINF from the original IPA
```

App Store iOS apps on Apple silicon are nested as `Wrapper/<name>.app`, with
`SC_Info` inside the inner bundle; `validate` detects this automatically.

### Model directory

`UnfairPlayModelStore` scans a model directory. It is reported unusable as a
whole when there are more than 256 models, the directory is not 0700, or any
file is accessible beyond 0600.

```swift
let store = UnfairPlayModelStore(directoryURL: modelDirectory)
let report = store.scan()
```

## Package layout

```
Sources/
  CUnfairPlay/          C core: IPA/ZIP, SINF/SUPF, Mach-O, license, models, decrypt, recovery
  UnfairPlayCore/       Swift API, manifest, model store, native setup/recovery
    Resources/          recovery interpreter assets (model, compact CFG, frame, kernels)
Tests/UnfairPlayCoreTests/
```

## Development

```sh
swift build
swift test
```

Tests use synthetic fixtures. Account-level artifacts (`*.ipa`, `*.sinf`,
`*.supf`, hardware MACs, and so on) are never committed; see `.gitignore`. The
interpreter assets under `Sources/UnfairPlayCore/Resources/` are package
resources and ship with the package.

## Notice

Use this package only for content you lawfully obtained on hardware you own.
Follow the laws of your jurisdiction and Apple's license terms; do not use it to
bypass DRM you are not entitled to remove.
