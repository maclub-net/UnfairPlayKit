# UnfairPlayKit

[English](README.md) · **简体中文**

macOS 上的 FairPlay 工具包，API 与上游 Go 版 `unfairplay` CLI 对齐。核心逻辑在
`CUnfairPlay`（纯 C，无外部依赖，除 `libz`），`UnfairPlayCore` 提供 Swift
封装、模型目录管理与原生 enrollment 流程。

- 进程内引擎：不再需要外部的 `unfairplay` 可执行文件，也不启动子进程。
- 同一套方法签名与 JSON 契约：`UnfairPlayCLI`（子进程）与
  `UnfairPlayNativeCLI`（进程内）都实现 `UnfairPlayClient`，可互换。

## 系统要求

- macOS 14 或更高
- Swift 6.0 工具链

## 安装

```swift
.package(url: "https://github.com/maclub-net/UnfairPlayKit.git", from: "0.2.0")
```

按需引入 `UnfairPlayCore`（Swift 层，含资源）或 `CUnfairPlay`（C API）。

## 功能

### IPA 预检与解密

```swift
import UnfairPlayCore

let cli = UnfairPlayNativeCLI()

// 预检：显式目录必须存在；nil 表示本次不加载模型
let report = try await cli.doctor(ipa: ipaURL, modelDirectory: modelDirectory)

// 解密：modelDirectory 为 nil 时按上游 CLI 规则回落到默认目录
let result = try await cli.decrypt(
    input: ipaURL,
    output: outputURL,
    report: reportURL,
    modelDirectory: modelDirectory
)
```

需要旧的子进程行为时改用 `UnfairPlayCLI(binaryPath:)`，调用方式相同。

### 获取 IPA

砸壳的 IPA 包可以通过 Mac 俱乐部网站下载：<https://www.maclub.net>。上面的解密
流程也接受你自己持有的加密 IPA，因此也可以在本地解密。

### Enrollment 模型（原生）

`UnfairPlaySetup` 分四个阶段，与 Go 版的 `validate → capture → recovery → install`
一一对应：

| 阶段 | 方法 | 权限 |
| --- | --- | --- |
| 校验 | `validate(options:)` | 普通用户 |
| 采集 | `capture(options:captureDirectory:owner:)` | 需要 root |
| 恢复 | `recover(capture:options:)` | 普通用户 |
| 安装 | `installModel(directory:selector:model:owner:)` | 普通用户 |

一次跑完（不含解密校验）：

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

采集会读取 `/private/var/db/fpsd`，因此需要以 root 运行；传入 `owner` 可把整个
采集目录交还给该账号。模型写入 `UnfairPlaySetupOptions.modelDirectoryURL`。

#### 模型命名

```
<selector>-<sha256>.bin
```

selector 中的 `:` 替换为 `-`。目录权限 0700、文件权限 0600；已存在同名且内容
相同的模型时直接复用。

#### 采集目录

```
capture/
  manifest.json            # schema: unfairplay-native-enrollment-capture-v1
  app/                     # 安装包内的 SINF / SUPF 等
  state/                   # /private/var/db/fpsd 下的状态文件
  hardware/iomac.bin       # 由 IORegistry 读取的 MAC（hardwareInterface，默认 en0）
  fairplayd/fairplayd.arm64e
  ipa/                     # 原始 IPA 中的匹配 SINF
```

App Store 的 iOS App 在 Apple Silicon 上以 `Wrapper/<name>.app` 嵌套安装，
`SC_Info` 位于内层 bundle，`validate` 会自动识别。

### 模型目录

`UnfairPlayModelStore` 扫描模型目录：超过 256 个模型、权限不是 0700、或存在
非 0600 的文件时，整体判定不可用。

```swift
let store = UnfairPlayModelStore(directoryURL: modelDirectory)
let report = store.scan()
```

## 包结构

```
Sources/
  CUnfairPlay/          C 核心：IPA/ZIP、SINF/SUPF、Mach-O、license、模型、解密、recovery
  UnfairPlayCore/       Swift API、manifest、模型目录、原生 setup/recovery
    Resources/          recovery 解释器资产（模型、compact CFG、frame、kernels）
Tests/UnfairPlayCoreTests/
```

## 开发

```sh
swift build
swift test
```

测试使用合成 fixture；账号级产物（`*.ipa`、`*.sinf`、`*.supf`、硬件 MAC 等）
不入库，见 `.gitignore`。`Sources/UnfairPlayCore/Resources/` 下的解释器资产是
包资源，随包发布。

## 声明

本包用于在自有设备上处理合法获取的内容。请遵守所在地法律及 Apple 的许可条款，
不要用它绕过你无权访问的 DRM 保护。
