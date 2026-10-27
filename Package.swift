// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "UnfairPlayKit",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "UnfairPlayCore", targets: ["UnfairPlayCore"])
    ],
    targets: [
        .target(name: "UnfairPlayCore"),
        .testTarget(name: "UnfairPlayCoreTests", dependencies: ["UnfairPlayCore"])
    ]
)
