// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "UnfairPlayKit",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "UnfairPlayCore", targets: ["UnfairPlayCore"]),
        .library(name: "CUnfairPlay", targets: ["CUnfairPlay"])
    ],
    targets: [
        .target(
            name: "CUnfairPlay",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedLibrary("z")
            ]
        ),
        .target(
            name: "UnfairPlayCore",
            dependencies: ["CUnfairPlay"],
            resources: [
                .copy("Resources")
            ]
        ),
        .testTarget(
            name: "UnfairPlayCoreTests",
            dependencies: ["UnfairPlayCore", "CUnfairPlay"]
        )
    ]
)
