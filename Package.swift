// swift-tools-version: 5.9
// Swift 5.9 and 5.10 toolchains read this manifest; Swift 6 toolchains read Package@swift-6.0.swift.
import PackageDescription

let package = Package(
    name: "Nine",
    platforms: [.iOS(.v15), .macOS(.v12), .macCatalyst(.v15), .visionOS(.v1)],
    products: [
        .library(name: "Nine", targets: ["Nine"]),
    ],
    targets: [
        .target(
            name: "Nine",
            path: "Sources/Nine",
            resources: [.copy("PrivacyInfo.xcprivacy")],
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]
        ),
        .testTarget(
            name: "NineTests",
            dependencies: ["Nine"],
            path: "Tests/NineTests",
            swiftSettings: [.enableExperimentalFeature("StrictConcurrency")]
        ),
    ]
)
