// swift-tools-version: 6.0
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
            resources: [.copy("PrivacyInfo.xcprivacy")]
        ),
        .testTarget(
            name: "NineTests",
            dependencies: ["Nine"],
            path: "Tests/NineTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
