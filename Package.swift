// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SerbianEIDSigner",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SignerCore", targets: ["SignerCore"]),
        .executable(name: "SignerApp", targets: ["SignerApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.65.0"),
    ],
    targets: [
        .systemLibrary(name: "CLibXML2", path: "Sources/CLibXML2"),
        .target(
            name: "SignerCore",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOWebSocket", package: "swift-nio"),
                "CLibXML2",
            ]
        ),
        .executableTarget(name: "SignerApp", dependencies: ["SignerCore"]),
        .testTarget(name: "SignerCoreTests", dependencies: ["SignerCore"]),
    ]
)
