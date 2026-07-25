// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "flutter_vless",
    platforms: [
        .iOS("15.0")
    ],
    products: [
        .library(name: "flutter-vless", targets: ["flutter_vless"]),
        .library(name: "flutter-vless-tunnel-support", targets: ["flutter_vless_tunnel_support"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework"),
        .package(path: "../../../../Tun2SocksKit")
    ],
    targets: [
        .target(
            name: "flutter_vless",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework"),
                "XRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_tunnel_support",
            dependencies: [
                "XRay",
                .product(name: "Tun2SocksKit", package: "Tun2SocksKit"),
                .product(name: "Tun2SocksKitC", package: "Tun2SocksKit")
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .binaryTarget(
            name: "XRay",
            url: "https://github.com/XIIIFOX/flutter_vless/releases/download/xray-ios-v26.6.22/XRay.xcframework.zip",
            checksum: "72b0a0bbbdce320a4ced885d22c118991e4cf4c50d25a8e90eb90560b3862c9a"
        ),
        .testTarget(
            name: "flutter_vless_tunnel_supportTests",
            dependencies: ["flutter_vless_tunnel_support"]
        )
    ]
)
