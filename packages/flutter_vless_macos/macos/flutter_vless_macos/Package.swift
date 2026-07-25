// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "flutter_vless_macos",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "flutter-vless-macos", targets: ["flutter_vless_macos"]),
        .library(name: "flutter-vless-macos-tunnel-support", targets: ["flutter_vless_macos_tunnel_support"]),
        .library(name: "flutter-vless-macos-app-proxy-support", targets: ["flutter_vless_macos_app_proxy_support"])
    ],
    dependencies: [
        .package(path: "../../../../../../Tun2SocksKit")
    ],
    targets: [
        .target(
            name: "flutter_vless_macos",
            dependencies: [
                "XRay",
                "CXRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_macos_tunnel_support",
            dependencies: [
                "XRay",
                "CXRay",
                .product(name: "Tun2SocksKit", package: "Tun2SocksKit"),
                .product(name: "Tun2SocksKitC", package: "Tun2SocksKit")
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "flutter_vless_macos_app_proxy_support",
            dependencies: [
                "XRay",
                "CXRay"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .target(
            name: "CXRay",
            dependencies: ["XRay"],
            publicHeadersPath: "include"
        ),
        .binaryTarget(
            name: "XRay",
            url: "https://github.com/XIIIFOX/flutter_vless/releases/download/xray-macos-v26.6.22/XRay.xcframework.zip",
            checksum: "9333d98830693a2ca8ab13b2c4e7f21a31fdccef5948c21f34e626aa902f4845"
        )
    ]
)
