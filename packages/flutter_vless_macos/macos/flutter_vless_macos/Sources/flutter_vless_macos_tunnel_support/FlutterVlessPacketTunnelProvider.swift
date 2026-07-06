//
//  PacketTunnelProvider.swift
//  XrayTunnel
//
//  Created by Vladimir Khudiakov on 17.08.2025. https://tfox.dev.
//

import NetworkExtension
import CXRay
import Tun2SocksKit
import Tun2SocksKitC
import HevSocks5Tunnel
import Foundation
import CFNetwork
import os
import Darwin

// MARK: - macOS Packet Tunnel Maintenance Notes
//
// This file is the Network Extension side of macOS VPN mode. It does not run in
// the Flutter app process. It runs inside the `XrayTunnel.appex` sandbox, owns
// the utun interface, starts Xray in-process, and starts HEV tun2socks to bridge
// packets from NetworkExtension into Xray's local SOCKS inbound.
//
// The working packet path is:
//
//   macOS apps
//     -> NetworkExtension Packet Tunnel utun
//     -> HEV socks5 tunnel / tun2socks
//     -> local Xray SOCKS inbound on 127.0.0.1
//     -> Xray proxy outbound
//     -> remote VLESS server
//
// Important lessons from the macOS bring-up:
//
// 1. `NEVPNStatus.connected` is not enough. macOS can report a connected tunnel
//    while DNS is unusable, Xray's outbound server route loops into utun, or
//    HEV only sees upload-side packets. Keep the layered health checks in this
//    file and treat them as part of the runtime contract.
// 2. Publish explicit Packet Tunnel DNS settings. macOS can otherwise create an
//    unreachable default resolver while ordinary app sockets already prefer the
//    utun route. Use public IPv4 DNS with `matchDomains = [""]` and keep DNS host
//    exclusions disabled so the resolver follows the validated packet path.
// 3. The remote proxy server needs a host route outside utun. Without it, Xray
//    tries to reach the server through the same tunnel that depends on Xray
//    reaching the server.
// 4. The packet path is intentionally IPv4-only until IPv6 route exclusions and
//    IPv6 health checks are designed as one feature. Partial IPv6 support caused
//    "connected but browser does not load" failures.
// 5. Do not replace the Xray outbound server domain with an IP here. The
//    preparer may add Xray DNS host mapping and the provider may exclude the
//    resolved IP, but the outbound config must preserve domain/SNI/authority
//    semantics for VLESS, XHTTP, TLS, and Reality transports.
//
// The companion architecture note is:
//   doc/macos_packet_tunnel_architecture.md
//
// If this file changes, run a real macOS Packet Tunnel smoke test and verify
// the golden logs listed in that note, not just a local proxy delay probe.

private let tunnelLog = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.XrayTunnel",
    category: "PacketTunnel"
)

/// Conservative MTU for a nested path of Packet Tunnel -> HEV -> SOCKS -> Xray.
///
/// `1500` looked tempting because the physical Wi-Fi interface often advertises
/// it, but the user-visible path is not just Wi-Fi. It includes utun, HEV, TLS,
/// and XHTTP/VLESS framing. `1280` avoids fragmentation-sensitive stalls and is
/// aligned with the minimum IPv6 MTU, even though this implementation currently
/// keeps the packet path IPv4-only.
private let tunnelMTU = 1280

/// IPv4 addresses for the virtual utun interface.
///
/// macOS behaved poorly with a broad `198.18.0.1/16` interface assignment: app
/// TCP connections selected the utun route, then failed immediately with
/// `ENETDOWN` before HEV saw a TCP session. A /32 local address was also not
/// reliable in the example app: route snapshots showed `default -> link#utun`
/// while app sockets failed with `ENETUNREACH`, and ifconfig still showed a
/// self-peer (`198.18.0.2 --> 198.18.0.2`). Current Apple sing-box builds keep
/// `tunnelRemoteAddress` independent from the IPv4 address, and HEV/Xray
/// examples commonly use the local tunnel address as the default-route gateway.
private let tunnelRemoteAddress = "127.0.0.1"
private let tunnelLocalAddress = "198.18.0.1"
private let tunnelDefaultGatewayAddress = "198.18.0.1"
private let tunnelLocalSubnetMask = "255.255.255.0"
private let tunnelLocalPrefixLength = 24
private let tunnelDefaultDNSServers = ["1.1.1.1", "8.8.8.8"]

/// Upper bound for macOS to accept Packet Tunnel network settings.
///
/// The provider must not remain in `NEVPNStatus.connecting` indefinitely. A
/// timeout here makes startup fail cleanly so the app can tear the profile down
/// instead of leaving the system route/DNS state half-transitioned.
private let networkSettingsTimeoutSeconds: TimeInterval = 15

/// HEV TCP buffer size used by the validated macOS path.
///
/// This is intentionally modest for an extension process. Increasing it can
/// improve throughput in some environments, but it should be tested together
/// with memory pressure and long-running browser traffic because extensions run
/// with tighter lifecycle constraints than the app.
private let hevTCPBufferSize = 4096

/// Small debug ring buffer shared by all provider callbacks.
///
/// macOS Network Extensions are painful to debug because the provider process is
/// not the Flutter Runner process. `print`/stdout output can disappear, LLDB has
/// to attach to another process, and Xcode stop/kill often races with provider
/// teardown. This store keeps the essential startup evidence in memory and, when
/// App Groups are configured, mirrors it to a shared file so the app can still
/// show diagnostics when `sendProviderMessage` is temporarily unavailable.
///
/// Keep this focused on operational facts, not noisy per-packet logs. The final
/// regression checklist depends on the exact messages for DNS publication,
/// server route exclusion, Xray startup, HEV startup, and SOCKS health checks.
private final class TunnelDebugStore {
    static let shared = TunnelDebugStore()
    private let lock = NSLock()
    private var lines: [String] = []
    private let maxLines = 1200
    private var fileURL: URL?

    /// Opens the optional App Group debug file.
    ///
    /// The App Group is not just convenience: when the app asks for
    /// `xray_debug` during startup or shutdown, `NETunnelProviderSession` may
    /// return nil even though the extension has useful evidence. The shared file
    /// is the fallback used by the app-side manager.
    func configure(groupIdentifier: String?) {
        lock.lock()
        defer { lock.unlock() }
        guard let groupIdentifier,
              !groupIdentifier.isEmpty,
              let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier) else {
            fileURL = nil
            return
        }
        fileURL = containerURL.appendingPathComponent("flutter_vless_tunnel_debug.log")
        let existingLines = lines.joined(separator: "\n")
        let initialContent = existingLines.isEmpty ? "" : "\(existingLines)\n"
        try? initialContent.write(to: fileURL!, atomically: true, encoding: .utf8)
    }

    /// Appends one timestamped provider event to memory and the shared file.
    ///
    /// This method intentionally swallows file errors. Diagnostics must never
    /// make the VPN fail to start; the in-memory buffer is still enough for the
    /// normal provider-message path.
    func append(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "\(timestamp) \(message)"
        lines.append(line)
        if lines.count > maxLines {
            lines.removeFirst(lines.count - maxLines)
        }
        if let fileURL {
            if let handle = try? FileHandle(forWritingTo: fileURL) {
                defer { try? handle.close() }
                _ = try? handle.seekToEnd()
                if let data = "\(line)\n".data(using: .utf8) {
                    try? handle.write(contentsOf: data)
                }
            }
        }
    }

    func snapshot() -> String {
        lock.lock()
        defer { lock.unlock() }
        return lines.joined(separator: "\n")
    }
}

private final class SingleResumeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resume(_ body: () -> Void) {
        lock.lock()
        guard !didResume else {
            lock.unlock()
            return
        }
        didResume = true
        lock.unlock()
        body()
    }
}

private func rememberTunnelLog(_ message: String) {
    TunnelDebugStore.shared.append(message)
}

/// Network Extension Packet Tunnel provider for macOS VPN mode.
///
/// This provider owns the validated Packet Tunnel path. It prepares imported
/// Xray JSON for the extension sandbox, applies NetworkExtension DNS/routing,
/// starts Xray, starts HEV tun2socks, and exposes debug/stat messages to the app.
///
/// Do not collapse this into the proxy-only path. Proxy-only and Packet Tunnel
/// mode solve different problems:
///
/// - Proxy-only configures macOS system proxy settings and cannot capture UDP or
///   apps that ignore the system proxy.
/// - Packet Tunnel mode captures IP packets through utun and needs explicit
///   DNS/server route handling to avoid self-recursion.
///
/// The provider deliberately emits multiple health checks because each one
/// proves a different layer:
///
/// - server TCP route check: Xray's remote server is reachable outside utun.
/// - SOCKS inbound check: local Xray is listening.
/// - SOCKS CONNECT check: Xray accepts outbound SOCKS requests.
/// - SOCKS HTTP literal-IP check: response bytes return through Xray.
/// - URLSession HTTPS through SOCKS: a higher-level client can complete HTTPS.
open class FlutterVlessPacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = CustomXRayLogger()
    private var lastTrafficLogDate: Date = .distantPast
    private var hevLogURL: URL?

    /// Legacy callback entrypoint used by macOS NetworkExtension.
    ///
    /// Keep this override even though Swift also supports async tunnel
    /// entrypoints. In practice, using the callback signature made startup
    /// behavior explicit and avoided ambiguity about which override macOS called
    /// from generated extension targets.
    open override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        rememberTunnelLog("Legacy startTunnel entrypoint called")
        tunnelLog.info("Legacy startTunnel entrypoint called")
        Task {
            do {
                try await startTunnelAsync(options: options)
                completionHandler(nil)
            } catch {
                rememberTunnelLog("startTunnel failed: \(error.localizedDescription)")
                tunnelLog.error("startTunnel failed: \(error.localizedDescription, privacy: .public)")
                cleanupAfterStartupFailure()
                completionHandler(error)
            }
        }
    }

    /// Starts the complete Packet Tunnel data path.
    ///
    /// Ordering matters:
    ///
    /// 1. Normalize Xray JSON before parsing ports/routes.
    /// 2. Apply `NEPacketTunnelNetworkSettings` before starting Xray/HEV so
    ///    packet flow and routes are owned by NetworkExtension first.
    /// 3. Start Xray before HEV because HEV immediately connects to the local
    ///    SOCKS inbound.
    /// 4. Run server-route and SOCKS health checks asynchronously after startup.
    ///    They are diagnostics only and must not block `startTunnel`, otherwise
    ///    macOS can leave the VPN profile stuck in `connecting`.
    private func startTunnelAsync(options: [String : NSObject]?) async throws {
        rememberTunnelLog("Starting Xray packet tunnel")
        tunnelLog.info("Starting Xray packet tunnel options=\(String(describing: options), privacy: .public)")
        guard
            let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol,
            let providerConfiguration = protocolConfiguration.providerConfiguration
        else {
            throw tunnelError("Missing tunnel provider configuration")
        }
        tunnelLog.info("Provider configuration keys: \(providerConfiguration.keys.sorted().joined(separator: ","), privacy: .public)")
        guard let xrayConfig: Data = providerConfiguration["xrayConfig"] as? Data else {
            throw tunnelError("Missing Xray config")
        }
        tunnelLog.info("Received Xray config bytes=\(xrayConfig.count, privacy: .public)")
        // The imported config is user/server owned, but it still has to be made
        // safe for an extension sandbox and deterministic Packet Tunnel routing.
        // If preparation fails, fall back to the original config so unsupported
        // future formats are not hard-blocked; health checks below will still
        // reveal whether the runtime path is usable.
        let preparedXrayConfig = prepareXrayConfigForTunnel(xrayConfig) ?? xrayConfig
        let bypassSubnets = providerConfiguration["bypassSubnets"] as? [String] ?? []
        TunnelDebugStore.shared.configure(groupIdentifier: providerConfiguration["groupIdentifier"] as? String)
        tunnelLog.info("Bypass subnet count=\(bypassSubnets.count, privacy: .public)")
        if (providerConfiguration["proxyOnly"] as? Bool) == true {
            tunnelLog.warning("proxyOnly is not supported by the macOS packet tunnel; starting VPN mode")
        }
        guard let parsedConfig = parseConfig(jsonData: preparedXrayConfig) else {
            throw tunnelError("Unable to find a SOCKS/HTTP inbound port in Xray config")
        }
        let appDNSServers = providerConfiguration["dnsServers"] as? [String] ?? []
        rememberTunnelLog("App provided DNS snapshot before VPN: \(appDNSServers.isEmpty ? "none" : appDNSServers.joined(separator: ","))")
        tunnelLog.info("App provided DNS snapshot before VPN: \(appDNSServers.isEmpty ? "none" : appDNSServers.joined(separator: ","), privacy: .public)")
        rememberTunnelLog("Using local Xray inbound port \(parsedConfig.inboundPort), server=\(parsedConfig.serverAddress ?? "nil")")
        tunnelLog.info("Using local Xray inbound port \(parsedConfig.inboundPort, privacy: .public)")

        // `tunnelRemoteAddress` is only the NetworkExtension remote endpoint
        // label. It is not the TUN IPv4 gateway and not the actual VLESS server.
        // The real server is carried in the Xray outbound and route-excluded
        // below.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        settings.mtu = NSNumber(value: tunnelMTU)
        rememberTunnelLog("Configured packet tunnel MTU=\(tunnelMTU)")
        settings.ipv4Settings = {
            let settings = NEIPv4Settings(
                addresses: [tunnelLocalAddress],
                subnetMasks: [tunnelLocalSubnetMask]
            )
            // Default route through utun is what makes this VPN mode, not just a
            // local proxy. The remote server host route is excluded to avoid
            // startup recursion.
            let defaultRoute = NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
            defaultRoute.gatewayAddress = tunnelDefaultGatewayAddress
            settings.includedRoutes = [defaultRoute]
            settings.excludedRoutes = buildIPv4ExcludedRoutes(
                serverAddress: parsedConfig.serverAddress,
                bypassSubnets: bypassSubnets
            )
            rememberTunnelLog("IPv4 settings local=\(tunnelLocalAddress)/\(tunnelLocalPrefixLength) gateway=\(tunnelDefaultGatewayAddress) remoteLabel=\(tunnelRemoteAddress) subnetMask=\(tunnelLocalSubnetMask) includedRoutes=default excludedRoutes=\(settings.excludedRoutes?.count ?? 0)")
            tunnelLog.info("IPv4 settings local=\(tunnelLocalAddress, privacy: .public)/\(tunnelLocalPrefixLength, privacy: .public) gateway=\(tunnelDefaultGatewayAddress, privacy: .public) remoteLabel=\(tunnelRemoteAddress, privacy: .public) subnetMask=\(tunnelLocalSubnetMask, privacy: .public) includedRoutes=default excludedRoutes=\(settings.excludedRoutes?.count ?? 0, privacy: .public)")
            return settings
        }()
        // Keep the packet path IPv4-only for now. With IPv6 enabled, macOS can
        // create IPv4-mapped IPv6 routes such as ::ffff:<xray-server> through
        // another utun interface, bypassing the explicit IPv4 server exclusion
        // and starving the Xray outbound connection.
        settings.ipv6Settings = nil
        rememberTunnelLog("IPv6 tunnel routing disabled; using IPv4-only packet tunnel")
        tunnelLog.info("IPv6 tunnel routing disabled; using IPv4-only packet tunnel")
        let dnsSettings = NEDNSSettings(servers: tunnelDefaultDNSServers)
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings
        rememberTunnelLog("Packet tunnel DNS servers=\(tunnelDefaultDNSServers.joined(separator: ",")) matchDomains=default appSnapshot=\(appDNSServers.isEmpty ? "none" : appDNSServers.joined(separator: ","))")
        tunnelLog.info("Packet tunnel DNS servers=\(tunnelDefaultDNSServers.joined(separator: ","), privacy: .public) matchDomains=default")
        try await applyTunnelNetworkSettings(settings)
        try self.startXRay(xrayConfig: preparedXrayConfig)
        let tunnelFileDescriptor = packetFlowFileDescriptor()
        self.startSocks5Tunnel(
            serverPort: parsedConfig.inboundPort,
            tunnelFileDescriptor: tunnelFileDescriptor
        )
        logServerTCPRouteHealthCheck(
            host: parsedConfig.serverAddress,
            port: parsedConfig.serverPort ?? 443
        )
        logSocksInboundHealthCheck(port: parsedConfig.inboundPort)
    }

    private func applyTunnelNetworkSettings(_ settings: NEPacketTunnelNetworkSettings) async throws {
        rememberTunnelLog("Applying tunnel network settings")
        tunnelLog.info("Applying tunnel network settings")
        try await setTunnelNetworkSettings(settings, timeoutSeconds: networkSettingsTimeoutSeconds)
        rememberTunnelLog("Tunnel network settings applied")
        tunnelLog.info("Tunnel network settings applied")
    }

    private func setTunnelNetworkSettings(
        _ settings: NEPacketTunnelNetworkSettings?,
        timeoutSeconds: TimeInterval
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeBox = SingleResumeBox()
            let timeoutTask = Task {
                let nanoseconds = UInt64(timeoutSeconds * 1_000_000_000)
                try? await Task.sleep(nanoseconds: nanoseconds)
                guard !Task.isCancelled else {
                    return
                }
                resumeBox.resume {
                    let message = "Timed out applying packet tunnel network settings after \(Int(timeoutSeconds))s"
                    rememberTunnelLog(message)
                    continuation.resume(throwing: tunnelError(message))
                }
            }

            self.setTunnelNetworkSettings(settings) { error in
                timeoutTask.cancel()
                resumeBox.resume {
                    if let error {
                        rememberTunnelLog("Applying tunnel network settings failed: \(error.localizedDescription)")
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume()
                    }
                }
            }
        }
    }

    private func cleanupAfterStartupFailure() {
        stopXRay()
        Socks5Tunnel.quit()
        setTunnelNetworkSettings(nil) { error in
            if let error {
                rememberTunnelLog("Clearing tunnel network settings after startup failure failed: \(error.localizedDescription)")
                tunnelLog.error("Clearing tunnel network settings after startup failure failed: \(error.localizedDescription, privacy: .public)")
            } else {
                rememberTunnelLog("Cleared tunnel network settings after startup failure")
                tunnelLog.info("Cleared tunnel network settings after startup failure")
            }
        }
    }

    /// Stops Xray and HEV.
    ///
    /// The HEV log tail is captured before shutdown because it is often the only
    /// evidence of whether real app traffic reached TCP splice or stayed as UDP
    /// churn. `Socks5Tunnel.quit()` is intentionally called even after Xray
    /// stops; HEV is the owner of the utun packet consumer thread.
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        rememberTunnelLog("Stopping Xray packet tunnel, reason=\(reason.rawValue)")
        tunnelLog.info("Stopping Xray packet tunnel, reason: \(reason.rawValue, privacy: .public)")
        logTrafficStats(context: "stop")
        if let hevTail = readHevLogTail(), !hevTail.isEmpty {
            rememberTunnelLog("--- HEV log tail before stop ---\n\(hevTail)")
        }
        stopXRay()
        Socks5Tunnel.quit()
        clearTunnelNetworkSettingsBeforeStop(completionHandler: completionHandler)
    }

    private func clearTunnelNetworkSettingsBeforeStop(completionHandler: @escaping () -> Void) {
        let resumeBox = SingleResumeBox()
        let timeoutTask = DispatchWorkItem {
            resumeBox.resume {
                rememberTunnelLog("Timed out clearing tunnel network settings during stop; completing stop anyway")
                tunnelLog.warning("Timed out clearing tunnel network settings during stop")
                completionHandler()
            }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3, execute: timeoutTask)
        setTunnelNetworkSettings(nil) { error in
            timeoutTask.cancel()
            resumeBox.resume {
                if let error {
                    rememberTunnelLog("Clearing tunnel network settings during stop failed: \(error.localizedDescription)")
                    tunnelLog.error("Clearing tunnel network settings during stop failed: \(error.localizedDescription, privacy: .public)")
                } else {
                    rememberTunnelLog("Cleared tunnel network settings during stop")
                    tunnelLog.info("Cleared tunnel network settings during stop")
                }
                completionHandler()
            }
        }
    }

    /// Provider-message bridge used by the Flutter app.
    ///
    /// This is not a public user API, but it is a critical internal operations
    /// API. It lets the app poll byte counters and retrieve the provider-side
    /// proof chain without attaching a debugger to the extension process.
    ///
    /// Supported messages:
    ///
    /// - `xray_traffic`: HEV byte counters as `up,down`.
    /// - `xray_debug`: provider ring buffer plus HEV log tail.
    /// - `xray_delay<url>`: connected Xray delay probe.
    open override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let message = String(data: messageData, encoding: .utf8) {
            if (message == "xray_traffic"){
                logTrafficStats(context: "poll")
                let stats = Socks5Tunnel.stats
                completionHandler?("\(stats.up.bytes),\(stats.down.bytes)".data(using: .utf8))
            } else if (message == "xray_debug") {
                // This bridge is intentionally part of the runtime API used by
                // smoke tests and manual Xcode runs. It is the fastest way to
                // compare TCP/Reality and XHTTP behavior without attaching LLDB
                // to the extension process separately.
                var snapshot = TunnelDebugStore.shared.snapshot()
                if let hevTail = readHevLogTail(), !hevTail.isEmpty {
                    snapshot += "\n--- HEV log tail ---\n\(hevTail)"
                }
                completionHandler?(snapshot.data(using: .utf8))
            }else if (message.hasPrefix("xray_delay")){
                var error: NSError?
                var delay: Int64 = -1
                let url = String(message[message.index(message.startIndex, offsetBy: 10)...])
                tunnelLog.info("Measuring connected delay url=\(url, privacy: .public)")
                XRayMeasureDelay(url, &delay, &error)
                if let error {
                    tunnelLog.error("Connected delay error: \(error.localizedDescription, privacy: .public)")
                } else {
                    tunnelLog.info("Connected delay result=\(delay, privacy: .public)")
                }
                completionHandler?("\(delay)".data(using: .utf8))
            }
            else{
                tunnelLog.info("Echoing unknown provider message: \(message, privacy: .public)")
                completionHandler?(messageData)
            }

        }else{
            tunnelLog.warning("Received non-UTF8 provider message bytes=\(messageData.count, privacy: .public)")
            completionHandler?(messageData)
        }
    }

    open override func sleep(completionHandler: @escaping () -> Void) {
        tunnelLog.info("Packet tunnel sleep")
        completionHandler()
    }

    open override func wake() {
        tunnelLog.info("Packet tunnel wake")
    }

    /// Starts HEV tun2socks against the local Xray SOCKS inbound.
    ///
    /// Xray can start successfully while no browser bytes return. HEV is the
    /// bridge that decides whether utun packets actually become SOCKS sessions.
    /// For this reason the HEV log is deliberately kept at `debug` level and
    /// exposed in provider snapshots during the macOS stabilization period.
    private func startSocks5Tunnel(serverPort port: Int, tunnelFileDescriptor: Int32?) {
        // HEV is the tun2socks bridge: it reads IP packets from NetworkExtension
        // and forwards them into the local SOCKS inbound opened by Xray.
        // Xray alone can start successfully while user traffic still cannot
        // leave the device; HEV logs close that gap during real-device tests.
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("hev-socks5-tunnel.log")
        hevLogURL = logURL
        try? FileManager.default.removeItem(at: logURL)
        let config = """
        tunnel:
          mtu: \(tunnelMTU)
        socks5:
          port: \(port)
          address: 127.0.0.1
          udp: 'tcp'
        misc:
          task-stack-size: 24576
          tcp-buffer-size: \(hevTCPBufferSize)
          max-session-count: 1200
          connect-timeout: 5000
          tcp-read-write-timeout: 60000
          udp-read-write-timeout: 60000
          log-file: \(logURL.path)
          log-level: debug
          limit-nofile: 65535
        """
        rememberTunnelLog("HEV config summary: tunnel.mtu=\(tunnelMTU), socks5=127.0.0.1:\(port), udp=tcp, tcpBuffer=\(hevTCPBufferSize), maxSessions=1200, timeoutMs=5000/60000")
        if let tunnelFileDescriptor {
            rememberTunnelLog("Starting HEV socks5 tunnel on 127.0.0.1:\(port), fd=\(tunnelFileDescriptor), mtu=\(tunnelMTU), tcpBuffer=\(hevTCPBufferSize), log=\(logURL.path)")
            tunnelLog.info("Starting HEV socks5 tunnel on 127.0.0.1:\(port, privacy: .public), fd \(tunnelFileDescriptor, privacy: .public), mtu \(tunnelMTU, privacy: .public), tcpBuffer \(hevTCPBufferSize, privacy: .public)")
        } else {
            rememberTunnelLog("Starting HEV socks5 tunnel on 127.0.0.1:\(port) using Tun2SocksKit fd autodetect fallback, mtu=\(tunnelMTU), tcpBuffer=\(hevTCPBufferSize), log=\(logURL.path)")
            tunnelLog.warning("Starting HEV socks5 tunnel using fd autodetect fallback on 127.0.0.1:\(port, privacy: .public)")
        }
        DispatchQueue.global(qos: .userInitiated).async {
            tunnelLog.info("HEV socks5 tunnel thread entered")
            let exitCode: Int32
            if let tunnelFileDescriptor {
                rememberTunnelLog("HEV explicit-fd run begin fd=\(tunnelFileDescriptor)")
                exitCode = config.withCString { rawPointer in
                    rawPointer.withMemoryRebound(to: UInt8.self, capacity: config.utf8.count) {
                        hev_socks5_tunnel_main_from_str($0, UInt32(config.utf8.count), tunnelFileDescriptor)
                    }
                }
            } else {
                exitCode = Socks5Tunnel.run(withConfig: .string(content: config))
            }
            rememberTunnelLog("HEV socks5 tunnel exited with code \(exitCode)")
            tunnelLog.error("HEV socks5 tunnel exited with code \(exitCode, privacy: .public)")
            NSLog("HEV_SOCKS5_TUNNEL_MAIN: \(exitCode)")
        }
    }

    private func packetFlowFileDescriptor() -> Int32? {
        var attempts: [String] = []
        for attempt in 1...12 {
            let rawValue = packetFlow.value(forKeyPath: "socket.fileDescriptor")
            let rawType = rawValue.map { String(describing: type(of: $0)) } ?? "nil"
            let rawDescription = String(describing: rawValue)
            if let fileDescriptor = int32FileDescriptor(from: rawValue) {
                let validation = describeUtunFileDescriptor(fileDescriptor)
                attempts.append("#\(attempt) rawType=\(rawType) raw=\(rawDescription) fd=\(fileDescriptor) \(validation)")
                rememberTunnelLog("packetFlow fd KVC attempts: \(attempts.joined(separator: " | "))")
                rememberTunnelLog("Detected utun fd candidates before HEV start: \(describeUtunFileDescriptorCandidates(utunFileDescriptorCandidates()))")
                rememberTunnelLog("Using explicit packetFlow file descriptor \(fileDescriptor) for HEV")
                tunnelLog.info("Using explicit packetFlow file descriptor \(fileDescriptor, privacy: .public) for HEV")
                return fileDescriptor
            }
            attempts.append("#\(attempt) rawType=\(rawType) raw=\(rawDescription) converted=nil")
            usleep(50_000)
        }
        let candidates = utunFileDescriptorCandidates()
        rememberTunnelLog("Could not read packetFlow socket file descriptor; attempts: \(attempts.joined(separator: " | "))")
        rememberTunnelLog("Detected utun fd candidates after KVC failure: \(describeUtunFileDescriptorCandidates(candidates))")
        if candidates.count == 1, let candidate = candidates.first {
            rememberTunnelLog("Using the only detected utun file descriptor for HEV after KVC failure: \(candidate.logDescription)")
            tunnelLog.info("Using only detected utun file descriptor \(candidate.fd, privacy: .public) for HEV after KVC failure")
            return candidate.fd
        }
        tunnelLog.warning("Could not read packetFlow socket file descriptor; HEV will use fd autodetect fallback")
        return nil
    }

    private func int32FileDescriptor(from value: Any?) -> Int32? {
        if let value = value as? Int32 {
            return value >= 0 ? value : nil
        }
        if let value = value as? Int {
            return value >= 0 && value <= Int(Int32.max) ? Int32(value) : nil
        }
        if let value = value as? NSNumber {
            let intValue = value.intValue
            return intValue >= 0 && intValue <= Int(Int32.max) ? Int32(intValue) : nil
        }
        return nil
    }

    private func describeUtunFileDescriptor(_ fd: Int32) -> String {
        guard let unit = utunUnit(for: fd) else {
            return "utunValidation=not-utun"
        }
        return "utunValidation=ok unit=\(unit)"
    }

    private struct UtunFileDescriptorCandidate {
        let fd: Int32
        let unit: UInt32

        var interfaceName: String {
            guard unit > 0 else {
                return "utun?"
            }
            return "utun\(unit - 1)"
        }

        var logDescription: String {
            "fd=\(fd)/unit=\(unit)/if=\(interfaceName)"
        }
    }

    private func utunFileDescriptorCandidates() -> [UtunFileDescriptorCandidate] {
        var candidates: [UtunFileDescriptorCandidate] = []
        for fd in Int32(0)...Int32(1024) {
            if let unit = utunUnit(for: fd) {
                candidates.append(UtunFileDescriptorCandidate(fd: fd, unit: unit))
            }
        }
        return candidates
    }

    private func describeUtunFileDescriptorCandidates(_ candidates: [UtunFileDescriptorCandidate]) -> String {
        if candidates.isEmpty {
            return "none"
        }
        return candidates.map(\.logDescription).joined(separator: ", ")
    }

    private func utunUnit(for fd: Int32) -> UInt32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }

        var address = sockaddr_ctl()
        var length = socklen_t(MemoryLayout.size(ofValue: address))
        let peerResult = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(fd, $0, &length)
            }
        }
        guard peerResult == 0, address.sc_family == AF_SYSTEM else {
            return nil
        }
        guard ioctl(fd, CTLIOCGINFO, &ctlInfo) == 0 else {
            return nil
        }
        guard address.sc_id == ctlInfo.ctl_id else {
            return nil
        }
        return address.sc_unit
    }

    /// Starts Xray inside the extension process.
    ///
    /// The config passed here should already be normalized by
    /// `TunnelXrayConfigPreparer`. In particular, file log paths must be cleared
    /// before this call because imported desktop paths may not exist inside the
    /// extension sandbox and can fail startup before networking is tested.
    private func startXRay(xrayConfig: Data) throws {
        XRaySetMemoryLimit()

        // Create an error pointer
        var error: NSError?

        // Start XRay with the config data
        tunnelLog.info("Starting XRay version=\(XRayGetVersion(), privacy: .public) configBytes=\(xrayConfig.count, privacy: .public)")
        let started = XRayStart(xrayConfig, logger, &error)

        if started {
            rememberTunnelLog("XRay started successfully")
            tunnelLog.info("XRay started successfully")
        } else if let error = error {
            rememberTunnelLog("Failed to start XRay: \(error.localizedDescription)")
            tunnelLog.error("Failed to start XRay: \(error.localizedDescription, privacy: .public)")
            throw error
        } else {
            rememberTunnelLog("Failed to start XRay with unknown error")
            throw tunnelError("Failed to start XRay with unknown error")
        }
    }

    private func stopXRay() {
        XRayStop()
        tunnelLog.info("XRay stopped \(XRayGetVersion(), privacy: .public)")
    }

    /// Minimal values the provider needs after config normalization.
    ///
    /// `serverAddress` intentionally stays as the original outbound domain when
    /// the config used a domain. The provider resolves it only for route
    /// exclusions and health checks; Xray keeps the domain semantics.
    private struct ParsedConfig {
        let inboundPort: Int
        let serverAddress: String?
        let serverPort: Int?
    }

    private func parseConfig(jsonData: Data) -> ParsedConfig? {
        guard let parsed = TunnelXrayConfigPreparer.parseConfig(jsonData: jsonData) else {
            tunnelLog.error("Failed to parse tunnel Xray config")
            return nil
        }
        if let serverAddress = parsed.serverAddress {
            tunnelLog.info("Parsed outbound server address: \(serverAddress, privacy: .public)")
        } else {
            tunnelLog.warning("Could not parse outbound server address; VPN routing loop exclusion will be skipped")
        }
        return ParsedConfig(
            inboundPort: parsed.inboundPort,
            serverAddress: parsed.serverAddress,
            serverPort: parsed.serverPort
        )
    }

    /// Normalizes imported Xray JSON for macOS packet-tunnel constraints.
    ///
    /// The same URL parser is used for standalone Xray configs and for this
    /// extension, but packet tunnels have tighter rules: file logs may be denied
    /// inside the extension sandbox, and the remote proxy server must not be
    /// reached through the tunnel that depends on it.
    private func prepareXrayConfigForTunnel(_ jsonData: Data) -> Data? {
        guard let prepared = TunnelXrayConfigPreparer.prepare(
            jsonData: jsonData,
            resolveIPv4: { resolveIPv4Addresses(for: $0).first }
        ) else {
            tunnelLog.warning("Could not prepare Xray config for macOS tunnel")
            return nil
        }
        for message in prepared.logMessages {
            rememberTunnelLog(message)
            tunnelLog.info("\(message, privacy: .public)")
        }
        return prepared.data
    }

    /// Builds IPv4 routes that must not enter the Packet Tunnel default route.
    ///
    /// This method is one of the most important guardrails in the macOS VPN
    /// path. The default route goes to utun, but these hosts/subnets must remain
    /// outside:
    ///
    /// - user-provided bypass subnets,
    /// - the resolved remote proxy server IP.
    ///
    /// Removing the server exclusion can create an Xray self-routing loop where
    /// the server connection tries to traverse the tunnel it is meant to
    /// establish.
    private func buildIPv4ExcludedRoutes(
        serverAddress: String?,
        bypassSubnets: [String]
    ) -> [NEIPv4Route] {
        var routes = bypassSubnets.compactMap { ipv4Route(fromCIDR: $0) }
        rememberTunnelLog("DNS route exclusions disabled; using Packet Tunnel DNS settings")
        tunnelLog.info("DNS route exclusions disabled; using Packet Tunnel DNS settings")
        if let serverAddress {
            let serverAddresses = resolveIPv4Addresses(for: serverAddress)
            let serverRoutes = serverAddresses.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
            }
            routes.append(contentsOf: serverRoutes)
            if serverRoutes.isEmpty {
                rememberTunnelLog("No IPv4 address resolved for outbound server \(serverAddress)")
                tunnelLog.warning("No IPv4 address resolved for outbound server \(serverAddress, privacy: .public)")
            } else {
                rememberTunnelLog("Excluded IPv4 server route(s): \(serverAddresses.joined(separator: ","))")
                tunnelLog.info("Excluded \(serverRoutes.count, privacy: .public) IPv4 server route(s) from VPN: \(serverAddresses.joined(separator: ","), privacy: .public)")
            }
        }
        return routes
    }

    /// Runs layered startup health checks after Xray has had a moment to bind.
    ///
    /// These checks intentionally overlap. A lower-level pass does not make the
    /// higher-level checks redundant:
    ///
    /// - SOCKS inbound pass proves Xray opened a local port.
    /// - CONNECT pass proves Xray accepts an outbound request.
    /// - literal-IP HTTP pass proves response bytes return through Xray.
    /// - URLSession HTTPS pass proves a higher-level Apple networking client can
    ///   complete HTTPS through the same local SOCKS path.
    private func logSocksInboundHealthCheck(port: Int) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.5) {
            rememberTunnelLog("SOCKS health checks begin port=\(port)")
            // The three checks separate local startup from real Internet reach:
            // 1. SOCKS inbound: Xray opened the local port.
            // 2. CONNECT: Xray accepted an outbound request.
            // 3. HTTP 204: bytes came back from the public Internet.
            // TCP/Reality is treated as working only after the third line is ok.
            let result = self.socksInboundHealthCheck(port: port)
            rememberTunnelLog("SOCKS inbound health check: \(result)")
            tunnelLog.info("SOCKS inbound health check: \(result, privacy: .public)")
            let connectResult = self.socksConnectHealthCheck(port: port)
            rememberTunnelLog("SOCKS CONNECT health check: \(connectResult)")
            tunnelLog.info("SOCKS CONNECT health check: \(connectResult, privacy: .public)")
            let httpResult = self.socksHTTPHealthCheck(port: port)
            rememberTunnelLog("SOCKS HTTP health check: \(httpResult)")
            tunnelLog.info("SOCKS HTTP health check: \(httpResult, privacy: .public)")
            let xrayDelayResult = self.xrayInternalDelayHealthCheck(url: "https://google.com/generate_204")
            rememberTunnelLog("XRay internal delay health check: \(xrayDelayResult)")
            tunnelLog.info("XRay internal delay health check: \(xrayDelayResult, privacy: .public)")
            Task {
                rememberTunnelLog("SOCKS URLSession HTTPS health check begin port=\(port) url=https://google.com/generate_204")
                let urlSessionResult = await self.socksURLSessionHealthCheck(
                    port: port,
                    url: "https://google.com/generate_204"
                )
                rememberTunnelLog("SOCKS URLSession HTTPS health check: \(urlSessionResult)")
                tunnelLog.info("SOCKS URLSession HTTPS health check: \(urlSessionResult, privacy: .public)")
            }
        }
    }

    private func logServerTCPRouteHealthCheck(host: String?, port: Int) {
        guard let host else {
            return
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.5) {
            rememberTunnelLog("Server TCP route health check begin host=\(host) port=\(port)")
            let serverRouteResult = self.serverTCPRouteHealthCheck(host: host, port: port)
            rememberTunnelLog("Server TCP route health check: \(serverRouteResult)")
            tunnelLog.info("Server TCP route health check: \(serverRouteResult, privacy: .public)")
        }
    }

    /// Calls Xray's own delay API from inside the provider.
    ///
    /// This check is useful for comparing with proxy-only behavior, but it is
    /// not sufficient as a Packet Tunnel success signal. It does not prove
    /// macOS DNS resolver health, HEV packet forwarding, or browser TCP
    /// fallback.
    private func xrayInternalDelayHealthCheck(url: String) -> String {
        var error: NSError?
        var delay: Int64 = -1
        XRayMeasureDelay(url, &delay, &error)
        if let error {
            return "failed delay=\(delay) error=\(error.localizedDescription)"
        }
        return "ok delay=\(delay)ms"
    }

    /// Runs a real `URLSession` HTTPS request through the local SOCKS inbound.
    ///
    /// This complements the raw socket HTTP probe. It exercises CFNetwork's
    /// client path, proxy dictionary handling, TLS, and response parsing. A
    /// `204` response from `https://google.com/generate_204` was the final
    /// "browser-like client can use this tunnel" proof in the macOS fix.
    private func socksURLSessionHealthCheck(port: Int, url: String) async -> String {
        guard let probeURL = URL(string: url) else {
            return "invalid url"
        }

        var request = URLRequest(url: probeURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = 8

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 8
        configuration.timeoutIntervalForResource = 8
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesSOCKSEnable as String: true,
            kCFNetworkProxiesSOCKSProxy as String: "127.0.0.1",
            kCFNetworkProxiesSOCKSPort as String: port
        ]

        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        let start = DispatchTime.now().uptimeNanoseconds
        do {
            let (_, response) = try await session.data(for: request)
            let elapsed = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
            if let httpResponse = response as? HTTPURLResponse {
                return "ok status=\(httpResponse.statusCode) delay=\(elapsed)ms"
            }
            return "ok non-http delay=\(elapsed)ms"
        } catch {
            return "failed error=\(error.localizedDescription)"
        }
    }

    /// Performs only the SOCKS no-auth greeting.
    ///
    /// A pass here means "Xray has a local SOCKS inbound and it responds to
    /// negotiation." It says nothing about routing to the remote server.
    private func socksInboundHealthCheck(port: Int) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
            return "inet_pton failed"
        }

        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            return "connect 127.0.0.1:\(port) failed errno=\(errno)"
        }

        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        let sent = greeting.withUnsafeBytes {
            send(fd, $0.baseAddress, greeting.count, 0)
        }
        guard sent == greeting.count else {
            return "send greeting failed sent=\(sent) errno=\(errno)"
        }

        var response = [UInt8](repeating: 0, count: 2)
        let responseCount = response.count
        let received = response.withUnsafeMutableBytes {
            recv(fd, $0.baseAddress, responseCount, 0)
        }
        guard received == 2 else {
            return "recv greeting failed received=\(received) errno=\(errno)"
        }

        return "ok response=\(response.map { String(format: "%02x", $0) }.joined(separator: " "))"
    }

    /// Verifies that the remote proxy server is reachable after tunnel routes.
    ///
    /// This runs after `setTunnelNetworkSettings`, so it observes the real
    /// routing table with utun installed. If this TCP connect fails, the most
    /// likely cause is an incorrect/missing server host exclusion or an IPv6
    /// path that bypasses the IPv4 exclusion strategy.
    private func serverTCPRouteHealthCheck(host: String, port: Int) -> String {
        let addresses = isIPv4Literal(host) ? [host] : resolveIPv4Addresses(for: host)
        rememberTunnelLog("Server TCP route health check resolved host=\(host) addresses=\(addresses.isEmpty ? "none" : addresses.joined(separator: ","))")
        guard let addressString = addresses.first else {
            return "resolve \(host) failed"
        }

        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, addressString, &address.sin_addr) == 1 else {
            return "inet_pton \(addressString) failed"
        }

        let start = DispatchTime.now().uptimeNanoseconds
        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        let elapsed = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
        guard connectResult == 0 else {
            return "connect \(addressString):\(port) failed errno=\(errno) delay=\(elapsed)ms"
        }
        return "ok \(addressString):\(port) delay=\(elapsed)ms"
    }

    /// Performs a SOCKS CONNECT to `1.1.1.1:80`.
    ///
    /// This is stronger than the greeting but still weaker than an HTTP byte
    /// check. It proves Xray accepted the request and returned a SOCKS success
    /// response. It does not prove the remote HTTP response made it back.
    private func socksConnectHealthCheck(port: Int) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
            return "inet_pton failed"
        }

        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            return "connect 127.0.0.1:\(port) failed errno=\(errno)"
        }

        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        guard sendAll(fd: fd, bytes: greeting) else {
            return "send greeting failed errno=\(errno)"
        }
        guard let greetingResponse = recvExact(fd: fd, count: 2) else {
            return "recv greeting failed errno=\(errno)"
        }
        guard greetingResponse == [0x05, 0x00] else {
            return "unexpected greeting=\(hex(greetingResponse))"
        }

        let request: [UInt8] = [
            0x05, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x01, 0x01,
            0x00, 0x50
        ]
        guard sendAll(fd: fd, bytes: request) else {
            return "send connect failed errno=\(errno)"
        }
        guard let header = recvExact(fd: fd, count: 4) else {
            return "recv connect header failed errno=\(errno)"
        }
        guard header.count == 4 else {
            return "short connect header=\(hex(header))"
        }
        let atyp = header[3]
        let remaining: Int
        switch atyp {
        case 0x01:
            remaining = 6
        case 0x03:
            guard let lengthBytes = recvExact(fd: fd, count: 1), let length = lengthBytes.first else {
                return "recv domain length failed errno=\(errno)"
            }
            remaining = Int(length) + 2
        case 0x04:
            remaining = 18
        default:
            return "unexpected connect atyp=\(String(format: "%02x", atyp)) header=\(hex(header))"
        }
        let tail = recvExact(fd: fd, count: remaining) ?? []
        let status = header[1] == 0x00 ? "ok" : "failed"
        return "\(status) response=\(hex(header + tail))"
    }

    /// Performs an HTTP request through the same local SOCKS inbound used by HEV.
    ///
    /// This is the decisive regression signal for the current investigation:
    /// TCP/Reality returned `HTTP/1.1 204 No Content` on device, while failing
    /// XHTTP links reached earlier stages but did not return usable page bytes.
    private func socksHTTPHealthCheck(port: Int) -> String {
        // Use a literal IP here so the health check validates Xray bytes
        // without depending on the extension process resolver after the system
        // default route has already moved into the packet tunnel. DNS is tested
        // separately through route snapshots and URLSession behavior.
        let targetAddress = "1.1.1.1"
        let hostHeader = "1.1.1.1"
        let path = "/cdn-cgi/trace"
        let targetOctets = targetAddress.split(separator: ".").compactMap { UInt8($0) }
        guard targetOctets.count == 4 else {
            return "invalid IPv4 target"
        }

        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return "socket failed errno=\(errno)"
        }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 8, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else {
            return "inet_pton failed"
        }

        let connectResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else {
            return "connect 127.0.0.1:\(port) failed errno=\(errno)"
        }

        guard sendAll(fd: fd, bytes: [0x05, 0x01, 0x00]),
              let greetingResponse = recvExact(fd: fd, count: 2),
              greetingResponse == [0x05, 0x00] else {
            return "socks greeting failed errno=\(errno)"
        }

        var request: [UInt8] = [0x05, 0x01, 0x00, 0x01]
        request.append(contentsOf: targetOctets)
        request.append(0x00)
        request.append(0x50)
        guard sendAll(fd: fd, bytes: request) else {
            return "send connect failed errno=\(errno)"
        }
        guard let header = recvExact(fd: fd, count: 4) else {
            return "recv connect header failed errno=\(errno)"
        }
        guard header.count == 4, header[1] == 0x00 else {
            return "connect failed response=\(hex(header)) errno=\(errno)"
        }
        let atyp = header[3]
        let remaining: Int
        switch atyp {
        case 0x01:
            remaining = 6
        case 0x03:
            guard let lengthBytes = recvExact(fd: fd, count: 1), let length = lengthBytes.first else {
                return "recv domain length failed errno=\(errno)"
            }
            remaining = Int(length) + 2
        case 0x04:
            remaining = 18
        default:
            return "unexpected connect atyp=\(String(format: "%02x", atyp))"
        }
        _ = recvExact(fd: fd, count: remaining)

        let httpRequest = """
        GET \(path) HTTP/1.1\r
        Host: \(hostHeader)\r
        User-Agent: flutter-vless-healthcheck\r
        Connection: close\r
        \r

        """
        guard sendAll(fd: fd, bytes: Array(httpRequest.utf8)) else {
            return "send http failed errno=\(errno)"
        }
        switch recvSome(fd: fd, maxCount: 512) {
        case .success(let response):
            let text = String(decoding: response, as: UTF8.self)
            let firstLine = text.components(separatedBy: "\r\n").first ?? text
            return "ok \(targetAddress)\(path) \(firstLine)"
        case .closed:
            return "recv http closed by peer"
        case .failed(let err):
            return "recv http failed errno=\(err)"
        }
    }

    /// Distinguishes a clean peer close from a socket error.
    ///
    /// During the regression, "no bytes returned" was materially different from
    /// "remote closed after CONNECT". Preserve that distinction in logs.
    private enum SocketReadResult {
        case success([UInt8])
        case closed
        case failed(Int32)
    }

    private func sendAll(fd: Int32, bytes: [UInt8]) -> Bool {
        var sentTotal = 0
        while sentTotal < bytes.count {
            let sent = bytes.withUnsafeBytes {
                send(fd, $0.baseAddress!.advanced(by: sentTotal), bytes.count - sentTotal, 0)
            }
            guard sent > 0 else {
                return false
            }
            sentTotal += sent
        }
        return true
    }

    private func recvExact(fd: Int32, count: Int) -> [UInt8]? {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        while result.count < count {
            var buffer = [UInt8](repeating: 0, count: count - result.count)
            let bufferCount = buffer.count
            let received = buffer.withUnsafeMutableBytes {
                recv(fd, $0.baseAddress, bufferCount, 0)
            }
            guard received > 0 else {
                return nil
            }
            result.append(contentsOf: buffer.prefix(received))
        }
        return result
    }

    private func recvSome(fd: Int32, maxCount: Int) -> SocketReadResult {
        var buffer = [UInt8](repeating: 0, count: maxCount)
        let received = buffer.withUnsafeMutableBytes {
            recv(fd, $0.baseAddress, maxCount, 0)
        }
        if received > 0 {
            return .success(Array(buffer.prefix(received)))
        }
        if received == 0 {
            return .closed
        }
        return .failed(errno)
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
    }

    /// Reads only the tail of HEV's debug log for provider snapshots.
    ///
    /// Full HEV logs can become very large. The tail is enough to identify
    /// whether recent traffic is TCP splice, UDP churn, or session timeout.
    private func readHevLogTail() -> String? {
        guard let hevLogURL,
              let data = try? Data(contentsOf: hevLogURL),
              let content = String(data: data, encoding: .utf8),
              !content.isEmpty else {
            return nil
        }
        return content.split(separator: "\n").suffix(160).joined(separator: "\n")
    }

    /// Kept for the future dual-stack path. It is intentionally unused while
    /// `settings.ipv6Settings` is nil, because enabling IPv6 without an HTTP
    /// health check recreated the "connected but browser does not load" state.
    private func buildIPv6ExcludedRoutes(serverAddress: String?) -> [NEIPv6Route] {
        guard let serverAddress else { return [] }
        let serverAddresses = resolveIPv6Addresses(for: serverAddress)
        let routes = serverAddresses.map {
            NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128)
        }
        if !routes.isEmpty {
            tunnelLog.info("Excluded \(routes.count, privacy: .public) IPv6 server route(s) from VPN: \(serverAddresses.joined(separator: ","), privacy: .public)")
        }
        return routes
    }

    /// Parses user bypass subnets.
    ///
    /// Only IPv4 bypasses are accepted in the current Packet Tunnel path because
    /// IPv6 routing is intentionally disabled. Silently accepting IPv6-looking
    /// values here would give users a false sense of coverage.
    private func ipv4Route(fromCIDR cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              (0...32).contains(prefix),
              let subnetMask = subnetMask(prefixLength: prefix) else {
            tunnelLog.warning("Ignoring invalid IPv4 bypass subnet: \(cidr, privacy: .public)")
            return nil
        }
        let address = String(parts[0])
        guard isIPv4Literal(address) else {
            tunnelLog.warning("Ignoring non-IPv4 bypass subnet: \(cidr, privacy: .public)")
            return nil
        }
        return NEIPv4Route(destinationAddress: address, subnetMask: subnetMask)
    }

    private func subnetMask(prefixLength: Int) -> String? {
        guard (0...32).contains(prefixLength) else { return nil }
        let mask = prefixLength == 0 ? UInt32(0) : UInt32.max << UInt32(32 - prefixLength)
        return [
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff
        ].map(String.init).joined(separator: ".")
    }

    /// Resolves IPv4 addresses for DNS host mapping and route exclusions.
    ///
    /// The first IPv4 is also what the server TCP route health check uses. If a
    /// provider returns multiple A records and one is bad, future work may need
    /// to test/exclude more than the first, but the current implementation logs
    /// all resolved addresses that it excludes.
    private func resolveIPv4Addresses(for host: String) -> [String] {
        if isIPv4Literal(host) {
            return [host]
        }
        return resolveAddresses(for: host, family: AF_INET)
    }

    private func resolveIPv6Addresses(for host: String) -> [String] {
        if isIPv6Literal(host) {
            return [host]
        }
        return resolveAddresses(for: host, family: AF_INET6)
    }

    private func resolveAddresses(for host: String, family: Int32) -> [String] {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: family,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let first = result else {
            rememberTunnelLog("Failed to resolve \(host): \(String(cString: gai_strerror(status)))")
            tunnelLog.warning("Failed to resolve \(host, privacy: .public): \(String(cString: gai_strerror(status)), privacy: .public)")
            return []
        }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var pointer: UnsafeMutablePointer<addrinfo>? = first
        while let current = pointer {
            if current.pointee.ai_family == AF_INET {
                var addr = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    addresses.append(String(cString: buffer))
                }
            } else if current.pointee.ai_family == AF_INET6 {
                var addr = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    addresses.append(String(cString: buffer))
                }
            }
            pointer = current.pointee.ai_next
        }
        return Array(Set(addresses)).sorted()
    }

    private func isIPv4Literal(_ address: String) -> Bool {
        var addr = in_addr()
        return address.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }

    private func isIPv6Literal(_ address: String) -> Bool {
        var addr = in6_addr()
        return address.withCString { inet_pton(AF_INET6, $0, &addr) } == 1
    }

    private func tunnelError(_ message: String) -> NSError {
        tunnelLog.error("\(message, privacy: .public)")
        return NSError(domain: "flutter_vless.packet_tunnel", code: 1, userInfo: [
            NSLocalizedDescriptionKey: message
        ])
    }

    private func logTrafficStats(context: String) {
        guard Date().timeIntervalSince(lastTrafficLogDate) >= 2 || context != "poll" else {
            return
        }
        lastTrafficLogDate = Date()
        let stats = Socks5Tunnel.stats
        rememberTunnelLog("Traffic \(context): upPackets=\(stats.up.packets) upBytes=\(stats.up.bytes) downPackets=\(stats.down.packets) downBytes=\(stats.down.bytes)")
        tunnelLog.info("Traffic stats context=\(context, privacy: .public) upPackets=\(stats.up.packets, privacy: .public) upBytes=\(stats.up.bytes, privacy: .public) downPackets=\(stats.down.packets, privacy: .public) downBytes=\(stats.down.bytes, privacy: .public)")
    }
}


class CustomXRayLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ s: String?) {
        if let logMessage = s {
            TunnelDebugStore.shared.append("XRay: \(logMessage)")
            tunnelLog.info("XRay: \(logMessage, privacy: .public)")
        }
    }
}
