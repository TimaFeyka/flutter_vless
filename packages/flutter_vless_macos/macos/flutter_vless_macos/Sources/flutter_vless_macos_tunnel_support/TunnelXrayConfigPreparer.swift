import Foundation
import Darwin

// MARK: - macOS Packet Tunnel Xray JSON Preparation
//
// The provider receives Xray JSON that can come from share links, subscriptions,
// raw app imports, or user-edited configs. The app-facing parser must preserve
// protocol details, but the macOS Packet Tunnel needs a few extra invariants:
//
// - file logs must not point at paths outside the extension sandbox;
// - Xray DNS must prefer IPv4 to match the provider's IPv4-only route model;
// - local SOCKS/HTTP inbounds must listen on 127.0.0.1 for HEV;
// - HEV traffic entering local inbounds must be forced to the proxy outbound;
// - UDP/443 must be blackholed to force browser QUIC fallback;
// - the outbound server domain must be preserved for TLS/SNI/Reality/XHTTP
//   semantics, even when we resolve an IPv4 for route exclusion.
//
// Keep this file pure and deterministic. It should not import NetworkExtension
// or start Xray. That separation is what makes unit tests possible for the
// highest-risk JSON mutations without launching an extension process.

/// Minimal parsed facts needed by the Packet Tunnel provider.
///
/// `serverAddress` is deliberately the logical Xray outbound address. If the
/// config used a domain, this stays a domain. The provider resolves it later for
/// host route exclusions, but Xray keeps the original domain so transports that
/// depend on SNI, Host, authority, or Reality metadata do not break.
public struct TunnelParsedConfig: Equatable {
    public let inboundPort: Int
    public let serverAddress: String?
    public let serverPort: Int?

    public init(inboundPort: Int, serverAddress: String?, serverPort: Int?) {
        self.inboundPort = inboundPort
        self.serverAddress = serverAddress
        self.serverPort = serverPort
    }
}

/// Result of preparing imported Xray JSON for the macOS extension.
///
/// `logMessages` are not cosmetic. They are surfaced in provider debug
/// snapshots and form the golden checklist for real-device Packet Tunnel
/// smoke tests.
public struct TunnelPreparedConfig {
    public let data: Data
    public let logMessages: [String]
    public let proxyUsesXhttp: Bool

    public init(data: Data, logMessages: [String], proxyUsesXhttp: Bool) {
        self.data = data
        self.logMessages = logMessages
        self.proxyUsesXhttp = proxyUsesXhttp
    }
}

/// Pure JSON normalizer for the macOS Packet Tunnel.
///
/// Keep this logic outside `NEPacketTunnelProvider` so we can unit-test the
/// failure-prone parts without launching a real NetworkExtension process. The
/// helper intentionally preserves proxy credentials and VLESS
/// `users[].encryption` values byte-for-byte; the XHTTP/none incident proved
/// that mutating or dropping those server-provisioned values can produce a VPN
/// that connects locally but cannot fetch HTTP bytes.
public enum TunnelXrayConfigPreparer {
    /// Parses the values the provider needs after normalization.
    ///
    /// SOCKS is preferred over HTTP because HEV speaks SOCKS to Xray. HTTP is a
    /// fallback only for old or unusual configs. If no local proxy inbound can
    /// be found, the provider cannot bridge utun packets into Xray.
    public static func parseConfig(jsonData: Data) -> TunnelParsedConfig? {
        guard
            let configJSON = try? JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any],
            let inboundPort = firstLocalInboundPort(configJSON: configJSON)
        else {
            return nil
        }
        return TunnelParsedConfig(
            inboundPort: inboundPort,
            serverAddress: parseServerAddress(configJSON: configJSON),
            serverPort: parseServerPort(configJSON: configJSON)
        )
    }

    /// Applies macOS Packet Tunnel safety edits to imported Xray JSON.
    ///
    /// The goal is not to "improve" user configs in general. The goal is to make
    /// them safe and deterministic inside this extension. Every mutation below
    /// is tied to a concrete observed failure:
    ///
    /// - file log outputs caused sandbox/path startup failures;
    /// - non-IPv4 DNS strategies allowed Xray to choose addresses the provider
    ///   did not route-exclude;
    /// - missing/remote-listening local inbounds broke HEV;
    /// - imported route rules sometimes sent HEV traffic to `freedom`;
    /// - UDP/443 can hide an otherwise healthy TCP fallback path.
    public static func prepare(
        jsonData: Data,
        resolveIPv4: (String) -> String? = { _ in nil }
    ) -> TunnelPreparedConfig? {
        do {
            guard var configJSON = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any] else {
                return nil
            }
            var messages: [String] = []

            // Network extensions do not share the app's filesystem assumptions.
            // Imported configs may contain desktop/mobile log paths that are not
            // writable here. Clear file outputs and keep logging through the
            // provider debug bridge instead.
            if var log = configJSON["log"] as? [String: Any] {
                log["access"] = ""
                log["error"] = ""
                log["loglevel"] = "debug"
                log["dnsLog"] = false
                configJSON["log"] = log
            } else {
                configJSON["log"] = [
                    "access": "",
                    "error": "",
                    "loglevel": "debug",
                    "dnsLog": false
                ]
            }
            messages.append("Disabled XRay file log outputs for packet tunnel")

            ensureXrayDNSUsesIPv4(configJSON: &configJSON, messages: &messages)

            // `AsIs` avoids Xray doing broad IP/domain rewrites that can fight
            // the provider's explicit server host-route exclusion. More
            // targeted IPv4 preference is handled in Xray DNS below.
            if var routing = configJSON["routing"] as? [String: Any] {
                routing["domainStrategy"] = "AsIs"
                configJSON["routing"] = routing
            } else {
                configJSON["routing"] = ["domainStrategy": "AsIs"]
            }

            var inbounds = configJSON["inbounds"] as? [[String: Any]] ?? []
            let localInboundTags = normalizeLocalInbounds(
                configJSON: &configJSON,
                inbounds: &inbounds,
                messages: &messages
            )

            var proxyUsesXhttp = false
            var proxyOutboundTag: String?
            if var outbounds = configJSON["outbounds"] as? [[String: Any]] {
                for index in outbounds.indices {
                    let tag = outbounds[index]["tag"] as? String
                    let protocolType = outbounds[index]["protocol"] as? String
                    guard tag == "proxy" || protocolType != "freedom" && protocolType != "blackhole" else {
                        continue
                    }
                    let candidateTag: String
                    if let tag, !tag.isEmpty {
                        candidateTag = tag
                    } else {
                        candidateTag = uniqueOutboundTag(outbounds: outbounds, preferred: "proxy")
                        outbounds[index]["tag"] = candidateTag
                        messages.append("Tagged proxy outbound as \(candidateTag) for packet tunnel routing")
                    }
                    proxyOutboundTag = candidateTag

                    var streamSettings = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
                    normalizeStreamSettingsAliases(streamSettings: &streamSettings, messages: &messages)
                    let network = (streamSettings["network"] as? String)?.lowercased() ?? "?"
                    proxyUsesXhttp = network == "xhttp"

                    if let serverAddress = parseServerAddress(configJSON: ["outbounds": [outbounds[index]]]),
                       shouldResolve(serverAddress) {
                        if let resolvedAddress = resolveIPv4(serverAddress) {
                            // Preserve the outbound domain in-place, but teach
                            // Xray to resolve that domain to the same IPv4 that
                            // the provider will exclude from utun. This keeps
                            // TLS/SNI/Reality/XHTTP semantics intact while
                            // preventing server-route recursion.
                            upsertXrayDNSHost(
                                configJSON: &configJSON,
                                host: serverAddress,
                                address: resolvedAddress
                            )
                            messages.append("Resolved proxy server domain \(serverAddress) to IPv4 \(resolvedAddress) for packet tunnel routing")
                        } else {
                            messages.append("Keeping proxy server domain unresolved in Xray config; route exclusion resolves it separately")
                        }
                    }

                    if var sockopt = streamSettings["sockopt"] as? [String: Any],
                       sockopt.removeValue(forKey: "domainStrategy") != nil {
                        // `sockopt.domainStrategy` can override the provider's
                        // IPv4-only model. Remove it so DNS behavior is
                        // centralized and logged in this preparer.
                        if sockopt.isEmpty {
                            streamSettings.removeValue(forKey: "sockopt")
                        } else {
                            streamSettings["sockopt"] = sockopt
                        }
                    }
                    outbounds[index]["streamSettings"] = streamSettings
                    break
                }
                configJSON["outbounds"] = outbounds
            }

            if let proxyOutboundTag,
               ensureForceProxyRule(
                configJSON: &configJSON,
                inboundTags: localInboundTags,
                outboundTag: proxyOutboundTag
               ) {
                messages.append("Forced local tunnel inbound(s) \(localInboundTags.joined(separator: ",")) to proxy outbound \(proxyOutboundTag)")
            }

            let blackholeTag = ensureBlackholeOutbound(configJSON: &configJSON)
            if ensureUdp443BlockRule(configJSON: &configJSON, outboundTag: blackholeTag) {
                messages.append("Added UDP/443 block rule to force browser QUIC fallback while allowing DNS")
            }

            let data = try JSONSerialization.data(withJSONObject: configJSON, options: [])
            return TunnelPreparedConfig(data: data, logMessages: messages, proxyUsesXhttp: proxyUsesXhttp)
        } catch {
            return nil
        }
    }

    /// Finds the first non-freedom/non-blackhole outbound server address.
    ///
    /// Supports common Xray schemas (`vnext`, `servers`, and flat `address`) so
    /// both VLESS/VMess-style and other outbound formats can be route-excluded.
    public static func parseServerAddress(configJSON: [String: Any]) -> String? {
        guard let outbounds = configJSON["outbounds"] as? [[String: Any]] else {
            return nil
        }
        for outbound in outbounds {
            let tag = outbound["tag"] as? String
            let protocolType = outbound["protocol"] as? String
            guard tag == "proxy" || protocolType != "freedom" && protocolType != "blackhole" else {
                continue
            }
            guard let settings = outbound["settings"] as? [String: Any] else {
                continue
            }
            if let vnext = settings["vnext"] as? [[String: Any]],
               let address = vnext.first?["address"] as? String,
               !address.isEmpty {
                return address
            }
            if let servers = settings["servers"] as? [[String: Any]],
               let address = servers.first?["address"] as? String,
               !address.isEmpty {
                return address
            }
            if let address = settings["address"] as? String, !address.isEmpty {
                return address
            }
        }
        return nil
    }

    /// Finds the first proxy outbound port.
    ///
    /// The provider uses this for the server TCP route health check. Defaulting
    /// to 443 is reasonable for many VLESS/TLS configs, but parsing the actual
    /// port avoids false failures on non-standard servers.
    public static func parseServerPort(configJSON: [String: Any]) -> Int? {
        guard let outbounds = configJSON["outbounds"] as? [[String: Any]] else {
            return nil
        }
        for outbound in outbounds {
            let tag = outbound["tag"] as? String
            let protocolType = outbound["protocol"] as? String
            guard tag == "proxy" || protocolType != "freedom" && protocolType != "blackhole" else {
                continue
            }
            guard let settings = outbound["settings"] as? [String: Any] else {
                continue
            }
            if let vnext = settings["vnext"] as? [[String: Any]],
               let port = vnext.first?["port"] as? Int {
                return port
            }
            if let servers = settings["servers"] as? [[String: Any]],
               let port = servers.first?["port"] as? Int {
                return port
            }
            if let port = settings["port"] as? Int {
                return port
            }
        }
        return nil
    }

    /// Chooses the local inbound port HEV should target.
    ///
    /// SOCKS is preferred because HEV is configured as a SOCKS client. HTTP is
    /// only a compatibility fallback. If `prepare` injected a SOCKS inbound,
    /// this will find that injected port.
    private static func firstLocalInboundPort(configJSON: [String: Any]) -> Int? {
        guard let inbounds = configJSON["inbounds"] as? [[String: Any]] else {
            return nil
        }
        for inbound in inbounds {
            guard let protocolType = inbound["protocol"] as? String,
                  let port = inbound["port"] as? Int else {
                continue
            }
            if protocolType == "socks" {
                return port
            }
        }
        for inbound in inbounds {
            guard let protocolType = inbound["protocol"] as? String,
                  let port = inbound["port"] as? Int else {
                continue
            }
            if protocolType == "http" {
                return port
            }
        }
        return nil
    }

    /// Forces Xray's own DNS layer to stay in the provider's IPv4 model.
    ///
    /// This is separate from `NEDNSSettings`. NetworkExtension DNS controls
    /// system resolver behavior; Xray DNS controls how Xray resolves its proxy
    /// outbound and routed destinations. They must agree on address family or
    /// route exclusions become unreliable.
    private static func ensureXrayDNSUsesIPv4(
        configJSON: inout [String: Any],
        messages: inout [String]
    ) {
        var dns = configJSON["dns"] as? [String: Any] ?? [:]
        let previousStrategy = dns["queryStrategy"] as? String
        dns["queryStrategy"] = "UseIPv4"
        configJSON["dns"] = dns

        if previousStrategy == nil {
            messages.append("Added Xray DNS queryStrategy=UseIPv4 for packet tunnel")
        } else if previousStrategy != "UseIPv4" {
            messages.append("Changed Xray DNS queryStrategy from \(previousStrategy ?? "nil") to UseIPv4 for packet tunnel")
        }
    }

    /// Pins an outbound domain inside Xray DNS without mutating the outbound.
    ///
    /// This is the key compromise: route exclusion needs an IP, but the outbound
    /// transport often needs the original domain. `dns.hosts` gives both sides
    /// the same IPv4 while preserving the outbound's domain string.
    private static func upsertXrayDNSHost(
        configJSON: inout [String: Any],
        host: String,
        address: String
    ) {
        var dns = configJSON["dns"] as? [String: Any] ?? [:]
        var hosts = dns["hosts"] as? [String: Any] ?? [:]
        hosts[host] = address
        dns["hosts"] = hosts
        dns["queryStrategy"] = "UseIPv4"
        configJSON["dns"] = dns
    }

    /// Makes local SOCKS/HTTP inbounds safe for HEV and deterministic routing.
    ///
    /// Rules:
    ///
    /// - listen on loopback only, because HEV and the provider live locally;
    /// - keep or create stable tags so forced routing can reference them;
    /// - enable sniffing metadata, but with `routeOnly = true`;
    /// - ensure SOCKS no-auth and allow local UDP ASSOC for HEV;
    /// - inject a SOCKS inbound if the config lacks one.
    ///
    /// `routeOnly = true` is intentional. It lets Xray use sniffed protocol
    /// hints for routing without rewriting destinations in ways that broke the
    /// literal-IP health check and made XHTTP behavior fragile.
    private static func normalizeLocalInbounds(
        configJSON: inout [String: Any],
        inbounds: inout [[String: Any]],
        messages: inout [String]
    ) -> [String] {
        let sniffing: [String: Any] = [
            "enabled": true,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": true
        ]

        var hasSocksInbound = false
        var changedSocksInbound = false
        var tunnelInboundTag: String?
        var fallbackHTTPInboundTag: String?
        var localInboundTags: [String] = []
        for index in inbounds.indices {
            let protocolType = inbounds[index]["protocol"] as? String
            guard protocolType == "socks" || protocolType == "http" else {
                continue
            }

            if let tag = inbounds[index]["tag"] as? String, !tag.isEmpty {
                localInboundTags.append(tag)
            } else {
                let tag = uniqueInboundTag(inbounds: inbounds, preferred: protocolType ?? "inbound")
                inbounds[index]["tag"] = tag
                localInboundTags.append(tag)
                messages.append("Tagged local \(protocolType ?? "proxy") inbound as \(tag) for packet tunnel routing")
            }
            inbounds[index]["listen"] = "127.0.0.1"
            inbounds[index]["sniffing"] = sniffing

            if protocolType == "http", fallbackHTTPInboundTag == nil {
                fallbackHTTPInboundTag = localInboundTags.last
            }
            guard protocolType == "socks" else {
                continue
            }

            hasSocksInbound = true
            if tunnelInboundTag == nil {
                tunnelInboundTag = localInboundTags.last
            }
            let oldSettings = inbounds[index]["settings"] as? [String: Any] ?? [:]
            var settings: [String: Any] = ["auth": "noauth", "udp": true]
            if let userLevel = oldSettings["userLevel"] as? Int {
                settings["userLevel"] = userLevel
            }
            if !NSDictionary(dictionary: oldSettings).isEqual(to: settings) {
                changedSocksInbound = true
            }
            inbounds[index]["settings"] = settings
        }

        if !hasSocksInbound {
            let port = nextAvailablePort(preferred: 10807, inbounds: inbounds)
            let tag = uniqueInboundTag(inbounds: inbounds, preferred: "socks")
            inbounds.insert([
                "tag": tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": ["auth": "noauth", "udp": true],
                "sniffing": sniffing
            ], at: 0)
            tunnelInboundTag = tag
            messages.append("Injected local SOCKS inbound for packet tunnel on port \(port)")
        } else if changedSocksInbound {
            messages.append("Enabled local SOCKS UDP ASSOC for HEV; UDP/443 remains blackholed")
        }

        configJSON["inbounds"] = inbounds
        return [tunnelInboundTag ?? fallbackHTTPInboundTag].compactMap { $0 }
    }

    /// Normalizes common app-export key variants to Xray's canonical JSON keys.
    ///
    /// Happ exports XHTTP as `xHTTPSettings`, while Xray's config struct expects
    /// `xhttpSettings`. Without this alias, Xray silently falls back to default
    /// XHTTP settings and imported configs no longer mean exactly what the user
    /// tested in the source client.
    private static func normalizeStreamSettingsAliases(
        streamSettings: inout [String: Any],
        messages: inout [String]
    ) {
        if let network = streamSettings["network"] as? String {
            let normalizedNetwork = network.lowercased()
            if normalizedNetwork != network {
                streamSettings["network"] = normalizedNetwork
            }
        }

        if let legacyXhttpSettings = streamSettings.removeValue(forKey: "xHTTPSettings") {
            if streamSettings["xhttpSettings"] == nil {
                streamSettings["xhttpSettings"] = legacyXhttpSettings
                messages.append("Normalized xHTTPSettings to xhttpSettings for Xray XHTTP transport")
            }
        }

        if let legacyHTTPUpgradeSettings = streamSettings.removeValue(forKey: "httpUpgradeSettings") {
            if streamSettings["httpupgradeSettings"] == nil {
                streamSettings["httpupgradeSettings"] = legacyHTTPUpgradeSettings
                messages.append("Normalized httpUpgradeSettings to httpupgradeSettings for Xray HTTPUpgrade transport")
            }
        }

        if let legacySplitHTTPSettings = streamSettings.removeValue(forKey: "splitHTTPSettings") {
            if streamSettings["splithttpSettings"] == nil {
                streamSettings["splithttpSettings"] = legacySplitHTTPSettings
                messages.append("Normalized splitHTTPSettings to splithttpSettings for Xray SplitHTTP transport")
            }
        }

        if var tlsSettings = streamSettings["tlsSettings"] as? [String: Any],
           tlsSettings.removeValue(forKey: "allowInsecure") != nil {
            streamSettings["tlsSettings"] = tlsSettings
            messages.append("Removed deprecated tlsSettings.allowInsecure for Xray 26.x")
        }
    }

    private static func nextAvailablePort(preferred: Int, inbounds: [[String: Any]]) -> Int {
        let usedPorts = Set(inbounds.compactMap { $0["port"] as? Int })
        var port = preferred
        while usedPorts.contains(port) {
            port += 1
        }
        return port
    }

    private static func uniqueInboundTag(inbounds: [[String: Any]], preferred: String) -> String {
        let usedTags = Set(inbounds.compactMap { $0["tag"] as? String })
        guard usedTags.contains(preferred) else {
            return preferred
        }
        var suffix = 1
        while usedTags.contains("\(preferred)-\(suffix)") {
            suffix += 1
        }
        return "\(preferred)-\(suffix)"
    }

    /// Ensures there is a blackhole outbound for defensive routing rules.
    ///
    /// We prefer reusing an existing blackhole tag because imported configs may
    /// already have policy around it. If absent, a minimal blackhole outbound is
    /// added solely for TCP-only packet tunnel control.
    private static func ensureBlackholeOutbound(configJSON: inout [String: Any]) -> String {
        var outbounds = configJSON["outbounds"] as? [[String: Any]] ?? []
        if let tag = outbounds.first(where: { outbound in
            (outbound["protocol"] as? String) == "blackhole"
        })?["tag"] as? String {
            return tag
        }

        let tag = uniqueOutboundTag(outbounds: outbounds, preferred: "blackhole")
        outbounds.append([
            "tag": tag,
            "protocol": "blackhole",
            "settings": [:]
        ])
        configJSON["outbounds"] = outbounds
        return tag
    }

    private static func uniqueOutboundTag(outbounds: [[String: Any]], preferred: String) -> String {
        let usedTags = Set(outbounds.compactMap { $0["tag"] as? String })
        guard usedTags.contains(preferred) else {
            return preferred
        }
        var suffix = 1
        while usedTags.contains("\(preferred)-\(suffix)") {
            suffix += 1
        }
        return "\(preferred)-\(suffix)"
    }

    /// Blocks UDP/443 to force browser QUIC/HTTP3 traffic back to TCP.
    ///
    /// This is not a general statement that UDP is unsupported forever. It is a
    /// deliberate guard for the currently validated path. DNS still needs UDP
    /// through HEV/Xray, while QUIC can hide or bypass the TCP evidence we rely
    /// on. Until QUIC over this Packet Tunnel is explicitly tested, UDP/443
    /// remains blocked.
    private static func ensureUdp443BlockRule(configJSON: inout [String: Any], outboundTag: String) -> Bool {
        var routing = configJSON["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        let originalCount = rules.count
        rules.removeAll { rule in
            (rule["type"] as? String) == "field" &&
            (rule["network"] as? String) == "udp" &&
            rule["port"] == nil &&
            (rule["outboundTag"] as? String) == outboundTag
        }
        let alreadyExists = rules.contains { rule in
            (rule["type"] as? String) == "field" &&
            (rule["network"] as? String) == "udp" &&
            String(describing: rule["port"] ?? "") == "443" &&
            (rule["outboundTag"] as? String) == outboundTag
        }
        if alreadyExists {
            routing["rules"] = rules
            configJSON["routing"] = routing
            return rules.count != originalCount
        }
        rules.insert([
            "type": "field",
            "network": "udp",
            "port": "443",
            "outboundTag": outboundTag
        ], at: 0)
        routing["rules"] = rules
        configJSON["routing"] = routing
        return true
    }

    /// Forces unmatched local tunnel inbound traffic to the proxy outbound.
    ///
    /// Imported configs often contain routing rules intended for normal Xray
    /// clients, not for a Network Extension feeding system traffic through one
    /// local inbound. This fallback rule prevents HEV-originated traffic from
    /// falling through to `freedom` or another default outbound, while still
    /// keeping user domain/IP split-routing rules above it.
    private static func ensureForceProxyRule(
        configJSON: inout [String: Any],
        inboundTags: [String],
        outboundTag: String
    ) -> Bool {
        guard !inboundTags.isEmpty else {
            return false
        }
        var routing = configJSON["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        let sortedInboundTags = inboundTags.sorted()
        let alreadyExists = rules.contains { rule in
            (rule["type"] as? String) == "field" &&
            (rule["outboundTag"] as? String) == outboundTag &&
            ((rule["inboundTag"] as? [String]) ?? []).sorted() == sortedInboundTags
        }
        if alreadyExists {
            return false
        }
        let insertionIndex = forceProxyRuleInsertionIndex(rules: rules)
        rules.insert([
            "type": "field",
            "inboundTag": sortedInboundTags,
            "outboundTag": outboundTag
        ], at: insertionIndex)
        routing["rules"] = rules
        configJSON["routing"] = routing
        return true
    }

    /// Keeps user-specific rules before the forced proxy fallback.
    ///
    /// Xray applies routing rules in order. A broad `inboundTag -> proxy` rule
    /// above `domain:example.com -> direct` makes split routing impossible. The
    /// fallback therefore goes after rules that constrain destination/protocol,
    /// but before broad inbound-only or catch-all rules that could leak Packet
    /// Tunnel traffic to `freedom`.
    private static func forceProxyRuleInsertionIndex(rules: [[String: Any]]) -> Int {
        for (index, rule) in rules.enumerated() {
            if !hasSpecificRoutingCondition(rule) {
                return index
            }
        }
        return rules.count
    }

    private static func hasSpecificRoutingCondition(_ rule: [String: Any]) -> Bool {
        let specificKeys = [
            "domain",
            "ip",
            "port",
            "network",
            "protocol",
            "source",
            "sourcePort",
            "user",
            "attrs"
        ]
        return specificKeys.contains { key in
            guard let value = rule[key] else {
                return false
            }
            if let list = value as? [Any] {
                return !list.isEmpty
            }
            if let string = value as? String {
                return !string.isEmpty
            }
            return true
        }
    }

    /// Legacy helper retained for tests/history, but not used by the current
    /// provider path.
    ///
    /// Directly replacing the outbound server domain with an IP was rejected
    /// because it can break TLS/SNI/Reality/XHTTP semantics. The current design
    /// resolves the domain for route exclusion and Xray DNS host mapping while
    /// preserving the outbound domain itself.
    private static func replaceProxyServerDomainWithIPv4(
        outbound: inout [String: Any],
        resolveIPv4: (String) -> String?
    ) -> Bool {
        guard var settings = outbound["settings"] as? [String: Any] else {
            return false
        }

        if var vnext = settings["vnext"] as? [[String: Any]],
           !vnext.isEmpty,
           let address = vnext[0]["address"] as? String,
           shouldResolve(address),
           let ip = resolveIPv4(address) {
            vnext[0]["address"] = ip
            settings["vnext"] = vnext
            outbound["settings"] = settings
            return true
        }

        if var servers = settings["servers"] as? [[String: Any]],
           !servers.isEmpty,
           let address = servers[0]["address"] as? String,
           shouldResolve(address),
           let ip = resolveIPv4(address) {
            servers[0]["address"] = ip
            settings["servers"] = servers
            outbound["settings"] = settings
            return true
        }

        if let address = settings["address"] as? String,
           shouldResolve(address),
           let ip = resolveIPv4(address) {
            settings["address"] = ip
            outbound["settings"] = settings
            return true
        }

        return false
    }

    private static func shouldResolve(_ address: String) -> Bool {
        !address.isEmpty && !isIPv4Literal(address) && !isIPv6Literal(address)
    }

    private static func isIPv4Literal(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    private static func isIPv6Literal(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }
}
