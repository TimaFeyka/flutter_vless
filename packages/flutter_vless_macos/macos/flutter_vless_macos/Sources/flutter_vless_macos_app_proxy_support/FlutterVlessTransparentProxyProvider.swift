import Foundation
import Network
import NetworkExtension
import CXRay
import os

private let appProxyLog = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "flutter_vless.XrayAppProxy",
    category: "TransparentProxy"
)
private let socksHost = "127.0.0.1"
private let socksPort: UInt16 = 10807

open class FlutterVlessTransparentProxyProvider: NETransparentProxyProvider {
    private let logger = AppProxyXRayLogger()
    private let flowLock = NSLock()
    private var bridges: [UUID: AnyObject] = [:]
    private var selectedApplicationIdentifiers: Set<String> = []

    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = tunnelProtocol.providerConfiguration,
              let config = providerConfiguration["xrayConfig"] as? Data,
              let selected = providerConfiguration["selectedApplicationIdentifiers"] as? [String],
              !selected.isEmpty else {
            completionHandler(proxyError("Missing Xray config or selected application identifiers"))
            return
        }
        selectedApplicationIdentifiers = Set(selected.filter { !$0.isEmpty })
        guard let preparedConfig = prepareXrayConfig(config) else {
            completionHandler(proxyError("Could not prepare Xray config for app proxy"))
            return
        }

        XRaySetMemoryLimit()
        var startError: NSError?
        guard XRayStart(preparedConfig, logger, &startError) else {
            completionHandler(startError ?? proxyError("Xray failed to start"))
            return
        }

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: socksHost)
        settings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .outbound
            )
        ]
        setTunnelNetworkSettings(settings) { error in
            if let error {
                XRayStop()
                completionHandler(error)
                return
            }
            appProxyLog.info("Transparent proxy ready selectedApps=\(selected.count, privacy: .public)")
            completionHandler(nil)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        flowLock.lock()
        let activeBridges = bridges.values
        bridges.removeAll()
        flowLock.unlock()
        for case let bridge as AppProxyBridge in activeBridges {
            bridge.stop()
        }
        XRayStop()
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcpFlow = flow as? NEAppProxyTCPFlow,
           proxyEndpoint(for: tcpFlow)?.port == 53 {
            return false
        }
        return acceptSelectedFlow(flow)
    }

    private func acceptSelectedFlow(_ flow: NEAppProxyFlow) -> Bool {
        let sourceIdentifier = flow.metaData.sourceAppSigningIdentifier
        guard selectedApplicationIdentifiers.contains(sourceIdentifier) else {
            return false
        }

        let id = UUID()
        let onClose: () -> Void = { [weak self] in
            self?.flowLock.lock()
            self?.bridges.removeValue(forKey: id)
            self?.flowLock.unlock()
        }
        let bridge: AppProxyBridge
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            bridge = TCPAppProxyBridge(flow: tcpFlow, onClose: onClose)
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            bridge = UDPAppProxyBridge(flow: udpFlow, onClose: onClose)
        } else {
            return false
        }

        flowLock.lock()
        bridges[id] = bridge
        flowLock.unlock()
        bridge.start()
        return true
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let message = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }
        if message == "xray_traffic" {
            let raw = XRayQueryStats("") ?? ""
            var upload: Int64 = 0
            var download: Int64 = 0
            for line in raw.components(separatedBy: "\n") {
                let parts = line.components(separatedBy: ">>>")
                guard let valueText = parts.last?.trimmingCharacters(in: .whitespaces),
                      let value = Int64(valueText) else { continue }
                if line.contains("uplink") { upload += value }
                if line.contains("downlink") { download += value }
            }
            completionHandler?("\(upload),\(download)".data(using: .utf8))
        } else if message.hasPrefix("xray_delay") {
            let url = String(message.dropFirst(10))
            var error: NSError?
            var delay: Int64 = -1
            XRayMeasureDelay(url, &delay, &error)
            completionHandler?("\(delay)".data(using: .utf8))
        } else if message == "xray_debug" {
            flowLock.lock()
            let bridgeCount = bridges.count
            flowLock.unlock()
            let snapshot = "selectedApps=\(selectedApplicationIdentifiers.sorted().joined(separator: ",")) activeFlows=\(bridgeCount)"
            completionHandler?(snapshot.data(using: .utf8))
        } else {
            completionHandler?(messageData)
        }
    }

    private func proxyError(_ message: String) -> NSError {
        NSError(
            domain: "FlutterVlessTransparentProxy",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

private protocol AppProxyBridge: AnyObject {
    func start()
    func stop()
}

private final class TCPAppProxyBridge: AppProxyBridge {
    private let flow: NEAppProxyTCPFlow
    private let onClose: () -> Void
    private let queue = DispatchQueue(label: "flutter_vless.app_proxy.tcp")
    private var connection: NWConnection?
    private var stopped = false

    init(flow: NEAppProxyTCPFlow, onClose: @escaping () -> Void) {
        self.flow = flow
        self.onClose = onClose
    }

    func start() {
        guard let destination = proxyEndpoint(for: flow) else {
            stop(with: proxyFlowError("Missing TCP destination"))
            return
        }
        let connection = NWConnection(
            host: NWEndpoint.Host(socksHost),
            port: NWEndpoint.Port(rawValue: socksPort)!,
            using: .tcp
        )
        self.connection = connection
        connection.start(queue: queue)
        Task {
            do {
                let session = Socks5Session(connection: connection)
                try await session.connect(to: destination)
                try await openFlow(flow)
                readFromFlow()
                readFromProxy()
            } catch {
                stop(with: error)
            }
        }
    }

    private func readFromFlow() {
        guard !stopped, let connection else { return }
        flow.readData { [weak self] data, error in
            guard let self else { return }
            if let error {
                self.stop(with: error)
                return
            }
            guard let data, !data.isEmpty else {
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                self.flow.closeReadWithError(nil)
                return
            }
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    self.stop(with: error)
                } else {
                    self.readFromFlow()
                }
            })
        }
    }

    private func readFromProxy() {
        guard !stopped, let connection else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let error {
                self.stop(with: error)
                return
            }
            if let data, !data.isEmpty {
                self.flow.write(data) { error in
                    if let error {
                        self.stop(with: error)
                    } else if complete {
                        self.stop(with: nil)
                    } else {
                        self.readFromProxy()
                    }
                }
            } else if complete {
                self.stop(with: nil)
            } else {
                self.readFromProxy()
            }
        }
    }

    func stop() { stop(with: nil) }

    private func stop(with error: Error?) {
        guard !stopped else { return }
        stopped = true
        if let error {
            appProxyLog.error("TCP bridge stopped: \(error.localizedDescription, privacy: .public)")
        }
        connection?.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        onClose()
    }
}

private final class UDPAppProxyBridge: AppProxyBridge {
    private let flow: NEAppProxyUDPFlow
    private let onClose: () -> Void
    private let queue = DispatchQueue(label: "flutter_vless.app_proxy.udp")
    private var controlConnection: NWConnection?
    private var datagramConnection: NWConnection?
    private var stopped = false

    init(flow: NEAppProxyUDPFlow, onClose: @escaping () -> Void) {
        self.flow = flow
        self.onClose = onClose
    }

    func start() {
        let control = NWConnection(
            host: NWEndpoint.Host(socksHost),
            port: NWEndpoint.Port(rawValue: socksPort)!,
            using: .tcp
        )
        controlConnection = control
        control.start(queue: queue)
        Task {
            do {
                let session = Socks5Session(connection: control)
                let relay = try await session.associateUDP()
                let datagram = NWConnection(
                    host: NWEndpoint.Host(relay.host),
                    port: NWEndpoint.Port(rawValue: relay.port)!,
                    using: .udp
                )
                datagramConnection = datagram
                datagram.start(queue: queue)
                try await openFlow(flow)
                readFromFlow()
                readFromProxy()
            } catch {
                stop(with: error)
            }
        }
    }

    private func readFromFlow() {
        guard !stopped, let datagramConnection else { return }
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self else { return }
            if let error {
                self.stop(with: error)
                return
            }
            guard let datagrams, let endpoints, datagrams.count == endpoints.count else {
                self.stop(with: proxyFlowError("Invalid UDP flow payload"))
                return
            }
            for (data, endpoint) in zip(datagrams, endpoints) {
                guard let destination = proxyEndpoint(for: endpoint) else {
                    continue
                }
                if destination.port == 53 {
                    self.sendDirectDNSDatagram(data, destination: destination)
                    continue
                }
                guard let packet = socksUDPDatagram(payload: data, destination: destination) else {
                    continue
                }
                datagramConnection.send(
                    content: packet,
                    contentContext: .defaultMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if let error { self.stop(with: error) }
                    }
                )
            }
            self.readFromFlow()
        }
    }

    private func sendDirectDNSDatagram(_ data: Data, destination: ProxyEndpoint) {
        guard let port = Network.NWEndpoint.Port(rawValue: destination.port) else { return }
        let connection = NWConnection(
            host: Network.NWEndpoint.Host(destination.host),
            port: port,
            using: .udp
        )
        connection.start(queue: queue)
        connection.send(
            content: data,
            contentContext: .defaultMessage,
            isComplete: true,
            completion: .contentProcessed { [weak self] error in
                guard let self else {
                    connection.cancel()
                    return
                }
                if let error {
                    appProxyLog.error("Direct DNS send failed: \(error.localizedDescription, privacy: .public)")
                    connection.cancel()
                    return
                }
                connection.receiveMessage { response, _, _, error in
                    defer { connection.cancel() }
                    if let error {
                        appProxyLog.error("Direct DNS receive failed: \(error.localizedDescription, privacy: .public)")
                        return
                    }
                    guard let response else { return }
                    let endpoint = NWHostEndpoint(
                        hostname: destination.host,
                        port: String(destination.port)
                    )
                    self.flow.writeDatagrams([response], sentBy: [endpoint]) { error in
                        if let error {
                            appProxyLog.error("Direct DNS response failed: \(error.localizedDescription, privacy: .public)")
                        }
                    }
                }
            }
        )
    }

    private func readFromProxy() {
        guard !stopped, let datagramConnection else { return }
        datagramConnection.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.stop(with: error)
                return
            }
            if let data, let decoded = decodeSocksUDPDatagram(data) {
                let endpoint = NWHostEndpoint(
                    hostname: decoded.source.host,
                    port: String(decoded.source.port)
                )
                self.flow.writeDatagrams([decoded.payload], sentBy: [endpoint]) { error in
                    if let error { self.stop(with: error) }
                }
            }
            self.readFromProxy()
        }
    }

    func stop() { stop(with: nil) }

    private func stop(with error: Error?) {
        guard !stopped else { return }
        stopped = true
        if let error {
            appProxyLog.error("UDP bridge stopped: \(error.localizedDescription, privacy: .public)")
        }
        controlConnection?.cancel()
        datagramConnection?.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        onClose()
    }
}

private struct ProxyEndpoint {
    let host: String
    let port: UInt16
}

private final class Socks5Session {
    private let connection: NWConnection
    private var buffered = Data()

    init(connection: NWConnection) {
        self.connection = connection
    }

    func connect(to destination: ProxyEndpoint) async throws {
        try await negotiate()
        try await send(Data([0x05, 0x01, 0x00]) + encodeSocksAddress(destination))
        _ = try await readReply()
    }

    func associateUDP() async throws -> ProxyEndpoint {
        try await negotiate()
        try await send(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        let relay = try await readReply()
        if relay.host == "0.0.0.0" || relay.host == "::" {
            return ProxyEndpoint(host: socksHost, port: relay.port)
        }
        return relay
    }

    private func negotiate() async throws {
        try await send(Data([0x05, 0x01, 0x00]))
        let reply = try await readExactly(2)
        guard reply == Data([0x05, 0x00]) else {
            throw proxyFlowError("SOCKS5 authentication negotiation failed")
        }
    }

    private func readReply() async throws -> ProxyEndpoint {
        let header = try await readExactly(4)
        guard header[header.startIndex] == 0x05, header[header.startIndex + 1] == 0x00 else {
            throw proxyFlowError("SOCKS5 request failed")
        }
        let addressType = header[header.startIndex + 3]
        let host: String
        switch addressType {
        case 0x01:
            let bytes = try await readExactly(4)
            host = bytes.map(String.init).joined(separator: ".")
        case 0x03:
            let lengthData = try await readExactly(1)
            let length = Int(lengthData[lengthData.startIndex])
            let bytes = try await readExactly(length)
            guard let value = String(data: bytes, encoding: .utf8) else {
                throw proxyFlowError("Invalid SOCKS5 domain")
            }
            host = value
        case 0x04:
            let bytes = try await readExactly(16)
            host = ipv6String(bytes) ?? "::"
        default:
            throw proxyFlowError("Unsupported SOCKS5 address type")
        }
        let portData = try await readExactly(2)
        let port = UInt16(portData[portData.startIndex]) << 8
            | UInt16(portData[portData.startIndex + 1])
        return ProxyEndpoint(host: host, port: port)
    }

    private func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: ()) }
            })
        }
    }

    private func readExactly(_ count: Int) async throws -> Data {
        while buffered.count < count {
            let next: Data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, complete, error in
                    if let error { continuation.resume(throwing: error) }
                    else if let data, !data.isEmpty { continuation.resume(returning: data) }
                    else if complete { continuation.resume(throwing: proxyFlowError("SOCKS5 connection closed")) }
                    else { continuation.resume(returning: Data()) }
                }
            }
            buffered.append(next)
        }
        let result = buffered.prefix(count)
        buffered.removeFirst(count)
        return Data(result)
    }
}

private func openFlow(_ flow: NEAppProxyFlow) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        flow.open(withLocalEndpoint: nil) { error in
            if let error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: ()) }
        }
    }
}

private func proxyEndpoint(for flow: NEAppProxyTCPFlow) -> ProxyEndpoint? {
    if let hostname = flow.remoteHostname,
       let endpoint = flow.remoteEndpoint as? NWHostEndpoint,
       let port = UInt16(endpoint.port) {
        return ProxyEndpoint(host: hostname, port: port)
    }
    return proxyEndpoint(for: flow.remoteEndpoint)
}

private func proxyEndpoint(for endpoint: Any) -> ProxyEndpoint? {
    if let endpoint = endpoint as? NWHostEndpoint,
       let port = UInt16(endpoint.port) {
        return ProxyEndpoint(host: endpoint.hostname, port: port)
    }
    if let endpoint = endpoint as? Network.NWEndpoint,
       case let .hostPort(host, port) = endpoint {
        return ProxyEndpoint(host: String(describing: host), port: port.rawValue)
    }
    return nil
}

private func encodeSocksAddress(_ endpoint: ProxyEndpoint) -> Data {
    var data = Data()
    var ipv4 = in_addr()
    var ipv6 = in6_addr()
    if endpoint.host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
        data.append(0x01)
        withUnsafeBytes(of: &ipv4.s_addr) { data.append(contentsOf: $0) }
    } else if endpoint.host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
        data.append(0x04)
        withUnsafeBytes(of: &ipv6) { data.append(contentsOf: $0) }
    } else {
        let hostData = Data(endpoint.host.utf8)
        guard hostData.count <= 255 else { return Data() }
        data.append(0x03)
        data.append(UInt8(hostData.count))
        data.append(hostData)
    }
    data.append(UInt8(endpoint.port >> 8))
    data.append(UInt8(endpoint.port & 0xff))
    return data
}

private func socksUDPDatagram(payload: Data, destination: ProxyEndpoint) -> Data? {
    let address = encodeSocksAddress(destination)
    guard !address.isEmpty else { return nil }
    return Data([0x00, 0x00, 0x00]) + address + payload
}

private func decodeSocksUDPDatagram(_ data: Data) -> (source: ProxyEndpoint, payload: Data)? {
    let bytes = [UInt8](data)
    guard bytes.count >= 7, bytes[0] == 0, bytes[1] == 0, bytes[2] == 0 else { return nil }
    var index = 3
    let host: String
    switch bytes[index] {
    case 0x01:
        guard bytes.count >= index + 1 + 4 + 2 else { return nil }
        index += 1
        host = bytes[index..<(index + 4)].map(String.init).joined(separator: ".")
        index += 4
    case 0x03:
        guard bytes.count > index + 1 else { return nil }
        let length = Int(bytes[index + 1])
        index += 2
        guard bytes.count >= index + length + 2,
              let value = String(bytes: bytes[index..<(index + length)], encoding: .utf8) else { return nil }
        host = value
        index += length
    case 0x04:
        index += 1
        guard bytes.count >= index + 16 + 2 else { return nil }
        host = ipv6String(Data(bytes[index..<(index + 16)])) ?? "::"
        index += 16
    default:
        return nil
    }
    let port = UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
    index += 2
    return (ProxyEndpoint(host: host, port: port), Data(bytes[index...]))
}

private func ipv6String(_ data: Data) -> String? {
    guard data.count == 16 else { return nil }
    var address = in6_addr()
    _ = withUnsafeMutableBytes(of: &address) { data.copyBytes(to: $0) }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else { return nil }
    return String(cString: buffer)
}

private func proxyFlowError(_ message: String) -> NSError {
    NSError(domain: "FlutterVlessTransparentProxy", code: 2, userInfo: [NSLocalizedDescriptionKey: message])
}

private func prepareXrayConfig(_ data: Data) -> Data? {
    guard var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    json["log"] = ["access": "", "error": "", "loglevel": "warning", "dnsLog": false]

    var inbounds = json["inbounds"] as? [[String: Any]] ?? []
    var inboundIndex = inbounds.firstIndex { ($0["protocol"] as? String)?.lowercased() == "socks" }
    if inboundIndex == nil {
        inbounds.append(["tag": "in_proxy", "listen": socksHost, "port": Int(socksPort), "protocol": "socks", "settings": ["auth": "noauth", "udp": true]])
        inboundIndex = inbounds.indices.last
    }
    guard let inboundIndex else { return nil }
    inbounds[inboundIndex]["tag"] = "in_proxy"
    inbounds[inboundIndex]["listen"] = socksHost
    inbounds[inboundIndex]["port"] = Int(socksPort)
    var inboundSettings = inbounds[inboundIndex]["settings"] as? [String: Any] ?? [:]
    inboundSettings["auth"] = "noauth"
    inboundSettings["udp"] = true
    inbounds[inboundIndex]["settings"] = inboundSettings
    json["inbounds"] = inbounds

    var outbounds = json["outbounds"] as? [[String: Any]] ?? []
    guard let outboundIndex = outbounds.firstIndex(where: {
        let type = ($0["protocol"] as? String)?.lowercased()
        return type != nil && type != "freedom" && type != "blackhole" && type != "dns"
    }) else { return nil }
    let outboundTag = (outbounds[outboundIndex]["tag"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "proxy"
    outbounds[outboundIndex]["tag"] = outboundTag
    json["outbounds"] = outbounds

    var routing = json["routing"] as? [String: Any] ?? [:]
    routing["domainStrategy"] = "AsIs"
    var rules = routing["rules"] as? [[String: Any]] ?? []
    rules.removeAll { ($0["inboundTag"] as? [String])?.contains("in_proxy") == true }
    rules.insert(["type": "field", "inboundTag": ["in_proxy"], "outboundTag": outboundTag], at: 0)
    routing["rules"] = rules
    json["routing"] = routing

    json["stats"] = json["stats"] ?? [String: Any]()
    var policy = json["policy"] as? [String: Any] ?? [:]
    var systemPolicy = policy["system"] as? [String: Any] ?? [:]
    systemPolicy["statsInboundUplink"] = true
    systemPolicy["statsInboundDownlink"] = true
    systemPolicy["statsOutboundUplink"] = true
    systemPolicy["statsOutboundDownlink"] = true
    policy["system"] = systemPolicy
    json["policy"] = policy
    return try? JSONSerialization.data(withJSONObject: json)
}

private final class AppProxyXRayLogger: NSObject, XRayLoggerProtocol {
    func logInput(_ value: String?) {
        if let value { appProxyLog.info("Xray: \(value, privacy: .public)") }
    }
}
