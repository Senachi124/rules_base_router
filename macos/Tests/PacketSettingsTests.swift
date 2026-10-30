import Foundation
import NetworkExtension

/// Standalone checks for the actual packet provider's settings builder. Link this
/// executable separately from SmokeTests and omit PacketExtension/main.swift.
/// These checks do not create a provider, activate a VPN, or change system routes.
@main
enum PacketSettingsTests {
    static func main() throws {
        let ipv4 = ProfileSummary(
            endpointHost: "127.0.0.1", endpointPort: 51820,
            addresses: ["10.0.0.2/24"], dns: ["10.0.0.1", "fd00::1"],
            mtu: 1280, hasIpv6: false
        )
        let a = try PacketTunnelProvider.settings(for: ipv4)
        precondition(a.ipv4Settings?.addresses == ["10.0.0.2"])
        precondition(a.ipv4Settings?.subnetMasks == ["255.255.255.0"])
        precondition(a.ipv4Settings?.includedRoutes?.count == 1)
        precondition(a.ipv4Settings?.includedRoutes?.first?.destinationAddress == "0.0.0.0")
        precondition(a.ipv4Settings?.includedRoutes?.first?.destinationSubnetMask == "0.0.0.0")
        precondition(a.ipv6Settings?.includedRoutes?.first?.destinationAddress == "::")
        precondition(a.ipv6Settings?.includedRoutes?.first?.destinationNetworkPrefixLength == 0)
        precondition(a.ipv6Settings?.addresses == ["fd00:726f:7574:6562::1"])
        precondition(a.dnsSettings?.servers == ["10.0.0.1"])
        precondition(a.dnsSettings?.matchDomains == [""])
        precondition(a.dnsSettings?.matchDomainsNoSearch == true)
        precondition(a.mtu == 1280)

        let dual = ProfileSummary(
            endpointHost: "::1", endpointPort: 51820,
            addresses: ["10.0.0.2/32", "fd00::2/64"], dns: ["10.0.0.1", "fd00::1"],
            mtu: 1420, hasIpv6: true
        )
        let b = try PacketTunnelProvider.settings(for: dual)
        precondition(b.ipv4Settings?.subnetMasks == ["255.255.255.255"])
        precondition(b.ipv6Settings?.addresses == ["fd00::2"])
        precondition(b.ipv6Settings?.networkPrefixLengths == [64])
        precondition(b.dnsSettings?.servers == ["10.0.0.1", "fd00::1"])

        let ipv6 = ProfileSummary(
            endpointHost: "::1", endpointPort: 51820,
            addresses: ["fd00::2/128"], dns: ["10.0.0.1", "fd00::1"],
            mtu: 1280, hasIpv6: true
        )
        let c = try PacketTunnelProvider.settings(for: ipv6)
        precondition(c.ipv4Settings?.addresses == ["198.18.0.1"])
        precondition(c.ipv4Settings?.includedRoutes?.first?.destinationAddress == "0.0.0.0")
        precondition(c.dnsSettings?.servers == ["fd00::1"])

        for address in ["10.0.0.2/33", "10.0.0.2", "fd00::2/129"] {
            var invalid = ipv4
            invalid.addresses = [address]
            var rejected = false
            do { _ = try PacketTunnelProvider.settings(for: invalid) } catch { rejected = true }
            precondition(rejected, "Invalid interface prefix was accepted")
        }
        print("Packet settings tests passed: default routes, both missing-family block routes, dual stack, DNS routing, MTU, and malformed prefixes.")
    }
}
