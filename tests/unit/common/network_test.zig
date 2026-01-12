//! Unit tests for network address parsing and matching
//!
//! Tests for IP address parsing, CIDR network matching, and related functionality.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const network = lib.common.network;
const IPv4Address = network.IPv4Address;
const IPv6Address = network.IPv6Address;
const IPv4Network = network.IPv4Network;
const IPv6Network = network.IPv6Network;
const IPAddress = network.IPAddress;
const IPNetwork = network.IPNetwork;

// ============================================
// IPv4 Address Tests
// ============================================

test "IPv4Address.parse common addresses" {
    // Localhost
    const localhost = IPv4Address.parse("127.0.0.1").?;
    try testing.expectEqual(@as(u8, 127), localhost.octets[0]);
    try testing.expectEqual(@as(u8, 0), localhost.octets[1]);
    try testing.expectEqual(@as(u8, 0), localhost.octets[2]);
    try testing.expectEqual(@as(u8, 1), localhost.octets[3]);
    
    // Private network addresses
    _ = IPv4Address.parse("10.0.0.1").?;
    _ = IPv4Address.parse("172.16.0.1").?;
    _ = IPv4Address.parse("192.168.0.1").?;
    
    // Broadcast
    const broadcast = IPv4Address.parse("255.255.255.255").?;
    for (broadcast.octets) |octet| {
        try testing.expectEqual(@as(u8, 255), octet);
    }
    
    // Zero
    const zero = IPv4Address.parse("0.0.0.0").?;
    for (zero.octets) |octet| {
        try testing.expectEqual(@as(u8, 0), octet);
    }
}

test "IPv4Address.parse invalid addresses" {
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse(""));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1.256"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1.1.1"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("abc.def.ghi.jkl"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168..1"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse(".192.168.1.1"));
    try testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1.1."));
}

test "IPv4Address.toU32 and fromU32" {
    const addr = IPv4Address.parse("192.168.1.1").?;
    const u32_val = addr.toU32();
    const reconstructed = IPv4Address.fromU32(u32_val);
    
    try testing.expect(addr.eql(reconstructed));
}

test "IPv4Address.eql" {
    const a1 = IPv4Address.parse("192.168.1.1").?;
    const a2 = IPv4Address.parse("192.168.1.1").?;
    const a3 = IPv4Address.parse("192.168.1.2").?;
    
    try testing.expect(a1.eql(a2));
    try testing.expect(!a1.eql(a3));
}

// ============================================
// IPv4 Network Tests
// ============================================

test "IPv4Network.parse valid networks" {
    const net1 = IPv4Network.parse("192.168.1.0/24").?;
    try testing.expectEqual(@as(u8, 24), net1.prefix_len);
    
    const net2 = IPv4Network.parse("10.0.0.0/8").?;
    try testing.expectEqual(@as(u8, 8), net2.prefix_len);
    
    const net3 = IPv4Network.parse("0.0.0.0/0").?;
    try testing.expectEqual(@as(u8, 0), net3.prefix_len);
    
    const net4 = IPv4Network.parse("192.168.1.1/32").?;
    try testing.expectEqual(@as(u8, 32), net4.prefix_len);
}

test "IPv4Network.parse invalid networks" {
    try testing.expectEqual(@as(?IPv4Network, null), IPv4Network.parse("192.168.1.0"));
    try testing.expectEqual(@as(?IPv4Network, null), IPv4Network.parse("192.168.1.0/33"));
    try testing.expectEqual(@as(?IPv4Network, null), IPv4Network.parse("192.168.1.0/-1"));
    try testing.expectEqual(@as(?IPv4Network, null), IPv4Network.parse("192.168.1/24"));
}

test "IPv4Network.contains /24" {
    const net = IPv4Network.parse("192.168.1.0/24").?;
    
    // Should contain
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.0").?));
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.1").?));
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.128").?));
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.255").?));
    
    // Should not contain
    try testing.expect(!net.contains(IPv4Address.parse("192.168.0.1").?));
    try testing.expect(!net.contains(IPv4Address.parse("192.168.2.1").?));
    try testing.expect(!net.contains(IPv4Address.parse("10.0.0.1").?));
}

test "IPv4Network.contains /8" {
    const net = IPv4Network.parse("10.0.0.0/8").?;
    
    try testing.expect(net.contains(IPv4Address.parse("10.0.0.1").?));
    try testing.expect(net.contains(IPv4Address.parse("10.255.255.255").?));
    try testing.expect(net.contains(IPv4Address.parse("10.128.64.32").?));
    
    try testing.expect(!net.contains(IPv4Address.parse("11.0.0.1").?));
    try testing.expect(!net.contains(IPv4Address.parse("192.168.1.1").?));
}

test "IPv4Network.contains /32 (single host)" {
    const net = IPv4Network.parse("192.168.1.100/32").?;
    
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.100").?));
    try testing.expect(!net.contains(IPv4Address.parse("192.168.1.101").?));
    try testing.expect(!net.contains(IPv4Address.parse("192.168.1.99").?));
}

test "IPv4Network.contains /0 (all addresses)" {
    const net = IPv4Network.parse("0.0.0.0/0").?;
    
    try testing.expect(net.contains(IPv4Address.parse("0.0.0.0").?));
    try testing.expect(net.contains(IPv4Address.parse("255.255.255.255").?));
    try testing.expect(net.contains(IPv4Address.parse("192.168.1.1").?));
    try testing.expect(net.contains(IPv4Address.parse("10.0.0.1").?));
}

// ============================================
// IPv6 Address Tests
// ============================================

test "IPv6Address.parse loopback" {
    const localhost = IPv6Address.parse("::1").?;
    
    // All zeros except last byte
    for (0..15) |i| {
        try testing.expectEqual(@as(u8, 0), localhost.bytes[i]);
    }
    try testing.expectEqual(@as(u8, 1), localhost.bytes[15]);
}

test "IPv6Address.parse full address" {
    const addr = IPv6Address.parse("2001:0db8:0000:0000:0000:0000:0000:0001").?;
    
    try testing.expectEqual(@as(u8, 0x20), addr.bytes[0]);
    try testing.expectEqual(@as(u8, 0x01), addr.bytes[1]);
    try testing.expectEqual(@as(u8, 0x0d), addr.bytes[2]);
    try testing.expectEqual(@as(u8, 0xb8), addr.bytes[3]);
}

test "IPv6Address.parse compressed" {
    const addr1 = IPv6Address.parse("2001:db8::1").?;
    const addr2 = IPv6Address.parse("2001:0db8:0000:0000:0000:0000:0000:0001").?;
    
    try testing.expect(addr1.eql(addr2));
}

test "IPv6Address.eql" {
    const a1 = IPv6Address.parse("::1").?;
    const a2 = IPv6Address.parse("0:0:0:0:0:0:0:1").?;
    const a3 = IPv6Address.parse("::2").?;
    
    try testing.expect(a1.eql(a2));
    try testing.expect(!a1.eql(a3));
}

// ============================================
// IPv6 Network Tests
// ============================================

test "IPv6Network.parse valid networks" {
    const net1 = IPv6Network.parse("2001:db8::/32").?;
    try testing.expectEqual(@as(u8, 32), net1.prefix_len);
    
    const net2 = IPv6Network.parse("fe80::/10").?;
    try testing.expectEqual(@as(u8, 10), net2.prefix_len);
    
    const net3 = IPv6Network.parse("::/0").?;
    try testing.expectEqual(@as(u8, 0), net3.prefix_len);
}

test "IPv6Network.contains" {
    const net = IPv6Network.parse("2001:db8::/32").?;
    
    try testing.expect(net.contains(IPv6Address.parse("2001:db8::1").?));
    try testing.expect(net.contains(IPv6Address.parse("2001:db8:1234::1").?));
    try testing.expect(net.contains(IPv6Address.parse("2001:db8:ffff:ffff::1").?));
    
    try testing.expect(!net.contains(IPv6Address.parse("2001:db9::1").?));
    try testing.expect(!net.contains(IPv6Address.parse("2002:db8::1").?));
}

// ============================================
// IPAddress (union) Tests
// ============================================

test "IPAddress.parse auto-detect IPv4" {
    const addr = IPAddress.parse("192.168.1.1").?;
    try testing.expect(addr == .v4);
}

test "IPAddress.parse auto-detect IPv6" {
    const addr = IPAddress.parse("::1").?;
    try testing.expect(addr == .v6);
}

test "IPAddress.eql same type" {
    const v4_1 = IPAddress.parse("192.168.1.1").?;
    const v4_2 = IPAddress.parse("192.168.1.1").?;
    const v6_1 = IPAddress.parse("::1").?;
    const v6_2 = IPAddress.parse("::1").?;
    
    try testing.expect(v4_1.eql(v4_2));
    try testing.expect(v6_1.eql(v6_2));
}

test "IPAddress.eql different types" {
    const v4 = IPAddress.parse("192.168.1.1").?;
    const v6 = IPAddress.parse("::1").?;
    
    try testing.expect(!v4.eql(v6));
}

// ============================================
// IPNetwork (union) Tests
// ============================================

test "IPNetwork.parse auto-detect" {
    const v4_net = IPNetwork.parse("192.168.1.0/24").?;
    try testing.expect(v4_net == .v4);
    
    const v6_net = IPNetwork.parse("2001:db8::/32").?;
    try testing.expect(v6_net == .v6);
}

test "IPNetwork.contains matching types" {
    const v4_net = IPNetwork.parse("192.168.1.0/24").?;
    const v4_addr = IPAddress.parse("192.168.1.100").?;
    
    try testing.expect(v4_net.contains(v4_addr));
}

test "IPNetwork.contains mismatched types" {
    const v4_net = IPNetwork.parse("192.168.1.0/24").?;
    const v6_addr = IPAddress.parse("::1").?;
    
    try testing.expect(!v4_net.contains(v6_addr));
}
