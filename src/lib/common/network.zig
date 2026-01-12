//! IP address and network matching utilities
//!
//! Provides functionality to parse and match IP addresses and CIDR networks
//! for sudoers host rules.

const std = @import("std");
const posix = std.posix;

/// IPv4 address (4 bytes)
pub const IPv4Address = struct {
    octets: [4]u8,

    pub fn parse(str: []const u8) ?IPv4Address {
        var octets: [4]u8 = undefined;
        var octet_idx: usize = 0;
        var current_val: u16 = 0;
        var digits: u8 = 0;

        for (str) |c| {
            if (c == '.') {
                if (digits == 0 or octet_idx >= 3) return null;
                if (current_val > 255) return null;
                octets[octet_idx] = @truncate(current_val);
                octet_idx += 1;
                current_val = 0;
                digits = 0;
            } else if (c >= '0' and c <= '9') {
                current_val = current_val * 10 + (c - '0');
                digits += 1;
                if (digits > 3) return null;
            } else {
                return null;
            }
        }

        // Final octet
        if (digits == 0 or octet_idx != 3) return null;
        if (current_val > 255) return null;
        octets[octet_idx] = @truncate(current_val);

        return .{ .octets = octets };
    }

    /// Convert to 32-bit integer for network calculations
    pub fn toU32(self: IPv4Address) u32 {
        return @as(u32, self.octets[0]) << 24 |
            @as(u32, self.octets[1]) << 16 |
            @as(u32, self.octets[2]) << 8 |
            @as(u32, self.octets[3]);
    }

    /// Create from 32-bit integer
    pub fn fromU32(val: u32) IPv4Address {
        return .{ .octets = .{
            @truncate(val >> 24),
            @truncate(val >> 16),
            @truncate(val >> 8),
            @truncate(val),
        } };
    }

    /// Check if this address matches another
    pub fn eql(self: IPv4Address, other: IPv4Address) bool {
        return std.mem.eql(u8, &self.octets, &other.octets);
    }

    /// Format as string
    pub fn format(self: IPv4Address, buf: []u8) []const u8 {
        const len = std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
        }) catch return "";
        return buf[0..len.len];
    }
};

/// IPv6 address (16 bytes)
pub const IPv6Address = struct {
    bytes: [16]u8,

    pub fn parse(str: []const u8) ?IPv6Address {
        var result: [16]u8 = undefined;
        var groups: [8]u16 = undefined;
        var group_idx: usize = 0;
        var current_val: u16 = 0;
        var digits: u8 = 0;
        var double_colon_idx: ?usize = null;
        var i: usize = 0;

        while (i < str.len) : (i += 1) {
            const c = str[i];

            if (c == ':') {
                if (i + 1 < str.len and str[i + 1] == ':') {
                    // Double colon - mark position
                    if (double_colon_idx != null) return null; // Only one allowed
                    if (digits > 0) {
                        if (group_idx >= 8) return null;
                        groups[group_idx] = current_val;
                        group_idx += 1;
                    }
                    double_colon_idx = group_idx;
                    current_val = 0;
                    digits = 0;
                    i += 1; // Skip second colon
                } else {
                    // Single colon
                    if (digits == 0) return null;
                    if (group_idx >= 8) return null;
                    groups[group_idx] = current_val;
                    group_idx += 1;
                    current_val = 0;
                    digits = 0;
                }
            } else if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
                const digit: u16 = if (c >= '0' and c <= '9')
                    c - '0'
                else if (c >= 'a' and c <= 'f')
                    c - 'a' + 10
                else
                    c - 'A' + 10;
                current_val = current_val * 16 + digit;
                digits += 1;
                if (digits > 4) return null;
            } else {
                return null;
            }
        }

        // Final group
        if (digits > 0) {
            if (group_idx >= 8) return null;
            groups[group_idx] = current_val;
            group_idx += 1;
        }

        // Expand double colon if present
        if (double_colon_idx) |dci| {
            const zeros_needed = 8 - group_idx;
            // Shift groups after double colon
            var j: usize = 7;
            while (j >= dci + zeros_needed) : (j -= 1) {
                groups[j] = groups[j - zeros_needed];
                if (j == 0) break;
            }
            // Fill with zeros
            for (dci..dci + zeros_needed) |k| {
                groups[k] = 0;
            }
        } else if (group_idx != 8) {
            return null;
        }

        // Convert to bytes
        for (0..8) |g| {
            result[g * 2] = @truncate(groups[g] >> 8);
            result[g * 2 + 1] = @truncate(groups[g]);
        }

        return .{ .bytes = result };
    }

    pub fn eql(self: IPv6Address, other: IPv6Address) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

/// IP address (either v4 or v6)
pub const IPAddress = union(enum) {
    v4: IPv4Address,
    v6: IPv6Address,

    pub fn parse(str: []const u8) ?IPAddress {
        // Try IPv4 first
        if (IPv4Address.parse(str)) |v4| {
            return .{ .v4 = v4 };
        }
        // Try IPv6
        if (IPv6Address.parse(str)) |v6| {
            return .{ .v6 = v6 };
        }
        return null;
    }

    pub fn eql(self: IPAddress, other: IPAddress) bool {
        return switch (self) {
            .v4 => |v4| switch (other) {
                .v4 => |ov4| v4.eql(ov4),
                .v6 => false,
            },
            .v6 => |v6| switch (other) {
                .v6 => |ov6| v6.eql(ov6),
                .v4 => false,
            },
        };
    }
};

/// IPv4 network (address + prefix length)
pub const IPv4Network = struct {
    address: IPv4Address,
    prefix_len: u8,

    /// Parse CIDR notation (e.g., "192.168.1.0/24")
    pub fn parse(str: []const u8) ?IPv4Network {
        // Find the /
        const slash_idx = std.mem.indexOf(u8, str, "/") orelse return null;
        
        const addr_str = str[0..slash_idx];
        const prefix_str = str[slash_idx + 1 ..];

        const address = IPv4Address.parse(addr_str) orelse return null;
        const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;
        
        if (prefix_len > 32) return null;

        return .{
            .address = address,
            .prefix_len = prefix_len,
        };
    }

    /// Check if an address is within this network
    pub fn contains(self: IPv4Network, addr: IPv4Address) bool {
        if (self.prefix_len == 0) return true;
        
        const mask: u32 = if (self.prefix_len >= 32) 
            0xFFFFFFFF 
        else 
            ~(@as(u32, 0xFFFFFFFF) >> @intCast(self.prefix_len));
        
        return (self.address.toU32() & mask) == (addr.toU32() & mask);
    }
};

/// IPv6 network (address + prefix length)
pub const IPv6Network = struct {
    address: IPv6Address,
    prefix_len: u8,

    pub fn parse(str: []const u8) ?IPv6Network {
        const slash_idx = std.mem.indexOf(u8, str, "/") orelse return null;
        
        const addr_str = str[0..slash_idx];
        const prefix_str = str[slash_idx + 1 ..];

        const address = IPv6Address.parse(addr_str) orelse return null;
        const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;
        
        if (prefix_len > 128) return null;

        return .{
            .address = address,
            .prefix_len = prefix_len,
        };
    }

    /// Check if an address is within this network
    pub fn contains(self: IPv6Network, addr: IPv6Address) bool {
        const full_bytes = self.prefix_len / 8;
        const remaining_bits = self.prefix_len % 8;

        // Check full bytes
        for (0..full_bytes) |i| {
            if (self.address.bytes[i] != addr.bytes[i]) return false;
        }

        // Check remaining bits
        if (remaining_bits > 0 and full_bytes < 16) {
            const mask: u8 = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((self.address.bytes[full_bytes] & mask) != (addr.bytes[full_bytes] & mask)) {
                return false;
            }
        }

        return true;
    }
};

/// IP network (either v4 or v6)
pub const IPNetwork = union(enum) {
    v4: IPv4Network,
    v6: IPv6Network,

    pub fn parse(str: []const u8) ?IPNetwork {
        if (IPv4Network.parse(str)) |v4| {
            return .{ .v4 = v4 };
        }
        if (IPv6Network.parse(str)) |v6| {
            return .{ .v6 = v6 };
        }
        return null;
    }

    pub fn contains(self: IPNetwork, addr: IPAddress) bool {
        return switch (self) {
            .v4 => |net| switch (addr) {
                .v4 => |a| net.contains(a),
                .v6 => false,
            },
            .v6 => |net| switch (addr) {
                .v6 => |a| net.contains(a),
                .v4 => false,
            },
        };
    }
};

/// Get the local host's IP addresses
pub fn getLocalAddresses(allocator: std.mem.Allocator) !std.ArrayList(IPAddress) {
    var addresses = std.ArrayList(IPAddress).init(allocator);
    errdefer addresses.deinit();

    // Use getifaddrs via C interop
    const c = @cImport({
        @cInclude("ifaddrs.h");
        @cInclude("netinet/in.h");
        @cInclude("arpa/inet.h");
    });

    var ifap: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) {
        return error.GetIfAddrsFailed;
    }
    defer c.freeifaddrs(ifap);

    var ifa = ifap;
    while (ifa != null) : (ifa = ifa.?.ifa_next) {
        const addr = ifa.?.ifa_addr orelse continue;

        if (addr.*.sa_family == c.AF_INET) {
            // IPv4
            const sin: *const c.struct_sockaddr_in = @ptrCast(@alignCast(addr));
            const ip_bytes = @as(*const [4]u8, @ptrCast(&sin.sin_addr.s_addr));
            try addresses.append(.{ .v4 = .{ .octets = ip_bytes.* } });
        } else if (addr.*.sa_family == c.AF_INET6) {
            // IPv6
            const sin6: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(addr));
            try addresses.append(.{ .v6 = .{ .bytes = sin6.sin6_addr.s6_addr } });
        }
    }

    return addresses;
}

// ============================================
// Tests
// ============================================

test "IPv4Address.parse valid" {
    const addr = IPv4Address.parse("192.168.1.1").?;
    try std.testing.expectEqual(@as(u8, 192), addr.octets[0]);
    try std.testing.expectEqual(@as(u8, 168), addr.octets[1]);
    try std.testing.expectEqual(@as(u8, 1), addr.octets[2]);
    try std.testing.expectEqual(@as(u8, 1), addr.octets[3]);
}

test "IPv4Address.parse edge cases" {
    _ = IPv4Address.parse("0.0.0.0").?;
    _ = IPv4Address.parse("255.255.255.255").?;
    _ = IPv4Address.parse("127.0.0.1").?;
}

test "IPv4Address.parse invalid" {
    try std.testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse(""));
    try std.testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1"));
    try std.testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1.256"));
    try std.testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("192.168.1.1.1"));
    try std.testing.expectEqual(@as(?IPv4Address, null), IPv4Address.parse("abc.def.ghi.jkl"));
}

test "IPv4Network.parse valid" {
    const net = IPv4Network.parse("192.168.1.0/24").?;
    try std.testing.expectEqual(@as(u8, 24), net.prefix_len);
}

test "IPv4Network.contains" {
    const net = IPv4Network.parse("192.168.1.0/24").?;
    
    try std.testing.expect(net.contains(IPv4Address.parse("192.168.1.1").?));
    try std.testing.expect(net.contains(IPv4Address.parse("192.168.1.254").?));
    try std.testing.expect(!net.contains(IPv4Address.parse("192.168.2.1").?));
    try std.testing.expect(!net.contains(IPv4Address.parse("10.0.0.1").?));
}

test "IPv4Network /32" {
    const net = IPv4Network.parse("192.168.1.1/32").?;
    
    try std.testing.expect(net.contains(IPv4Address.parse("192.168.1.1").?));
    try std.testing.expect(!net.contains(IPv4Address.parse("192.168.1.2").?));
}

test "IPv4Network /0" {
    const net = IPv4Network.parse("0.0.0.0/0").?;
    
    try std.testing.expect(net.contains(IPv4Address.parse("192.168.1.1").?));
    try std.testing.expect(net.contains(IPv4Address.parse("10.0.0.1").?));
}

test "IPv6Address.parse simple" {
    const addr = IPv6Address.parse("2001:db8::1").?;
    try std.testing.expectEqual(@as(u8, 0x20), addr.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x01), addr.bytes[1]);
}

test "IPv6Address.parse full" {
    _ = IPv6Address.parse("2001:0db8:0000:0000:0000:0000:0000:0001").?;
}

test "IPv6Network.contains" {
    const net = IPv6Network.parse("2001:db8::/32").?;
    
    try std.testing.expect(net.contains(IPv6Address.parse("2001:db8::1").?));
    try std.testing.expect(net.contains(IPv6Address.parse("2001:db8:1234::1").?));
    try std.testing.expect(!net.contains(IPv6Address.parse("2001:db9::1").?));
}

test "IPAddress.parse auto-detect" {
    const v4 = IPAddress.parse("192.168.1.1").?;
    try std.testing.expect(v4 == .v4);
    
    const v6 = IPAddress.parse("::1").?;
    try std.testing.expect(v6 == .v6);
}
