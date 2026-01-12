//! Command digest verification
//!
//! Provides functionality to verify command executables against SHA digests
//! specified in sudoers rules. This prevents execution of modified binaries.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Digest algorithms supported by sudoers
pub const DigestAlgorithm = enum {
    sha224,
    sha256,
    sha384,
    sha512,

    /// Get the digest length in bytes for this algorithm
    pub fn digestLength(self: DigestAlgorithm) usize {
        return switch (self) {
            .sha224 => 28,
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// A digest specification from sudoers
pub const Digest = struct {
    algorithm: DigestAlgorithm,
    hash: []const u8, // hex-encoded or base64 hash
};

/// Verify that a file matches the expected digest
pub fn verifyFileDigest(path: []const u8, expected: Digest) !bool {
    // Read the file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    defer file.close();

    // Compute the hash
    const computed = try computeFileHash(file, expected.algorithm);

    // Compare with expected (which may be hex or base64 encoded)
    return compareDigest(&computed, expected);
}

fn computeFileHash(file: std.fs.File, algorithm: DigestAlgorithm) ![64]u8 {
    var result: [64]u8 = undefined;

    switch (algorithm) {
        .sha256 => {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            var buf: [8192]u8 = undefined;
            while (true) {
                const n = file.read(&buf) catch break;
                if (n == 0) break;
                hasher.update(buf[0..n]);
            }
            const digest = hasher.finalResult();
            @memcpy(result[0..32], &digest);
        },
        .sha512 => {
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            var buf: [8192]u8 = undefined;
            while (true) {
                const n = file.read(&buf) catch break;
                if (n == 0) break;
                hasher.update(buf[0..n]);
            }
            const digest = hasher.finalResult();
            @memcpy(result[0..64], &digest);
        },
        .sha384 => {
            var hasher = std.crypto.hash.sha2.Sha384.init(.{});
            var buf: [8192]u8 = undefined;
            while (true) {
                const n = file.read(&buf) catch break;
                if (n == 0) break;
                hasher.update(buf[0..n]);
            }
            const digest = hasher.finalResult();
            @memcpy(result[0..48], &digest);
        },
        .sha224 => {
            var hasher = std.crypto.hash.sha2.Sha224.init(.{});
            var buf: [8192]u8 = undefined;
            while (true) {
                const n = file.read(&buf) catch break;
                if (n == 0) break;
                hasher.update(buf[0..n]);
            }
            const digest = hasher.finalResult();
            @memcpy(result[0..28], &digest);
        },
    }

    return result;
}

fn compareDigest(computed: *const [64]u8, expected: Digest) bool {
    const digest_len = expected.algorithm.digestLength();
    const computed_slice = computed[0..digest_len];

    // Try hex decoding first
    if (hexDecode(expected.hash)) |decoded| {
        if (decoded.len != digest_len) return false;
        return std.mem.eql(u8, computed_slice, decoded[0..digest_len]);
    }

    // Try base64 decoding
    if (base64Decode(expected.hash)) |decoded| {
        if (decoded.len != digest_len) return false;
        return std.mem.eql(u8, computed_slice, decoded[0..digest_len]);
    }

    return false;
}

fn hexDecode(hex: []const u8) ?[64]u8 {
    if (hex.len % 2 != 0 or hex.len > 128) return null;

    var result: [64]u8 = undefined;
    const out_len = hex.len / 2;

    for (0..out_len) |i| {
        const high = hexCharToNibble(hex[i * 2]) orelse return null;
        const low = hexCharToNibble(hex[i * 2 + 1]) orelse return null;
        result[i] = (@as(u8, high) << 4) | @as(u8, low);
    }

    return result;
}

fn hexCharToNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

fn base64Decode(encoded: []const u8) ?[64]u8 {
    var result: [64]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(encoded) catch return null;
    if (decoded_len > 64) return null;

    decoder.decode(&result, encoded) catch return null;
    return result;
}

/// Convert a hash to hex string for display
pub fn hashToHex(hash: []const u8, out: []u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    const len = @min(hash.len * 2, out.len);

    for (0..len / 2) |i| {
        out[i * 2] = hex_chars[hash[i] >> 4];
        out[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }

    return out[0..len];
}

// ============================================
// Tests
// ============================================

test "DigestAlgorithm lengths" {
    try std.testing.expectEqual(@as(usize, 28), DigestAlgorithm.sha224.digestLength());
    try std.testing.expectEqual(@as(usize, 32), DigestAlgorithm.sha256.digestLength());
    try std.testing.expectEqual(@as(usize, 48), DigestAlgorithm.sha384.digestLength());
    try std.testing.expectEqual(@as(usize, 64), DigestAlgorithm.sha512.digestLength());
}

test "hexDecode valid" {
    const decoded = hexDecode("48656c6c6f").?;
    try std.testing.expectEqualStrings("Hello", decoded[0..5]);
}

test "hexDecode invalid" {
    try std.testing.expectEqual(@as(?[64]u8, null), hexDecode("xyz"));
    try std.testing.expectEqual(@as(?[64]u8, null), hexDecode("123")); // odd length
}

test "hashToHex" {
    const hash = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var buf: [64]u8 = undefined;
    const hex = hashToHex(&hash, &buf);
    try std.testing.expectEqualStrings("48656c6c6f", hex);
}
