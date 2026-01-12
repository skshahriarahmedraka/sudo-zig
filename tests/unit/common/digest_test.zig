//! Unit tests for command digest verification
//!
//! Tests for SHA digest algorithms, encoding, and verification.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const digest = lib.common.digest;
const DigestAlgorithm = digest.DigestAlgorithm;
const Digest = digest.Digest;

// ============================================
// DigestAlgorithm Tests
// ============================================

test "DigestAlgorithm.digestLength returns correct sizes" {
    try testing.expectEqual(@as(usize, 28), DigestAlgorithm.sha224.digestLength());
    try testing.expectEqual(@as(usize, 32), DigestAlgorithm.sha256.digestLength());
    try testing.expectEqual(@as(usize, 48), DigestAlgorithm.sha384.digestLength());
    try testing.expectEqual(@as(usize, 64), DigestAlgorithm.sha512.digestLength());
}

test "DigestAlgorithm enum values are distinct" {
    const algorithms = [_]DigestAlgorithm{ .sha224, .sha256, .sha384, .sha512 };

    for (algorithms, 0..) |a1, i| {
        for (algorithms[i + 1 ..]) |a2| {
            try testing.expect(a1 != a2);
        }
    }
}

// ============================================
// Digest Struct Tests
// ============================================

test "Digest struct creation with sha256" {
    const d = Digest{
        .algorithm = .sha256,
        .hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };

    try testing.expectEqual(DigestAlgorithm.sha256, d.algorithm);
    try testing.expectEqual(@as(usize, 64), d.hash.len); // 32 bytes * 2 hex chars
}

test "Digest struct creation with sha512" {
    const d = Digest{
        .algorithm = .sha512,
        .hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    };

    try testing.expectEqual(DigestAlgorithm.sha512, d.algorithm);
    try testing.expectEqual(@as(usize, 128), d.hash.len); // 64 bytes * 2 hex chars
}

// ============================================
// hashToHex Tests
// ============================================

test "hashToHex converts bytes to hex string" {
    const hash = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    var buf: [64]u8 = undefined;
    const hex = digest.hashToHex(&hash, &buf);

    try testing.expectEqualStrings("48656c6c6f", hex);
}

test "hashToHex with zero bytes" {
    const hash = [_]u8{ 0x00, 0x00, 0x00 };
    var buf: [64]u8 = undefined;
    const hex = digest.hashToHex(&hash, &buf);

    try testing.expectEqualStrings("000000", hex);
}

test "hashToHex with all ff bytes" {
    const hash = [_]u8{ 0xff, 0xff, 0xff };
    var buf: [64]u8 = undefined;
    const hex = digest.hashToHex(&hash, &buf);

    try testing.expectEqualStrings("ffffff", hex);
}

test "hashToHex with sha256 length" {
    // SHA256 produces 32 bytes
    var hash: [32]u8 = undefined;
    for (&hash, 0..) |*b, i| {
        b.* = @intCast(i);
    }

    var buf: [64]u8 = undefined;
    const hex = digest.hashToHex(&hash, &buf);

    try testing.expectEqual(@as(usize, 64), hex.len);
    try testing.expect(std.mem.startsWith(u8, hex, "000102030405"));
}

test "hashToHex mixed values" {
    const hash = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe };
    var buf: [64]u8 = undefined;
    const hex = digest.hashToHex(&hash, &buf);

    try testing.expectEqualStrings("deadbeefcafe", hex);
}

// ============================================
// Common SHA Digest Patterns Tests
// ============================================

test "empty file sha256 hash format" {
    // The SHA256 hash of an empty file is a well-known value
    const empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    try testing.expectEqual(@as(usize, 64), empty_sha256.len);

    // Verify it's valid hex
    for (empty_sha256) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "empty file sha512 hash format" {
    // The SHA512 hash of an empty file is a well-known value
    const empty_sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    try testing.expectEqual(@as(usize, 128), empty_sha512.len);

    // Verify it's valid hex
    for (empty_sha512) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

// ============================================
// Algorithm Selection Tests
// ============================================

test "algorithm selection by security level" {
    // SHA512 is the strongest
    try testing.expect(DigestAlgorithm.sha512.digestLength() > DigestAlgorithm.sha384.digestLength());
    try testing.expect(DigestAlgorithm.sha384.digestLength() > DigestAlgorithm.sha256.digestLength());
    try testing.expect(DigestAlgorithm.sha256.digestLength() > DigestAlgorithm.sha224.digestLength());
}

test "digest lengths match SHA family specifications" {
    // SHA-224: 224 bits = 28 bytes
    try testing.expectEqual(@as(usize, 224 / 8), DigestAlgorithm.sha224.digestLength());

    // SHA-256: 256 bits = 32 bytes
    try testing.expectEqual(@as(usize, 256 / 8), DigestAlgorithm.sha256.digestLength());

    // SHA-384: 384 bits = 48 bytes
    try testing.expectEqual(@as(usize, 384 / 8), DigestAlgorithm.sha384.digestLength());

    // SHA-512: 512 bits = 64 bytes
    try testing.expectEqual(@as(usize, 512 / 8), DigestAlgorithm.sha512.digestLength());
}
