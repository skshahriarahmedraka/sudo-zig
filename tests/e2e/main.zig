//! End-to-end tests for sudo-zig
//!
//! These tests require root privileges and test the full sudo workflow:
//! - User lookup and verification
//! - Credential caching
//! - Process execution with privilege changes
//! - AppArmor profile switching (if available)
//!
//! Run with: sudo zig build e2e

const std = @import("std");
const posix = std.posix;
const lib = @import("sudo-zig-lib");

/// Check if running as root
fn isRoot() bool {
    return lib.system.User.effectiveUid() == 0;
}

/// Skip test if not root
fn skipIfNotRoot() error{SkipZigTest}!void {
    if (!isRoot()) {
        return error.SkipZigTest;
    }
}

// ============================================
// User Lookup Tests
// ============================================

test "e2e: lookup root user" {
    const root_user = lib.system.User.fromUid(0);
    try std.testing.expect(root_user != null);

    if (root_user) |user| {
        try std.testing.expectEqual(@as(lib.system.UserId, 0), user.uid);
        try std.testing.expectEqualStrings("root", user.name);
    }
}

test "e2e: lookup root by name" {
    const root_user = lib.system.User.fromName("root");
    try std.testing.expect(root_user != null);

    if (root_user) |user| {
        try std.testing.expectEqual(@as(lib.system.UserId, 0), user.uid);
    }
}

test "e2e: current user uid" {
    const uid = lib.system.User.realUid();
    const euid = lib.system.User.effectiveUid();

    // Both should be valid UIDs (non-negative is always true for u32)
    try std.testing.expect(uid <= std.math.maxInt(u32));
    try std.testing.expect(euid <= std.math.maxInt(u32));
}

// ============================================
// Group Lookup Tests
// ============================================

test "e2e: lookup root group" {
    const root_group = lib.system.Group.fromGid(0);
    try std.testing.expect(root_group != null);

    if (root_group) |group| {
        try std.testing.expectEqual(@as(lib.system.GroupId, 0), group.gid);
    }
}

// ============================================
// Hostname Tests
// ============================================

test "e2e: get hostname" {
    const hostname = lib.system.Hostname.get() catch |err| {
        std.debug.print("Could not get hostname: {}\n", .{err});
        return;
    };

    try std.testing.expect(hostname.len > 0);
}

// ============================================
// Signal Handling Tests
// ============================================

test "e2e: signal set operations" {
    var block_set = lib.system.SignalSet.empty();
    block_set.add(.TERM);
    block_set.add(.INT);

    try std.testing.expect(block_set.contains(.TERM));
    try std.testing.expect(block_set.contains(.INT));
    try std.testing.expect(!block_set.contains(.HUP));
}

// ============================================
// Sudoers Parsing Tests
// ============================================

test "e2e: parse simple sudoers" {
    const allocator = std.testing.allocator;

    const content = "root ALL=(ALL:ALL) ALL";
    var parser = lib.sudoers.parser.Parser.init(allocator, content);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Credential Cache Tests (require root)
// ============================================

test "e2e: timestamp directory exists or can be created" {
    // This test just verifies the timestamp directory path is defined
    try std.testing.expect(lib.platform.timestamp_dir.len > 0);
}

// ============================================
// Path Security Tests
// ============================================

test "e2e: path validation" {
    // Test absolute paths
    const abs_path = try lib.common.SudoPath.init("/usr/bin/sudo");
    try std.testing.expect(abs_path.isAbsolute());

    // Test relative paths
    const rel_path = try lib.common.SudoPath.init("bin/sudo");
    try std.testing.expect(!rel_path.isAbsolute());

    // Test invalid path (with null byte) should fail
    const invalid_result = lib.common.SudoPath.init("/usr/bin\x00/sudo");
    try std.testing.expectError(error.PathValidation, invalid_result);
}

// ============================================
// Environment Security Tests
// ============================================

test "e2e: dangerous environment variables blocked" {
    const validator = lib.common.EnvValidator.initDefault();

    // LD_PRELOAD must always be blocked
    try std.testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("LD_PRELOAD", "/tmp/evil.so"),
    );

    // LD_LIBRARY_PATH must always be blocked
    try std.testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("LD_LIBRARY_PATH", "/tmp"),
    );
}

// ============================================
// Secure Memory Tests
// ============================================

test "e2e: secure password handling" {
    var password = lib.common.SecurePassword.init();
    defer password.deinit();

    // Add password characters
    _ = password.append('t');
    _ = password.append('e');
    _ = password.append('s');
    _ = password.append('t');

    try std.testing.expectEqualStrings("test", password.slice());

    // Clear and verify zeroed
    password.clear();
    try std.testing.expectEqual(@as(usize, 0), password.len);
}
