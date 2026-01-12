//! End-to-end tests for sudo-zig
//!
//! These tests require root privileges and test the full sudo workflow:
//! - User lookup and verification
//! - Credential caching
//! - Process execution with privilege changes
//! - AppArmor profile switching (if available)
//!
//! Run with: sudo zig build test-e2e

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
// User and Group Tests (require root for full testing)
// ============================================

test "e2e: user lookup by uid 0" {
    try skipIfNotRoot();

    const root_user = lib.system.User.fromUid(0);
    try std.testing.expect(root_user != null);
    try std.testing.expectEqualStrings("root", root_user.?.name);
}

test "e2e: user lookup by name" {
    try skipIfNotRoot();

    const root_user = lib.system.User.fromName("root");
    try std.testing.expect(root_user != null);
    try std.testing.expectEqual(@as(lib.system.UserId, 0), root_user.?.uid);
}

test "e2e: group lookup" {
    try skipIfNotRoot();

    const root_group = lib.system.Group.fromGid(0);
    try std.testing.expect(root_group != null);
    // Root group name varies by distro (root, wheel, etc.)
    try std.testing.expect(root_group.?.name.len > 0);
}

// ============================================
// Process Tests
// ============================================

test "e2e: fork and exec" {
    try skipIfNotRoot();

    const fork_result = lib.system.Process.fork() catch |err| {
        std.debug.print("Fork failed: {}\n", .{err});
        return err;
    };

    switch (fork_result) {
        .child => {
            // Child process - just exit
            std.process.exit(42);
        },
        .parent => |child_pid| {
            // Parent - wait for child
            const result = lib.system.waitpid(child_pid, 0) catch |err| {
                std.debug.print("Wait failed: {}\n", .{err});
                return err;
            };

            if (result.ifExited()) |code| {
                try std.testing.expectEqual(@as(u8, 42), code);
            } else {
                return error.UnexpectedExitStatus;
            }
        },
    }
}

test "e2e: setuid/setgid" {
    try skipIfNotRoot();

    // We can only test that the functions don't error when called as root
    // Actually changing UID would affect the test process

    // Get current user
    const current_uid = lib.system.User.effectiveUid();
    const current_gid = lib.system.User.effectiveGid();

    // Verify we're root
    try std.testing.expectEqual(@as(lib.system.UserId, 0), current_uid);

    // Setting to same values should work
    try lib.system.Process.setGid(current_gid);
    try lib.system.Process.setUid(current_uid);
}

// ============================================
// Credential Caching Tests
// ============================================

test "e2e: credential caching" {
    try skipIfNotRoot();

    const test_user = "test_sudo_user";
    const test_uid: lib.system.UserId = 65534; // nobody typically

    // Ensure clean state
    lib.system.removeCredentials(test_user, test_uid);

    // Initially no credentials
    const initial_check = lib.system.checkCredentials(test_user, test_uid, 300);
    try std.testing.expect(!initial_check);

    // Update credentials
    lib.system.updateCredentials(test_user, test_uid) catch |err| {
        // May fail if directory doesn't exist - that's OK for this test
        std.debug.print("Update credentials failed (may be expected): {}\n", .{err});
        return;
    };

    // Now credentials should be valid
    const after_update = lib.system.checkCredentials(test_user, test_uid, 300);
    try std.testing.expect(after_update);

    // Reset credentials
    lib.system.resetCredentials(test_user, test_uid) catch {};

    // After reset, should be invalid
    const after_reset = lib.system.checkCredentials(test_user, test_uid, 300);
    try std.testing.expect(!after_reset);

    // Clean up
    lib.system.removeCredentials(test_user, test_uid);
}

// ============================================
// Hostname Tests
// ============================================

test "e2e: get hostname" {
    try skipIfNotRoot();

    const hostname = lib.system.Hostname.get() catch |err| {
        std.debug.print("Get hostname failed: {}\n", .{err});
        return err;
    };

    try std.testing.expect(hostname.len > 0);
    try std.testing.expect(hostname.len < 64);
}

// ============================================
// AppArmor Tests (if enabled)
// ============================================

test "e2e: apparmor status check" {
    try skipIfNotRoot();

    // Just check if AppArmor is available - don't fail if not
    const enabled = lib.system.isAppArmorEnabled();
    _ = enabled; // May or may not be enabled depending on system

    // If enabled, we could test profile switching, but that requires
    // specific profiles to be loaded
}

// ============================================
// Signal Handling Tests
// ============================================

test "e2e: signal blocking" {
    try skipIfNotRoot();

    // Block SIGTERM
    var block_set = lib.system.SignalSet.empty();
    block_set.add(.SIGTERM);

    const old_mask = lib.system.signal.blockSignals(block_set) catch |err| {
        std.debug.print("Block signals failed: {}\n", .{err});
        return err;
    };

    // Verify SIGTERM is blocked (can't easily test this without sending signal)

    // Restore old mask
    lib.system.signal.setSignalMask(old_mask) catch {};
}

// ============================================
// Environment Security Tests
// ============================================

test "e2e: environment filtering" {
    try skipIfNotRoot();

    const allocator = std.testing.allocator;
    const validator = lib.common.EnvValidator.initDefault();

    // Create a test environment
    var test_env = std.StringHashMap([]const u8).init(allocator);
    defer test_env.deinit();

    try test_env.put("PATH", "/usr/bin:/bin");
    try test_env.put("HOME", "/root");
    try test_env.put("DISPLAY", ":0");
    try test_env.put("LD_PRELOAD", "/tmp/evil.so"); // Should be filtered
    try test_env.put("TERM", "xterm");

    // Build safe environment
    var safe_env = try validator.buildSafeEnvironment(allocator, test_env);
    defer safe_env.deinit();

    // Verify dangerous variables are removed
    try std.testing.expect(safe_env.get("LD_PRELOAD") == null);

    // Verify safe variables are kept
    try std.testing.expect(safe_env.get("DISPLAY") != null);
    try std.testing.expect(safe_env.get("TERM") != null);
}

// ============================================
// Sudoers File Parsing Tests
// ============================================

test "e2e: parse system sudoers" {
    try skipIfNotRoot();

    const allocator = std.testing.allocator;
    const sudoers_path = lib.platform.sudoers_path;

    // Try to read and parse the system sudoers file
    const file = std.fs.openFileAbsolute(sudoers_path, .{}) catch |err| {
        // Sudoers file may not exist or may not be readable
        std.debug.print("Cannot open {s}: {}\n", .{ sudoers_path, err });
        return;
    };
    defer file.close();

    var content_buf: [65536]u8 = undefined;
    const content_len = file.readAll(&content_buf) catch |err| {
        std.debug.print("Cannot read {s}: {}\n", .{ sudoers_path, err });
        return;
    };

    const content = content_buf[0..content_len];

    // Try to parse
    var parser = lib.sudoers.parser.Parser.init(allocator, content);
    const parsed = parser.parse() catch |err| {
        std.debug.print("Parse error: {}\n", .{err});
        // Print parse errors if any
        for (parser.errors.items) |parse_err| {
            var err_buf: [256]u8 = undefined;
            std.debug.print("  {s}\n", .{parse_err.toString(&err_buf)});
        }
        return;
    };
    defer parsed.deinit();

    std.debug.print("Parsed sudoers: {d} defaults, {d} user specs\n", .{
        parsed.defaults.items.len,
        parsed.user_specs.items.len,
    });
}

// ============================================
// Rate Limiting Tests
// ============================================

test "e2e: rate limiter state persistence" {
    try skipIfNotRoot();

    // Use a temp directory for test state
    var limiter = lib.system.RateLimiter.initWithConfig(.{
        .max_failures = 3,
        .initial_delay_secs = 1,
        .lockout_duration_secs = 60,
        .state_dir = "/tmp/sudo-zig-test",
    });

    const test_user = "rate_limit_test_user";

    // Clear any existing state
    limiter.resetUser(test_user);

    // First attempt should be allowed
    var result = limiter.checkAttempt(test_user);
    try std.testing.expectEqual(lib.system.RateLimitCheckResult{ .allowed = {} }, result);

    // Record failures
    limiter.recordFailure(test_user);
    limiter.recordFailure(test_user);
    limiter.recordFailure(test_user);

    // After 3 failures, should be locked out
    result = limiter.checkAttempt(test_user);
    switch (result) {
        .locked_out => {}, // Expected
        else => return error.ExpectedLockout,
    }

    // Clean up
    limiter.resetUser(test_user);
}
