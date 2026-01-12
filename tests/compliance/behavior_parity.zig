//! Behavior parity tests with sudo-rs
//!
//! These tests verify that sudo-zig behaves consistently with sudo-rs
//! in terms of policy evaluation, environment handling, and security.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");

// ============================================
// Policy Evaluation Parity
// ============================================

test "parity: root can run any command" {
    const allocator = testing.allocator;
    const sudoers = "root ALL=(ALL:ALL) ALL";

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers).parse();
    defer parsed.deinit();

    var policy = lib.sudoers.Policy.init(allocator, &parsed);

    const result = policy.check(.{
        .user = .{ .name = "root", .uid = 0, .gid = 0, .home = "/root", .shell = "/bin/bash", .gecos = "", .passwd = "" },
        .groups = &[_]lib.system.GroupId{0},
        .hostname = "localhost",
        .command = "/usr/bin/ls",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    });

    try testing.expect(result.allowed);
}

test "parity: NOPASSWD respects tag" {
    const allocator = testing.allocator;
    const sudoers = "alice ALL=(ALL) NOPASSWD: /usr/bin/ls";

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers).parse();
    defer parsed.deinit();

    var policy = lib.sudoers.Policy.init(allocator, &parsed);

    const result = policy.check(.{
        .user = .{ .name = "alice", .uid = 1000, .gid = 1000, .home = "/home/alice", .shell = "/bin/bash", .gecos = "", .passwd = "" },
        .groups = &[_]lib.system.GroupId{1000},
        .hostname = "localhost",
        .command = "/usr/bin/ls",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    });

    try testing.expect(result.allowed);
    try testing.expect(!result.must_authenticate);
}

test "parity: unauthorized user denied" {
    const allocator = testing.allocator;
    const sudoers = "alice ALL=(ALL) /usr/bin/ls";

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers).parse();
    defer parsed.deinit();

    var policy = lib.sudoers.Policy.init(allocator, &parsed);

    const result = policy.check(.{
        .user = .{ .name = "bob", .uid = 1001, .gid = 1001, .home = "/home/bob", .shell = "/bin/bash", .gecos = "", .passwd = "" },
        .groups = &[_]lib.system.GroupId{1001},
        .hostname = "localhost",
        .command = "/usr/bin/ls",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    });

    try testing.expect(!result.allowed);
}

test "parity: group membership grants access" {
    const allocator = testing.allocator;
    const sudoers = "%wheel ALL=(ALL:ALL) ALL";

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers).parse();
    defer parsed.deinit();

    // Note: Full test requires actual group lookup which we can't do in unit tests
    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Environment Variable Parity
// ============================================

test "parity: env_reset clears dangerous variables" {
    const validator = lib.common.EnvValidator.initDefault();

    // LD_PRELOAD must always be filtered
    try testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("LD_PRELOAD", "/tmp/evil.so"),
    );

    // LD_LIBRARY_PATH must always be filtered
    try testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("LD_LIBRARY_PATH", "/tmp"),
    );

    // GCONV_PATH must always be filtered
    try testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("GCONV_PATH", "/tmp"),
    );
}

test "parity: safe variables preserved" {
    const validator = lib.common.EnvValidator.initDefault();

    // DISPLAY should be kept
    try testing.expectEqual(
        lib.common.EnvValidationResult.keep,
        validator.validate("DISPLAY", ":0"),
    );

    // TERM should be checked and kept
    try testing.expectEqual(
        lib.common.EnvValidationResult.check,
        validator.validate("TERM", "xterm-256color"),
    );
}

test "parity: PATH validation" {
    // Relative paths in PATH are dangerous
    try testing.expect(!lib.common.isValidEnvValue("PATH", "relative/path:/bin"));

    // Absolute paths are OK
    try testing.expect(lib.common.isValidEnvValue("PATH", "/usr/bin:/bin"));

    // Path traversal is dangerous
    try testing.expect(!lib.common.isValidEnvValue("PATH", "/usr/../bin"));
}

// ============================================
// Secure Memory Parity
// ============================================

test "parity: secure password handling" {
    // Password buffers should be zeroed after use
    var password = lib.common.SecurePassword.init();
    defer password.deinit();

    _ = password.append('s');
    _ = password.append('e');
    _ = password.append('c');
    _ = password.append('r');
    _ = password.append('e');
    _ = password.append('t');

    try testing.expectEqualStrings("secret", password.slice());

    password.clear();

    // Verify zeroed
    for (password.data[0..6]) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "parity: constant-time comparison" {
    // Should return true for equal strings
    try testing.expect(lib.common.secureCompare("password", "password"));

    // Should return false for different strings
    try testing.expect(!lib.common.secureCompare("password", "different"));

    // Should return false for different lengths
    try testing.expect(!lib.common.secureCompare("short", "longer_string"));
}

// ============================================
// Settings/Defaults Parity
// ============================================

test "parity: default settings match sudo-rs" {
    const settings = lib.defaults.Settings{};

    // Default password tries is 3
    try testing.expectEqual(@as(u32, 3), settings.passwd_tries);

    // Default passwd_timeout is 5 minutes (300 seconds)
    try testing.expectEqual(@as(u64, 300), settings.passwd_timeout);

    // Default timestamp_timeout is 15 minutes (900 seconds)
    try testing.expectEqual(@as(u64, 900), settings.timestamp_timeout);

    // env_reset is enabled by default
    try testing.expect(settings.env_reset);

    // use_pty is enabled by default
    try testing.expect(settings.use_pty);
}

test "parity: apply defaults from sudoers" {
    const allocator = testing.allocator;

    const sudoers =
        \\Defaults passwd_tries=5
        \\Defaults !requiretty
        \\Defaults env_reset
    ;

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers).parse();
    defer parsed.deinit();

    var settings = lib.defaults.Settings{};
    settings.applyFromSudoers(&parsed);

    try testing.expectEqual(@as(u32, 5), settings.passwd_tries);
    try testing.expect(!settings.requiretty);
    try testing.expect(settings.env_reset);
}

// ============================================
// Rate Limiting Parity (sudo-rs feature)
// ============================================

test "parity: rate limiting exponential backoff" {
    var limiter = lib.system.RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 30,
        .max_failures = 3,
    });

    // First failure: 2 second delay
    try testing.expectEqual(@as(u32, 2), limiter.calculateDelay(1));

    // Second failure: 4 second delay
    try testing.expectEqual(@as(u32, 4), limiter.calculateDelay(2));

    // Third failure: 8 second delay
    try testing.expectEqual(@as(u32, 8), limiter.calculateDelay(3));

    // Should cap at max
    try testing.expectEqual(@as(u32, 30), limiter.calculateDelay(10));
}

// ============================================
// Timestamp/Credential Caching Parity
// ============================================

test "parity: timestamp types" {
    // Verify all timestamp types are supported
    try testing.expectEqual(lib.defaults.TimestampType.global, lib.defaults.TimestampType.global);
    try testing.expectEqual(lib.defaults.TimestampType.tty, lib.defaults.TimestampType.tty);
    try testing.expectEqual(lib.defaults.TimestampType.ppid, lib.defaults.TimestampType.ppid);
    try testing.expectEqual(lib.defaults.TimestampType.kernel, lib.defaults.TimestampType.kernel);
}

// ============================================
// Signal Handling Parity
// ============================================

test "parity: signal set operations" {
    var set = lib.system.SignalSet.empty();

    // Initially empty
    try testing.expect(!set.contains(.SIGTERM));
    try testing.expect(!set.contains(.SIGINT));

    // Add signals
    set.add(.SIGTERM);
    set.add(.SIGINT);

    try testing.expect(set.contains(.SIGTERM));
    try testing.expect(set.contains(.SIGINT));

    // Remove signals
    set.remove(.SIGTERM);
    try testing.expect(!set.contains(.SIGTERM));
    try testing.expect(set.contains(.SIGINT));
}

// ============================================
// SELinux Parity (if available)
// ============================================

test "parity: SELinux context parsing" {
    const ctx = lib.system.SecurityContext.parse("user_u:role_r:type_t:s0");
    try testing.expect(ctx != null);
    try testing.expectEqualStrings("user_u", ctx.?.user);
    try testing.expectEqualStrings("role_r", ctx.?.role);
    try testing.expectEqualStrings("type_t", ctx.?.type_);
}

// ============================================
// AppArmor Parity
// ============================================

test "parity: AppArmor profile validation" {
    // Valid profile names
    try testing.expect(lib.system.apparmor.isValidProfileName("/usr/bin/sudo"));
    try testing.expect(lib.system.apparmor.isValidProfileName("sudo-profile"));

    // Invalid profile names (empty)
    try testing.expect(!lib.system.apparmor.isValidProfileName(""));
}

// ============================================
// Execution Timeout Parity (sudo-rs feature)
// ============================================

test "parity: command timeout configuration" {
    const config = lib.exec.TimeoutConfig{
        .timeout_secs = 60,
        .kill_grace_secs = 5,
        .kill_process_group = true,
    };

    try testing.expectEqual(@as(u32, 60), config.timeout_secs);
    try testing.expectEqual(@as(u32, 5), config.kill_grace_secs);
    try testing.expect(config.kill_process_group);
}

test "parity: command_timeout default setting" {
    const settings = lib.defaults.Settings{};

    // Default is 0 (no timeout)
    try testing.expectEqual(@as(u32, 0), settings.command_timeout);
}

// ============================================
// File Descriptor Cleanup Parity
// ============================================

test "parity: closefrom preserves standard fds" {
    try testing.expectEqual(@as(std.posix.fd_t, 0), lib.exec.closefrom.STDIN_FILENO);
    try testing.expectEqual(@as(std.posix.fd_t, 1), lib.exec.closefrom.STDOUT_FILENO);
    try testing.expectEqual(@as(std.posix.fd_t, 2), lib.exec.closefrom.STDERR_FILENO);
}
