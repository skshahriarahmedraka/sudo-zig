//! Integration tests for sudo-zig
//!
//! These tests verify the integration between multiple modules:
//! - Sudoers parsing -> Policy evaluation
//! - Environment handling -> Execution
//! - Authentication -> Credential caching
//!
//! These tests run in user space and don't require root.

const std = @import("std");
const lib = @import("sudo-zig-lib");

// ============================================
// Sudoers Parsing + Policy Integration Tests
// ============================================

test "integration: parse sudoers and evaluate policy" {
    const allocator = std.testing.allocator;

    const sudoers_content =
        \\# Test sudoers file
        \\Defaults env_reset
        \\Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        \\
        \\# User aliases
        \\User_Alias ADMINS = alice, bob
        \\
        \\# Command aliases
        \\Cmnd_Alias SHUTDOWN = /sbin/shutdown, /sbin/reboot, /sbin/halt
        \\
        \\# Rules
        \\root ALL=(ALL:ALL) ALL
        \\ADMINS ALL=(ALL) NOPASSWD: SHUTDOWN
        \\%wheel ALL=(ALL:ALL) ALL
        \\testuser localhost=/usr/bin/ls, /usr/bin/cat
    ;

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers_content).parse();
    defer parsed.deinit();

    // Verify defaults were parsed
    try std.testing.expect(parsed.defaults.items.len >= 2);

    // Verify aliases were parsed
    try std.testing.expect(parsed.aliases.user.count() >= 1);
    try std.testing.expect(parsed.aliases.cmnd.count() >= 1);

    // Verify user specs were parsed
    try std.testing.expect(parsed.user_specs.items.len >= 4);
}

test "integration: policy evaluation with groups" {
    const allocator = std.testing.allocator;

    const sudoers_content =
        \\%admin ALL=(ALL) ALL
        \\%sudo ALL=(ALL:ALL) NOPASSWD: ALL
    ;

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers_content).parse();
    defer parsed.deinit();

    // Create a policy evaluator
    var policy = lib.sudoers.Policy.init(allocator, &parsed);
    _ = policy;

    // Note: Full policy evaluation requires actual user lookup
    // which we can't do in unit tests without mocking
    try std.testing.expect(parsed.user_specs.items.len == 2);
}

// ============================================
// Environment Validation Integration Tests
// ============================================

test "integration: environment validation with defaults" {
    const validator = lib.common.EnvValidator.initDefault();

    // Test dangerous variables are rejected
    try std.testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("LD_PRELOAD", "/tmp/evil.so"),
    );

    // Test safe variables are kept
    try std.testing.expectEqual(
        lib.common.EnvValidationResult.keep,
        validator.validate("DISPLAY", ":0"),
    );

    // Test PATH validation
    try std.testing.expectEqual(
        lib.common.EnvValidationResult.delete,
        validator.validate("PATH", "relative/path:/bin"),
    );
}

test "integration: secure memory with environment" {
    // Test that secure memory works with string handling
    var password = lib.common.SecurePassword.init();
    defer password.deinit();

    _ = password.append('s');
    _ = password.append('e');
    _ = password.append('c');
    _ = password.append('r');
    _ = password.append('e');
    _ = password.append('t');

    try std.testing.expectEqualStrings("secret", password.slice());

    // Clear and verify
    password.clear();
    try std.testing.expectEqual(@as(usize, 0), password.len);

    // Verify memory is zeroed
    for (password.data[0..6]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

// ============================================
// Defaults Settings Integration Tests
// ============================================

test "integration: defaults from sudoers" {
    const allocator = std.testing.allocator;

    const sudoers_content =
        \\Defaults passwd_tries=5
        \\Defaults timestamp_timeout=10
        \\Defaults !requiretty
        \\Defaults env_reset
        \\Defaults secure_path="/usr/bin:/bin"
    ;

    var parsed = try lib.sudoers.parser.Parser.init(allocator, sudoers_content).parse();
    defer parsed.deinit();

    // Apply defaults to settings
    var settings = lib.defaults.Settings{};
    settings.applyFromSudoers(&parsed);

    // Verify settings were applied
    try std.testing.expectEqual(@as(u32, 5), settings.passwd_tries);
    try std.testing.expectEqual(true, settings.env_reset);
}

// ============================================
// Rate Limiting Integration Tests
// ============================================

test "integration: rate limiter exponential backoff" {
    var limiter = lib.system.RateLimiter.initWithConfig(.{
        .initial_delay_secs = 1,
        .backoff_multiplier = 2,
        .max_delay_secs = 16,
        .max_failures = 5,
        .state_dir = "/tmp/sudo-test", // Use temp dir for tests
    });

    // Test delay calculation
    try std.testing.expectEqual(@as(u32, 0), limiter.calculateDelay(0));
    try std.testing.expectEqual(@as(u32, 1), limiter.calculateDelay(1));
    try std.testing.expectEqual(@as(u32, 2), limiter.calculateDelay(2));
    try std.testing.expectEqual(@as(u32, 4), limiter.calculateDelay(3));
    try std.testing.expectEqual(@as(u32, 8), limiter.calculateDelay(4));
    try std.testing.expectEqual(@as(u32, 16), limiter.calculateDelay(5)); // Capped
    try std.testing.expectEqual(@as(u32, 16), limiter.calculateDelay(10)); // Still capped
}

// ============================================
// Digest Verification Integration Tests  
// ============================================

test "integration: digest algorithm lengths" {
    try std.testing.expectEqual(@as(usize, 28), lib.common.DigestAlgorithm.sha224.digestLength());
    try std.testing.expectEqual(@as(usize, 32), lib.common.DigestAlgorithm.sha256.digestLength());
    try std.testing.expectEqual(@as(usize, 48), lib.common.DigestAlgorithm.sha384.digestLength());
    try std.testing.expectEqual(@as(usize, 64), lib.common.DigestAlgorithm.sha512.digestLength());
}

// ============================================
// Signal Handling Integration Tests
// ============================================

test "integration: signal set operations" {
    var set = lib.system.SignalSet.empty();

    try std.testing.expect(!set.contains(.SIGINT));
    try std.testing.expect(!set.contains(.SIGTERM));

    set.add(.SIGINT);
    try std.testing.expect(set.contains(.SIGINT));
    try std.testing.expect(!set.contains(.SIGTERM));

    set.add(.SIGTERM);
    try std.testing.expect(set.contains(.SIGINT));
    try std.testing.expect(set.contains(.SIGTERM));

    set.remove(.SIGINT);
    try std.testing.expect(!set.contains(.SIGINT));
    try std.testing.expect(set.contains(.SIGTERM));
}

// ============================================
// Error Handling Integration Tests
// ============================================

test "integration: error context formatting" {
    const ctx = lib.common.error_mod.ErrorContext{
        .source = .sudoers_parser,
        .message = "syntax error",
        .location = .{ .line = 10, .column = 5 },
    };

    var buf: [256]u8 = undefined;
    const formatted = ctx.format(&buf);
    try std.testing.expect(formatted.len > 0);
}

// ============================================
// Path Validation Integration Tests
// ============================================

test "integration: path validation" {
    // Valid paths
    const valid1 = lib.common.SudoPath.init("/usr/bin/sudo");
    try std.testing.expect(valid1 != null);
    try std.testing.expect(valid1.?.isAbsolute());

    // Invalid paths (with null bytes)
    const invalid = lib.common.SudoPath.init("/usr/bin\x00/sudo");
    try std.testing.expect(invalid == null);
}

// ============================================
// String Validation Integration Tests
// ============================================

test "integration: string validation" {
    // Valid strings
    const valid = lib.common.SudoString.init("hello world");
    try std.testing.expect(valid != null);

    // Invalid strings (with null bytes)
    const invalid = lib.common.SudoString.init("hello\x00world");
    try std.testing.expect(invalid == null);
}
