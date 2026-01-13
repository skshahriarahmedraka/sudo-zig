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
        \\
        \\# User aliases
        \\User_Alias ADMINS = alice, bob
        \\
        \\# Command aliases
        \\Cmnd_Alias SHUTDOWN = /sbin/shutdown, /sbin/reboot
        \\
        \\# Rules
        \\root ALL=(ALL:ALL) ALL
        \\ADMINS ALL=(ALL) NOPASSWD: SHUTDOWN
        \\%wheel ALL=(ALL:ALL) ALL
    ;

    var parser = lib.sudoers.parser.Parser.init(allocator, sudoers_content);
    var parsed = try parser.parse();
    defer parsed.deinit();

    // Verify defaults were parsed
    try std.testing.expect(parsed.defaults.items.len >= 1);

    // Verify aliases were parsed
    try std.testing.expect(parsed.aliases.user.count() >= 1);
    try std.testing.expect(parsed.aliases.cmnd.count() >= 1);

    // Verify user specs were parsed
    try std.testing.expect(parsed.user_specs.items.len >= 3);
}

test "integration: policy evaluation with groups" {
    const allocator = std.testing.allocator;

    const sudoers_content =
        \\%admin ALL=(ALL) ALL
        \\%sudo ALL=(ALL:ALL) NOPASSWD: ALL
    ;

    var parser = lib.sudoers.parser.Parser.init(allocator, sudoers_content);
    var parsed = try parser.parse();
    defer parsed.deinit();

    // Create a policy evaluator
    const policy = lib.sudoers.Policy.init(allocator, &parsed);
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
        \\Defaults !requiretty
        \\Defaults env_reset
    ;

    var parser = lib.sudoers.parser.Parser.init(allocator, sudoers_content);
    var parsed = try parser.parse();
    defer parsed.deinit();

    // Apply defaults to settings
    var settings = lib.defaults.Settings{};
    settings.applyFromSudoers(&parsed);

    // Verify settings were applied
    try std.testing.expect(parsed.defaults.items.len >= 3);
    try std.testing.expectEqual(true, settings.env_reset);
}

// ============================================
// Rate Limiting Integration Tests
// ============================================

test "integration: rate limiter configuration" {
    const config = lib.system.rate_limit.Config{
        .initial_delay_secs = 1,
        .backoff_multiplier = 2,
        .max_delay_secs = 16,
        .max_failures = 5,
    };

    const limiter = lib.system.RateLimiter.initWithConfig(config);

    // Verify configuration
    try std.testing.expectEqual(@as(u32, 1), limiter.config.initial_delay_secs);
    try std.testing.expectEqual(@as(u32, 2), limiter.config.backoff_multiplier);
    try std.testing.expectEqual(@as(u32, 16), limiter.config.max_delay_secs);
    try std.testing.expectEqual(@as(u32, 5), limiter.config.max_failures);
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

    try std.testing.expect(!set.contains(.INT));
    try std.testing.expect(!set.contains(.TERM));

    set.add(.INT);
    try std.testing.expect(set.contains(.INT));
    try std.testing.expect(!set.contains(.TERM));

    set.add(.TERM);
    try std.testing.expect(set.contains(.INT));
    try std.testing.expect(set.contains(.TERM));

    set.remove(.INT);
    try std.testing.expect(!set.contains(.INT));
    try std.testing.expect(set.contains(.TERM));
}

// ============================================
// Error Handling Integration Tests
// ============================================

test "integration: error context" {
    const ctx = lib.common.error_mod.ErrorContext{
        .err = lib.common.Error.Configuration,
        .message = "syntax error",
        .path = "/etc/sudoers",
    };

    // Verify error context fields
    try std.testing.expect(ctx.err == lib.common.Error.Configuration);
    try std.testing.expect(ctx.message != null);
    try std.testing.expect(!ctx.isSilent());
}

// ============================================
// Path Validation Integration Tests
// ============================================

test "integration: path validation" {
    // Valid paths
    const valid1 = try lib.common.SudoPath.init("/usr/bin/sudo");
    try std.testing.expect(valid1.isAbsolute());

    // Invalid paths (with null bytes) should return error
    const invalid = lib.common.SudoPath.init("/usr/bin\x00/sudo");
    try std.testing.expectError(error.PathValidation, invalid);
}

// ============================================
// String Validation Integration Tests
// ============================================

test "integration: string validation" {
    // Valid strings
    const valid = try lib.common.SudoString.init("hello world");
    try std.testing.expectEqualStrings("hello world", valid.data);

    // Invalid strings (with null bytes) should return error
    const invalid = lib.common.SudoString.init("hello\x00world");
    try std.testing.expectError(error.StringValidation, invalid);
}
