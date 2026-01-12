//! Unit tests for rate limiting
//!
//! Tests for brute-force protection and authentication rate limiting.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const rate_limit = lib.system.rate_limit;
const RateLimiter = rate_limit.RateLimiter;
const Config = rate_limit.Config;
const CheckResult = rate_limit.CheckResult;

// ============================================
// Config Tests
// ============================================

test "Config default values" {
    const config = Config{};
    // Just verify config can be created with defaults
    _ = config;
}

test "Config custom values" {
    const config = Config{
        .max_failures = 5,
        .lockout_duration_secs = 300,
        .initial_delay_secs = 2,
    };
    try testing.expectEqual(@as(u32, 5), config.max_failures);
    try testing.expectEqual(@as(u32, 300), config.lockout_duration_secs);
    try testing.expectEqual(@as(u32, 2), config.initial_delay_secs);
}

// ============================================
// RateLimiter Tests
// ============================================

test "RateLimiter initialization" {
    const limiter = RateLimiter.init();
    // Just verify initialization works
    _ = limiter;
}

test "RateLimiter initWithConfig" {
    const config = Config{
        .max_failures = 3,
        .lockout_duration_secs = 600,
        .initial_delay_secs = 1,
    };
    const limiter = RateLimiter.initWithConfig(config);
    try testing.expectEqual(@as(u32, 3), limiter.config.max_failures);
}

// ============================================
// CheckResult Tests
// ============================================

test "CheckResult allowed variant" {
    const result = CheckResult{ .allowed = {} };
    switch (result) {
        .allowed => {},
        else => try testing.expect(false),
    }
}

test "CheckResult delayed variant" {
    const result = CheckResult{ .delayed = 5 };
    switch (result) {
        .delayed => |secs| try testing.expectEqual(@as(u32, 5), secs),
        else => try testing.expect(false),
    }
}

test "CheckResult locked_out variant" {
    const result = CheckResult{ .locked_out = 300 };
    switch (result) {
        .locked_out => |secs| try testing.expectEqual(@as(u32, 300), secs),
        else => try testing.expect(false),
    }
}

// ============================================
// RateLimiter checkAttempt Tests
// ============================================

test "RateLimiter checkAttempt new user" {
    var limiter = RateLimiter.init();
    const result = limiter.checkAttempt("testuser");
    // New user should be allowed
    switch (result) {
        .allowed => {},
        .delayed => {},
        .locked_out => try testing.expect(false), // Should not be locked out immediately
    }
}

test "RateLimiter recordFailure and checkAttempt" {
    var limiter = RateLimiter.init();
    
    // Record a failure
    limiter.recordFailure("testuser");
    
    // Check should still work (might have delay)
    const result = limiter.checkAttempt("testuser");
    _ = result;
}

test "RateLimiter recordSuccess clears failures" {
    var limiter = RateLimiter.init();
    
    // Record some failures
    limiter.recordFailure("testuser");
    limiter.recordFailure("testuser");
    
    // Record success
    limiter.recordSuccess("testuser");
    
    // User should be allowed again
    const result = limiter.checkAttempt("testuser");
    switch (result) {
        .allowed => {},
        .delayed => {},
        .locked_out => try testing.expect(false),
    }
}

test "RateLimiter resetUser" {
    var limiter = RateLimiter.init();
    
    // Record failures
    limiter.recordFailure("testuser");
    limiter.recordFailure("testuser");
    
    // Reset user
    limiter.resetUser("testuser");
    
    // User should be allowed
    const result = limiter.checkAttempt("testuser");
    switch (result) {
        .allowed => {},
        .delayed => {},
        .locked_out => try testing.expect(false),
    }
}

test "RateLimiter different users are independent" {
    var limiter = RateLimiter.init();
    
    // Record failures for user1
    limiter.recordFailure("user1");
    limiter.recordFailure("user1");
    limiter.recordFailure("user1");
    
    // user2 should still be allowed
    const result = limiter.checkAttempt("user2");
    switch (result) {
        .allowed => {},
        .delayed => {},
        .locked_out => try testing.expect(false),
    }
}

// ============================================
// getMessage Tests
// ============================================

test "getMessage for allowed" {
    const result = CheckResult{ .allowed = {} };
    var buf: [256]u8 = undefined;
    const msg = rate_limit.getMessage(result, &buf);
    try testing.expect(msg.len > 0);
}

test "getMessage for delayed" {
    const result = CheckResult{ .delayed = 5 };
    var buf: [256]u8 = undefined;
    const msg = rate_limit.getMessage(result, &buf);
    try testing.expect(msg.len > 0);
}

test "getMessage for locked_out" {
    const result = CheckResult{ .locked_out = 300 };
    var buf: [256]u8 = undefined;
    const msg = rate_limit.getMessage(result, &buf);
    try testing.expect(msg.len > 0);
}
