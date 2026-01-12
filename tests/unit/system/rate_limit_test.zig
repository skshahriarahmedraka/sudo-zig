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
    try testing.expectEqual(@as(u32, 2), config.initial_delay_secs);
    try testing.expectEqual(@as(u32, 2), config.backoff_multiplier);
    try testing.expectEqual(@as(u32, 60), config.max_delay_secs);
    try testing.expectEqual(@as(u32, 5), config.max_failures);
}

test "Config custom values" {
    const config = Config{
        .initial_delay_secs = 5,
        .backoff_multiplier = 3,
        .max_delay_secs = 120,
        .max_failures = 10,
    };
    try testing.expectEqual(@as(u32, 5), config.initial_delay_secs);
    try testing.expectEqual(@as(u32, 3), config.backoff_multiplier);
    try testing.expectEqual(@as(u32, 120), config.max_delay_secs);
    try testing.expectEqual(@as(u32, 10), config.max_failures);
}

// ============================================
// RateLimiter Tests
// ============================================

test "RateLimiter initialization" {
    const limiter = RateLimiter.init();
    try testing.expectEqual(@as(u32, 0), limiter.failure_count);
}

test "RateLimiter initWithConfig" {
    const config = Config{
        .initial_delay_secs = 3,
        .backoff_multiplier = 4,
        .max_delay_secs = 180,
        .max_failures = 8,
    };
    const limiter = RateLimiter.initWithConfig(config);
    try testing.expectEqual(@as(u32, 0), limiter.failure_count);
    try testing.expectEqual(@as(u32, 3), limiter.config.initial_delay_secs);
}

test "RateLimiter calculateDelay exponential backoff" {
    const limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 60,
        .max_failures = 10,
    });

    // First failure: 2 seconds
    try testing.expectEqual(@as(u32, 2), limiter.calculateDelay(1));

    // Second failure: 4 seconds (2 * 2)
    try testing.expectEqual(@as(u32, 4), limiter.calculateDelay(2));

    // Third failure: 8 seconds (4 * 2)
    try testing.expectEqual(@as(u32, 8), limiter.calculateDelay(3));

    // Fourth failure: 16 seconds (8 * 2)
    try testing.expectEqual(@as(u32, 16), limiter.calculateDelay(4));

    // Fifth failure: 32 seconds (16 * 2)
    try testing.expectEqual(@as(u32, 32), limiter.calculateDelay(5));
}

test "RateLimiter calculateDelay respects max_delay" {
    const limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 30,
        .max_failures = 10,
    });

    // High failure count should cap at max
    try testing.expectEqual(@as(u32, 30), limiter.calculateDelay(10));
    try testing.expectEqual(@as(u32, 30), limiter.calculateDelay(20));
}

test "RateLimiter calculateDelay zero failures" {
    const limiter = RateLimiter.init();
    // Zero failures should return 0 delay
    try testing.expectEqual(@as(u32, 0), limiter.calculateDelay(0));
}

test "RateLimiter recordFailure increments count" {
    var limiter = RateLimiter.init();
    try testing.expectEqual(@as(u32, 0), limiter.failure_count);

    limiter.recordFailure();
    try testing.expectEqual(@as(u32, 1), limiter.failure_count);

    limiter.recordFailure();
    try testing.expectEqual(@as(u32, 2), limiter.failure_count);
}

test "RateLimiter recordSuccess resets count" {
    var limiter = RateLimiter.init();
    limiter.recordFailure();
    limiter.recordFailure();
    limiter.recordFailure();
    try testing.expectEqual(@as(u32, 3), limiter.failure_count);

    limiter.recordSuccess();
    try testing.expectEqual(@as(u32, 0), limiter.failure_count);
}

test "RateLimiter reset clears state" {
    var limiter = RateLimiter.init();
    limiter.recordFailure();
    limiter.recordFailure();
    try testing.expectEqual(@as(u32, 2), limiter.failure_count);

    limiter.reset();
    try testing.expectEqual(@as(u32, 0), limiter.failure_count);
}

// ============================================
// CheckResult Tests
// ============================================

test "CheckResult allowed" {
    const result = CheckResult{ .allowed = true, .delay_secs = 0 };
    try testing.expect(result.allowed);
    try testing.expectEqual(@as(u32, 0), result.delay_secs);
}

test "CheckResult delayed" {
    const result = CheckResult{ .allowed = true, .delay_secs = 5 };
    try testing.expect(result.allowed);
    try testing.expectEqual(@as(u32, 5), result.delay_secs);
}

test "CheckResult locked_out" {
    const result = CheckResult{ .allowed = false, .delay_secs = 0 };
    try testing.expect(!result.allowed);
}

// ============================================
// RateLimiter check Tests
// ============================================

test "RateLimiter check no failures" {
    var limiter = RateLimiter.init();
    const result = limiter.check();
    try testing.expect(result.allowed);
    try testing.expectEqual(@as(u32, 0), result.delay_secs);
}

test "RateLimiter check with failures" {
    var limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 60,
        .max_failures = 10,
    });

    limiter.recordFailure();
    const result = limiter.check();
    try testing.expect(result.allowed);
    try testing.expectEqual(@as(u32, 2), result.delay_secs);
}

test "RateLimiter check lockout after max failures" {
    var limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 60,
        .max_failures = 3,
    });

    limiter.recordFailure();
    limiter.recordFailure();
    limiter.recordFailure();

    const result = limiter.check();
    try testing.expect(!result.allowed);
}

// ============================================
// Multiplier Variations Tests
// ============================================

test "RateLimiter with multiplier 3" {
    const limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 1,
        .backoff_multiplier = 3,
        .max_delay_secs = 100,
        .max_failures = 10,
    });

    // 1, 3, 9, 27, 81
    try testing.expectEqual(@as(u32, 1), limiter.calculateDelay(1));
    try testing.expectEqual(@as(u32, 3), limiter.calculateDelay(2));
    try testing.expectEqual(@as(u32, 9), limiter.calculateDelay(3));
    try testing.expectEqual(@as(u32, 27), limiter.calculateDelay(4));
    try testing.expectEqual(@as(u32, 81), limiter.calculateDelay(5));
}

test "RateLimiter with multiplier 1 (no backoff)" {
    const limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 5,
        .backoff_multiplier = 1,
        .max_delay_secs = 100,
        .max_failures = 10,
    });

    // All delays should be the same
    try testing.expectEqual(@as(u32, 5), limiter.calculateDelay(1));
    try testing.expectEqual(@as(u32, 5), limiter.calculateDelay(2));
    try testing.expectEqual(@as(u32, 5), limiter.calculateDelay(5));
}

// ============================================
// Edge Cases
// ============================================

test "RateLimiter very high failure count" {
    const limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 1,
        .backoff_multiplier = 2,
        .max_delay_secs = 60,
        .max_failures = 1000,
    });

    // Should cap at max_delay, not overflow
    const delay = limiter.calculateDelay(100);
    try testing.expectEqual(@as(u32, 60), delay);
}

test "RateLimiter max_failures of 0" {
    var limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 60,
        .max_failures = 0,
    });

    // Any failure should lock out immediately
    const result = limiter.check();
    try testing.expect(!result.allowed);
}
