//! Rate limiting for authentication attempts
//!
//! This module provides protection against brute-force attacks by:
//! - Tracking failed authentication attempts per user
//! - Implementing exponential backoff delays
//! - Temporarily locking out users after too many failures

const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("time.h");
    @cInclude("sys/stat.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});

/// Rate limiter configuration
pub const Config = struct {
    /// Maximum failed attempts before lockout
    max_failures: u32 = 3,
    /// Initial delay after first failure (in seconds)
    initial_delay_secs: u32 = 2,
    /// Maximum delay between attempts (in seconds)
    max_delay_secs: u32 = 30,
    /// Lockout duration after max failures (in seconds)
    lockout_duration_secs: u32 = 300, // 5 minutes
    /// Multiplier for exponential backoff
    backoff_multiplier: u32 = 2,
    /// Directory to store rate limit state
    state_dir: []const u8 = "/var/run/sudo",
};

/// Result of checking rate limit
pub const CheckResult = union(enum) {
    /// Request is allowed
    allowed: void,
    /// Request is delayed - wait the specified number of seconds
    delayed: u32,
    /// User is locked out - wait the specified number of seconds
    locked_out: u32,
};

/// State file format for a user's failed attempts
const UserState = struct {
    failure_count: u32,
    last_failure_time: i64,
    lockout_until: i64,
};

/// Rate limiter for authentication attempts
pub const RateLimiter = struct {
    config: Config,

    const Self = @This();

    /// Create a new rate limiter with default configuration
    pub fn init() Self {
        return .{ .config = Config{} };
    }

    /// Create a new rate limiter with custom configuration
    pub fn initWithConfig(config: Config) Self {
        return .{ .config = config };
    }

    /// Check if an authentication attempt is allowed for the given user
    /// Returns the current state and whether to proceed
    pub fn checkAttempt(self: *Self, username: []const u8) CheckResult {
        const state = self.loadState(username) orelse return .{ .allowed = {} };
        const current_time = std.time.timestamp();

        // Check if user is locked out
        if (state.lockout_until > current_time) {
            const wait_time: u32 = @intCast(@max(0, state.lockout_until - current_time));
            return .{ .locked_out = wait_time };
        }

        // Check if we're still in delay period
        if (state.failure_count > 0) {
            const delay = self.calculateDelay(state.failure_count);
            const allowed_time = state.last_failure_time + @as(i64, delay);

            if (current_time < allowed_time) {
                const wait_time: u32 = @intCast(@max(0, allowed_time - current_time));
                return .{ .delayed = wait_time };
            }
        }

        return .{ .allowed = {} };
    }

    /// Record a failed authentication attempt
    pub fn recordFailure(self: *Self, username: []const u8) void {
        var state = self.loadState(username) orelse UserState{
            .failure_count = 0,
            .last_failure_time = 0,
            .lockout_until = 0,
        };

        const current_time = std.time.timestamp();
        state.failure_count += 1;
        state.last_failure_time = current_time;

        // Check if we should lock out the user
        if (state.failure_count >= self.config.max_failures) {
            state.lockout_until = current_time + @as(i64, self.config.lockout_duration_secs);
        }

        self.saveState(username, state);
    }

    /// Record a successful authentication (resets failure count)
    pub fn recordSuccess(self: *Self, username: []const u8) void {
        // Simply remove the state file on success
        self.clearState(username);
    }

    /// Reset rate limit state for a user (admin function)
    pub fn resetUser(self: *Self, username: []const u8) void {
        self.clearState(username);
    }

    /// Calculate delay based on failure count (exponential backoff)
    fn calculateDelay(self: *Self, failure_count: u32) u32 {
        if (failure_count == 0) return 0;

        // Exponential backoff: initial_delay * (multiplier ^ (failures - 1))
        var delay: u32 = self.config.initial_delay_secs;
        var i: u32 = 1;
        while (i < failure_count) : (i += 1) {
            delay *|= self.config.backoff_multiplier;
            if (delay >= self.config.max_delay_secs) {
                delay = self.config.max_delay_secs;
                break;
            }
        }

        return delay;
    }

    /// Get the path for a user's state file
    fn getStatePath(self: *Self, username: []const u8, buf: []u8) ?[]const u8 {
        const len = std.fmt.bufPrint(buf, "{s}/rl_{s}", .{ self.config.state_dir, username }) catch return null;
        return len;
    }

    /// Load state from disk
    fn loadState(self: *Self, username: []const u8) ?UserState {
        var path_buf: [256]u8 = undefined;
        const path = self.getStatePath(username, &path_buf) orelse return null;

        const file = std.fs.openFileAbsolute(path, .{}) catch return null;
        defer file.close();

        var state_buf: [@sizeOf(UserState)]u8 = undefined;
        const n = file.read(&state_buf) catch return null;
        if (n < @sizeOf(UserState)) return null;

        return @as(*const UserState, @ptrCast(@alignCast(&state_buf))).*;
    }

    /// Save state to disk
    fn saveState(self: *Self, username: []const u8, state: UserState) void {
        var path_buf: [256]u8 = undefined;
        const path = self.getStatePath(username, &path_buf) orelse return;

        // Ensure directory exists
        std.fs.makeDirAbsolute(self.config.state_dir) catch {};

        // Create file with restricted permissions (root only)
        const file = std.fs.createFileAbsolute(path, .{ .mode = 0o600 }) catch return;
        defer file.close();

        const state_bytes: *const [@sizeOf(UserState)]u8 = @ptrCast(&state);
        file.writeAll(state_bytes) catch {};
    }

    /// Clear state file for a user
    fn clearState(self: *Self, username: []const u8) void {
        var path_buf: [256]u8 = undefined;
        const path = self.getStatePath(username, &path_buf) orelse return;
        std.fs.deleteFileAbsolute(path) catch {};
    }
};

/// Apply rate limiting delay (sleep if needed)
pub fn applyDelay(result: CheckResult) !void {
    switch (result) {
        .allowed => return,
        .delayed => |secs| {
            std.Thread.sleep(@as(u64, secs) * std.time.ns_per_s);
        },
        .locked_out => |secs| {
            // For lockout, we could either sleep or return an error
            // Returning an error is more user-friendly
            _ = secs;
            return error.UserLockedOut;
        },
    }
}

/// Get human-readable message for rate limit result
pub fn getMessage(result: CheckResult, buf: []u8) []const u8 {
    return switch (result) {
        .allowed => "Authentication allowed",
        .delayed => |secs| std.fmt.bufPrint(buf, "Please wait {d} seconds before trying again", .{secs}) catch "Please wait before trying again",
        .locked_out => |secs| std.fmt.bufPrint(buf, "Account temporarily locked. Try again in {d} seconds", .{secs}) catch "Account temporarily locked",
    };
}

// ============================================
// Tests
// ============================================

test "RateLimiter init" {
    const limiter = RateLimiter.init();
    try std.testing.expectEqual(@as(u32, 3), limiter.config.max_failures);
    try std.testing.expectEqual(@as(u32, 2), limiter.config.initial_delay_secs);
}

test "RateLimiter calculateDelay" {
    var limiter = RateLimiter.initWithConfig(.{
        .initial_delay_secs = 2,
        .backoff_multiplier = 2,
        .max_delay_secs = 30,
    });

    try std.testing.expectEqual(@as(u32, 0), limiter.calculateDelay(0));
    try std.testing.expectEqual(@as(u32, 2), limiter.calculateDelay(1));
    try std.testing.expectEqual(@as(u32, 4), limiter.calculateDelay(2));
    try std.testing.expectEqual(@as(u32, 8), limiter.calculateDelay(3));
    try std.testing.expectEqual(@as(u32, 16), limiter.calculateDelay(4));
    try std.testing.expectEqual(@as(u32, 30), limiter.calculateDelay(5)); // Capped at max
}

test "CheckResult allowed" {
    const result = CheckResult{ .allowed = {} };
    var buf: [128]u8 = undefined;
    const msg = getMessage(result, &buf);
    try std.testing.expectEqualStrings("Authentication allowed", msg);
}

test "CheckResult delayed" {
    const result = CheckResult{ .delayed = 5 };
    var buf: [128]u8 = undefined;
    const msg = getMessage(result, &buf);
    try std.testing.expectEqualStrings("Please wait 5 seconds before trying again", msg);
}

test "CheckResult locked_out" {
    const result = CheckResult{ .locked_out = 300 };
    var buf: [128]u8 = undefined;
    const msg = getMessage(result, &buf);
    try std.testing.expectEqualStrings("Account temporarily locked. Try again in 300 seconds", msg);
}

test "applyDelay allowed" {
    const result = CheckResult{ .allowed = {} };
    try applyDelay(result);
}

test "applyDelay locked_out returns error" {
    const result = CheckResult{ .locked_out = 10 };
    try std.testing.expectError(error.UserLockedOut, applyDelay(result));
}
