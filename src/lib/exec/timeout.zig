//! Command execution timeout handling
//!
//! This module provides timeout functionality for command execution:
//! - Configurable command timeout (command_timeout sudoers option)
//! - Process group management for clean termination
//! - Graceful shutdown with SIGTERM followed by SIGKILL

const std = @import("std");
const posix = std.posix;
const system = @import("../system/mod.zig");

const c = @cImport({
    @cInclude("signal.h");
    @cInclude("sys/types.h");
    @cInclude("unistd.h");
});

/// Timeout configuration
pub const TimeoutConfig = struct {
    /// Command execution timeout in seconds (0 = no timeout)
    timeout_secs: u32 = 0,
    /// Grace period before SIGKILL after SIGTERM (seconds)
    kill_grace_secs: u32 = 5,
    /// Whether to kill the entire process group
    kill_process_group: bool = true,
};

/// Timeout state for tracking execution time
pub const TimeoutState = struct {
    config: TimeoutConfig,
    start_time: i64,
    term_sent: bool = false,
    kill_sent: bool = false,

    const Self = @This();

    /// Initialize timeout state
    pub fn init(config: TimeoutConfig) Self {
        return .{
            .config = config,
            .start_time = std.time.timestamp(),
        };
    }

    /// Check if timeout has been reached
    pub fn isExpired(self: *const Self) bool {
        if (self.config.timeout_secs == 0) return false;
        const elapsed = std.time.timestamp() - self.start_time;
        return elapsed >= @as(i64, self.config.timeout_secs);
    }

    /// Check if grace period after TERM has expired (time to send KILL)
    pub fn isGraceExpired(self: *const Self) bool {
        if (!self.term_sent) return false;
        const elapsed = std.time.timestamp() - self.start_time;
        const total_timeout = @as(i64, self.config.timeout_secs + self.config.kill_grace_secs);
        return elapsed >= total_timeout;
    }

    /// Get remaining time until timeout (in seconds)
    pub fn remainingTime(self: *const Self) ?u32 {
        if (self.config.timeout_secs == 0) return null;
        const elapsed = std.time.timestamp() - self.start_time;
        const remaining = @as(i64, self.config.timeout_secs) - elapsed;
        return if (remaining > 0) @intCast(remaining) else 0;
    }

    /// Get timeout for poll() in milliseconds
    pub fn pollTimeout(self: *const Self) i32 {
        if (self.config.timeout_secs == 0) {
            return 100; // Default 100ms poll interval
        }

        const remaining = self.remainingTime() orelse return 100;
        if (remaining == 0) return 0;

        // Use shorter intervals as we approach timeout
        const ms = @min(remaining * 1000, 1000);
        return @intCast(ms);
    }
};

/// Timeout handler that can terminate a process on timeout
pub const TimeoutHandler = struct {
    state: TimeoutState,
    target_pid: posix.pid_t,
    target_pgid: ?posix.pid_t,

    const Self = @This();

    /// Initialize timeout handler for a process
    pub fn init(config: TimeoutConfig, pid: posix.pid_t) Self {
        return .{
            .state = TimeoutState.init(config),
            .target_pid = pid,
            .target_pgid = if (config.kill_process_group) getProcessGroup(pid) else null,
        };
    }

    /// Check and handle timeout
    /// Returns true if process should continue, false if terminated
    pub fn check(self: *Self) bool {
        if (self.state.config.timeout_secs == 0) return true;

        if (self.state.isGraceExpired() and !self.state.kill_sent) {
            // Grace period expired, send SIGKILL
            self.sendSignal(c.SIGKILL);
            self.state.kill_sent = true;
            return false;
        }

        if (self.state.isExpired() and !self.state.term_sent) {
            // Initial timeout, send SIGTERM
            self.sendSignal(c.SIGTERM);
            self.state.term_sent = true;
        }

        return true;
    }

    /// Send signal to process (or process group)
    fn sendSignal(self: *Self, sig: c_int) void {
        if (self.state.config.kill_process_group) {
            if (self.target_pgid) |pgid| {
                // Kill entire process group
                _ = c.killpg(pgid, sig);
                return;
            }
        }
        // Kill single process
        _ = c.kill(self.target_pid, sig);
    }

    /// Get poll timeout in milliseconds
    pub fn pollTimeout(self: *const Self) i32 {
        return self.state.pollTimeout();
    }

    /// Check if timeout is enabled
    pub fn isEnabled(self: *const Self) bool {
        return self.state.config.timeout_secs > 0;
    }
};

/// Get the process group ID for a process
fn getProcessGroup(pid: posix.pid_t) ?posix.pid_t {
    const pgid = c.getpgid(pid);
    return if (pgid >= 0) pgid else null;
}

/// Create a new process group for the current process
pub fn createProcessGroup() !void {
    if (c.setpgid(0, 0) != 0) {
        return error.SetProcessGroupFailed;
    }
}

/// Set process group for a process
pub fn setProcessGroup(pid: posix.pid_t, pgid: posix.pid_t) !void {
    if (c.setpgid(pid, pgid) != 0) {
        return error.SetProcessGroupFailed;
    }
}

// ============================================
// Tests
// ============================================

test "TimeoutConfig defaults" {
    const config = TimeoutConfig{};
    try std.testing.expectEqual(@as(u32, 0), config.timeout_secs);
    try std.testing.expectEqual(@as(u32, 5), config.kill_grace_secs);
    try std.testing.expect(config.kill_process_group);
}

test "TimeoutState no timeout" {
    const state = TimeoutState.init(.{ .timeout_secs = 0 });
    try std.testing.expect(!state.isExpired());
    try std.testing.expect(state.remainingTime() == null);
}

test "TimeoutState with timeout" {
    const state = TimeoutState.init(.{ .timeout_secs = 60 });
    try std.testing.expect(!state.isExpired());
    const remaining = state.remainingTime();
    try std.testing.expect(remaining != null);
    try std.testing.expect(remaining.? > 0);
    try std.testing.expect(remaining.? <= 60);
}

test "TimeoutState pollTimeout" {
    const state_no_timeout = TimeoutState.init(.{ .timeout_secs = 0 });
    try std.testing.expectEqual(@as(i32, 100), state_no_timeout.pollTimeout());

    const state_with_timeout = TimeoutState.init(.{ .timeout_secs = 60 });
    const poll_ms = state_with_timeout.pollTimeout();
    try std.testing.expect(poll_ms > 0);
    try std.testing.expect(poll_ms <= 1000);
}

test "TimeoutHandler init" {
    const handler = TimeoutHandler.init(.{ .timeout_secs = 30 }, 12345);
    try std.testing.expectEqual(@as(posix.pid_t, 12345), handler.target_pid);
    try std.testing.expect(handler.isEnabled());
}

test "TimeoutHandler disabled" {
    const handler = TimeoutHandler.init(.{ .timeout_secs = 0 }, 12345);
    try std.testing.expect(!handler.isEnabled());
}
