//! Process management
//!
//! Provides process creation, credential management, and execution.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const user = @import("user.zig");
pub const UserId = user.UserId;
pub const GroupId = user.GroupId;

/// Process information and operations.
pub const Process = struct {
    pid: posix.pid_t,
    ppid: posix.pid_t,

    const Self = @This();

    /// Get information about the current process.
    pub fn current() Self {
        return .{
            .pid = std.c.getpid(),
            .ppid = std.c.getppid(),
        };
    }

    /// Fork the current process.
    pub fn fork() !ForkResult {
        const pid = try posix.fork();
        if (pid == 0) {
            return .child;
        } else {
            return .{ .parent = pid };
        }
    }

    /// Set the real and effective user ID.
    pub fn setUid(uid: UserId) !void {
        try posix.setuid(uid);
    }

    /// Set the real and effective group ID.
    pub fn setGid(gid: GroupId) !void {
        try posix.setgid(gid);
    }

    /// Set the effective user ID.
    pub fn setEuid(uid: UserId) !void {
        try posix.seteuid(uid);
    }

    /// Set the effective group ID.
    pub fn setEgid(gid: GroupId) !void {
        try posix.setegid(gid);
    }

    /// Create a new session.
    pub fn setsid() !posix.pid_t {
        return try posix.setsid();
    }

    /// Set the process group ID.
    pub fn setpgid(pid: posix.pid_t, pgid: posix.pid_t) !void {
        try posix.setpgid(pid, pgid);
    }
};

/// Result of a fork operation.
pub const ForkResult = union(enum) {
    /// We are the parent process; contains child PID.
    parent: posix.pid_t,
    /// We are the child process.
    child: void,
};

/// Wait for a child process to change state.
pub fn waitpid(pid: posix.pid_t, options: u32) !WaitResult {
    const result = posix.waitpid(pid, options);
    return .{
        .pid = result.pid,
        .status = result.status,
    };
}

/// Result of waiting for a process.
pub const WaitResult = struct {
    pid: posix.pid_t,
    status: u32,

    const Self = @This();

    /// Check if the process exited normally.
    pub fn ifExited(self: Self) ?u8 {
        if (self.status & 0x7f == 0) {
            return @truncate((self.status >> 8) & 0xff);
        }
        return null;
    }

    /// Check if the process was killed by a signal.
    pub fn ifSignaled(self: Self) ?u32 {
        const sig = self.status & 0x7f;
        if (sig != 0 and sig != 0x7f) {
            return sig;
        }
        return null;
    }
};

/// Send a signal to a process.
pub fn kill(pid: posix.pid_t, sig: u32) !void {
    try posix.kill(pid, @intCast(sig));
}

// ============================================
// Tests
// ============================================

test "Process.current" {
    const proc = Process.current();
    try std.testing.expect(proc.pid > 0);
}

test "ForkResult" {
    // Just test the type works
    const result: ForkResult = .child;
    switch (result) {
        .child => {},
        .parent => |_| {},
    }
}
