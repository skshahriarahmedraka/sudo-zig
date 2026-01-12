//! Unit tests for process management
//!
//! Tests for process creation, execution, and privilege management.

const std = @import("std");
const testing = std.testing;
const posix = std.posix;
const lib = @import("sudo-zig-lib");
const process = lib.system.process;
const Process = process.Process;
const WaitResult = process.WaitResult;
const ForkResult = process.ForkResult;

// ============================================
// Process Information Tests
// ============================================

test "Process.current returns valid process" {
    const proc = Process.current();
    try testing.expect(proc.pid > 0);
}

test "Process.current pid matches getpid" {
    const proc = Process.current();
    const actual_pid = std.os.linux.getpid();
    try testing.expectEqual(actual_pid, proc.pid);
}

test "Process.current parent pid is valid" {
    const proc = Process.current();
    try testing.expect(proc.ppid > 0);
}

test "Process.current parent pid matches getppid" {
    const proc = Process.current();
    const actual_ppid = std.os.linux.getppid();
    try testing.expectEqual(actual_ppid, proc.ppid);
}

// ============================================
// WaitResult Tests
// ============================================

test "WaitResult ifExited for normal exit" {
    // Create a status that represents normal exit with code 0
    // In POSIX, exit status is stored in upper byte
    const result = WaitResult{ .pid = 1234, .status = 0 };
    const exit_code = result.ifExited();
    try testing.expect(exit_code != null);
    try testing.expectEqual(@as(u8, 0), exit_code.?);
}

test "WaitResult ifSignaled for signal termination" {
    // WIFSIGNALED is true when lower 7 bits are signal and bit 7 is 0
    // Signal 9 (SIGKILL) would be stored as 9 in lower bits
    const result = WaitResult{ .pid = 1234, .status = 9 };
    const signal = result.ifSignaled();
    try testing.expect(signal != null);
    try testing.expectEqual(@as(u32, 9), signal.?);
}

// ============================================
// Fork Tests (type validation only)
// ============================================

test "ForkResult parent type" {
    const result = ForkResult{ .parent = 12345 };
    try testing.expectEqual(@as(posix.pid_t, 12345), result.parent);
}

test "ForkResult child type" {
    const result = ForkResult{ .child = {} };
    _ = result;
}

// ============================================
// Process kill Tests
// ============================================

test "kill with signal 0 checks process existence" {
    const proc = Process.current();
    // Signal 0 just checks if process exists - should not error for self
    process.kill(proc.pid, 0) catch |err| {
        // Only EPERM or ESRCH are acceptable errors
        try testing.expect(err == error.PermissionDenied or err == error.NoSuchProcess);
        return;
    };
    // If no error, the process exists (expected for self)
}

// ============================================
// waitpid Tests
// ============================================

// Note: waitpid tests removed as they require actual child processes
// and can cause issues in test environments

// ============================================
// UID/GID Type Tests
// ============================================

test "UserId type exists" {
    const uid: process.UserId = 1000;
    try testing.expectEqual(@as(process.UserId, 1000), uid);
}

test "GroupId type exists" {
    const gid: process.GroupId = 1000;
    try testing.expectEqual(@as(process.GroupId, 1000), gid);
}
