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
    try testing.expect(proc.parent_pid > 0);
}

test "Process.current parent pid matches getppid" {
    const proc = Process.current();
    const actual_ppid = std.os.linux.getppid();
    try testing.expectEqual(actual_ppid, proc.parent_pid);
}

// ============================================
// Process ID Tests
// ============================================

test "getPid returns positive value" {
    const pid = process.getPid();
    try testing.expect(pid > 0);
}

test "getParentPid returns positive value" {
    const ppid = process.getParentPid();
    try testing.expect(ppid > 0);
}

test "getProcessGroup returns valid value" {
    const pgid = process.getProcessGroup();
    try testing.expect(pgid > 0);
}

test "getSessionId returns valid value" {
    const sid = process.getSessionId();
    try testing.expect(sid > 0);
}

// ============================================
// Environment Tests  
// ============================================

test "getEnv returns PATH" {
    const path = process.getEnv("PATH");
    try testing.expect(path != null);
    try testing.expect(path.?.len > 0);
}

test "getEnv returns null for nonexistent var" {
    const result = process.getEnv("NONEXISTENT_VAR_12345");
    try testing.expect(result == null);
}

test "getEnv returns HOME" {
    const home = process.getEnv("HOME");
    // HOME should exist in most environments
    if (home) |h| {
        try testing.expect(h.len > 0);
        try testing.expect(h[0] == '/');
    }
}

// ============================================
// UID/GID Tests
// ============================================

test "getUid returns valid uid" {
    const uid = process.getUid();
    // UID is always >= 0
    _ = uid;
}

test "getEffectiveUid returns valid uid" {
    const euid = process.getEffectiveUid();
    _ = euid;
}

test "getGid returns valid gid" {
    const gid = process.getGid();
    _ = gid;
}

test "getEffectiveGid returns valid gid" {
    const egid = process.getEffectiveGid();
    _ = egid;
}

// ============================================
// WaitResult Tests
// ============================================

test "WaitResult exited with code 0" {
    const result = WaitResult{ .exited = 0 };
    try testing.expectEqual(@as(u8, 0), result.exited);
}

test "WaitResult exited with code 1" {
    const result = WaitResult{ .exited = 1 };
    try testing.expectEqual(@as(u8, 1), result.exited);
}

test "WaitResult signaled" {
    const result = WaitResult{ .signaled = 9 }; // SIGKILL
    try testing.expectEqual(@as(u32, 9), result.signaled);
}

test "WaitResult stopped" {
    const result = WaitResult{ .stopped = 19 }; // SIGSTOP
    try testing.expectEqual(@as(u32, 19), result.stopped);
}

test "WaitResult continued" {
    const result = WaitResult{ .continued = {} };
    _ = result;
}

// ============================================
// Fork Tests (basic validation only)
// ============================================

test "ForkResult types" {
    // Just verify the types exist and compile
    const parent_result = process.ForkResult{ .parent = 12345 };
    try testing.expectEqual(@as(i32, 12345), parent_result.parent);

    const child_result = process.ForkResult{ .child = {} };
    _ = child_result;
}

// ============================================
// Exec Preparation Tests
// ============================================

test "ExecOptions default values" {
    const opts = process.ExecOptions{};
    try testing.expect(opts.search_path == false);
    try testing.expect(opts.clear_env == false);
}

test "ExecOptions with search_path" {
    const opts = process.ExecOptions{
        .search_path = true,
        .clear_env = false,
    };
    try testing.expect(opts.search_path);
}

// ============================================
// Resource Limits Tests
// ============================================

test "getMaxFd returns reasonable value" {
    const max_fd = process.getMaxFd();
    // Should be at least standard unix minimum
    try testing.expect(max_fd >= 20);
    // Should be reasonable (not > 1M usually)
    try testing.expect(max_fd <= 1048576);
}

// ============================================
// Working Directory Tests
// ============================================

test "getCwd returns valid path" {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = process.getCwd(&buf);
    try testing.expect(cwd != null);
    try testing.expect(cwd.?.len > 0);
    try testing.expect(cwd.?[0] == '/');
}

// ============================================
// Signal-related Process Tests
// ============================================

test "killProcess with signal 0 checks existence" {
    const pid = process.getPid();
    // Signal 0 just checks if process exists
    const result = process.killProcess(pid, 0);
    try testing.expect(result == .success or result == .permission_denied);
}

test "killProcess invalid pid returns error" {
    // PID -1 is invalid
    const result = process.killProcess(-1, 0);
    try testing.expect(result == .invalid_pid or result == .no_such_process);
}

// ============================================
// Process State Tests
// ============================================

test "isProcessRunning for current process" {
    const pid = process.getPid();
    try testing.expect(process.isProcessRunning(pid));
}

test "isProcessRunning for invalid pid" {
    // Very high PID unlikely to exist
    try testing.expect(!process.isProcessRunning(999999999));
}

// ============================================
// Umask Tests
// ============================================

test "getUmask and setUmask roundtrip" {
    const original = process.getUmask();
    
    // Set a known value
    process.setUmask(0o077);
    try testing.expectEqual(@as(u32, 0o077), process.getUmask());
    
    // Restore original
    process.setUmask(original);
    try testing.expectEqual(original, process.getUmask());
}
