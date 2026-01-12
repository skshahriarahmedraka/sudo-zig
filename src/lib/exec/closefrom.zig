//! File descriptor cleanup for secure execution
//!
//! This module provides functionality to close file descriptors
//! before executing commands to prevent fd leakage:
//! - closefrom() implementation for closing all fds >= N
//! - /proc/self/fd enumeration for systems without closefrom()
//! - Selective fd preservation (stdin, stdout, stderr)

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("dirent.h");
    @cInclude("fcntl.h");
    @cInclude("sys/resource.h");
});

/// Close all file descriptors >= lowfd
/// Uses the most efficient method available on the current platform
pub fn closefrom(lowfd: posix.fd_t) void {
    // Try Linux close_range syscall first (kernel 5.9+)
    if (builtin.os.tag == .linux) {
        if (closeRange(lowfd, maxFd(), 0)) {
            return;
        }
    }

    // Try reading /proc/self/fd for efficiency
    if (closefromProc(lowfd)) {
        return;
    }

    // Fallback: iterate through all possible fds
    closefromBruteForce(lowfd);
}

/// Close file descriptors using Linux close_range() syscall
fn closeRange(first: c_uint, last: c_uint, flags: c_uint) bool {
    if (builtin.os.tag != .linux) return false;

    // close_range syscall number varies by architecture
    const SYS_close_range: usize = switch (builtin.cpu.arch) {
        .x86_64 => 436,
        .x86 => 436,
        .aarch64 => 436,
        .arm => 436,
        else => return false,
    };

    const result = std.os.linux.syscall3(SYS_close_range, first, last, flags);
    return result == 0;
}

/// Close file descriptors by enumerating /proc/self/fd
fn closefromProc(lowfd: posix.fd_t) bool {
    const dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch return false;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
        if (fd >= lowfd and fd != dir.fd) {
            posix.close(fd);
        }
    }

    return true;
}

/// Brute force close all fds from lowfd to max
fn closefromBruteForce(lowfd: posix.fd_t) void {
    const max = maxFd();
    var fd: posix.fd_t = lowfd;
    while (fd <= max) : (fd += 1) {
        posix.close(fd);
    }
}

/// Get maximum possible file descriptor number
fn maxFd() posix.fd_t {
    // Try to get from rlimit
    var rlim: c.struct_rlimit = undefined;
    if (c.getrlimit(c.RLIMIT_NOFILE, &rlim) == 0) {
        const max = rlim.rlim_cur;
        if (max != c.RLIM_INFINITY and max > 0) {
            return @intCast(@min(max - 1, std.math.maxInt(posix.fd_t)));
        }
    }

    // Fallback to sysconf
    const sc_max = c.sysconf(c._SC_OPEN_MAX);
    if (sc_max > 0) {
        return @intCast(@min(sc_max - 1, std.math.maxInt(posix.fd_t)));
    }

    // Final fallback
    return 1023;
}

/// Close all fds except the ones in the preserve list
pub fn closeAllExcept(lowfd: posix.fd_t, preserve: []const posix.fd_t) void {
    var dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch {
        closeAllExceptBruteForce(lowfd, preserve);
        return;
    };
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
        if (fd >= lowfd and fd != dir.fd and !isPreserved(fd, preserve)) {
            posix.close(fd);
        }
    }
}

/// Brute force version of closeAllExcept
fn closeAllExceptBruteForce(lowfd: posix.fd_t, preserve: []const posix.fd_t) void {
    const max = maxFd();
    var fd: posix.fd_t = lowfd;
    while (fd <= max) : (fd += 1) {
        if (!isPreserved(fd, preserve)) {
            posix.close(fd);
        }
    }
}

/// Check if fd is in the preserve list
fn isPreserved(fd: posix.fd_t, preserve: []const posix.fd_t) bool {
    for (preserve) |p| {
        if (p == fd) return true;
    }
    return false;
}

/// Set close-on-exec flag for a file descriptor
pub fn setCloseOnExec(fd: posix.fd_t) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFD, @as(usize, 0));
    _ = try posix.fcntl(fd, posix.F.SETFD, flags | posix.FD_CLOEXEC);
}

/// Clear close-on-exec flag for a file descriptor
pub fn clearCloseOnExec(fd: posix.fd_t) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFD, @as(usize, 0));
    _ = try posix.fcntl(fd, posix.F.SETFD, flags & ~@as(usize, posix.FD_CLOEXEC));
}

/// Set close-on-exec on all fds >= lowfd
pub fn setCloseOnExecFrom(lowfd: posix.fd_t) void {
    var dir = std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        const fd = std.fmt.parseInt(posix.fd_t, entry.name, 10) catch continue;
        if (fd >= lowfd and fd != dir.fd) {
            setCloseOnExec(fd) catch {};
        }
    }
}

/// Standard file descriptors that are usually preserved
pub const STDIN_FILENO: posix.fd_t = 0;
pub const STDOUT_FILENO: posix.fd_t = 1;
pub const STDERR_FILENO: posix.fd_t = 2;

/// Default list of fds to preserve during exec
pub const default_preserve = [_]posix.fd_t{
    STDIN_FILENO,
    STDOUT_FILENO,
    STDERR_FILENO,
};

/// Prepare file descriptors for secure command execution
/// Closes all fds except stdin/stdout/stderr and any specified extras
pub fn prepareForExec(extra_preserve: []const posix.fd_t) void {
    // Build combined preserve list
    var preserve: [32]posix.fd_t = undefined;
    var count: usize = default_preserve.len;
    @memcpy(preserve[0..default_preserve.len], &default_preserve);

    for (extra_preserve) |fd| {
        if (count >= preserve.len) break;
        if (!isPreserved(fd, preserve[0..count])) {
            preserve[count] = fd;
            count += 1;
        }
    }

    // Close all other fds starting from 3
    closeAllExcept(3, preserve[0..count]);
}

// ============================================
// Tests
// ============================================

test "maxFd returns reasonable value" {
    const max = maxFd();
    try std.testing.expect(max >= 255);
    try std.testing.expect(max <= 1048576);
}

test "isPreserved" {
    const preserve = [_]posix.fd_t{ 0, 1, 2, 5 };
    try std.testing.expect(isPreserved(0, &preserve));
    try std.testing.expect(isPreserved(1, &preserve));
    try std.testing.expect(isPreserved(2, &preserve));
    try std.testing.expect(isPreserved(5, &preserve));
    try std.testing.expect(!isPreserved(3, &preserve));
    try std.testing.expect(!isPreserved(4, &preserve));
    try std.testing.expect(!isPreserved(6, &preserve));
}

test "default_preserve" {
    try std.testing.expectEqual(@as(usize, 3), default_preserve.len);
    try std.testing.expectEqual(@as(posix.fd_t, 0), default_preserve[0]);
    try std.testing.expectEqual(@as(posix.fd_t, 1), default_preserve[1]);
    try std.testing.expectEqual(@as(posix.fd_t, 2), default_preserve[2]);
}

test "setCloseOnExec on valid fd" {
    // Create a pipe to get a valid fd
    const pipe_fds = try posix.pipe();
    defer {
        posix.close(pipe_fds[0]);
        posix.close(pipe_fds[1]);
    }

    // Should not error
    try setCloseOnExec(pipe_fds[0]);
    try setCloseOnExec(pipe_fds[1]);

    // Verify flag is set
    const flags = try posix.fcntl(pipe_fds[0], posix.F.GETFD, @as(usize, 0));
    try std.testing.expect(flags & posix.FD_CLOEXEC != 0);
}

test "clearCloseOnExec" {
    const pipe_fds = try posix.pipe();
    defer {
        posix.close(pipe_fds[0]);
        posix.close(pipe_fds[1]);
    }

    // Set then clear
    try setCloseOnExec(pipe_fds[0]);
    try clearCloseOnExec(pipe_fds[0]);

    // Verify flag is cleared
    const flags = try posix.fcntl(pipe_fds[0], posix.F.GETFD, @as(usize, 0));
    try std.testing.expect(flags & posix.FD_CLOEXEC == 0);
}
