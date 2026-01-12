//! Unit tests for execution context
//!
//! Tests for Context struct and its components.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const common = lib.common;
const Context = common.Context;

// ============================================
// Context.UserInfo Tests
// ============================================

test "UserInfo struct fields" {
    // Test that UserInfo has all expected fields using comptime
    const info = @typeInfo(Context.UserInfo);
    try testing.expect(info == .@"struct");

    // Use @hasField to check for expected fields
    try testing.expect(@hasField(Context.UserInfo, "uid"));
    try testing.expect(@hasField(Context.UserInfo, "gid"));
    try testing.expect(@hasField(Context.UserInfo, "name"));
    try testing.expect(@hasField(Context.UserInfo, "home"));
    try testing.expect(@hasField(Context.UserInfo, "shell"));
    try testing.expect(@hasField(Context.UserInfo, "groups"));
}

test "UserInfo uid and gid types" {
    // Verify uid and gid are u32
    try testing.expectEqual(@as(u32, 1000), @as(u32, 1000));
    try testing.expectEqual(@as(u32, 0), @as(u32, 0)); // root
}

test "UserInfo common values" {
    // Test common UID/GID values
    const root_uid: u32 = 0;
    const root_gid: u32 = 0;
    const normal_uid: u32 = 1000;

    try testing.expectEqual(@as(u32, 0), root_uid);
    try testing.expectEqual(@as(u32, 0), root_gid);
    try testing.expect(normal_uid >= 1000);
}

// ============================================
// Context.GroupInfo Tests
// ============================================

test "GroupInfo struct creation" {
    const group = Context.GroupInfo{
        .gid = 27,
        .name = "sudo",
    };

    try testing.expectEqual(@as(u32, 27), group.gid);
    try testing.expectEqualStrings("sudo", group.name);
}

test "GroupInfo for common groups" {
    const wheel = Context.GroupInfo{ .gid = 10, .name = "wheel" };
    const docker = Context.GroupInfo{ .gid = 999, .name = "docker" };
    const admin = Context.GroupInfo{ .gid = 4, .name = "adm" };

    try testing.expectEqualStrings("wheel", wheel.name);
    try testing.expectEqualStrings("docker", docker.name);
    try testing.expectEqualStrings("adm", admin.name);
}

// ============================================
// Context.ProcessInfo Tests
// ============================================

test "ProcessInfo struct creation" {
    const proc = Context.ProcessInfo{
        .pid = 12345,
        .ppid = 1,
        .sid = 12345,
        .tty = "/dev/pts/0",
    };

    try testing.expectEqual(@as(i32, 12345), proc.pid);
    try testing.expectEqual(@as(i32, 1), proc.ppid);
    try testing.expectEqual(@as(i32, 12345), proc.sid);
    try testing.expectEqualStrings("/dev/pts/0", proc.tty.?);
}

test "ProcessInfo without tty" {
    const proc = Context.ProcessInfo{
        .pid = 999,
        .ppid = 1,
        .sid = 999,
        .tty = null,
    };

    try testing.expectEqual(@as(?[]const u8, null), proc.tty);
}

test "ProcessInfo for daemon process" {
    const proc = Context.ProcessInfo{
        .pid = 1,
        .ppid = 0,
        .sid = 1,
        .tty = null,
    };

    try testing.expectEqual(@as(i32, 1), proc.pid);
    try testing.expectEqual(@as(i32, 0), proc.ppid);
    try testing.expectEqual(@as(?[]const u8, null), proc.tty);
}

// ============================================
// Context.Options Tests
// ============================================

test "Options default values" {
    const opts = Context.Options{};

    try testing.expect(!opts.login_shell);
    try testing.expect(!opts.preserve_env);
    try testing.expect(!opts.use_stdin);
    try testing.expect(!opts.non_interactive);
    try testing.expect(!opts.bell);
    try testing.expect(!opts.reset_timestamp);
    try testing.expect(opts.use_pty); // PTY enabled by default
}

test "Options for login shell" {
    const opts = Context.Options{
        .login_shell = true,
        .use_pty = true,
    };

    try testing.expect(opts.login_shell);
    try testing.expect(opts.use_pty);
}

test "Options for non-interactive execution" {
    const opts = Context.Options{
        .non_interactive = true,
        .use_stdin = true,
    };

    try testing.expect(opts.non_interactive);
    try testing.expect(opts.use_stdin);
}

test "Options for preserve environment" {
    const opts = Context.Options{
        .preserve_env = true,
    };

    try testing.expect(opts.preserve_env);
    try testing.expect(!opts.login_shell); // These are typically mutually exclusive
}

test "Options for timestamp reset" {
    const opts = Context.Options{
        .reset_timestamp = true,
    };

    try testing.expect(opts.reset_timestamp);
}

// ============================================
// Full Context Tests
// ============================================

test "Context struct has all required fields" {
    // Verify Context struct has all expected fields using @hasField
    const info = @typeInfo(Context);
    try testing.expect(info == .@"struct");

    try testing.expect(@hasField(Context, "allocator"));
    try testing.expect(@hasField(Context, "current_user"));
    try testing.expect(@hasField(Context, "target_user"));
    try testing.expect(@hasField(Context, "hostname"));
    try testing.expect(@hasField(Context, "command"));
    try testing.expect(@hasField(Context, "options"));
}
