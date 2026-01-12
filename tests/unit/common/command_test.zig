//! Unit tests for command parsing and representation
//!
//! Tests for CommandAndArguments parsing and validation.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const common = lib.common;
const CommandAndArguments = common.CommandAndArguments;
const SudoPath = common.SudoPath;

// ============================================
// CommandAndArguments.parse Tests
// ============================================

test "parse simple command without arguments" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{"/bin/ls"});
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/ls", cmd.command.slice());
    try testing.expectEqual(@as(usize, 0), cmd.arguments.len);
}

test "parse command with single argument" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/ls", "-l" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/ls", cmd.command.slice());
    try testing.expectEqual(@as(usize, 1), cmd.arguments.len);
    try testing.expectEqualStrings("-l", cmd.arguments[0]);
}

test "parse command with multiple arguments" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/usr/bin/grep", "-r", "-n", "pattern", "/path/to/search" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/usr/bin/grep", cmd.command.slice());
    try testing.expectEqual(@as(usize, 4), cmd.arguments.len);
    try testing.expectEqualStrings("-r", cmd.arguments[0]);
    try testing.expectEqualStrings("-n", cmd.arguments[1]);
    try testing.expectEqualStrings("pattern", cmd.arguments[2]);
    try testing.expectEqualStrings("/path/to/search", cmd.arguments[3]);
}

test "parse command with spaces in arguments" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/echo", "hello world", "foo bar" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/echo", cmd.command.slice());
    try testing.expectEqual(@as(usize, 2), cmd.arguments.len);
    try testing.expectEqualStrings("hello world", cmd.arguments[0]);
    try testing.expectEqualStrings("foo bar", cmd.arguments[1]);
}

test "parse empty args returns error" {
    const result = CommandAndArguments.parse(testing.allocator, &.{});
    try testing.expectError(error.InvalidArgument, result);
}

// ============================================
// CommandAndArguments.init Tests
// ============================================

test "init with pre-validated path" {
    const path = try SudoPath.init("/usr/bin/sudo");
    const args = &[_][]const u8{ "-u", "root", "ls" };

    const cmd = CommandAndArguments.init(path, args);

    try testing.expectEqualStrings("/usr/bin/sudo", cmd.command.slice());
    try testing.expectEqual(@as(usize, 3), cmd.arguments.len);
    try testing.expectEqualStrings("-u", cmd.arguments[0]);
    try testing.expectEqualStrings("root", cmd.arguments[1]);
    try testing.expectEqualStrings("ls", cmd.arguments[2]);
    // No allocator, so no deinit needed
    try testing.expectEqual(@as(?std.mem.Allocator, null), cmd.allocator);
}

test "init with empty arguments" {
    const path = try SudoPath.init("/bin/true");
    const args = &[_][]const u8{};

    const cmd = CommandAndArguments.init(path, args);

    try testing.expectEqualStrings("/bin/true", cmd.command.slice());
    try testing.expectEqual(@as(usize, 0), cmd.arguments.len);
}

// ============================================
// Common Command Patterns Tests
// ============================================

test "parse apt-get update command" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/usr/bin/apt-get", "update" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/usr/bin/apt-get", cmd.command.slice());
    try testing.expectEqual(@as(usize, 1), cmd.arguments.len);
    try testing.expectEqualStrings("update", cmd.arguments[0]);
}

test "parse systemctl command" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/systemctl", "restart", "nginx.service" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/systemctl", cmd.command.slice());
    try testing.expectEqual(@as(usize, 2), cmd.arguments.len);
    try testing.expectEqualStrings("restart", cmd.arguments[0]);
    try testing.expectEqualStrings("nginx.service", cmd.arguments[1]);
}

test "parse command with flags and values" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/usr/bin/useradd", "-m", "-s", "/bin/bash", "-G", "sudo,docker", "newuser" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/usr/bin/useradd", cmd.command.slice());
    try testing.expectEqual(@as(usize, 6), cmd.arguments.len);
    try testing.expectEqualStrings("-m", cmd.arguments[0]);
    try testing.expectEqualStrings("-s", cmd.arguments[1]);
    try testing.expectEqualStrings("/bin/bash", cmd.arguments[2]);
    try testing.expectEqualStrings("-G", cmd.arguments[3]);
    try testing.expectEqualStrings("sudo,docker", cmd.arguments[4]);
    try testing.expectEqualStrings("newuser", cmd.arguments[5]);
}

test "parse command with double dash separator" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/usr/bin/find", "/home", "-name", "*.txt", "--", "-print" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/usr/bin/find", cmd.command.slice());
    try testing.expectEqual(@as(usize, 5), cmd.arguments.len);
    try testing.expectEqualStrings("--", cmd.arguments[3]);
}

// ============================================
// Edge Cases Tests
// ============================================

test "parse command with very long path" {
    const long_path = "/very/long/path/to/some/deeply/nested/directory/structure/bin/command";
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{long_path});
    defer cmd.deinit();

    try testing.expectEqualStrings(long_path, cmd.command.slice());
}

test "parse command with special characters in arguments" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/sh", "-c", "echo $HOME && ls -la" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/sh", cmd.command.slice());
    try testing.expectEqual(@as(usize, 2), cmd.arguments.len);
    try testing.expectEqualStrings("-c", cmd.arguments[0]);
    try testing.expectEqualStrings("echo $HOME && ls -la", cmd.arguments[1]);
}

test "parse command with numeric arguments" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/sleep", "60" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/sleep", cmd.command.slice());
    try testing.expectEqualStrings("60", cmd.arguments[0]);
}

test "parse command with empty string argument" {
    var cmd = try CommandAndArguments.parse(testing.allocator, &.{ "/bin/echo", "" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/echo", cmd.command.slice());
    try testing.expectEqual(@as(usize, 1), cmd.arguments.len);
    try testing.expectEqualStrings("", cmd.arguments[0]);
}
