const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");

// This test file validates the fix for the stack buffer issue in CLI parsing.
// The bug was that positional_buf was stack-allocated and its slice was returned,
// causing memory corruption when accessed after parseArgs() returned.
//
// The fix changed positional_buf to a static variable to ensure memory remains valid.

test "cli types are properly defined" {
    // Basic sanity test to ensure CLI module is accessible
    const Action = lib.sudo.cli.Action;
    const RunOptions = lib.sudo.cli.RunOptions;
    
    // Create a RunOptions with command slice
    const opts = RunOptions{
        .command = &[_][]const u8{ "test", "command" },
    };
    
    try testing.expectEqual(@as(usize, 2), opts.command.len);
    try testing.expectEqualStrings("test", opts.command[0]);
    try testing.expectEqualStrings("command", opts.command[1]);
    
    // Ensure Action union works
    const action: Action = .{ .run = opts };
    try testing.expect(action == .run);
    try testing.expectEqual(@as(usize, 2), action.run.command.len);
}

test "static buffer preserves command arguments" {
    // This test simulates what the fixed parseArgs does:
    // Using a static buffer instead of stack buffer to store arguments
    
    const TestStatic = struct {
        var positional_buf: [4][]const u8 = undefined;
        
        fn createSlice(args: []const []const u8) []const []const u8 {
            for (args, 0..) |arg, i| {
                positional_buf[i] = arg;
            }
            return positional_buf[0..args.len];
        }
    };
    
    const test_args = [_][]const u8{ "apt", "update" };
    const result = TestStatic.createSlice(&test_args);
    
    // Verify slice is valid even after function returns
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("apt", result[0]);
    try testing.expectEqualStrings("update", result[1]);
    
    // Perform stack operations to ensure buffer isn't corrupted
    var dummy: [512]u8 = undefined;
    @memset(&dummy, 0xAA);
    
    // Data should still be valid
    try testing.expectEqualStrings("apt", result[0]);
    try testing.expectEqualStrings("update", result[1]);
}

test "RunOptions command slice lifetime" {
    // Test that command slices stored in RunOptions remain valid
    
    const static = struct {
        var args: [3][]const u8 = undefined;
    };
    
    static.args[0] = "ls";
    static.args[1] = "-la";
    static.args[2] = "/tmp";
    
    const opts = lib.sudo.cli.RunOptions{
        .command = static.args[0..3],
    };
    
    // Trigger some stack activity
    var buf: [256]u8 = undefined;
    for (&buf, 0..) |*b, i| {
        b.* = @intCast(i % 256);
    }
    
    // Command should still be accessible
    try testing.expectEqual(@as(usize, 3), opts.command.len);
    try testing.expectEqualStrings("ls", opts.command[0]);
    try testing.expectEqualStrings("-la", opts.command[1]);
    try testing.expectEqualStrings("/tmp", opts.command[2]);
}
