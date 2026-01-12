//! Command parsing and representation
//!
//! Handles parsing and validation of commands to be executed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const path_mod = @import("path.zig");

pub const SudoPath = path_mod.SudoPath;

/// A command with its arguments.
pub const CommandAndArguments = struct {
    /// The command path (absolute or relative)
    command: SudoPath,

    /// Command arguments (not including the command itself)
    arguments: []const []const u8,

    /// Allocator used for arguments
    allocator: ?Allocator,

    const Self = @This();

    /// Parse command and arguments from a slice.
    pub fn parse(allocator: Allocator, args: []const []const u8) !Self {
        if (args.len == 0) {
            return error.InvalidArgument;
        }

        const cmd_path = try SudoPath.init(args[0]);

        // Copy arguments
        const arguments = if (args.len > 1)
            try allocator.dupe([]const u8, args[1..])
        else
            &[_][]const u8{};

        return .{
            .command = cmd_path,
            .arguments = arguments,
            .allocator = allocator,
        };
    }

    /// Create from a pre-validated path and arguments.
    pub fn init(command: SudoPath, arguments: []const []const u8) Self {
        return .{
            .command = command,
            .arguments = arguments,
            .allocator = null,
        };
    }

    /// Free allocated resources.
    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.arguments);
        }
    }
};

// ============================================
// Tests
// ============================================

test "CommandAndArguments parse" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var cmd = try CommandAndArguments.parse(allocator, &.{ "/bin/ls", "-la", "/tmp" });
    defer cmd.deinit();

    try testing.expectEqualStrings("/bin/ls", cmd.command.slice());
    try testing.expectEqual(@as(usize, 2), cmd.arguments.len);
    try testing.expectEqualStrings("-la", cmd.arguments[0]);
    try testing.expectEqualStrings("/tmp", cmd.arguments[1]);
}
