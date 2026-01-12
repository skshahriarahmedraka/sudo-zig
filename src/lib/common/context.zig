//! Execution context for sudo operations
//!
//! Contains all the information needed to execute a command,
//! including user info, target user, command, and environment.

const std = @import("std");
const Allocator = std.mem.Allocator;

const path_mod = @import("path.zig");
const string_mod = @import("string.zig");
const command_mod = @import("command.zig");

pub const SudoPath = path_mod.SudoPath;
pub const SudoString = string_mod.SudoString;
pub const CommandAndArguments = command_mod.CommandAndArguments;

/// Execution context containing all information for a sudo operation.
pub const Context = struct {
    allocator: Allocator,

    /// Current (invoking) user information
    current_user: UserInfo,

    /// Target user to run command as
    target_user: UserInfo,

    /// Target group (if explicitly specified)
    target_group: ?GroupInfo,

    /// Command and arguments to execute
    command: CommandAndArguments,

    /// Working directory (if --chdir specified)
    working_dir: ?SudoPath,

    /// Environment variables for the command
    environment: std.StringHashMap([]const u8),

    /// Hostname of the current machine
    hostname: []const u8,

    /// Process information
    process: ProcessInfo,

    /// Runtime options
    options: Options,

    const Self = @This();

    pub const UserInfo = struct {
        uid: u32,
        gid: u32,
        name: []const u8,
        home: []const u8,
        shell: []const u8,
        groups: []u32,
    };

    pub const GroupInfo = struct {
        gid: u32,
        name: []const u8,
    };

    pub const ProcessInfo = struct {
        pid: i32,
        ppid: i32,
        sid: i32,
        tty: ?[]const u8,
    };

    pub const Options = struct {
        login_shell: bool = false,
        preserve_env: bool = false,
        use_stdin: bool = false,
        non_interactive: bool = false,
        bell: bool = false,
        reset_timestamp: bool = false,
        use_pty: bool = true,
    };

    /// Clean up allocated resources.
    pub fn deinit(self: *Self) void {
        self.environment.deinit();
    }
};
