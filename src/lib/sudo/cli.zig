//! Command-line argument parsing for sudo

const std = @import("std");

/// Parsed sudo action
pub const Action = union(enum) {
    help: void,
    version: void,
    run: RunOptions,
    edit: EditOptions,
    list: ListOptions,
    validate: void,
    remove_timestamp: void,
};

/// Options for running a command
pub const RunOptions = struct {
    target_user: ?[]const u8 = null,
    target_group: ?[]const u8 = null,
    working_dir: ?[]const u8 = null,
    login: bool = false,
    shell: bool = false,
    preserve_env: bool = false,
    stdin: bool = false,
    non_interactive: bool = false,
    bell: bool = false,
    reset_timestamp: bool = false,
    prompt: ?[]const u8 = null,
    command: []const []const u8 = &.{},
};

/// Options for editing files (sudoedit mode)
pub const EditOptions = struct {
    target_user: ?[]const u8 = null,
    target_group: ?[]const u8 = null,
    files: []const []const u8 = &.{},
    stdin: bool = false,
    non_interactive: bool = false,
    bell: bool = false,
    prompt: ?[]const u8 = null,
};

/// Options for listing privileges
pub const ListOptions = struct {
    other_user: ?[]const u8 = null,
    target_user: ?[]const u8 = null,
    target_group: ?[]const u8 = null,
    long_format: bool = false,
    command: []const []const u8 = &.{},
};

/// Check if invoked as sudoedit
fn isSudoedit() bool {
    var args = std.process.args();
    if (args.next()) |prog| {
        // Check if program name ends with "sudoedit"
        if (std.mem.endsWith(u8, prog, "sudoedit")) {
            return true;
        }
    }
    return false;
}

/// Parse command-line arguments
pub fn parseArgs() !Action {
    var args = std.process.args();
    const prog_name = args.next(); // get program name
    _ = prog_name;

    const is_sudoedit = isSudoedit();

    var options = RunOptions{};
    var edit_mode = is_sudoedit;
    var list_mode = false;
    var validate_mode = false;
    var remove_timestamp = false;
    var list_opts = ListOptions{};

    // Use a fixed-size buffer for positional args
    var positional_buf: [64][]const u8 = undefined;
    var positional_count: usize = 0;

    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                return .help;
            } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
                return .version;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--edit")) {
                edit_mode = true;
            } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
                list_mode = true;
            } else if (std.mem.eql(u8, arg, "-ll")) {
                list_mode = true;
                list_opts.long_format = true;
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--validate")) {
                validate_mode = true;
            } else if (std.mem.eql(u8, arg, "-K") or std.mem.eql(u8, arg, "--remove-timestamp")) {
                remove_timestamp = true;
            } else if (std.mem.eql(u8, arg, "-U") or std.mem.eql(u8, arg, "--other-user")) {
                list_opts.other_user = args.next() orelse return error.MissingArgument;
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
                const user = args.next() orelse return error.MissingArgument;
                options.target_user = user;
                list_opts.target_user = user;
            } else if (std.mem.eql(u8, arg, "-g") or std.mem.eql(u8, arg, "--group")) {
                const group = args.next() orelse return error.MissingArgument;
                options.target_group = group;
                list_opts.target_group = group;
            } else if (std.mem.eql(u8, arg, "-D") or std.mem.eql(u8, arg, "--chdir")) {
                options.working_dir = args.next() orelse return error.MissingArgument;
            } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--login")) {
                options.login = true;
            } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--shell")) {
                options.shell = true;
            } else if (std.mem.eql(u8, arg, "-S") or std.mem.eql(u8, arg, "--stdin")) {
                options.stdin = true;
            } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--non-interactive")) {
                options.non_interactive = true;
            } else if (std.mem.eql(u8, arg, "-B") or std.mem.eql(u8, arg, "--bell")) {
                options.bell = true;
            } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--reset-timestamp")) {
                options.reset_timestamp = true;
            } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--prompt")) {
                options.prompt = args.next() orelse return error.MissingArgument;
            } else if (std.mem.eql(u8, arg, "-E") or std.mem.eql(u8, arg, "--preserve-env")) {
                options.preserve_env = true;
            } else if (std.mem.eql(u8, arg, "--")) {
                // Rest are positional
                while (args.next()) |pos| {
                    if (positional_count >= positional_buf.len) return error.TooManyArguments;
                    positional_buf[positional_count] = pos;
                    positional_count += 1;
                }
                break;
            } else {
                return error.UnknownOption;
            }
        } else {
            if (positional_count >= positional_buf.len) return error.TooManyArguments;
            positional_buf[positional_count] = arg;
            positional_count += 1;
            // Rest are command arguments
            while (args.next()) |pos| {
                if (positional_count >= positional_buf.len) return error.TooManyArguments;
                positional_buf[positional_count] = pos;
                positional_count += 1;
            }
            break;
        }
    }

    // Handle special modes
    if (remove_timestamp) {
        return .remove_timestamp;
    }

    if (validate_mode) {
        return .validate;
    }

    if (list_mode) {
        list_opts.command = positional_buf[0..positional_count];
        return .{ .list = list_opts };
    }

    if (edit_mode) {
        return .{ .edit = .{
            .target_user = options.target_user,
            .target_group = options.target_group,
            .files = positional_buf[0..positional_count],
            .stdin = options.stdin,
            .non_interactive = options.non_interactive,
            .bell = options.bell,
            .prompt = options.prompt,
        } };
    }

    options.command = positional_buf[0..positional_count];
    return .{ .run = options };
}

test "parseArgs help" {
    // Note: Can't easily test parseArgs without mocking std.process.args
}
