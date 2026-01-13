//! visudo command implementation
//!
//! Safely edit sudoers files with syntax checking.

const std = @import("std");
const posix = std.posix;
const root = @import("../root.zig");
const log = @import("../log/mod.zig");
const sudoers = @import("../sudoers/mod.zig");
const system = @import("../system/mod.zig");

const version = root.version;

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/file.h");
    @cInclude("stdlib.h");
    @cInclude("signal.h");
    @cInclude("stdio.h");
});

/// Parsed visudo action
pub const Action = union(enum) {
    help: void,
    version: void,
    edit: EditOptions,
    check: CheckOptions,
};

pub const EditOptions = struct {
    file: ?[]const u8 = null,
    strict: bool = false,
    quiet: bool = false,
    no_includes: bool = false,
};

pub const CheckOptions = struct {
    file: ?[]const u8 = null,
    strict: bool = false,
    quiet: bool = false,
};

/// User prompt responses
const WhatNowResponse = enum {
    edit_again,
    exit_without_saving,
    quit_and_save,
};

/// Main entry point for visudo
pub fn main() void {
    process() catch |err| {
        log.userError("error: {}", .{err});
        std.process.exit(1);
    };
}

fn process() !void {
    log.SudoLogger.init("visudo: ").intoGlobalLogger();

    const action = try parseArgs();

    switch (action) {
        .help => printHelp(),
        .version => printVersion(),
        .edit => |opts| try edit(opts),
        .check => |opts| try check(opts),
    }
}

fn edit(options: EditOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const sudoers_path = options.file orelse root.platform.sudoers_path;

    // Must be root to edit sudoers
    if (system.User.effectiveUid() != 0) {
        log.userError("visudo: must be run as root", .{});
        return error.PermissionDenied;
    }

    // Open and lock the sudoers file
    const sudoers_fd = posix.open(sudoers_path, .{ .ACCMODE = .RDWR, .CREAT = true }, 0o440) catch |err| {
        log.userError("unable to open {s}: {}", .{ sudoers_path, err });
        return error.OpenFailed;
    };
    defer posix.close(sudoers_fd);

    // Lock the file exclusively
    if (c.flock(sudoers_fd, c.LOCK_EX | c.LOCK_NB) != 0) {
        log.userError("{s} is busy, try again later", .{sudoers_path});
        return error.FileLocked;
    }
    defer _ = c.flock(sudoers_fd, c.LOCK_UN);

    // Create temporary file
    var temp_path_buf: [256]u8 = undefined;
    const temp_path = std.fmt.bufPrint(&temp_path_buf, "{s}.tmp.{d}", .{ sudoers_path, c.getpid() }) catch {
        return error.PathTooLong;
    };
    temp_path_buf[temp_path.len] = 0;

    // Copy sudoers to temp file
    try copyFile(sudoers_fd, temp_path);
    defer posix.unlink(temp_path_buf[0..temp_path.len :0]) catch {};

    // Set secure permissions on temp file
    _ = c.chmod(temp_path_buf[0..temp_path.len :0].ptr, 0o600);

    // Get editor
    const editor = getEditor();

    // Edit loop
    while (true) {
        // Launch editor
        try launchEditor(allocator, editor, temp_path);

        // Validate syntax
        var parsed = sudoers.parseFile(allocator, temp_path) catch |err| {
            if (!options.quiet) {
                log.userError("{s}: parse error: {}", .{ temp_path, err });
            }

            // Prompt user for action
            const response = whatNowPrompt() catch .exit_without_saving;
            switch (response) {
                .edit_again => continue,
                .exit_without_saving => {
                    if (!options.quiet) {
                        var buf: [64]u8 = undefined;
                        const msg = std.fmt.bufPrint(&buf, "sudoers file unchanged\n", .{}) catch return;
                        _ = posix.write(posix.STDOUT_FILENO, msg) catch {};
                    }
                    return;
                },
                .quit_and_save => break,
            }
        };
        defer parsed.deinit();

        // Check for strict mode errors
        if (options.strict) {
            // Additional strict checks could go here
        }

        // Parsing succeeded
        if (!options.quiet) {
            var buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "{s}: parsed OK\n", .{temp_path}) catch break;
            _ = posix.write(posix.STDOUT_FILENO, msg) catch {};
        }
        break;
    }

    // Install the new sudoers file
    try installSudoers(temp_path, sudoers_path, options);

    if (!options.quiet) {
        _ = posix.write(posix.STDOUT_FILENO, "sudoers file updated\n") catch {};
    }
}

fn check(options: CheckOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file_path = options.file orelse root.platform.sudoers_path;

    // Check file exists and has correct permissions
    const file_stat = std.fs.cwd().statFile(file_path) catch |err| {
        if (!options.quiet) {
            log.userError("unable to stat {s}: {}", .{ file_path, err });
        }
        std.process.exit(1);
    };

    // Check ownership and permissions (should be root:root, mode 0440 or 0400)
    if (options.strict) {
        if (file_stat.mode & 0o077 != 0) {
            if (!options.quiet) {
                log.userError("{s}: bad permissions, should be mode 0440", .{file_path});
            }
            std.process.exit(1);
        }
    }

    // Parse the file
    var parsed = sudoers.parseFile(allocator, file_path) catch |err| {
        if (!options.quiet) {
            log.userError("{s}: parse error: {}", .{ file_path, err });
        }
        std.process.exit(1);
    };
    defer parsed.deinit();

    // Report success
    if (!options.quiet) {
        var buf: [256]u8 = undefined;

        var msg = std.fmt.bufPrint(&buf, "{s}: parsed OK\n", .{file_path}) catch return;
        _ = posix.write(posix.STDOUT_FILENO, msg) catch {};

        // Print summary
        msg = std.fmt.bufPrint(&buf, "  {d} user specifications\n", .{parsed.user_specs.items.len}) catch return;
        _ = posix.write(posix.STDOUT_FILENO, msg) catch {};

        msg = std.fmt.bufPrint(&buf, "  {d} defaults entries\n", .{parsed.defaults.items.len}) catch return;
        _ = posix.write(posix.STDOUT_FILENO, msg) catch {};

        const alias_count = parsed.aliases.user.count() +
            parsed.aliases.host.count() +
            parsed.aliases.cmnd.count() +
            parsed.aliases.runas.count();
        if (alias_count > 0) {
            msg = std.fmt.bufPrint(&buf, "  {d} aliases defined\n", .{alias_count}) catch return;
            _ = posix.write(posix.STDOUT_FILENO, msg) catch {};
        }
    }
}

fn copyFile(src_fd: posix.fd_t, dest_path: []const u8) !void {
    // Create null-terminated path
    var path_buf: [256:0]u8 = undefined;
    if (dest_path.len >= path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..dest_path.len], dest_path);
    path_buf[dest_path.len] = 0;

    // Create destination file
    const dest_fd = posix.open(path_buf[0..dest_path.len :0], .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o600) catch return error.CreateFailed;
    defer posix.close(dest_fd);

    // Seek to beginning of source
    _ = c.lseek(src_fd, 0, c.SEEK_SET);

    // Copy contents
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(src_fd, &buf) catch break;
        if (n == 0) break;
        _ = posix.write(dest_fd, buf[0..n]) catch return error.WriteFailed;
    }
}

fn getEditor() []const u8 {
    // Check environment variables
    if (std.posix.getenv("SUDO_EDITOR")) |e| {
        if (e.len > 0) return e;
    }
    if (std.posix.getenv("VISUAL")) |e| {
        if (e.len > 0) return e;
    }
    if (std.posix.getenv("EDITOR")) |e| {
        if (e.len > 0) return e;
    }

    // Try common editors
    const editors = [_][]const u8{
        "/usr/bin/editor",
        "/usr/bin/nano",
        "/usr/bin/vim",
        "/usr/bin/vi",
        "/bin/vi",
    };

    for (editors) |ed| {
        if (std.fs.accessAbsolute(ed, .{})) {
            return ed;
        } else |_| {}
    }

    // Fallback
    return "/usr/bin/vi";
}

fn launchEditor(allocator: std.mem.Allocator, editor: []const u8, file_path: []const u8) !void {
    // Fork and exec editor
    const fork_result = try system.Process.fork();

    switch (fork_result) {
        .child => {
            // Build argv
            var argv_buf: [3][*:0]const u8 = undefined;
            var editor_buf: [256:0]u8 = undefined;
            var file_buf: [256:0]u8 = undefined;

            @memcpy(editor_buf[0..editor.len], editor);
            editor_buf[editor.len] = 0;
            argv_buf[0] = &editor_buf;

            @memcpy(file_buf[0..file_path.len], file_path);
            file_buf[file_path.len] = 0;
            argv_buf[1] = &file_buf;

            const argv: [*:null]const ?[*:0]const u8 = @ptrCast(&argv_buf);

            // Get current environment
            const env = std.c.environ;

            posix.execveZ(&editor_buf, argv, @ptrCast(env)) catch {};
            std.process.exit(127);
        },
        .parent => |child_pid| {
            _ = allocator;
            // Wait for editor to exit
            const result = try system.waitpid(child_pid, 0);
            if (result.ifExited()) |code| {
                if (code != 0) {
                    return error.EditorFailed;
                }
            } else {
                return error.EditorFailed;
            }
        },
    }
}

fn whatNowPrompt() !WhatNowResponse {
    _ = posix.write(posix.STDOUT_FILENO, "What now? ") catch {};

    var buf: [32]u8 = undefined;
    const n = posix.read(posix.STDIN_FILENO, &buf) catch return .exit_without_saving;
    if (n == 0) return .exit_without_saving;

    const response = std.mem.trim(u8, buf[0..n], " \t\n\r");
    if (response.len == 0) return .edit_again;

    return switch (response[0]) {
        'e', 'E' => .edit_again,
        'x', 'X' => .exit_without_saving,
        'Q' => .quit_and_save,
        else => blk: {
            _ = posix.write(posix.STDOUT_FILENO, "Options are:\n") catch {};
            _ = posix.write(posix.STDOUT_FILENO, "  (e)dit sudoers file again\n") catch {};
            _ = posix.write(posix.STDOUT_FILENO, "  e(x)it without saving changes\n") catch {};
            _ = posix.write(posix.STDOUT_FILENO, "  (Q)uit and save changes (DANGER!)\n") catch {};
            break :blk whatNowPrompt();
        },
    };
}

fn installSudoers(temp_path: []const u8, dest_path: []const u8, options: EditOptions) !void {
    _ = options;

    // Create null-terminated paths
    var temp_buf: [256:0]u8 = undefined;
    var dest_buf: [256:0]u8 = undefined;

    if (temp_path.len >= temp_buf.len) return error.PathTooLong;
    if (dest_path.len >= dest_buf.len) return error.PathTooLong;

    @memcpy(temp_buf[0..temp_path.len], temp_path);
    temp_buf[temp_path.len] = 0;

    @memcpy(dest_buf[0..dest_path.len], dest_path);
    dest_buf[dest_path.len] = 0;

    // Set correct ownership (root:root)
    if (c.chown(&temp_buf, 0, 0) != 0) {
        log.userError("failed to set ownership on {s}", .{temp_path});
        return error.ChownFailed;
    }

    // Set correct permissions (0440)
    if (c.chmod(&temp_buf, 0o440) != 0) {
        log.userError("failed to set permissions on {s}", .{temp_path});
        return error.ChmodFailed;
    }

    // Rename temp file to dest (atomic on same filesystem)
    if (c.rename(&temp_buf, &dest_buf) != 0) {
        // If rename fails (cross-device), fall back to copy
        const temp_fd = posix.open(temp_buf[0..temp_path.len :0], .{ .ACCMODE = .RDONLY }, 0) catch {
            return error.OpenFailed;
        };
        defer posix.close(temp_fd);

        const dest_fd = posix.open(dest_buf[0..dest_path.len :0], .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
        }, 0o440) catch {
            return error.CreateFailed;
        };
        defer posix.close(dest_fd);

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = posix.read(temp_fd, &buf) catch break;
            if (n == 0) break;
            _ = posix.write(dest_fd, buf[0..n]) catch return error.WriteFailed;
        }

        // Set ownership on dest
        if (c.fchown(dest_fd, 0, 0) != 0) {
            return error.ChownFailed;
        }
    }
}

fn parseArgs() !Action {
    var args = std.process.args();
    _ = args.skip();

    var edit_opts = EditOptions{};
    var is_check = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            return .version;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--check")) {
            is_check = true;
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
            edit_opts.file = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--strict")) {
            edit_opts.strict = true;
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            edit_opts.quiet = true;
        } else if (std.mem.eql(u8, arg, "-I") or std.mem.eql(u8, arg, "--no-includes")) {
            edit_opts.no_includes = true;
        }
    }

    if (is_check) {
        return .{ .check = .{
            .file = edit_opts.file,
            .strict = edit_opts.strict,
            .quiet = edit_opts.quiet,
        } };
    }

    return .{ .edit = edit_opts };
}

fn printHelp() void {
    const help_text =
        \\usage: visudo [-chqsV] [-f sudoers]
        \\
        \\Options:
        \\  -h, --help              display this help and exit
        \\  -V, --version           display version and exit
        \\  -c, --check             check-only mode
        \\  -f, --file=sudoers      specify sudoers file
        \\  -q, --quiet             quiet mode
        \\  -s, --strict            strict syntax checking
        \\  -I, --no-includes       don't edit include files
        \\
    ;
    _ = posix.write(posix.STDOUT_FILENO, help_text) catch return;
}

fn printVersion() void {
    var buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "visudo-zig {s}\n", .{version}) catch return;
    _ = posix.write(posix.STDOUT_FILENO, msg) catch return;
}
