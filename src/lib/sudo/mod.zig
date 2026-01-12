//! sudo command implementation
//!
//! Main entry point and logic for the sudo command.

const std = @import("std");
const root = @import("../root.zig");
const log = @import("../log/mod.zig");
const system = @import("../system/mod.zig");
const common = @import("../common/mod.zig");
const sudoers = @import("../sudoers/mod.zig");
const exec = @import("../exec/mod.zig");
const defaults = @import("../defaults/mod.zig");
const pam = @import("../pam/mod.zig");
const build_options = @import("build_options");

pub const cli = @import("cli.zig");
pub const lecture = @import("lecture.zig");

const version = root.version;

/// Main entry point for sudo
pub fn main() void {
    process() catch |err| {
        log.userError("error: {}", .{err});
        std.process.exit(1);
    };
}

fn process() !void {
    // Initialize logger
    log.SudoLogger.init("sudo: ").intoGlobalLogger();

    // Parse command line first (so --help and --version work without root)
    const action = try cli.parseArgs();

    switch (action) {
        .help => {
            printHelp();
            return;
        },
        .version => {
            printVersion();
            return;
        },
        .run => |opts| {
            // Self-check: must be running as root (setuid)
            try selfCheck();
            try run(opts);
        },
        .edit => |opts| {
            // Self-check: must be running as root (setuid)
            try selfCheck();
            try runEdit(opts);
        },
        .list => |opts| {
            try selfCheck();
            try runList(opts);
        },
        .validate => {
            try selfCheck();
            try runValidate();
        },
        .remove_timestamp => {
            // Remove timestamp doesn't require root
            const real_uid = system.User.realUid();
            if (system.User.fromUid(real_uid)) |current_user| {
                system.removeCredentials(current_user.name, current_user.uid);
            }
        },
    }
}

fn selfCheck() !void {
    const euid = system.User.effectiveUid();
    if (euid != 0) {
        log.userError("sudo must be owned by uid 0 and have the setuid bit set", .{});
        return error.SelfCheck;
    }
}

fn run(options: cli.RunOptions) !void {
    // Get page allocator for this operation
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Get current user info
    const real_uid = system.User.realUid();
    const current_user = system.User.fromUid(real_uid) orelse {
        log.userError("unknown uid: {d}", .{real_uid});
        return error.UserNotFound;
    };

    // Get user's groups
    var groups_buf: [system.user.MAX_GROUPS]system.GroupId = undefined;
    const user_groups = current_user.getGroups(&groups_buf) catch &[_]system.GroupId{current_user.gid};

    // 2. Get hostname
    const hostname = system.Hostname.get() catch |err| {
        log.userError("cannot get hostname: {}", .{err});
        return error.SystemError;
    };

    // 3. Check if we have a command to run
    if (options.command.len == 0) {
        if (options.shell or options.login) {
            // Run shell as target user
            return runShell(allocator, options, &current_user, user_groups, hostname.slice());
        }
        log.userError("no command specified", .{});
        return error.NoCommand;
    }

    // 4. Resolve command path
    const command_path = try resolveCommand(allocator, options.command[0]);
    defer if (command_path.ptr != options.command[0].ptr) allocator.free(command_path);

    // 5. Build arguments string for policy check
    const args_string = if (options.command.len > 1)
        try joinArgs(allocator, options.command[1..])
    else
        null;
    defer if (args_string) |s| allocator.free(s);

    // 6. Parse sudoers and check authorization
    const auth = try checkAuthorization(
        allocator,
        &current_user,
        user_groups,
        hostname.slice(),
        command_path,
        args_string,
        options.target_user,
        options.target_group,
    );

    if (!auth.allowed) {
        log.userError("{s} is not allowed to run '{s}' as {s}", .{
            current_user.name,
            command_path,
            options.target_user orelse "root",
        });
        // Log to syslog would happen here
        return error.NotAllowed;
    }

    // 7. Authenticate if required
    const settings = defaults.Settings{};
    if (auth.must_authenticate and !options.non_interactive) {
        try authenticate(&current_user, options, &settings);
    } else if (auth.must_authenticate and options.non_interactive) {
        log.userError("a password is required", .{});
        return error.AuthenticationRequired;
    }

    // 8. Resolve target user/group
    const target_user = resolveTargetUser(options.target_user) orelse {
        log.userError("unknown user: {s}", .{options.target_user orelse "root"});
        return error.UserNotFound;
    };

    const target_gid = if (options.target_group) |g|
        (system.Group.fromName(g) orelse {
            log.userError("unknown group: {s}", .{g});
            return error.GroupNotFound;
        }).gid
    else
        target_user.gid;

    // 9. Execute command
    const run_options = exec.RunOptions{
        .command = command_path,
        .arguments = options.command,
        .uid = target_user.uid,
        .gid = target_gid,
        .cwd = options.working_dir,
        .use_pty = !options.stdin, // Use PTY unless reading password from stdin
        .noexec = auth.flags.noexec,
    };

    // Build environment
    var env = std.StringHashMap([]const u8).init(allocator);
    defer env.deinit();
    try buildEnvironment(&env, &current_user, &target_user, options);

    const exit_reason = try exec.runCommand(run_options, env);

    // Exit with same status as command
    std.process.exit(exit_reason.toExitCode());
}

fn runShell(
    allocator: std.mem.Allocator,
    options: cli.RunOptions,
    current_user: *const system.User,
    user_groups: []const system.GroupId,
    hostname: []const u8,
) !void {
    // Get target user's shell
    const target_user = resolveTargetUser(options.target_user) orelse {
        log.userError("unknown user: {s}", .{options.target_user orelse "root"});
        return error.UserNotFound;
    };

    const shell = if (target_user.shell.len > 0) target_user.shell else "/bin/sh";

    // Check authorization for shell
    const auth = try checkAuthorization(
        allocator,
        current_user,
        user_groups,
        hostname,
        shell,
        null,
        options.target_user,
        options.target_group,
    );

    if (!auth.allowed) {
        log.userError("{s} is not allowed to run a shell as {s}", .{
            current_user.name,
            options.target_user orelse "root",
        });
        return error.NotAllowed;
    }

    // Authenticate if required
    const settings = defaults.Settings{};
    if (auth.must_authenticate and !options.non_interactive) {
        try authenticate(current_user, options, &settings);
    } else if (auth.must_authenticate and options.non_interactive) {
        log.userError("a password is required", .{});
        return error.AuthenticationRequired;
    }

    const target_gid = if (options.target_group) |g|
        (system.Group.fromName(g) orelse return error.GroupNotFound).gid
    else
        target_user.gid;

    // Build shell arguments
    var shell_args: [2][]const u8 = undefined;
    shell_args[0] = shell;
    const arg_count: usize = if (options.login) blk: {
        shell_args[1] = "-l";
        break :blk 2;
    } else 1;

    const run_options = exec.RunOptions{
        .command = shell,
        .arguments = shell_args[0..arg_count],
        .uid = target_user.uid,
        .gid = target_gid,
        .cwd = if (options.login) target_user.home else options.working_dir,
        .use_pty = true,
        .noexec = false,
    };

    var env = std.StringHashMap([]const u8).init(allocator);
    defer env.deinit();
    try buildEnvironment(&env, current_user, &target_user, options);

    const exit_reason = try exec.runCommand(run_options, env);
    std.process.exit(exit_reason.toExitCode());
}

fn checkAuthorization(
    allocator: std.mem.Allocator,
    current_user: *const system.User,
    user_groups: []const system.GroupId,
    hostname: []const u8,
    command: []const u8,
    arguments: ?[]const u8,
    target_user: ?[]const u8,
    target_group: ?[]const u8,
) !sudoers.Authorization {
    // Parse sudoers file
    const sudoers_path = root.platform.sudoers_path;

    var parsed = sudoers.parse(allocator, sudoers_path) catch |err| {
        log.userError("error parsing {s}: {}", .{ sudoers_path, err });
        return error.Configuration;
    };
    defer parsed.deinit();

    // Create policy and check
    var policy = sudoers.Policy.init(allocator, &parsed);

    const request = sudoers.AuthRequest{
        .user = current_user.*,
        .groups = user_groups,
        .hostname = hostname,
        .command = command,
        .arguments = arguments,
        .target_user = target_user,
        .target_group = target_group,
    };

    return policy.check(request);
}

fn authenticate(current_user: *const system.User, options: cli.RunOptions, settings: *const defaults.Settings) !void {
    // Check for cached credentials first (unless -k flag is set)
    if (!options.reset_timestamp) {
        if (system.checkCredentials(current_user.name, current_user.uid, settings.timestamp_timeout)) {
            log.debug("using cached credentials", .{});
            return;
        }
    } else {
        // Reset timestamp if -k flag is set
        system.resetCredentials(current_user.name, current_user.uid) catch {};
    }

    // Get TTY name for PAM
    var tty_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tty_name: ?[]const u8 = blk: {
        const tty_link = std.fs.readLinkAbsolute("/proc/self/fd/0", &tty_buf) catch break :blk null;
        break :blk tty_link;
    };

    // Build password prompt
    var prompt_buf: [128]u8 = undefined;
    const prompt = if (options.prompt) |p|
        p
    else
        std.fmt.bufPrint(&prompt_buf, "[sudo] password for {s}: ", .{current_user.name}) catch "Password: ";

    // Attempt authentication with retries
    var attempts: u32 = 0;
    const max_attempts = settings.passwd_tries;

    while (attempts < max_attempts) : (attempts += 1) {
        if (build_options.enable_pam) {
            // Use PAM authentication
            pam.authenticateUser(.{
                .service = if (build_options.pam_login and options.login) "sudo-i" else "sudo",
                .username = current_user.name,
                .requesting_user = current_user.name,
                .tty = tty_name,
                .use_stdin = options.stdin,
                .show_asterisks = settings.pwfeedback,
                .prompt = prompt,
                .non_interactive = options.non_interactive,
            }) catch |err| {
                switch (err) {
                    error.AuthenticationFailed => {
                        log.userError("Sorry, try again.", .{});
                        continue;
                    },
                    error.MaxAuthAttempts => {
                        log.userError("sudo: {d} incorrect password attempts", .{attempts + 1});
                        return error.AuthenticationFailed;
                    },
                    error.PamNotEnabled => {
                        // Fall through to simple authentication
                        break;
                    },
                    else => return err,
                }
            };

            // Authentication succeeded
            system.updateCredentials(current_user.name, current_user.uid) catch {};
            return;
        } else {
            // Simple password prompt without PAM (for testing/development)
            const password = pam.readPassword(prompt, options.stdin, settings.pwfeedback, options.bell) catch {
                return error.AuthenticationFailed;
            };
            _ = password;
            // Without PAM, we can't actually verify the password
            // This is just for development/testing
            log.debug("PAM not enabled - authentication bypassed", .{});
            system.updateCredentials(current_user.name, current_user.uid) catch {};
            return;
        }
    }

    log.userError("sudo: {d} incorrect password attempts", .{max_attempts});
    return error.AuthenticationFailed;
}

fn resolveCommand(allocator: std.mem.Allocator, command: []const u8) ![]const u8 {
    // If command is absolute path, use it directly
    if (command.len > 0 and command[0] == '/') {
        return command;
    }

    // Search in PATH
    const path_env = std.posix.getenv("PATH") orelse "/usr/local/bin:/usr/bin:/bin";

    var path_iter = std.mem.splitScalar(u8, path_env, ':');
    while (path_iter.next()) |dir| {
        const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, command });

        // Check if file exists and is executable
        const file = std.fs.openFileAbsolute(full_path, .{}) catch {
            allocator.free(full_path);
            continue;
        };
        file.close();

        // Check if executable (simplified - just check it exists for now)
        return full_path;
    }

    log.userError("command not found: {s}", .{command});
    return error.CommandNotFound;
}

fn resolveTargetUser(target: ?[]const u8) ?system.User {
    const username = target orelse "root";
    return system.User.fromName(username);
}

fn joinArgs(allocator: std.mem.Allocator, args: []const []const u8) ![]const u8 {
    if (args.len == 0) return "";

    var total_len: usize = 0;
    for (args) |arg| {
        total_len += arg.len + 1; // +1 for space
    }

    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    for (args, 0..) |arg, i| {
        @memcpy(result[pos .. pos + arg.len], arg);
        pos += arg.len;
        if (i < args.len - 1) {
            result[pos] = ' ';
            pos += 1;
        }
    }

    return result[0..pos];
}

fn buildEnvironment(
    env: *std.StringHashMap([]const u8),
    current_user: *const system.User,
    target_user: *const system.User,
    options: cli.RunOptions,
) !void {
    _ = current_user;
    
    // Set basic environment variables
    try env.put("HOME", target_user.home);
    try env.put("SHELL", if (target_user.shell.len > 0) target_user.shell else "/bin/sh");
    try env.put("USER", target_user.name);
    try env.put("LOGNAME", target_user.name);

    // Set PATH (use secure_path if configured, otherwise default)
    const settings = defaults.Settings{};
    if (settings.secure_path) |sp| {
        try env.put("PATH", sp);
    } else {
        try env.put("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }

    // Preserve TERM
    if (std.posix.getenv("TERM")) |term| {
        try env.put("TERM", term);
    }

    // Handle -E (preserve environment)
    if (options.preserve_env) {
        // Copy relevant environment variables
        // This is a simplified version - full implementation would check env_keep
        const preserve_vars = [_][]const u8{ "DISPLAY", "XAUTHORITY", "LANG", "LC_ALL" };
        for (preserve_vars) |varname| {
            if (std.posix.getenv(varname)) |value| {
                try env.put(varname, value);
            }
        }
    }
}

/// Run sudoedit mode - safely edit files as another user
fn runEdit(options: cli.EditOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Check we have files to edit
    if (options.files.len == 0) {
        log.userError("no files specified", .{});
        return error.NoFilesSpecified;
    }

    // Get current user info
    const real_uid = system.User.realUid();
    const current_user = system.User.fromUid(real_uid) orelse {
        log.userError("unknown uid: {d}", .{real_uid});
        return error.UserNotFound;
    };

    // Get user's groups
    var groups_buf: [system.user.MAX_GROUPS]system.GroupId = undefined;
    const user_groups = current_user.getGroups(&groups_buf) catch &[_]system.GroupId{current_user.gid};

    // Get hostname
    const hostname = system.Hostname.get() catch |err| {
        log.userError("cannot get hostname: {}", .{err});
        return error.SystemError;
    };

    // Resolve target user (default: root)
    const target_user = resolveTargetUser(options.target_user) orelse {
        log.userError("unknown user: {s}", .{options.target_user orelse "root"});
        return error.UserNotFound;
    };

    // Check authorization for sudoedit on each file
    for (options.files) |file| {
        const auth = try checkAuthorization(
            allocator,
            &current_user,
            user_groups,
            hostname.slice(),
            "sudoedit",
            file,
            options.target_user,
            options.target_group,
        );

        if (!auth.allowed) {
            log.userError("{s} is not allowed to edit {s} as {s}", .{
                current_user.name,
                file,
                options.target_user orelse "root",
            });
            return error.NotAllowed;
        }
    }

    // Authenticate if required
    const settings = defaults.Settings{};
    // Note: sudoedit typically requires authentication
    if (!options.non_interactive) {
        try authenticate(&current_user, .{
            .stdin = options.stdin,
            .non_interactive = options.non_interactive,
            .bell = options.bell,
            .prompt = options.prompt,
        }, &settings);
    }

    // Get editor
    const editor = getEditor();

    // Create temporary copies of files owned by the invoking user
    var temp_files: [64]TempFile = undefined;
    var temp_count: usize = 0;
    defer {
        for (temp_files[0..temp_count]) |*tf| {
            tf.cleanup();
        }
    }

    for (options.files) |file| {
        if (temp_count >= temp_files.len) break;
        temp_files[temp_count] = TempFile.create(allocator, file, real_uid, current_user.gid) catch |err| {
            log.userError("failed to create temp file for {s}: {}", .{ file, err });
            return error.TempFileFailed;
        };
        temp_count += 1;
    }

    // Drop privileges to invoking user for editing
    try system.Process.setEuid(real_uid);

    // Launch editor with temp files
    launchEditorMultiple(allocator, editor, temp_files[0..temp_count]) catch |err| {
        // Re-acquire root privileges before returning
        system.Process.setEuid(0) catch {};
        log.userError("editor failed: {}", .{err});
        return error.EditorFailed;
    };

    // Re-acquire root privileges
    try system.Process.setEuid(0);

    // Copy modified temp files back to originals
    for (temp_files[0..temp_count]) |*tf| {
        tf.copyBack(target_user.uid, target_user.gid) catch |err| {
            log.userError("failed to copy back {s}: {}", .{ tf.original_path, err });
        };
    }
}

/// Temporary file for sudoedit
const TempFile = struct {
    original_path: []const u8,
    temp_path: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    fn create(allocator: std.mem.Allocator, original: []const u8, uid: system.UserId, gid: system.GroupId) !Self {
        // Generate temp path
        const temp_path = try std.fmt.allocPrint(allocator, "/tmp/sudoedit-{d}-{s}", .{
            std.posix.system.getpid(),
            std.fs.path.basename(original),
        });
        errdefer allocator.free(temp_path);

        // Copy original to temp
        const src_file = std.fs.openFileAbsolute(original, .{}) catch |err| {
            if (err == error.FileNotFound) {
                // Create empty temp file for new files
                const dest = try std.fs.createFileAbsolute(temp_path, .{ .mode = 0o600 });
                dest.close();
                
                // Change ownership to invoking user
                var path_buf: [256:0]u8 = undefined;
                @memcpy(path_buf[0..temp_path.len], temp_path);
                path_buf[temp_path.len] = 0;

                const c_inner = @cImport({
                    @cInclude("unistd.h");
                });
                _ = c_inner.chown(&path_buf, uid, gid);

                return .{
                    .original_path = original,
                    .temp_path = temp_path,
                    .allocator = allocator,
                };
            } else {
                return err;
            }
        };
        defer src_file.close();

        const dest = try std.fs.createFileAbsolute(temp_path, .{ .mode = 0o600 });
        defer dest.close();

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = src_file.read(&buf) catch break;
            if (n == 0) break;
            dest.writeAll(buf[0..n]) catch break;
        }

        // Change ownership to invoking user
        var path_buf: [256:0]u8 = undefined;
        @memcpy(path_buf[0..temp_path.len], temp_path);
        path_buf[temp_path.len] = 0;

        const c_chown = @cImport({
            @cInclude("unistd.h");
        });
        _ = c_chown.chown(&path_buf, uid, gid);

        return .{
            .original_path = original,
            .temp_path = temp_path,
            .allocator = allocator,
        };
    }

    fn copyBack(self: *Self, uid: system.UserId, gid: system.GroupId) !void {
        // Copy temp back to original
        const src = try std.fs.openFileAbsolute(self.temp_path, .{});
        defer src.close();

        const dest = try std.fs.createFileAbsolute(self.original_path, .{ .mode = 0o644 });
        defer dest.close();

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = src.read(&buf) catch break;
            if (n == 0) break;
            dest.writeAll(buf[0..n]) catch break;
        }

        // Set ownership on original
        var path_buf: [256:0]u8 = undefined;
        @memcpy(path_buf[0..self.original_path.len], self.original_path);
        path_buf[self.original_path.len] = 0;

        const c = @cImport({
            @cInclude("unistd.h");
        });
        _ = c.chown(&path_buf, uid, gid);
    }

    fn cleanup(self: *Self) void {
        std.fs.deleteFileAbsolute(self.temp_path) catch {};
        self.allocator.free(self.temp_path);
    }
};

fn getEditor() []const u8 {
    if (std.posix.getenv("SUDO_EDITOR")) |e| {
        if (e.len > 0) return e;
    }
    if (std.posix.getenv("VISUAL")) |e| {
        if (e.len > 0) return e;
    }
    if (std.posix.getenv("EDITOR")) |e| {
        if (e.len > 0) return e;
    }
    return "/usr/bin/vi";
}

fn launchEditorMultiple(allocator: std.mem.Allocator, editor: []const u8, temp_files: []TempFile) !void {
    const fork_result = try system.Process.fork();

    switch (fork_result) {
        .child => {
            // Build argv: editor file1 file2 ...
            var argv_buf: [66][*:0]const u8 = undefined;
            var string_bufs: [66][512:0]u8 = undefined;

            @memcpy(string_bufs[0][0..editor.len], editor);
            string_bufs[0][editor.len] = 0;
            argv_buf[0] = &string_bufs[0];

            var argc: usize = 1;
            for (temp_files) |tf| {
                if (argc >= argv_buf.len - 1) break;
                @memcpy(string_bufs[argc][0..tf.temp_path.len], tf.temp_path);
                string_bufs[argc][tf.temp_path.len] = 0;
                argv_buf[argc] = &string_bufs[argc];
                argc += 1;
            }

            const argv: [*:null]const ?[*:0]const u8 = @ptrCast(argv_buf[0..argc].ptr);
            const env = std.c.environ;

            std.posix.execveZ(&string_bufs[0], argv, @ptrCast(env)) catch {};
            std.process.exit(127);
        },
        .parent => |child_pid| {
            _ = allocator;
            const result = try system.waitpid(child_pid, 0);
            if (result.ifExited()) |code| {
                if (code != 0) return error.EditorFailed;
            } else {
                return error.EditorFailed;
            }
        },
    }
}

/// Run list mode - show user's privileges
fn runList(options: cli.ListOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get current user info
    const real_uid = system.User.realUid();
    const current_user = system.User.fromUid(real_uid) orelse {
        log.userError("unknown uid: {d}", .{real_uid});
        return error.UserNotFound;
    };

    // Determine which user to list privileges for
    const list_user_name = options.other_user orelse current_user.name;
    const list_user = system.User.fromName(list_user_name) orelse {
        log.userError("unknown user: {s}", .{list_user_name});
        return error.UserNotFound;
    };

    // Parse sudoers
    const sudoers_path = root.platform.sudoers_path;
    var parsed = sudoers.parse(allocator, sudoers_path) catch |err| {
        log.userError("error parsing {s}: {}", .{ sudoers_path, err });
        return error.Configuration;
    };
    defer parsed.deinit();

    // Print user's privileges
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "User {s} may run the following commands:\n", .{list_user.name}) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch {};

    // List matching rules (simplified - full implementation would expand aliases)
    for (parsed.user_specs.items) |user_spec| {
        // Check if this spec applies to the user
        for (user_spec.host_specs.items) |host_spec| {
            for (host_spec.cmnd_specs.items) |cmnd_spec| {
                // Print each command spec
                for (cmnd_spec.commands.items.items) |cmd_item| {
                    var cmd_buf: [512]u8 = undefined;
                    const cmd_msg = switch (cmd_item.value) {
                        .all => std.fmt.bufPrint(&cmd_buf, "    (ALL) ALL\n", .{}) catch continue,
                        .command => |cmd| std.fmt.bufPrint(&cmd_buf, "    {s}\n", .{cmd.path}) catch continue,
                        else => continue,
                    };
                    _ = std.posix.write(std.posix.STDOUT_FILENO, cmd_msg) catch {};
                }
            }
        }
    }

    // Handle command check if provided
    if (options.command.len > 0) {
        // Could check if specific command is allowed
    }
}

/// Run validate mode - just check credentials
fn runValidate() !void {
    // Get current user info
    const real_uid = system.User.realUid();
    const current_user = system.User.fromUid(real_uid) orelse {
        log.userError("unknown uid: {d}", .{real_uid});
        return error.UserNotFound;
    };

    const settings = defaults.Settings{};

    // Authenticate
    try authenticate(&current_user, .{}, &settings);

    // Update timestamp
    system.updateCredentials(current_user.name, current_user.uid) catch {};
}

fn printHelp() void {
    const help_text =
        \\usage: sudo -h | -V
        \\usage: sudo [-BknS] [-D directory] [-g group] [-p prompt] [-u user] command [arg ...]
        \\usage: sudo -e [-BknS] [-D directory] [-g group] [-p prompt] [-u user] file ...
        \\usage: sudo -l [-U user] [-u user] [-g group] [command [arg ...]]
        \\usage: sudo -v [-BknS]
        \\
        \\Options:
        \\  -B, --bell              ring bell on password prompt
        \\  -D, --chdir=directory   change working directory
        \\  -e, --edit              edit files instead of running command
        \\  -g, --group=group       run command as specified group
        \\  -h, --help              display help message and exit
        \\  -i, --login             run login shell as target user
        \\  -k, --reset-timestamp   invalidate timestamp
        \\  -K, --remove-timestamp  remove timestamp file
        \\  -l, --list              list user's privileges
        \\  -n, --non-interactive   non-interactive mode
        \\  -p, --prompt=prompt     custom password prompt
        \\  -s, --shell             run shell as target user
        \\  -S, --stdin             read password from stdin
        \\  -u, --user=user         run command as specified user
        \\  -U, --other-user=user   in list mode, show privileges for user
        \\  -v, --validate          update user timestamp
        \\  -V, --version           display version and exit
        \\
    ;
    _ = std.posix.write(std.posix.STDOUT_FILENO, help_text) catch return;
}

fn printVersion() void {
    var buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "sudo-zig {s}\n", .{version}) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch return;
}
