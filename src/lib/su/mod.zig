//! su command implementation
//!
//! Main entry point and logic for the su command.
//!
//! su allows running a shell or command as another user, authenticating
//! as the target user (unlike sudo which authenticates as the invoking user).

const std = @import("std");
const root = @import("../root.zig");
const log = @import("../log/mod.zig");
const system = @import("../system/mod.zig");
const exec = @import("../exec/mod.zig");
const pam = @import("../pam/mod.zig");
const build_options = @import("build_options");

const version = root.version;

/// Parsed su action
pub const Action = union(enum) {
    help: void,
    version: void,
    run: RunOptions,
};

/// Options for su
pub const RunOptions = struct {
    user: []const u8 = "root",
    login: bool = false,
    shell: ?[]const u8 = null,
    command: ?[]const u8 = null,
    preserve_env: bool = false,
    group: ?[]const u8 = null,
    supp_group: ?[]const u8 = null,
    pty: bool = false,
    whitelist_env: []const []const u8 = &.{},
};

/// Main entry point for su
pub fn main() void {
    process() catch |err| {
        log.userError("error: {}", .{err});
        std.process.exit(1);
    };
}

fn process() !void {
    log.SudoLogger.init("su: ").intoGlobalLogger();

    const action = try parseArgs();

    switch (action) {
        .help => printHelp(),
        .version => printVersion(),
        .run => |opts| try run(opts),
    }
}

fn run(options: RunOptions) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Get current (requesting) user info
    const real_uid = system.User.realUid();
    var current_user: system.User = undefined;
    if (!system.User.fromUidInto(real_uid, &current_user)) {
        log.userError("cannot determine current user", .{});
        return error.UserNotFound;
    }

    // 2. Resolve target user
    var target_user: system.User = undefined;
    if (!system.User.fromNameInto(options.user, &target_user)) {
        log.userError("unknown user: {s}", .{options.user});
        return error.UserNotFound;
    }

    // 3. Resolve target group
    const target_gid = if (options.group) |g|
        (system.Group.fromName(g) orelse {
            log.userError("unknown group: {s}", .{g});
            return error.GroupNotFound;
        }).gid
    else
        target_user.gid;

    // 4. Authenticate as target user (unless we're root)
    if (real_uid != 0) {
        try authenticate(current_user.getName(), target_user.getName());
    }

    // 5. Determine shell to use
    const shell = options.shell orelse
        (if (target_user.getShell().len > 0) target_user.getShell() else "/bin/sh");

    // 6. Build command arguments
    var args_buf: [64][]const u8 = undefined;
    var args_count: usize = 0;

    // Static buffer for login shell name (must outlive function scope for exec)
    const static = struct {
        var login_shell_buf: [256]u8 = undefined;
    };

    // First arg is shell name (or -shell for login)
    if (options.login) {
        // For login shell, argv[0] should start with '-'
        const shell_basename = std.fs.path.basename(shell);
        static.login_shell_buf[0] = '-';
        @memcpy(static.login_shell_buf[1 .. shell_basename.len + 1], shell_basename);
        args_buf[0] = static.login_shell_buf[0 .. shell_basename.len + 1];
    } else {
        args_buf[0] = shell;
    }
    args_count = 1;

    // Add -c command if specified
    if (options.command) |cmd| {
        args_buf[args_count] = "-c";
        args_count += 1;
        args_buf[args_count] = cmd;
        args_count += 1;
    }

    // 7. Build environment
    var env = std.StringHashMap([]const u8).init(allocator);
    defer env.deinit();
    try buildEnvironment(&env, &current_user, &target_user, options);

    // 8. Execute
    const run_options = exec.RunOptions{
        .command = shell,
        .arguments = args_buf[0..args_count],
        .uid = target_user.uid,
        .gid = target_gid,
        .cwd = if (options.login) target_user.getHome() else null,
        .use_pty = options.pty,
        .noexec = false,
    };

    const exit_reason = try exec.runCommand(run_options, env);

    // Exit with same status as command
    std.process.exit(exit_reason.toExitCode());
}

fn authenticate(requesting_user: []const u8, target_user: []const u8) !void {
    if (!build_options.enable_pam) {
        // Without PAM, we can't authenticate - just warn in dev mode
        log.debug("PAM not enabled, skipping authentication", .{});
        return;
    }

    // Initialize PAM context for su service
    var pam_ctx = pam.PamContext.init(.{
        .service_name = "su",
        .username = target_user,
        .use_stdin = false,
        .show_asterisks = false,
    }) catch |err| {
        log.userError("PAM initialization failed: {}", .{err});
        return error.AuthenticationFailed;
    };
    defer pam_ctx.deinit();

    // Set the requesting user
    pam_ctx.setRequestingUser(requesting_user) catch {};

    // Authenticate
    pam_ctx.authenticate(0) catch |err| {
        log.userError("Authentication failed", .{});
        return err;
    };

    // Check account validity
    pam_ctx.accountManagement(0) catch |err| {
        log.userError("Account check failed", .{});
        return err;
    };

    // Open session
    pam_ctx.openSession(0) catch |err| {
        log.userError("Failed to open session", .{});
        return err;
    };

    // Note: Session will be closed when pam_ctx is deinitialized
}

fn buildEnvironment(
    env: *std.StringHashMap([]const u8),
    current_user: *const system.User,
    target_user: *const system.User,
    options: RunOptions,
) !void {
    // Get current environment
    const env_map = std.process.getEnvMap(env.allocator) catch return;
    defer {
        var map_copy = env_map;
        map_copy.deinit();
    }

    if (options.login) {
        // Login shell: minimal environment
        try env.put("HOME", target_user.getHome());
        try env.put("SHELL", if (target_user.getShell().len > 0) target_user.getShell() else "/bin/sh");
        try env.put("USER", target_user.getName());
        try env.put("LOGNAME", target_user.getName());
        try env.put("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin");

        // Preserve TERM
        if (env_map.get("TERM")) |term| {
            try env.put("TERM", term);
        }
    } else if (options.preserve_env) {
        // Preserve entire environment
        var it = env_map.iterator();
        while (it.next()) |entry| {
            try env.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        // But update USER and HOME
        try env.put("USER", target_user.getName());
        try env.put("HOME", target_user.getHome());
    } else {
        // Default: preserve most, update user-specific
        var it = env_map.iterator();
        while (it.next()) |entry| {
            // Skip potentially dangerous variables
            const key = entry.key_ptr.*;
            if (std.mem.startsWith(u8, key, "LD_") or
                std.mem.startsWith(u8, key, "BASH_") or
                std.mem.eql(u8, key, "IFS") or
                std.mem.eql(u8, key, "ENV") or
                std.mem.eql(u8, key, "CDPATH"))
            {
                continue;
            }
            try env.put(key, entry.value_ptr.*);
        }

        // Update user-specific variables
        try env.put("HOME", target_user.getHome());
        try env.put("USER", target_user.getName());
        try env.put("LOGNAME", target_user.getName());
        if (target_user.getShell().len > 0) {
            try env.put("SHELL", target_user.getShell());
        }
    }

    // Handle whitelisted env vars
    for (options.whitelist_env) |varname| {
        if (env_map.get(varname)) |value| {
            try env.put(varname, value);
        }
    }

    _ = current_user;
}

fn parseArgs() !Action {
    var args = std.process.args();
    _ = args.skip();

    var options = RunOptions{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            return .version;
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--login") or std.mem.eql(u8, arg, "-")) {
            options.login = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--command")) {
            options.command = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--shell")) {
            options.shell = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--preserve-environment")) {
            options.preserve_env = true;
        } else if (std.mem.eql(u8, arg, "-g") or std.mem.eql(u8, arg, "--group")) {
            options.group = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-G") or std.mem.eql(u8, arg, "--supp-group")) {
            options.supp_group = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-P") or std.mem.eql(u8, arg, "--pty")) {
            options.pty = true;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            options.user = arg;
        }
    }

    return .{ .run = options };
}

fn printHelp() void {
    const help_text =
        \\usage: su [options] [user]
        \\
        \\Options:
        \\  -h, --help              display this help and exit
        \\  -V, --version           display version and exit
        \\  -, -l, --login          make the shell a login shell
        \\  -c, --command=CMD       run command with -c
        \\  -s, --shell=SHELL       use SHELL instead of default
        \\  -m, -p, --preserve-environment
        \\                          preserve environment variables
        \\  -g, --group=GROUP       set primary group
        \\  -G, --supp-group=GROUP  set supplementary group
        \\  -P, --pty               create pseudo-terminal
        \\
    ;
    _ = std.posix.write(std.posix.STDOUT_FILENO, help_text) catch return;
}

fn printVersion() void {
    var buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "su-zig {s}\n", .{version}) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, msg) catch return;
}
