//! Command execution
//!
//! Handles executing commands with proper:
//! - Credential switching (setuid/setgid)
//! - PTY allocation
//! - Signal forwarding
//! - Process monitoring

const std = @import("std");
const posix = std.posix;
const system = @import("../system/mod.zig");
const signal = system.signal;

pub const pty = @import("pty.zig");
pub const monitor = @import("monitor.zig");
pub const timeout = @import("timeout.zig");
pub const closefrom = @import("closefrom.zig");

// Re-export key types
pub const TimeoutConfig = timeout.TimeoutConfig;
pub const TimeoutHandler = timeout.TimeoutHandler;
pub const prepareForExec = closefrom.prepareForExec;

const Pty = pty.Pty;
const Terminal = pty.Terminal;
const Backchannel = monitor.Backchannel;
const BackchannelMessage = monitor.BackchannelMessage;
const Monitor = monitor.Monitor;

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/types.h");
    @cInclude("grp.h");
    @cInclude("poll.h");
    @cInclude("signal.h");
    @cInclude("sys/ioctl.h");
});

/// Exit reason for executed command
pub const ExitReason = union(enum) {
    /// Normal exit with status code
    code: u8,
    /// Terminated by signal
    signal: u32,

    pub fn toExitCode(self: ExitReason) u8 {
        return switch (self) {
            .code => |code| code,
            .signal => |sig| @truncate(128 + sig),
        };
    }
};

/// Options for running a command
pub const RunOptions = struct {
    /// Command path
    command: []const u8,
    /// Command arguments
    arguments: []const []const u8,
    /// Target user ID
    uid: system.UserId,
    /// Target group ID
    gid: system.GroupId,
    /// Supplementary groups
    groups: []const system.GroupId = &.{},
    /// Working directory
    cwd: ?[]const u8 = null,
    /// Use pseudo-terminal
    use_pty: bool = true,
    /// Prevent exec of child processes
    noexec: bool = false,
};

/// Run a command with the specified options
pub fn runCommand(options: RunOptions, environment: std.StringHashMap([]const u8)) !ExitReason {
    if (options.use_pty) {
        return runWithPty(options, environment);
    } else {
        return runWithoutPty(options, environment);
    }
}

/// Global for SIGWINCH handling in parent
var g_parent_backchannel_write_fd: posix.fd_t = -1;
var g_sigwinch_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn parentSigwinchHandler(_: c_int) callconv(.c) void {
    g_sigwinch_received.store(true, .release);
}

fn parentSigchldHandler(_: c_int) callconv(.c) void {
    // Just interrupt poll
}

/// Run command with PTY for full terminal handling
fn runWithPty(options: RunOptions, environment: std.StringHashMap([]const u8)) !ExitReason {
    // Open user's terminal to copy settings
    var user_term: ?Terminal = Terminal.open() catch null;
    defer if (user_term) |*t| t.close();

    // Create PTY pair
    var pty_pair = try Pty.open();
    defer pty_pair.close();

    // Copy terminal settings and window size from user's terminal
    if (user_term) |ut| {
        pty_pair.copyTerminalAttributes(ut.fd) catch {};
        pty_pair.copyWindowSize(ut.fd) catch {};
    }

    // Create backchannels for parent <-> monitor communication
    const channels = try Backchannel.createPair();
    var parent_channel = channels.parent;
    var monitor_channel = channels.monitor;
    defer parent_channel.close();

    // Fork monitor process
    const monitor_fork = try system.Process.fork();

    switch (monitor_fork) {
        .child => {
            // === MONITOR PROCESS ===
            parent_channel.close();

            // Close user terminal in monitor
            if (user_term) |*t| {
                t.close();
                user_term = null;
            }

            // Fork command process
            const cmd_fork = try system.Process.fork();

            switch (cmd_fork) {
                .child => {
                    // === COMMAND PROCESS ===
                    monitor_channel.close();

                    // Close master side of PTY
                    pty_pair.closeMaster();

                    // Set up PTY as controlling terminal
                    try pty_pair.makeControllingTerminal();

                    // Duplicate slave to stdin/stdout/stderr
                    try posix.dup2(pty_pair.slave_fd, posix.STDIN_FILENO);
                    try posix.dup2(pty_pair.slave_fd, posix.STDOUT_FILENO);
                    try posix.dup2(pty_pair.slave_fd, posix.STDERR_FILENO);

                    // Close original slave fd if not one of std fds
                    if (pty_pair.slave_fd > posix.STDERR_FILENO) {
                        pty_pair.closeSlave();
                    }

                    // Execute command
                    executeInChild(options, environment) catch |err| {
                        const msg = switch (err) {
                            error.AccessDenied => "permission denied",
                            error.FileNotFound => "command not found",
                            else => "execution failed",
                        };
                        _ = posix.write(posix.STDERR_FILENO, msg) catch {};
                        _ = posix.write(posix.STDERR_FILENO, "\n") catch {};
                        std.process.exit(if (err == error.FileNotFound) 127 else 126);
                    };
                    unreachable;
                },
                .parent => |command_pid| {
                    // === MONITOR PROCESS (continued) ===
                    // Close slave side of PTY
                    pty_pair.closeSlave();

                    // Run monitor loop
                    var mon = Monitor.init(command_pid, monitor_channel, pty_pair.master_fd);
                    const result = mon.run() catch .error_occurred;

                    // Exit with appropriate status
                    switch (result) {
                        .exit_code => |code| std.process.exit(code),
                        .exit_signal => |sig| {
                            // Re-raise signal to exit with correct status
                            _ = c.signal(@intCast(sig), c.SIG_DFL);
                            _ = c.raise(@intCast(sig));
                            std.process.exit(128 + @as(u8, @truncate(sig)));
                        },
                        else => std.process.exit(1),
                    }
                },
            }
        },
        .parent => |monitor_pid| {
            // === PARENT PROCESS ===
            monitor_channel.close();
            pty_pair.closeSlave();

            // Set up SIGWINCH handler
            var old_sigwinch: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
            var sigwinch_action: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
            sigwinch_action.__sigaction_handler.sa_handler = parentSigwinchHandler;
            _ = c.sigaction(c.SIGWINCH, &sigwinch_action, &old_sigwinch);

            defer _ = c.sigaction(c.SIGWINCH, &old_sigwinch, null);

            // Set raw mode on user terminal for pass-through
            if (user_term) |*ut| {
                ut.setRaw() catch {};
            }

            // Set non-blocking on PTY master and backchannel
            pty_pair.setNonBlocking() catch {};
            parent_channel.setNonBlocking() catch {};

            // I/O relay loop
            var poll_fds = [_]posix.pollfd{
                .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = pty_pair.master_fd, .events = posix.POLL.IN, .revents = 0 },
                .{ .fd = parent_channel.read_fd, .events = posix.POLL.IN, .revents = 0 },
            };

            var result: ExitReason = .{ .code = 1 };
            var running = true;

            while (running) {
                // Check for SIGWINCH
                if (g_sigwinch_received.swap(false, .acquire)) {
                    if (user_term) |ut| {
                        if (ut.getWindowSize()) |ws| {
                            parent_channel.send(.{ .window_change = .{
                                .rows = ws.rows,
                                .cols = ws.cols,
                            } }) catch {};
                        }
                    }
                }

                const ready = posix.poll(&poll_fds, 100) catch continue;

                if (ready > 0) {
                    // User input -> PTY master
                    if (poll_fds[0].revents & posix.POLL.IN != 0) {
                        var buf: [4096]u8 = undefined;
                        const n = posix.read(posix.STDIN_FILENO, &buf) catch 0;
                        if (n > 0) {
                            _ = posix.write(pty_pair.master_fd, buf[0..n]) catch {};
                        }
                    }

                    // PTY master output -> user stdout
                    if (poll_fds[1].revents & posix.POLL.IN != 0) {
                        var buf: [4096]u8 = undefined;
                        const n = posix.read(pty_pair.master_fd, &buf) catch 0;
                        if (n > 0) {
                            _ = posix.write(posix.STDOUT_FILENO, buf[0..n]) catch {};
                        }
                    }

                    // Check for HUP on PTY (command exited)
                    if (poll_fds[1].revents & posix.POLL.HUP != 0) {
                        // Drain any remaining output
                        while (true) {
                            var buf: [4096]u8 = undefined;
                            const n = posix.read(pty_pair.master_fd, &buf) catch break;
                            if (n == 0) break;
                            _ = posix.write(posix.STDOUT_FILENO, buf[0..n]) catch {};
                        }
                    }

                    // Backchannel message from monitor
                    if (poll_fds[2].revents & posix.POLL.IN != 0) {
                        if (parent_channel.receive() catch null) |msg| {
                            switch (msg) {
                                .exit_code => |code| {
                                    result = .{ .code = code };
                                    running = false;
                                },
                                .exit_signal => |sig| {
                                    result = .{ .signal = sig };
                                    running = false;
                                },
                                .error_occurred => {
                                    result = .{ .code = 1 };
                                    running = false;
                                },
                                else => {},
                            }
                        }
                    }

                    // Check for HUP on backchannel (monitor exited unexpectedly)
                    if (poll_fds[2].revents & posix.POLL.HUP != 0) {
                        running = false;
                    }
                }
            }

            // Wait for monitor to exit
            _ = system.waitpid(monitor_pid, 0) catch {};

            // Restore terminal
            if (user_term) |*ut| {
                ut.restore();
            }

            return result;
        },
    }
}

/// Run command without PTY (simpler path)
fn runWithoutPty(options: RunOptions, environment: std.StringHashMap([]const u8)) !ExitReason {
    const fork_result = try system.Process.fork();

    switch (fork_result) {
        .child => {
            // Set up credentials and execute
            executeInChild(options, environment) catch |err| {
                // Write error to stderr
                const msg = switch (err) {
                    error.AccessDenied => "permission denied",
                    error.FileNotFound => "command not found",
                    else => "execution failed",
                };
                _ = posix.write(posix.STDERR_FILENO, msg) catch {};
                _ = posix.write(posix.STDERR_FILENO, "\n") catch {};
                std.process.exit(if (err == error.FileNotFound) 127 else 126);
            };
            // exec never returns on success
            unreachable;
        },
        .parent => |child_pid| {
            // Wait for child
            const wait_result = try system.waitpid(child_pid, 0);

            if (wait_result.ifExited()) |code| {
                return .{ .code = code };
            } else if (wait_result.ifSignaled()) |sig| {
                return .{ .signal = sig };
            }

            return .{ .code = 1 };
        },
    }
}

/// Execute command in child process after fork
fn executeInChild(options: RunOptions, environment: std.StringHashMap([]const u8)) !void {
    // 1. Set supplementary groups (must be done as root)
    if (options.groups.len > 0) {
        var c_groups: [64]c.gid_t = undefined;
        const count = @min(options.groups.len, c_groups.len);
        for (0..count) |i| {
            c_groups[i] = @intCast(options.groups[i]);
        }
        if (c.setgroups(@intCast(count), &c_groups) != 0) {
            // Non-fatal, continue
        }
    } else {
        // Clear supplementary groups
        _ = c.setgroups(0, null);
    }

    // 2. Set GID first (must be done before setuid drops privileges)
    try system.Process.setGid(options.gid);

    // 3. Set UID (this drops root privileges)
    try system.Process.setUid(options.uid);

    // 4. Change working directory if specified
    if (options.cwd) |cwd| {
        try posix.chdir(cwd);
    }

    // 5. Build environment array for execve
    var env_ptrs: [256][*:0]const u8 = undefined;
    var env_bufs: [256][512]u8 = undefined;
    var env_count: usize = 0;

    var env_iter = environment.iterator();
    while (env_iter.next()) |entry| {
        if (env_count >= env_ptrs.len - 1) break;

        // Format as "KEY=value"
        const written = std.fmt.bufPrint(&env_bufs[env_count], "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* }) catch continue;
        env_bufs[env_count][written.len] = 0;
        env_ptrs[env_count] = @ptrCast(&env_bufs[env_count]);
        env_count += 1;
    }
    env_ptrs[env_count] = undefined; // Null terminator will be set by sentinel

    // 6. Build argv array
    var argv_ptrs: [64][*:0]const u8 = undefined;
    var argv_bufs: [64][512]u8 = undefined;

    // First arg is the command itself
    const cmd_len = @min(options.command.len, argv_bufs[0].len - 1);
    @memcpy(argv_bufs[0][0..cmd_len], options.command[0..cmd_len]);
    argv_bufs[0][cmd_len] = 0;
    argv_ptrs[0] = @ptrCast(&argv_bufs[0]);

    var argc: usize = 1;
    for (options.arguments) |arg| {
        if (argc >= argv_ptrs.len - 1) break;
        const arg_len = @min(arg.len, argv_bufs[argc].len - 1);
        @memcpy(argv_bufs[argc][0..arg_len], arg[0..arg_len]);
        argv_bufs[argc][arg_len] = 0;
        argv_ptrs[argc] = @ptrCast(&argv_bufs[argc]);
        argc += 1;
    }

    // 7. Create null-terminated command path
    var cmd_buf: [512:0]u8 = undefined;
    const path_len = @min(options.command.len, cmd_buf.len - 1);
    @memcpy(cmd_buf[0..path_len], options.command[0..path_len]);
    cmd_buf[path_len] = 0;

    // 8. Execute!
    const argv_slice: [*:null]const ?[*:0]const u8 = @ptrCast(argv_ptrs[0..argc].ptr);
    const env_slice: [*:null]const ?[*:0]const u8 = @ptrCast(env_ptrs[0..env_count].ptr);

    const err = posix.execveZ(&cmd_buf, argv_slice, env_slice);
    return err;
}

test {
    std.testing.refAllDecls(@This());
}

test "ExitReason toExitCode" {
    const testing = std.testing;

    const normal: ExitReason = .{ .code = 42 };
    try testing.expectEqual(@as(u8, 42), normal.toExitCode());

    const signaled: ExitReason = .{ .signal = 9 };
    try testing.expectEqual(@as(u8, 137), signaled.toExitCode()); // 128 + 9
}
