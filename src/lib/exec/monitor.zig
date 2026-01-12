//! Process monitor for PTY execution
//!
//! The monitor process sits between the parent (sudo) and the command process.
//! It handles:
//! - Signal forwarding to the command
//! - Process group management
//! - Communication back to parent via backchannel

const std = @import("std");
const posix = std.posix;
const system = @import("../system/mod.zig");
const pty_mod = @import("pty.zig");
const signal = system.signal;

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("sys/wait.h");
    @cInclude("sys/ioctl.h");
    @cInclude("poll.h");
});

/// Messages sent between parent and monitor via backchannel
pub const BackchannelMessage = union(enum) {
    /// Command exited normally
    exit_code: u8,
    /// Command was killed by signal
    exit_signal: u32,
    /// Error occurred
    error_occurred: void,
    /// Window size changed (parent -> monitor)
    window_change: struct { rows: u16, cols: u16 },
    /// Signal to forward (parent -> monitor)
    forward_signal: u32,

    const Self = @This();

    /// Serialize message for transmission
    pub fn serialize(self: Self, buf: *[8]u8) void {
        @memset(buf, 0);
        switch (self) {
            .exit_code => |code| {
                buf[0] = 1;
                buf[1] = code;
            },
            .exit_signal => |sig| {
                buf[0] = 2;
                buf[1] = @truncate(sig);
            },
            .error_occurred => {
                buf[0] = 3;
            },
            .window_change => |wc| {
                buf[0] = 4;
                buf[1] = @truncate(wc.rows >> 8);
                buf[2] = @truncate(wc.rows);
                buf[3] = @truncate(wc.cols >> 8);
                buf[4] = @truncate(wc.cols);
            },
            .forward_signal => |sig| {
                buf[0] = 5;
                buf[1] = @truncate(sig);
            },
        }
    }

    /// Deserialize message from buffer
    pub fn deserialize(buf: *const [8]u8) ?Self {
        return switch (buf[0]) {
            1 => .{ .exit_code = buf[1] },
            2 => .{ .exit_signal = buf[1] },
            3 => .error_occurred,
            4 => .{ .window_change = .{
                .rows = (@as(u16, buf[1]) << 8) | buf[2],
                .cols = (@as(u16, buf[3]) << 8) | buf[4],
            } },
            5 => .{ .forward_signal = buf[1] },
            else => null,
        };
    }
};

/// Backchannel for communication between parent and monitor
pub const Backchannel = struct {
    read_fd: posix.fd_t,
    write_fd: posix.fd_t,

    const Self = @This();

    /// Create a new backchannel pipe pair
    pub fn create() !Self {
        const pipe_fds = try posix.pipe();
        return .{
            .read_fd = pipe_fds[0],
            .write_fd = pipe_fds[1],
        };
    }

    /// Create a pair of backchannels for bidirectional communication
    pub fn createPair() !struct { parent: Self, monitor: Self } {
        // Parent -> Monitor pipe
        const p2m = try posix.pipe();
        // Monitor -> Parent pipe
        const m2p = try posix.pipe();

        return .{
            .parent = .{
                .read_fd = m2p[0], // Parent reads from monitor
                .write_fd = p2m[1], // Parent writes to monitor
            },
            .monitor = .{
                .read_fd = p2m[0], // Monitor reads from parent
                .write_fd = m2p[1], // Monitor writes to parent
            },
        };
    }

    /// Send a message
    pub fn send(self: Self, msg: BackchannelMessage) !void {
        var buf: [8]u8 = undefined;
        msg.serialize(&buf);
        _ = try posix.write(self.write_fd, &buf);
    }

    /// Receive a message (blocking)
    pub fn receive(self: Self) !?BackchannelMessage {
        var buf: [8]u8 = undefined;
        const n = posix.read(self.read_fd, &buf) catch |err| {
            if (err == error.WouldBlock) return null;
            return err;
        };
        if (n == 0) return null; // EOF
        if (n < 8) return null; // Incomplete message
        return BackchannelMessage.deserialize(&buf);
    }

    /// Close the read end
    pub fn closeRead(self: *Self) void {
        if (self.read_fd >= 0) {
            posix.close(self.read_fd);
            self.read_fd = -1;
        }
    }

    /// Close the write end
    pub fn closeWrite(self: *Self) void {
        if (self.write_fd >= 0) {
            posix.close(self.write_fd);
            self.write_fd = -1;
        }
    }

    /// Close both ends
    pub fn close(self: *Self) void {
        self.closeRead();
        self.closeWrite();
    }

    /// Set non-blocking mode on read end
    pub fn setNonBlocking(self: *Self) !void {
        const flags = try posix.fcntl(self.read_fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(self.read_fd, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    }
};

/// Global variable for signal handling in monitor process
var g_command_pid: posix.pid_t = 0;
var g_backchannel_write_fd: posix.fd_t = -1;
var g_received_signal: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Signal handler for monitor process
fn monitorSignalHandler(sig: c_int) callconv(.c) void {
    const signal_num: u32 = @intCast(sig);

    // Store received signal for main loop to handle
    g_received_signal.store(signal_num, .release);

    // For SIGCHLD, we'll handle it in the main loop
    if (sig == c.SIGCHLD) return;

    // Forward other signals to command process
    if (g_command_pid > 0) {
        _ = c.kill(g_command_pid, sig);
    }
}

/// Monitor process main function
pub const Monitor = struct {
    command_pid: posix.pid_t,
    backchannel: Backchannel,
    pty_master_fd: posix.fd_t,

    const Self = @This();

    pub fn init(command_pid: posix.pid_t, backchannel: Backchannel, pty_master_fd: posix.fd_t) Self {
        return .{
            .command_pid = command_pid,
            .backchannel = backchannel,
            .pty_master_fd = pty_master_fd,
        };
    }

    /// Run the monitor event loop
    pub fn run(self: *Self) !BackchannelMessage {
        // Set up globals for signal handler
        g_command_pid = self.command_pid;
        g_backchannel_write_fd = self.backchannel.write_fd;

        // Install signal handlers
        try installSignalHandlers();
        defer restoreSignalHandlers();

        // Set backchannel to non-blocking
        try self.backchannel.setNonBlocking();

        // Event loop
        var poll_fds = [_]posix.pollfd{
            .{ .fd = self.backchannel.read_fd, .events = posix.POLL.IN, .revents = 0 },
        };

        while (true) {
            // Check for received signals
            const sig = g_received_signal.swap(0, .acquire);
            if (sig != 0) {
                if (sig == c.SIGCHLD) {
                    // Child status changed
                    const result = try self.checkChild();
                    if (result) |msg| {
                        try self.backchannel.send(msg);
                        return msg;
                    }
                }
            }

            // Poll for events
            const ready = posix.poll(&poll_fds, 100) catch 0; // 100ms timeout

            if (ready > 0) {
                // Check backchannel for messages from parent
                if (poll_fds[0].revents & posix.POLL.IN != 0) {
                    if (try self.backchannel.receive()) |msg| {
                        try self.handleParentMessage(msg);
                    }
                }
            }

            // Check if child has exited (non-blocking)
            const result = try self.checkChild();
            if (result) |msg| {
                try self.backchannel.send(msg);
                return msg;
            }
        }
    }

    /// Check if command process has exited
    fn checkChild(self: *Self) !?BackchannelMessage {
        const wait_result = posix.waitpid(self.command_pid, posix.W.NOHANG);

        if (wait_result.pid == 0) {
            // Child still running
            return null;
        }

        if (wait_result.pid == self.command_pid) {
            // Child exited
            if (posix.W.IFEXITED(wait_result.status)) {
                return .{ .exit_code = posix.W.EXITSTATUS(wait_result.status) };
            } else if (posix.W.IFSIGNALED(wait_result.status)) {
                return .{ .exit_signal = posix.W.TERMSIG(wait_result.status) };
            }
        }

        return null;
    }

    /// Handle message from parent
    fn handleParentMessage(self: *Self, msg: BackchannelMessage) !void {
        switch (msg) {
            .forward_signal => |sig| {
                // Forward signal to command
                _ = c.kill(self.command_pid, @intCast(sig));
            },
            .window_change => |wc| {
                // Update PTY window size
                const ws = c.winsize{
                    .ws_row = wc.rows,
                    .ws_col = wc.cols,
                    .ws_xpixel = 0,
                    .ws_ypixel = 0,
                };
                _ = c.ioctl(self.pty_master_fd, c.TIOCSWINSZ, &ws);
                // Send SIGWINCH to command
                _ = c.kill(self.command_pid, c.SIGWINCH);
            },
            else => {},
        }
    }
};

fn installSignalHandlers() !void {
    const signals_to_handle = [_]c_int{
        c.SIGHUP,
        c.SIGINT,
        c.SIGQUIT,
        c.SIGTERM,
        c.SIGTSTP,
        c.SIGCONT,
        c.SIGCHLD,
        c.SIGWINCH,
    };

    for (signals_to_handle) |sig| {
        var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
        sa.__sigaction_handler.sa_handler = monitorSignalHandler;
        sa.sa_flags = c.SA_RESTART;
        _ = c.sigaction(sig, &sa, null);
    }
}

fn restoreSignalHandlers() void {
    const signals_to_restore = [_]c_int{
        c.SIGHUP,
        c.SIGINT,
        c.SIGQUIT,
        c.SIGTERM,
        c.SIGTSTP,
        c.SIGCONT,
        c.SIGCHLD,
        c.SIGWINCH,
    };

    for (signals_to_restore) |sig| {
        var sa: c.struct_sigaction = std.mem.zeroes(c.struct_sigaction);
        sa.__sigaction_handler.sa_handler = c.SIG_DFL;
        _ = c.sigaction(sig, &sa, null);
    }
}

test "BackchannelMessage serialization" {
    const testing = std.testing;

    var buf: [8]u8 = undefined;

    const msg1: BackchannelMessage = .{ .exit_code = 42 };
    msg1.serialize(&buf);
    const decoded1 = BackchannelMessage.deserialize(&buf).?;
    try testing.expectEqual(@as(u8, 42), decoded1.exit_code);

    const msg2: BackchannelMessage = .{ .exit_signal = 9 };
    msg2.serialize(&buf);
    const decoded2 = BackchannelMessage.deserialize(&buf).?;
    try testing.expectEqual(@as(u32, 9), decoded2.exit_signal);
}

test "Backchannel struct" {
    // Just verify compilation
    _ = Backchannel;
    _ = Monitor;
}
