//! Pseudo-terminal (PTY) handling
//!
//! Provides PTY allocation and management for command execution.
//! This enables proper terminal handling for interactive commands.

const std = @import("std");
const posix = std.posix;
const system = @import("../system/mod.zig");

const c = @cImport({
    @cDefine("_XOPEN_SOURCE", "600");
    @cInclude("stdlib.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("termios.h");
    @cInclude("sys/ioctl.h");
});

/// Pseudo-terminal pair
pub const Pty = struct {
    master_fd: posix.fd_t,
    slave_fd: posix.fd_t,
    slave_name: [64:0]u8,
    slave_name_len: usize,

    const Self = @This();

    /// Open a new PTY pair
    pub fn open() !Self {
        var self = Self{
            .master_fd = -1,
            .slave_fd = -1,
            .slave_name = undefined,
            .slave_name_len = 0,
        };

        // Use posix_openpt for portability
        self.master_fd = c.posix_openpt(c.O_RDWR | c.O_NOCTTY);
        if (self.master_fd < 0) {
            return error.PtyOpenFailed;
        }
        errdefer posix.close(self.master_fd);

        // Grant access to the slave
        if (c.grantpt(self.master_fd) != 0) {
            return error.PtyGrantFailed;
        }

        // Unlock the slave
        if (c.unlockpt(self.master_fd) != 0) {
            return error.PtyUnlockFailed;
        }

        // Get slave name
        const slave_name_ptr = c.ptsname(self.master_fd);
        if (slave_name_ptr == null) {
            return error.PtyNameFailed;
        }

        const slave_name = std.mem.span(slave_name_ptr);
        if (slave_name.len >= self.slave_name.len) {
            return error.PtyNameTooLong;
        }
        @memcpy(self.slave_name[0..slave_name.len], slave_name);
        self.slave_name[slave_name.len] = 0;
        self.slave_name_len = slave_name.len;

        // Open the slave side
        self.slave_fd = posix.open(self.slave_name[0..self.slave_name_len :0], .{ .ACCMODE = .RDWR }, 0) catch {
            return error.PtySlaveOpenFailed;
        };

        return self;
    }

    /// Get the slave device name
    pub fn getSlaveName(self: *const Self) []const u8 {
        return self.slave_name[0..self.slave_name_len];
    }

    /// Set the slave as the controlling terminal for the current process
    pub fn makeControllingTerminal(self: *Self) !void {
        // Create a new session
        _ = posix.setsid() catch {};

        // Set controlling terminal using TIOCSCTTY
        if (c.ioctl(self.slave_fd, c.TIOCSCTTY, @as(c_int, 0)) < 0) {
            // Not fatal on all systems
        }
    }

    /// Copy terminal attributes from another terminal
    pub fn copyTerminalAttributes(self: *Self, source_fd: posix.fd_t) !void {
        var attrs: c.termios = undefined;
        if (c.tcgetattr(source_fd, &attrs) == 0) {
            _ = c.tcsetattr(self.slave_fd, c.TCSANOW, &attrs);
        }
    }

    /// Copy window size from another terminal
    pub fn copyWindowSize(self: *Self, source_fd: posix.fd_t) !void {
        var ws: c.winsize = undefined;
        if (c.ioctl(source_fd, c.TIOCGWINSZ, &ws) == 0) {
            _ = c.ioctl(self.slave_fd, c.TIOCSWINSZ, &ws);
        }
    }

    /// Set window size on the PTY
    pub fn setWindowSize(self: *Self, rows: u16, cols: u16) void {
        var ws = c.winsize{
            .ws_row = rows,
            .ws_col = cols,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        _ = c.ioctl(self.slave_fd, c.TIOCSWINSZ, &ws);
    }

    /// Get window size from the PTY
    pub fn getWindowSize(self: *const Self) ?struct { rows: u16, cols: u16 } {
        var ws: c.winsize = undefined;
        if (c.ioctl(self.master_fd, c.TIOCGWINSZ, &ws) == 0) {
            return .{ .rows = ws.ws_row, .cols = ws.ws_col };
        }
        return null;
    }

    /// Close the master side only
    pub fn closeMaster(self: *Self) void {
        if (self.master_fd >= 0) {
            posix.close(self.master_fd);
            self.master_fd = -1;
        }
    }

    /// Close the slave side only
    pub fn closeSlave(self: *Self) void {
        if (self.slave_fd >= 0) {
            posix.close(self.slave_fd);
            self.slave_fd = -1;
        }
    }

    /// Close both sides
    pub fn close(self: *Self) void {
        self.closeMaster();
        self.closeSlave();
    }

    /// Set non-blocking mode on master
    pub fn setNonBlocking(self: *Self) !void {
        const flags = try posix.fcntl(self.master_fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(self.master_fd, posix.F.SETFL, flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    }
};

/// Terminal settings helper
pub const Terminal = struct {
    fd: posix.fd_t,
    original_attrs: c.termios,
    attrs_saved: bool,

    const Self = @This();

    /// Open the controlling terminal
    pub fn open() !Self {
        const fd = posix.open("/dev/tty", .{ .ACCMODE = .RDWR }, 0) catch {
            return error.NoControllingTerminal;
        };

        var self = Self{
            .fd = fd,
            .original_attrs = undefined,
            .attrs_saved = false,
        };

        // Save original attributes
        if (c.tcgetattr(fd, &self.original_attrs) == 0) {
            self.attrs_saved = true;
        }

        return self;
    }

    /// Get current window size
    pub fn getWindowSize(self: Self) ?struct { rows: u16, cols: u16 } {
        var ws: c.winsize = undefined;
        if (c.ioctl(self.fd, c.TIOCGWINSZ, &ws) == 0) {
            return .{ .rows = ws.ws_row, .cols = ws.ws_col };
        }
        return null;
    }

    /// Set raw mode (disable line buffering and echo)
    pub fn setRaw(self: *Self) !void {
        if (!self.attrs_saved) return error.NoTerminalAttributes;

        var raw = self.original_attrs;

        // Input flags: disable break, CR to NL, parity check, strip 8th bit, flow control
        raw.c_iflag &= ~@as(c_uint, c.BRKINT | c.ICRNL | c.INPCK | c.ISTRIP | c.IXON);

        // Output flags: disable post-processing
        raw.c_oflag &= ~@as(c_uint, c.OPOST);

        // Control flags: set 8 bit chars
        raw.c_cflag |= c.CS8;

        // Local flags: disable echo, canonical mode, extensions, signal chars
        raw.c_lflag &= ~@as(c_uint, c.ECHO | c.ICANON | c.IEXTEN | c.ISIG);

        // Control chars: set return condition for non-canonical reads
        raw.c_cc[c.VMIN] = 1;
        raw.c_cc[c.VTIME] = 0;

        if (c.tcsetattr(self.fd, c.TCSAFLUSH, &raw) != 0) {
            return error.SetAttrFailed;
        }
    }

    /// Restore original terminal settings
    pub fn restore(self: *Self) void {
        if (self.attrs_saved) {
            _ = c.tcsetattr(self.fd, c.TCSAFLUSH, &self.original_attrs);
        }
    }

    /// Close the terminal
    pub fn close(self: *Self) void {
        self.restore();
        posix.close(self.fd);
    }
};

/// I/O relay between two file descriptors
pub const IoRelay = struct {
    source_fd: posix.fd_t,
    dest_fd: posix.fd_t,

    const Self = @This();
    const BUFFER_SIZE = 4096;

    /// Relay data from source to dest (non-blocking, returns bytes written or 0 if would block)
    pub fn relay(self: Self) !usize {
        var buf: [BUFFER_SIZE]u8 = undefined;

        const n = posix.read(self.source_fd, &buf) catch |err| {
            if (err == error.WouldBlock) return 0;
            return err;
        };

        if (n == 0) return 0; // EOF

        var written: usize = 0;
        while (written < n) {
            const w = posix.write(self.dest_fd, buf[written..n]) catch |err| {
                if (err == error.WouldBlock) continue;
                return err;
            };
            written += w;
        }

        return written;
    }
};

// PTY errors
pub const PtyError = error{
    PtyOpenFailed,
    PtyGrantFailed,
    PtyUnlockFailed,
    PtyNameFailed,
    PtyNameTooLong,
    PtySlaveOpenFailed,
    NoControllingTerminal,
    NoTerminalAttributes,
    SetAttrFailed,
};

test "Pty struct" {
    // Just verify compilation
    _ = Pty;
    _ = Terminal;
    _ = IoRelay;
}
