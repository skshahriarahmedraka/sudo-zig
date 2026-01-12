//! Logging infrastructure
//!
//! Provides logging to stderr, syslog, mail notifications, and audit logging.

const std = @import("std");
const build_options = @import("build_options");

// Sub-modules
pub const mail = @import("mail.zig");
pub const audit = @import("audit.zig");

// Re-export main types
pub const MailConfig = mail.MailConfig;
pub const MailSender = mail.MailSender;
pub const SecurityEvent = mail.SecurityEvent;
pub const AuditConfig = audit.AuditConfig;
pub const AuditLogger = audit.AuditLogger;
pub const AuditEvent = audit.AuditEvent;
pub const AuditRecord = audit.AuditRecord;

const c = @cImport({
    @cInclude("syslog.h");
});

/// Syslog facility constants
pub const Facility = enum(c_int) {
    auth = c.LOG_AUTH,
    authpriv = c.LOG_AUTHPRIV,
    daemon = c.LOG_DAEMON,
    local0 = c.LOG_LOCAL0,
    local1 = c.LOG_LOCAL1,
    local2 = c.LOG_LOCAL2,
    local3 = c.LOG_LOCAL3,
    local4 = c.LOG_LOCAL4,
    local5 = c.LOG_LOCAL5,
    local6 = c.LOG_LOCAL6,
    local7 = c.LOG_LOCAL7,
    user = c.LOG_USER,
};

/// Syslog priority constants
pub const Priority = enum(c_int) {
    emerg = c.LOG_EMERG,
    alert = c.LOG_ALERT,
    crit = c.LOG_CRIT,
    err = c.LOG_ERR,
    warning = c.LOG_WARNING,
    notice = c.LOG_NOTICE,
    info = c.LOG_INFO,
    debug = c.LOG_DEBUG,
};

/// Syslog options
pub const SyslogOptions = struct {
    /// Include PID in messages
    pid: bool = true,
    /// Log to stderr as well
    perror: bool = false,
    /// Open connection immediately
    ndelay: bool = false,
    /// Don't wait for child processes
    nowait: bool = false,

    fn toFlags(self: SyslogOptions) c_int {
        var flags: c_int = 0;
        if (self.pid) flags |= c.LOG_PID;
        if (self.perror) flags |= c.LOG_PERROR;
        if (self.ndelay) flags |= c.LOG_NDELAY;
        if (self.nowait) flags |= c.LOG_NOWAIT;
        return flags;
    }
};

/// Log levels
pub const Level = enum {
    debug,
    info,
    warning,
    err,
    critical,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warning => "WARNING",
            .err => "ERROR",
            .critical => "CRITICAL",
        };
    }

    /// Convert to syslog priority
    pub fn toSyslogPriority(self: Level) Priority {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warning => .warning,
            .err => .err,
            .critical => .crit,
        };
    }
};

/// Global logger instance
var global_logger: ?SudoLogger = null;

/// Logger for sudo operations
pub const SudoLogger = struct {
    prefix: []const u8,
    use_syslog: bool = true,
    facility: Facility = .authpriv,
    syslog_opened: bool = false,
    _ident_buf: [64:0]u8 = undefined,

    const Self = @This();

    /// Create a new logger
    pub fn init(prefix: []const u8) Self {
        return .{ .prefix = prefix };
    }

    /// Create a new logger with custom syslog settings
    pub fn initWithSyslog(prefix: []const u8, facility: Facility, use_syslog: bool) Self {
        return .{
            .prefix = prefix,
            .use_syslog = use_syslog,
            .facility = facility,
        };
    }

    /// Set as the global logger
    pub fn intoGlobalLogger(self: Self) void {
        global_logger = self;
        if (self.use_syslog) {
            global_logger.?.openSyslog(.{});
        }
    }

    /// Open syslog connection
    pub fn openSyslog(self: *Self, options: SyslogOptions) void {
        if (self.syslog_opened) return;

        // Copy prefix to null-terminated buffer (remove trailing ": " if present)
        var ident_len = self.prefix.len;
        if (ident_len > 2 and std.mem.endsWith(u8, self.prefix, ": ")) {
            ident_len -= 2;
        }
        if (ident_len >= self._ident_buf.len) {
            ident_len = self._ident_buf.len - 1;
        }
        @memcpy(self._ident_buf[0..ident_len], self.prefix[0..ident_len]);
        self._ident_buf[ident_len] = 0;

        c.openlog(&self._ident_buf, options.toFlags(), @intFromEnum(self.facility));
        self.syslog_opened = true;
    }

    /// Close syslog connection
    pub fn closeSyslog(self: *Self) void {
        if (self.syslog_opened) {
            c.closelog();
            self.syslog_opened = false;
        }
    }

    /// Log a message
    pub fn log(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        // In dev mode, always print debug
        if (level == .debug and !build_options.dev_mode) {
            return;
        }

        var buf: [1024]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;

        // Log to stderr
        var prefix_buf: [128]u8 = undefined;
        const full_prefix = std.fmt.bufPrint(&prefix_buf, "{s}{s}: ", .{ self.prefix, level.toString() }) catch return;

        _ = std.posix.write(std.posix.STDERR_FILENO, full_prefix) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch return;

        // Log to syslog if enabled
        if (self.use_syslog and self.syslog_opened) {
            self.syslogWrite(level, msg);
        }
    }

    /// Write directly to syslog
    fn syslogWrite(self: Self, level: Level, msg: []const u8) void {
        // Need null-terminated message for syslog
        var syslog_buf: [1024:0]u8 = undefined;
        const len = @min(msg.len, syslog_buf.len - 1);
        @memcpy(syslog_buf[0..len], msg[0..len]);
        syslog_buf[len] = 0;

        const priority = @intFromEnum(self.facility) | @intFromEnum(level.toSyslogPriority());
        c.syslog(priority, "%s", &syslog_buf);
    }

    /// Log an authentication event (always goes to syslog)
    pub fn logAuth(self: *Self, user: []const u8, tty: []const u8, command: []const u8, allowed: bool) void {
        var buf: [512]u8 = undefined;
        const msg = if (allowed)
            std.fmt.bufPrint(&buf, "{s} : TTY={s} ; COMMAND={s}", .{ user, tty, command }) catch return
        else
            std.fmt.bufPrint(&buf, "{s} : TTY={s} ; COMMAND={s} ; NOT ALLOWED", .{ user, tty, command }) catch return;

        if (self.use_syslog) {
            if (!self.syslog_opened) {
                self.openSyslog(.{});
            }
            self.syslogWrite(if (allowed) .info else .warning, msg);
        }

        // Also write to stderr
        _ = std.posix.write(std.posix.STDERR_FILENO, self.prefix) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
        _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch return;
    }
};

/// Log to the global logger (if set)
pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (global_logger) |logger| {
        logger.log(level, fmt, args);
    }
}

/// Log a debug message (only in dev mode)
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

/// Log an info message
pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

/// Log a warning message
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warning, fmt, args);
}

/// Log an error message
pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

/// Print a warning to the user (always shown)
pub fn userWarn(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;

    if (global_logger) |logger| {
        _ = std.posix.write(std.posix.STDERR_FILENO, logger.prefix) catch return;
    }
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch return;
}

/// Print an error to the user (always shown)
pub fn userError(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;

    if (global_logger) |logger| {
        _ = std.posix.write(std.posix.STDERR_FILENO, logger.prefix) catch return;
    }
    _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, "\n") catch return;
}

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(mail);
    std.testing.refAllDecls(audit);
}

test "Level.toString" {
    try std.testing.expectEqualStrings("ERROR", Level.err.toString());
    try std.testing.expectEqualStrings("DEBUG", Level.debug.toString());
}
