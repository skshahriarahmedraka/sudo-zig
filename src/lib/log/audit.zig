//! Audit logging for sudo events
//!
//! Provides audit trail logging for security-relevant sudo operations.
//! Supports multiple backends: syslog, file, and Linux audit subsystem.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// Audit event types
pub const AuditEvent = enum {
    /// User authentication succeeded
    auth_success,
    /// User authentication failed
    auth_failure,
    /// Command authorized and executed
    command_allowed,
    /// Command denied by policy
    command_denied,
    /// User not in sudoers
    user_unknown,
    /// Session started
    session_open,
    /// Session closed
    session_close,
    /// Timestamp updated
    timestamp_update,
    /// Timestamp removed
    timestamp_remove,
    /// Configuration error
    config_error,
    /// sudoedit file edited
    edit_file,

    pub fn toString(self: AuditEvent) []const u8 {
        return switch (self) {
            .auth_success => "AUTH_SUCCESS",
            .auth_failure => "AUTH_FAILURE",
            .command_allowed => "COMMAND_ALLOWED",
            .command_denied => "COMMAND_DENIED",
            .user_unknown => "USER_UNKNOWN",
            .session_open => "SESSION_OPEN",
            .session_close => "SESSION_CLOSE",
            .timestamp_update => "TIMESTAMP_UPDATE",
            .timestamp_remove => "TIMESTAMP_REMOVE",
            .config_error => "CONFIG_ERROR",
            .edit_file => "EDIT_FILE",
        };
    }

    pub fn isFailure(self: AuditEvent) bool {
        return switch (self) {
            .auth_failure, .command_denied, .user_unknown, .config_error => true,
            else => false,
        };
    }
};

/// Audit record with all relevant information
pub const AuditRecord = struct {
    /// Event type
    event: AuditEvent,
    /// Unix timestamp
    timestamp: i64,
    /// User invoking sudo
    invoking_user: []const u8,
    /// User's UID
    invoking_uid: u32,
    /// Target user (runas)
    target_user: ?[]const u8 = null,
    /// Target UID
    target_uid: ?u32 = null,
    /// Hostname
    hostname: []const u8,
    /// TTY device
    tty: ?[]const u8 = null,
    /// Current working directory
    cwd: ?[]const u8 = null,
    /// Command executed
    command: ?[]const u8 = null,
    /// Command arguments
    arguments: ?[]const u8 = null,
    /// Result/exit code
    result: ?i32 = null,
    /// Additional message
    message: ?[]const u8 = null,

    /// Format as a log line
    pub fn format(self: *const AuditRecord, buf: []u8) []const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        // Format: timestamp event user@host:tty [runas] command
        writer.print("{d} {s} {s}@{s}", .{
            self.timestamp,
            self.event.toString(),
            self.invoking_user,
            self.hostname,
        }) catch {};

        if (self.tty) |tty| {
            writer.print(":{s}", .{tty}) catch {};
        }

        if (self.target_user) |target| {
            writer.print(" [{s}]", .{target}) catch {};
        }

        if (self.command) |cmd| {
            writer.print(" CMD={s}", .{cmd}) catch {};
            if (self.arguments) |args| {
                writer.print(" {s}", .{args}) catch {};
            }
        }

        if (self.cwd) |cwd| {
            writer.print(" CWD={s}", .{cwd}) catch {};
        }

        if (self.result) |res| {
            writer.print(" RESULT={d}", .{res}) catch {};
        }

        if (self.message) |msg| {
            writer.print(" MSG=\"{s}\"", .{msg}) catch {};
        }

        return buf[0..stream.pos];
    }

    /// Format as JSON
    pub fn formatJson(self: *const AuditRecord, buf: []u8) []const u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        writer.writeAll("{") catch {};
        writer.print("\"timestamp\":{d},", .{self.timestamp}) catch {};
        writer.print("\"event\":\"{s}\",", .{self.event.toString()}) catch {};
        writer.print("\"user\":\"{s}\",", .{self.invoking_user}) catch {};
        writer.print("\"uid\":{d},", .{self.invoking_uid}) catch {};
        writer.print("\"host\":\"{s}\"", .{self.hostname}) catch {};

        if (self.target_user) |target| {
            writer.print(",\"runas_user\":\"{s}\"", .{target}) catch {};
        }
        if (self.target_uid) |uid| {
            writer.print(",\"runas_uid\":{d}", .{uid}) catch {};
        }
        if (self.tty) |tty| {
            writer.print(",\"tty\":\"{s}\"", .{tty}) catch {};
        }
        if (self.cwd) |cwd| {
            writer.print(",\"cwd\":\"{s}\"", .{cwd}) catch {};
        }
        if (self.command) |cmd| {
            writer.print(",\"command\":\"{s}\"", .{cmd}) catch {};
        }
        if (self.arguments) |args| {
            writer.print(",\"arguments\":\"{s}\"", .{args}) catch {};
        }
        if (self.result) |res| {
            writer.print(",\"result\":{d}", .{res}) catch {};
        }
        if (self.message) |msg| {
            writer.print(",\"message\":\"{s}\"", .{msg}) catch {};
        }

        writer.writeAll("}") catch {};

        return buf[0..stream.pos];
    }
};

/// Audit backend types
pub const AuditBackend = enum {
    syslog,
    file,
    linux_audit,
    json_file,
};

/// Audit logger configuration
pub const AuditConfig = struct {
    /// Enabled backends
    backends: []const AuditBackend = &.{.syslog},
    /// Log file path (for file backend)
    log_file: []const u8 = "/var/log/sudo.log",
    /// JSON log file path
    json_file: []const u8 = "/var/log/sudo.json",
    /// Syslog facility
    syslog_facility: u8 = 10, // LOG_AUTHPRIV
    /// Log successful commands
    log_allowed: bool = true,
    /// Log denied commands
    log_denied: bool = true,
    /// Log authentication events
    log_auth: bool = true,
};

/// Audit logger
pub const AuditLogger = struct {
    config: AuditConfig,
    allocator: Allocator,
    log_file: ?std.fs.File = null,
    json_file: ?std.fs.File = null,

    const Self = @This();

    pub fn init(allocator: Allocator, config: AuditConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.log_file) |f| f.close();
        if (self.json_file) |f| f.close();
    }

    /// Log an audit event
    pub fn log(self: *Self, record: AuditRecord) void {
        // Check if we should log this event type
        if (!self.shouldLog(record.event)) return;

        for (self.config.backends) |backend| {
            switch (backend) {
                .syslog => self.logToSyslog(&record),
                .file => self.logToFile(&record),
                .json_file => self.logToJsonFile(&record),
                .linux_audit => self.logToLinuxAudit(&record),
            }
        }
    }

    fn shouldLog(self: *Self, event: AuditEvent) bool {
        return switch (event) {
            .command_allowed, .session_open, .session_close => self.config.log_allowed,
            .command_denied, .user_unknown => self.config.log_denied,
            .auth_success, .auth_failure => self.config.log_auth,
            else => true,
        };
    }

    fn logToSyslog(self: *Self, record: *const AuditRecord) void {
        _ = self;
        var buf: [2048]u8 = undefined;
        const msg = record.format(&buf);

        // Use C syslog
        const c = @cImport({
            @cInclude("syslog.h");
        });

        const priority: c_int = if (record.event.isFailure())
            c.LOG_WARNING
        else
            c.LOG_INFO;

        // Null-terminate for C
        var msg_z: [2049]u8 = undefined;
        @memcpy(msg_z[0..msg.len], msg);
        msg_z[msg.len] = 0;

        c.syslog(priority, "%s", &msg_z);
    }

    fn logToFile(self: *Self, record: *const AuditRecord) void {
        const file = self.log_file orelse blk: {
            self.log_file = std.fs.createFileAbsolute(self.config.log_file, .{
                .truncate = false,
            }) catch return;
            // Seek to end
            if (self.log_file) |f| {
                f.seekFromEnd(0) catch {};
            }
            break :blk self.log_file.?;
        };

        var buf: [2048]u8 = undefined;
        const msg = record.format(&buf);

        file.writeAll(msg) catch {};
        file.writeAll("\n") catch {};
    }

    fn logToJsonFile(self: *Self, record: *const AuditRecord) void {
        const file = self.json_file orelse blk: {
            self.json_file = std.fs.createFileAbsolute(self.config.json_file, .{
                .truncate = false,
            }) catch return;
            if (self.json_file) |f| {
                f.seekFromEnd(0) catch {};
            }
            break :blk self.json_file.?;
        };

        var buf: [4096]u8 = undefined;
        const json = record.formatJson(&buf);

        file.writeAll(json) catch {};
        file.writeAll("\n") catch {};
    }

    fn logToLinuxAudit(self: *Self, record: *const AuditRecord) void {
        _ = self;
        // Linux audit subsystem via netlink
        // This is a simplified version - full implementation would use
        // libaudit or direct netlink socket
        //
        // Note: NETLINK_AUDIT may not be available on all systems.
        // In production, this should use libaudit for proper audit logging.

        var buf: [2048]u8 = undefined;
        const msg = record.format(&buf);

        // Format audit message
        var audit_buf: [2100]u8 = undefined;
        const audit_msg = std.fmt.bufPrint(&audit_buf, "op=sudo {s}", .{msg}) catch return;

        // For now, just log to syslog as a fallback since netlink audit
        // requires kernel headers that may not be available
        const c_syslog = @cImport({
            @cInclude("syslog.h");
        });

        var msg_z: [2101]u8 = undefined;
        @memcpy(msg_z[0..audit_msg.len], audit_msg);
        msg_z[audit_msg.len] = 0;

        c_syslog.syslog(c_syslog.LOG_AUTH | c_syslog.LOG_INFO, "%s", &msg_z);
    }

    /// Convenience method to create and log a command event
    pub fn logCommand(
        self: *Self,
        allowed: bool,
        invoking_user: []const u8,
        invoking_uid: u32,
        target_user: []const u8,
        target_uid: u32,
        hostname: []const u8,
        tty: ?[]const u8,
        cwd: ?[]const u8,
        command: []const u8,
        arguments: ?[]const u8,
    ) void {
        const record = AuditRecord{
            .event = if (allowed) .command_allowed else .command_denied,
            .timestamp = std.time.timestamp(),
            .invoking_user = invoking_user,
            .invoking_uid = invoking_uid,
            .target_user = target_user,
            .target_uid = target_uid,
            .hostname = hostname,
            .tty = tty,
            .cwd = cwd,
            .command = command,
            .arguments = arguments,
        };
        self.log(record);
    }

    /// Log authentication event
    pub fn logAuth(
        self: *Self,
        success: bool,
        user: []const u8,
        uid: u32,
        hostname: []const u8,
        tty: ?[]const u8,
        message: ?[]const u8,
    ) void {
        const record = AuditRecord{
            .event = if (success) .auth_success else .auth_failure,
            .timestamp = std.time.timestamp(),
            .invoking_user = user,
            .invoking_uid = uid,
            .hostname = hostname,
            .tty = tty,
            .message = message,
        };
        self.log(record);
    }
};

/// Global audit logger instance
var global_audit_logger: ?*AuditLogger = null;

pub fn setGlobalAuditLogger(logger: *AuditLogger) void {
    global_audit_logger = logger;
}

pub fn getGlobalAuditLogger() ?*AuditLogger {
    return global_audit_logger;
}

/// Quick audit log function using global logger
pub fn audit(record: AuditRecord) void {
    if (global_audit_logger) |logger| {
        logger.log(record);
    }
}

// ============================================
// Tests
// ============================================

test "AuditEvent toString" {
    try std.testing.expectEqualStrings("AUTH_SUCCESS", AuditEvent.auth_success.toString());
    try std.testing.expectEqualStrings("COMMAND_DENIED", AuditEvent.command_denied.toString());
}

test "AuditEvent isFailure" {
    try std.testing.expect(AuditEvent.auth_failure.isFailure());
    try std.testing.expect(AuditEvent.command_denied.isFailure());
    try std.testing.expect(!AuditEvent.command_allowed.isFailure());
    try std.testing.expect(!AuditEvent.auth_success.isFailure());
}

test "AuditRecord format" {
    const record = AuditRecord{
        .event = .command_allowed,
        .timestamp = 1704067200,
        .invoking_user = "alice",
        .invoking_uid = 1000,
        .target_user = "root",
        .hostname = "localhost",
        .command = "/usr/bin/ls",
    };

    var buf: [2048]u8 = undefined;
    const formatted = record.format(&buf);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "COMMAND_ALLOWED") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "[root]") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "/usr/bin/ls") != null);
}

test "AuditRecord formatJson" {
    const record = AuditRecord{
        .event = .auth_failure,
        .timestamp = 1704067200,
        .invoking_user = "bob",
        .invoking_uid = 1001,
        .hostname = "server1",
        .message = "3 incorrect attempts",
    };

    var buf: [4096]u8 = undefined;
    const json = record.formatJson(&buf);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"event\":\"AUTH_FAILURE\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"user\":\"bob\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"3 incorrect attempts\"") != null);
}

test "AuditConfig defaults" {
    const config = AuditConfig{};
    try std.testing.expect(config.log_allowed);
    try std.testing.expect(config.log_denied);
    try std.testing.expectEqualStrings("/var/log/sudo.log", config.log_file);
}
