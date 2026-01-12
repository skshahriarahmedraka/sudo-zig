//! Unit tests for logging infrastructure
//!
//! Tests for log levels, mail notifications, and audit logging.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const log = lib.log;
const Level = log.Level;
const Facility = log.Facility;
const Priority = log.Priority;
const SudoLogger = log.SudoLogger;
const MailConfig = log.MailConfig;
const MailSender = log.MailSender;
const SecurityEvent = log.SecurityEvent;
const AuditEvent = log.AuditEvent;
const AuditRecord = log.AuditRecord;
const AuditConfig = log.AuditConfig;
const AuditLogger = log.AuditLogger;

// ============================================
// Log Level Tests
// ============================================

test "Level.toString returns correct strings" {
    try testing.expectEqualStrings("DEBUG", Level.debug.toString());
    try testing.expectEqualStrings("INFO", Level.info.toString());
    try testing.expectEqualStrings("WARNING", Level.warning.toString());
    try testing.expectEqualStrings("ERROR", Level.err.toString());
    try testing.expectEqualStrings("CRITICAL", Level.critical.toString());
}

test "Level.toSyslogPriority returns correct priorities" {
    try testing.expectEqual(Priority.debug, Level.debug.toSyslogPriority());
    try testing.expectEqual(Priority.info, Level.info.toSyslogPriority());
    try testing.expectEqual(Priority.warning, Level.warning.toSyslogPriority());
    try testing.expectEqual(Priority.err, Level.err.toSyslogPriority());
    try testing.expectEqual(Priority.crit, Level.critical.toSyslogPriority());
}

// ============================================
// SudoLogger Tests
// ============================================

test "SudoLogger.init creates logger with prefix" {
    const logger = SudoLogger.init("sudo: ");
    try testing.expectEqualStrings("sudo: ", logger.prefix);
    try testing.expect(logger.use_syslog);
    try testing.expect(!logger.syslog_opened);
}

test "SudoLogger.initWithSyslog creates custom logger" {
    const logger = SudoLogger.initWithSyslog("test: ", .local0, false);
    try testing.expectEqualStrings("test: ", logger.prefix);
    try testing.expect(!logger.use_syslog);
    try testing.expectEqual(Facility.local0, logger.facility);
}

// ============================================
// MailConfig Tests
// ============================================

test "MailConfig default values" {
    const config = MailConfig{};

    try testing.expect(!config.mailto_user);
    try testing.expect(!config.mail_badpass);
    try testing.expect(!config.mail_always);
    try testing.expect(config.mail_no_user);
    try testing.expect(!config.mail_no_host);
    try testing.expect(config.mail_no_perms);
    try testing.expectEqualStrings("root", config.mailto);
    try testing.expectEqualStrings("/usr/sbin/sendmail", config.mailerpath);
    try testing.expectEqualStrings("-t", config.mailerflags);
}

test "MailConfig custom values" {
    const config = MailConfig{
        .mailto = "admin@example.com",
        .mail_always = true,
        .mail_badpass = true,
        .mailerpath = "/usr/bin/msmtp",
    };

    try testing.expectEqualStrings("admin@example.com", config.mailto);
    try testing.expect(config.mail_always);
    try testing.expect(config.mail_badpass);
    try testing.expectEqualStrings("/usr/bin/msmtp", config.mailerpath);
}

// ============================================
// SecurityEvent Tests
// ============================================

test "SecurityEvent enum values" {
    // Test that all security events are distinct
    const events = [_]SecurityEvent{
        .user_not_in_sudoers,
        .permission_denied,
        .bad_password,
        .auth_failure,
        .command_denied,
        .host_denied,
        .successful_sudo,
    };

    for (events, 0..) |e1, i| {
        for (events[i + 1 ..]) |e2| {
            try testing.expect(e1 != e2);
        }
    }
}

// ============================================
// MailSender Tests
// ============================================

test "MailSender.shouldSendMail with defaults" {
    var sender = MailSender.init(testing.allocator, .{}, "localhost");

    // Default config: mail_no_user and mail_no_perms are true
    try testing.expect(sender.shouldSendMail(.user_not_in_sudoers));
    try testing.expect(sender.shouldSendMail(.permission_denied));
    try testing.expect(sender.shouldSendMail(.command_denied));

    // Default config: these are false
    try testing.expect(!sender.shouldSendMail(.bad_password));
    try testing.expect(!sender.shouldSendMail(.auth_failure));
    try testing.expect(!sender.shouldSendMail(.host_denied));
    try testing.expect(!sender.shouldSendMail(.successful_sudo));
}

test "MailSender.shouldSendMail with mail_always" {
    const config = MailConfig{ .mail_always = true };
    var sender = MailSender.init(testing.allocator, config, "localhost");

    try testing.expect(sender.shouldSendMail(.successful_sudo));
}

test "MailSender.shouldSendMail with mail_badpass" {
    const config = MailConfig{ .mail_badpass = true };
    var sender = MailSender.init(testing.allocator, config, "localhost");

    try testing.expect(sender.shouldSendMail(.bad_password));
    try testing.expect(sender.shouldSendMail(.auth_failure));
}

// Note: formatSubject is a private function, tested via inline tests in mail.zig

// ============================================
// AuditEvent Tests
// ============================================

test "AuditEvent.toString returns correct strings" {
    try testing.expectEqualStrings("AUTH_SUCCESS", AuditEvent.auth_success.toString());
    try testing.expectEqualStrings("AUTH_FAILURE", AuditEvent.auth_failure.toString());
    try testing.expectEqualStrings("COMMAND_ALLOWED", AuditEvent.command_allowed.toString());
    try testing.expectEqualStrings("COMMAND_DENIED", AuditEvent.command_denied.toString());
    try testing.expectEqualStrings("USER_UNKNOWN", AuditEvent.user_unknown.toString());
    try testing.expectEqualStrings("SESSION_OPEN", AuditEvent.session_open.toString());
    try testing.expectEqualStrings("SESSION_CLOSE", AuditEvent.session_close.toString());
    try testing.expectEqualStrings("TIMESTAMP_UPDATE", AuditEvent.timestamp_update.toString());
    try testing.expectEqualStrings("TIMESTAMP_REMOVE", AuditEvent.timestamp_remove.toString());
    try testing.expectEqualStrings("CONFIG_ERROR", AuditEvent.config_error.toString());
    try testing.expectEqualStrings("EDIT_FILE", AuditEvent.edit_file.toString());
}

test "AuditEvent.isFailure identifies failures correctly" {
    // These should be failures
    try testing.expect(AuditEvent.auth_failure.isFailure());
    try testing.expect(AuditEvent.command_denied.isFailure());
    try testing.expect(AuditEvent.user_unknown.isFailure());
    try testing.expect(AuditEvent.config_error.isFailure());

    // These should NOT be failures
    try testing.expect(!AuditEvent.auth_success.isFailure());
    try testing.expect(!AuditEvent.command_allowed.isFailure());
    try testing.expect(!AuditEvent.session_open.isFailure());
    try testing.expect(!AuditEvent.session_close.isFailure());
    try testing.expect(!AuditEvent.timestamp_update.isFailure());
    try testing.expect(!AuditEvent.edit_file.isFailure());
}

// ============================================
// AuditRecord Tests
// ============================================

test "AuditRecord.format includes all fields" {
    const record = AuditRecord{
        .event = .command_allowed,
        .timestamp = 1704067200,
        .invoking_user = "alice",
        .invoking_uid = 1000,
        .target_user = "root",
        .target_uid = 0,
        .hostname = "server1",
        .tty = "pts/0",
        .cwd = "/home/alice",
        .command = "/usr/bin/apt",
        .arguments = "update",
        .result = 0,
    };

    var buf: [2048]u8 = undefined;
    const formatted = record.format(&buf);

    try testing.expect(std.mem.indexOf(u8, formatted, "1704067200") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "COMMAND_ALLOWED") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "alice@server1") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, ":pts/0") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "[root]") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "CMD=/usr/bin/apt") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "update") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "CWD=/home/alice") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "RESULT=0") != null);
}

test "AuditRecord.format minimal record" {
    const record = AuditRecord{
        .event = .auth_failure,
        .timestamp = 1704067200,
        .invoking_user = "bob",
        .invoking_uid = 1001,
        .hostname = "localhost",
    };

    var buf: [2048]u8 = undefined;
    const formatted = record.format(&buf);

    try testing.expect(std.mem.indexOf(u8, formatted, "AUTH_FAILURE") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "bob@localhost") != null);
    // Should not have optional fields
    try testing.expect(std.mem.indexOf(u8, formatted, "CMD=") == null);
    try testing.expect(std.mem.indexOf(u8, formatted, "CWD=") == null);
}

test "AuditRecord.format with message" {
    const record = AuditRecord{
        .event = .auth_failure,
        .timestamp = 1704067200,
        .invoking_user = "eve",
        .invoking_uid = 1002,
        .hostname = "secure-server",
        .message = "3 incorrect password attempts",
    };

    var buf: [2048]u8 = undefined;
    const formatted = record.format(&buf);

    try testing.expect(std.mem.indexOf(u8, formatted, "MSG=\"3 incorrect password attempts\"") != null);
}

test "AuditRecord.formatJson produces valid JSON structure" {
    const record = AuditRecord{
        .event = .command_allowed,
        .timestamp = 1704067200,
        .invoking_user = "alice",
        .invoking_uid = 1000,
        .target_user = "root",
        .target_uid = 0,
        .hostname = "server1",
        .command = "/bin/ls",
    };

    var buf: [4096]u8 = undefined;
    const json = record.formatJson(&buf);

    // Check JSON structure
    try testing.expect(std.mem.startsWith(u8, json, "{"));
    try testing.expect(std.mem.endsWith(u8, json, "}"));

    // Check required fields
    try testing.expect(std.mem.indexOf(u8, json, "\"timestamp\":1704067200") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"event\":\"COMMAND_ALLOWED\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"user\":\"alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"uid\":1000") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"host\":\"server1\"") != null);

    // Check optional fields
    try testing.expect(std.mem.indexOf(u8, json, "\"runas_user\":\"root\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"runas_uid\":0") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"command\":\"/bin/ls\"") != null);
}

test "AuditRecord.formatJson minimal record" {
    const record = AuditRecord{
        .event = .session_close,
        .timestamp = 1704067200,
        .invoking_user = "user",
        .invoking_uid = 1000,
        .hostname = "host",
    };

    var buf: [4096]u8 = undefined;
    const json = record.formatJson(&buf);

    // Should not have optional fields
    try testing.expect(std.mem.indexOf(u8, json, "runas_user") == null);
    try testing.expect(std.mem.indexOf(u8, json, "command") == null);
    try testing.expect(std.mem.indexOf(u8, json, "tty") == null);
}

// ============================================
// AuditConfig Tests
// ============================================

test "AuditConfig default values" {
    const config = AuditConfig{};

    try testing.expect(config.log_allowed);
    try testing.expect(config.log_denied);
    try testing.expect(config.log_auth);
    try testing.expectEqualStrings("/var/log/sudo.log", config.log_file);
    try testing.expectEqualStrings("/var/log/sudo.json", config.json_file);
}

test "AuditConfig custom backends" {
    const config = AuditConfig{
        .backends = &.{ .syslog, .file, .json_file },
        .log_file = "/var/log/custom-sudo.log",
    };

    try testing.expectEqual(@as(usize, 3), config.backends.len);
    try testing.expectEqualStrings("/var/log/custom-sudo.log", config.log_file);
}

// ============================================
// AuditLogger Tests
// ============================================

test "AuditLogger.init creates logger" {
    var logger = AuditLogger.init(testing.allocator, .{});
    defer logger.deinit();

    try testing.expect(logger.config.log_allowed);
    try testing.expect(logger.config.log_denied);
}

// Note: shouldLog is a private function, tested via inline tests in audit.zig
// We test the config flags indirectly through the public interface

test "AuditLogger config flags are set correctly" {
    // Test with log_allowed = false
    var logger1 = AuditLogger.init(testing.allocator, .{ .log_allowed = false });
    defer logger1.deinit();
    try testing.expect(!logger1.config.log_allowed);

    // Test with log_denied = false
    var logger2 = AuditLogger.init(testing.allocator, .{ .log_denied = false });
    defer logger2.deinit();
    try testing.expect(!logger2.config.log_denied);

    // Test with log_auth = false
    var logger3 = AuditLogger.init(testing.allocator, .{ .log_auth = false });
    defer logger3.deinit();
    try testing.expect(!logger3.config.log_auth);
}

// ============================================
// Facility Tests
// ============================================

test "Facility enum values" {
    // Just verify these compile and have distinct values
    const facilities = [_]Facility{
        .auth,
        .authpriv,
        .daemon,
        .local0,
        .local1,
        .local2,
        .local3,
        .local4,
        .local5,
        .local6,
        .local7,
        .user,
    };

    for (facilities, 0..) |f1, i| {
        for (facilities[i + 1 ..]) |f2| {
            try testing.expect(@intFromEnum(f1) != @intFromEnum(f2));
        }
    }
}

// ============================================
// Priority Tests
// ============================================

test "Priority enum values are ordered" {
    // Syslog priorities should be in severity order (lower = more severe)
    try testing.expect(@intFromEnum(Priority.emerg) < @intFromEnum(Priority.alert));
    try testing.expect(@intFromEnum(Priority.alert) < @intFromEnum(Priority.crit));
    try testing.expect(@intFromEnum(Priority.crit) < @intFromEnum(Priority.err));
    try testing.expect(@intFromEnum(Priority.err) < @intFromEnum(Priority.warning));
    try testing.expect(@intFromEnum(Priority.warning) < @intFromEnum(Priority.notice));
    try testing.expect(@intFromEnum(Priority.notice) < @intFromEnum(Priority.info));
    try testing.expect(@intFromEnum(Priority.info) < @intFromEnum(Priority.debug));
}
