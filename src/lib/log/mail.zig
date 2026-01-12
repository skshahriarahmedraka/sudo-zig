//! Mail notification for security events
//!
//! Sends email notifications for security-relevant sudo events such as
//! failed authentication, unauthorized access attempts, and policy violations.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// Mail configuration from sudoers Defaults
pub const MailConfig = struct {
    /// Send mail when user is not in sudoers
    mailto_user: bool = false,
    /// Send mail when user is denied
    mail_badpass: bool = false,
    /// Send mail on all sudo invocations
    mail_always: bool = false,
    /// Send mail when no user is allowed
    mail_no_user: bool = true,
    /// Send mail when no host is allowed
    mail_no_host: bool = false,
    /// Send mail when no perms match
    mail_no_perms: bool = true,
    /// Email address to send to
    mailto: []const u8 = "root",
    /// Mail subject prefix
    mail_subject: []const u8 = "*** SECURITY information for %h ***",
    /// Path to sendmail binary
    mailerpath: []const u8 = "/usr/sbin/sendmail",
    /// Mailer flags
    mailerflags: []const u8 = "-t",
};

/// Security event types that can trigger mail
pub const SecurityEvent = enum {
    /// User not found in sudoers
    user_not_in_sudoers,
    /// User denied by policy
    permission_denied,
    /// Bad password entered
    bad_password,
    /// Authentication failure (max attempts)
    auth_failure,
    /// Command not allowed
    command_denied,
    /// Host not allowed
    host_denied,
    /// Successful sudo (if mail_always)
    successful_sudo,
};

/// Mail sender for security notifications
pub const MailSender = struct {
    config: MailConfig,
    allocator: Allocator,
    hostname: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, config: MailConfig, hostname: []const u8) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .hostname = hostname,
        };
    }

    /// Check if mail should be sent for this event
    pub fn shouldSendMail(self: *Self, event: SecurityEvent) bool {
        return switch (event) {
            .user_not_in_sudoers => self.config.mail_no_user,
            .permission_denied => self.config.mail_no_perms,
            .bad_password => self.config.mail_badpass,
            .auth_failure => self.config.mail_badpass,
            .command_denied => self.config.mail_no_perms,
            .host_denied => self.config.mail_no_host,
            .successful_sudo => self.config.mail_always,
        };
    }

    /// Send mail notification for a security event
    pub fn sendMail(
        self: *Self,
        event: SecurityEvent,
        user: []const u8,
        command: ?[]const u8,
        details: ?[]const u8,
    ) !void {
        if (!self.shouldSendMail(event)) return;

        // Format the subject
        var subject_buf: [256]u8 = undefined;
        const subject = self.formatSubject(&subject_buf);

        // Format the message body
        var body_buf: [4096]u8 = undefined;
        const body = self.formatBody(&body_buf, event, user, command, details);

        // Send via sendmail
        try self.invokeSendmail(subject, body);
    }

    fn formatSubject(self: *Self, buf: []u8) []const u8 {
        // Replace %h with hostname in subject
        var result_len: usize = 0;
        var i: usize = 0;
        const template = self.config.mail_subject;

        while (i < template.len and result_len < buf.len) {
            if (i + 1 < template.len and template[i] == '%' and template[i + 1] == 'h') {
                // Replace %h with hostname
                const copy_len = @min(self.hostname.len, buf.len - result_len);
                @memcpy(buf[result_len..][0..copy_len], self.hostname[0..copy_len]);
                result_len += copy_len;
                i += 2;
            } else {
                buf[result_len] = template[i];
                result_len += 1;
                i += 1;
            }
        }

        return buf[0..result_len];
    }

    fn formatBody(
        self: *Self,
        buf: []u8,
        event: SecurityEvent,
        user: []const u8,
        command: ?[]const u8,
        details: ?[]const u8,
    ) []const u8 {
        _ = self;
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        // Event description
        const event_desc = switch (event) {
            .user_not_in_sudoers => "user NOT in sudoers",
            .permission_denied => "user NOT authorized on host",
            .bad_password => "incorrect password attempt",
            .auth_failure => "authentication failure",
            .command_denied => "command not allowed",
            .host_denied => "host not allowed",
            .successful_sudo => "sudo command executed",
        };

        writer.print("{s} ; {s}", .{ user, event_desc }) catch {};

        if (command) |cmd| {
            writer.print(" ; COMMAND={s}", .{cmd}) catch {};
        }

        if (details) |d| {
            writer.print(" ; {s}", .{d}) catch {};
        }

        writer.writeByte('\n') catch {};

        return buf[0..stream.pos];
    }

    fn invokeSendmail(self: *Self, subject: []const u8, body: []const u8) !void {
        // Build the full email message
        var msg_buf: [8192]u8 = undefined;
        var stream = std.io.fixedBufferStream(&msg_buf);
        const writer = stream.writer();

        try writer.print("To: {s}\n", .{self.config.mailto});
        try writer.print("Subject: {s}\n", .{subject});
        try writer.writeAll("Auto-Submitted: auto-generated\n");
        try writer.writeAll("X-Mailer: sudo-zig\n");
        try writer.writeAll("\n");
        try writer.writeAll(body);

        const message = msg_buf[0..stream.pos];

        // Fork and exec sendmail
        const pid = try posix.fork();

        if (pid == 0) {
            // Child process
            // Redirect stdin to read message
            const pipe = try posix.pipe();

            // Write message to pipe
            _ = posix.write(pipe[1], message) catch {};
            posix.close(pipe[1]);

            // Dup read end to stdin
            posix.dup2(pipe[0], posix.STDIN_FILENO) catch {};
            posix.close(pipe[0]);

            // Close stdout/stderr to avoid output
            posix.close(posix.STDOUT_FILENO);
            posix.close(posix.STDERR_FILENO);

            // Exec sendmail
            const path_z: [*:0]const u8 = @ptrCast(self.config.mailerpath.ptr);
            const argv = [_:null]?[*:0]const u8{
                path_z,
                @ptrCast(self.config.mailerflags.ptr),
                null,
            };
            const envp = [_:null]?[*:0]const u8{null};

            posix.execveZ(path_z, &argv, &envp) catch {};
            posix.exit(1);
        } else {
            // Parent - wait for child (don't block on mail errors)
            _ = posix.waitpid(pid, 0);
        }
    }
};

/// Quick helper to send security mail
pub fn sendSecurityMail(
    allocator: Allocator,
    config: MailConfig,
    hostname: []const u8,
    event: SecurityEvent,
    user: []const u8,
    command: ?[]const u8,
    details: ?[]const u8,
) void {
    var sender = MailSender.init(allocator, config, hostname);
    sender.sendMail(event, user, command, details) catch |err| {
        // Log error but don't fail - mail is best-effort
        std.log.warn("Failed to send security mail: {}", .{err});
    };
}

// ============================================
// Tests
// ============================================

test "MailConfig defaults" {
    const config = MailConfig{};
    try std.testing.expect(config.mail_no_user);
    try std.testing.expect(config.mail_no_perms);
    try std.testing.expect(!config.mail_always);
    try std.testing.expectEqualStrings("root", config.mailto);
}

test "shouldSendMail" {
    var sender = MailSender.init(std.testing.allocator, .{}, "testhost");

    try std.testing.expect(sender.shouldSendMail(.user_not_in_sudoers));
    try std.testing.expect(sender.shouldSendMail(.permission_denied));
    try std.testing.expect(!sender.shouldSendMail(.successful_sudo));
}

test "formatSubject replaces hostname" {
    var sender = MailSender.init(std.testing.allocator, .{}, "myhost");
    var buf: [256]u8 = undefined;
    const subject = sender.formatSubject(&buf);

    try std.testing.expect(std.mem.indexOf(u8, subject, "myhost") != null);
}

test "SecurityEvent enum" {
    try std.testing.expectEqual(SecurityEvent.user_not_in_sudoers, SecurityEvent.user_not_in_sudoers);
    try std.testing.expectEqual(SecurityEvent.bad_password, SecurityEvent.bad_password);
}
