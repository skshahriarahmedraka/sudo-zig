//! Unit tests for defaults/settings module
//!
//! Tests for sudoers Defaults parsing and settings management.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const defaults = lib.defaults;
const Settings = defaults.Settings;
const TimestampType = defaults.TimestampType;

// ============================================
// Settings Default Values Tests
// ============================================

test "Settings has correct default values" {
    const settings = Settings{};

    // Boolean defaults
    try testing.expect(settings.use_pty);
    try testing.expect(!settings.pwfeedback);
    try testing.expect(!settings.rootpw);
    try testing.expect(!settings.targetpw);
    try testing.expect(!settings.runaspw);
    try testing.expect(!settings.noexec);
    try testing.expect(!settings.setenv);
    try testing.expect(settings.env_reset);
    try testing.expect(settings.env_editor);
    try testing.expect(!settings.visiblepw);
    try testing.expect(!settings.insults);
    try testing.expect(!settings.requiretty);
    try testing.expect(!settings.mail_always);
    try testing.expect(!settings.mail_badpass);
    try testing.expect(settings.mail_no_user);
    try testing.expect(settings.mail_no_perms);
    try testing.expect(!settings.mail_no_host);
    try testing.expect(settings.set_home);
    try testing.expect(!settings.always_set_home);
    try testing.expect(settings.set_logname);
    try testing.expect(!settings.log_host);
    try testing.expect(!settings.log_year);
    try testing.expect(!settings.fqdn);
    try testing.expect(!settings.fast_glob);
    try testing.expect(settings.ignore_dot);

    // Integer defaults
    try testing.expectEqual(@as(u32, 3), settings.passwd_tries);
    try testing.expectEqual(@as(u64, 300), settings.passwd_timeout); // 5 minutes in seconds
    try testing.expectEqual(@as(u64, 900), settings.timestamp_timeout); // 15 minutes in seconds
    try testing.expectEqual(@as(u32, 0o022), settings.umask);
    try testing.expectEqual(@as(u32, 80), settings.loglinelen);

    // Enum defaults
    try testing.expectEqual(TimestampType.tty, settings.timestamp_type);

    // String defaults
    try testing.expectEqual(@as(?[]const u8, null), settings.secure_path);
    try testing.expectEqualStrings("[sudo] password for %p: ", settings.passprompt);
    try testing.expectEqualStrings("Sorry, try again.", settings.badpass_message);
    try testing.expectEqualStrings("/run/sudo/ts", settings.timestampdir);
    try testing.expectEqualStrings("root", settings.timestampowner);
}

// ============================================
// Settings.set() Tests
// ============================================

test "Settings.set passwd_tries" {
    var settings = Settings{};

    try settings.set("passwd_tries", "5");
    try testing.expectEqual(@as(u32, 5), settings.passwd_tries);

    try settings.set("passwd_tries", "1");
    try testing.expectEqual(@as(u32, 1), settings.passwd_tries);

    try settings.set("passwd_tries", "10");
    try testing.expectEqual(@as(u32, 10), settings.passwd_tries);
}

test "Settings.set string values" {
    var settings = Settings{};

    try settings.set("secure_path", "/usr/bin:/bin:/usr/sbin:/sbin");
    try testing.expectEqualStrings("/usr/bin:/bin:/usr/sbin:/sbin", settings.secure_path.?);

    try settings.set("badpass_message", "Access denied!");
    try testing.expectEqualStrings("Access denied!", settings.badpass_message);

    try settings.set("passprompt", "Enter password: ");
    try testing.expectEqualStrings("Enter password: ", settings.passprompt);

    try settings.set("editor", "/usr/bin/vim");
    try testing.expectEqualStrings("/usr/bin/vim", settings.editor);
}

test "Settings.set mailto" {
    var settings = Settings{};

    try settings.set("mailto", "admin@example.com");
    try testing.expectEqualStrings("admin@example.com", settings.mailto.?);

    try settings.set("mailfrom", "sudo@example.com");
    try testing.expectEqualStrings("sudo@example.com", settings.mailfrom.?);
}

test "Settings.set boolean as string" {
    var settings = Settings{};

    try settings.set("use_pty", "true");
    try testing.expect(settings.use_pty);

    try settings.set("pwfeedback", "yes");
    try testing.expect(settings.pwfeedback);

    try settings.set("env_reset", "1");
    try testing.expect(settings.env_reset);
}

test "Settings.set unknown setting returns error" {
    var settings = Settings{};
    const result = settings.set("unknown_setting", "value");
    try testing.expectError(error.UnknownSetting, result);
}

test "Settings.set invalid integer returns error" {
    var settings = Settings{};
    const result = settings.set("passwd_tries", "not_a_number");
    try testing.expectError(error.InvalidValue, result);
}

// ============================================
// Settings.negate() Tests
// ============================================

test "Settings.negate boolean settings" {
    var settings = Settings{};

    // Start with default true values
    try testing.expect(settings.use_pty);
    try settings.negate("use_pty");
    try testing.expect(!settings.use_pty);

    try testing.expect(settings.env_reset);
    try settings.negate("env_reset");
    try testing.expect(!settings.env_reset);

    try testing.expect(settings.set_home);
    try settings.negate("set_home");
    try testing.expect(!settings.set_home);
}

test "Settings.negate unknown setting returns error" {
    var settings = Settings{};
    const result = settings.negate("nonexistent");
    try testing.expectError(error.UnknownSetting, result);
}

// ============================================
// TimestampType Tests
// ============================================

test "TimestampType enum values" {
    try testing.expectEqual(@as(u2, 0), @intFromEnum(TimestampType.global));
    try testing.expectEqual(@as(u2, 1), @intFromEnum(TimestampType.tty));
    try testing.expectEqual(@as(u2, 2), @intFromEnum(TimestampType.ppid));
    try testing.expectEqual(@as(u2, 3), @intFromEnum(TimestampType.kernel));
}

// ============================================
// Environment List Tests
// ============================================

test "Settings default env_keep list" {
    const settings = Settings{};

    // Check that common environment variables are in keep list
    var found_path = false;
    var found_display = false;
    for (settings.env_keep) |env| {
        if (std.mem.eql(u8, env, "PATH")) found_path = true;
        if (std.mem.eql(u8, env, "DISPLAY")) found_display = true;
    }
    try testing.expect(found_path);
    try testing.expect(found_display);
}

test "Settings default env_delete list" {
    const settings = Settings{};

    // Check that dangerous environment variables are in delete list
    var found_ld = false;
    var found_ifs = false;
    for (settings.env_delete) |env| {
        if (std.mem.eql(u8, env, "IFS")) found_ifs = true;
        if (std.mem.eql(u8, env, "LD_*")) found_ld = true;
    }
    try testing.expect(found_ifs);
    try testing.expect(found_ld);
}

test "Settings default env_check list" {
    const settings = Settings{};

    // Check that common checked variables are present
    var found_term = false;
    var found_lang = false;
    for (settings.env_check) |env| {
        if (std.mem.eql(u8, env, "TERM")) found_term = true;
        if (std.mem.eql(u8, env, "LANG")) found_lang = true;
    }
    try testing.expect(found_term);
    try testing.expect(found_lang);
}
