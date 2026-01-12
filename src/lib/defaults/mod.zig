//! Default settings from sudoers
//!
//! Manages the Defaults entries from sudoers files.
//! This module provides a way to apply parsed Defaults from sudoers AST
//! to a Settings structure that controls sudo behavior.

const std = @import("std");
const ast = @import("../sudoers/ast.zig");

/// Default settings that can be configured in sudoers
pub const Settings = struct {
    // Boolean flags
    use_pty: bool = true,
    pwfeedback: bool = false,
    rootpw: bool = false,
    targetpw: bool = false,
    runaspw: bool = false,
    noexec: bool = false,
    noninteractive_auth: bool = false,
    setenv: bool = false,
    env_reset: bool = true,
    env_editor: bool = true,
    umask_override: bool = false,
    visiblepw: bool = false,
    insults: bool = false,
    requiretty: bool = false,
    mail_always: bool = false,
    mail_badpass: bool = false,
    mail_no_user: bool = true,
    mail_no_perms: bool = true,
    mail_no_host: bool = false,
    stay_setuid: bool = false,
    set_home: bool = true,
    always_set_home: bool = false,
    shell_noargs: bool = false,
    set_logname: bool = true,
    log_host: bool = false,
    log_year: bool = false,
    fqdn: bool = false,
    fast_glob: bool = false,
    ignore_dot: bool = true,
    ignore_local_sudoers: bool = false,

    // Integer values
    passwd_tries: u32 = 3,
    passwd_timeout: u64 = 5 * 60, // seconds
    timestamp_timeout: u64 = 15 * 60, // seconds
    command_timeout: u32 = 0, // seconds, 0 = no timeout
    umask: u32 = 0o022,
    loglinelen: u32 = 80,
    timestamp_type: TimestampType = .tty,

    // String values
    secure_path: ?[]const u8 = null,
    editor: []const u8 = "/usr/bin/editor:/usr/bin/nano:/usr/bin/vi",
    apparmor_profile: ?[]const u8 = null,
    badpass_message: []const u8 = "Sorry, try again.",
    passprompt: []const u8 = "[sudo] password for %p: ",
    mailsub: []const u8 = "*** SECURITY information for %h ***",
    mailfrom: ?[]const u8 = null,
    mailto: ?[]const u8 = null,
    sudoers_locale: []const u8 = "C",
    timestampdir: []const u8 = "/run/sudo/ts",
    timestampowner: []const u8 = "root",
    lecture_file: ?[]const u8 = null,

    // List values (stored as comma-separated for simplicity)
    env_keep: []const []const u8 = &default_env_keep,
    env_check: []const []const u8 = &default_env_check,
    env_delete: []const []const u8 = &default_env_delete,

    const Self = @This();

    /// Apply all Defaults from a parsed sudoers structure
    pub fn applyFromSudoers(self: *Self, sudoers: *const ast.Sudoers) void {
        for (sudoers.defaults.items) |default| {
            // Only apply global scope defaults for now
            // User/host/command specific defaults require context
            switch (default.scope) {
                .global => self.applyDefault(&default) catch {},
                else => {}, // Skip scoped defaults - they need runtime evaluation
            }
        }
    }

    /// Apply a single Default from the AST
    pub fn applyDefault(self: *Self, default: *const ast.Default) !void {
        switch (default.operator) {
            .negate => try self.negate(default.name),
            .set => {
                if (default.value) |value| {
                    try self.applyValue(default.name, value);
                } else {
                    // Setting without value = enable boolean
                    try self.enableBoolean(default.name);
                }
            },
            .add => {
                // += for list values
                if (default.value) |value| {
                    try self.addToList(default.name, value);
                }
            },
            .remove => {
                // -= for list values
                if (default.value) |value| {
                    try self.removeFromList(default.name, value);
                }
            },
        }
    }

    /// Apply a value to a setting
    fn applyValue(self: *Self, name: []const u8, value: ast.DefaultValue) !void {
        switch (value) {
            .boolean => |b| try self.setBoolean(name, b),
            .string => |s| try self.set(name, s),
            .integer => |i| try self.setInteger(name, i),
            .list => {}, // Lists handled separately
        }
    }

    /// Enable a boolean setting (no value specified)
    fn enableBoolean(self: *Self, name: []const u8) !void {
        try self.setBoolean(name, true);
    }

    /// Set a boolean setting
    fn setBoolean(self: *Self, name: []const u8, value: bool) !void {
        if (std.mem.eql(u8, name, "use_pty")) {
            self.use_pty = value;
        } else if (std.mem.eql(u8, name, "pwfeedback")) {
            self.pwfeedback = value;
        } else if (std.mem.eql(u8, name, "env_reset")) {
            self.env_reset = value;
        } else if (std.mem.eql(u8, name, "rootpw")) {
            self.rootpw = value;
        } else if (std.mem.eql(u8, name, "targetpw")) {
            self.targetpw = value;
        } else if (std.mem.eql(u8, name, "runaspw")) {
            self.runaspw = value;
        } else if (std.mem.eql(u8, name, "noexec")) {
            self.noexec = value;
        } else if (std.mem.eql(u8, name, "setenv")) {
            self.setenv = value;
        } else if (std.mem.eql(u8, name, "visiblepw")) {
            self.visiblepw = value;
        } else if (std.mem.eql(u8, name, "insults")) {
            self.insults = value;
        } else if (std.mem.eql(u8, name, "requiretty")) {
            self.requiretty = value;
        } else if (std.mem.eql(u8, name, "mail_always")) {
            self.mail_always = value;
        } else if (std.mem.eql(u8, name, "mail_badpass")) {
            self.mail_badpass = value;
        } else if (std.mem.eql(u8, name, "mail_no_user")) {
            self.mail_no_user = value;
        } else if (std.mem.eql(u8, name, "mail_no_perms")) {
            self.mail_no_perms = value;
        } else if (std.mem.eql(u8, name, "mail_no_host")) {
            self.mail_no_host = value;
        } else if (std.mem.eql(u8, name, "stay_setuid")) {
            self.stay_setuid = value;
        } else if (std.mem.eql(u8, name, "set_home")) {
            self.set_home = value;
        } else if (std.mem.eql(u8, name, "always_set_home")) {
            self.always_set_home = value;
        } else if (std.mem.eql(u8, name, "shell_noargs")) {
            self.shell_noargs = value;
        } else if (std.mem.eql(u8, name, "set_logname")) {
            self.set_logname = value;
        } else if (std.mem.eql(u8, name, "log_host")) {
            self.log_host = value;
        } else if (std.mem.eql(u8, name, "log_year")) {
            self.log_year = value;
        } else if (std.mem.eql(u8, name, "fqdn")) {
            self.fqdn = value;
        } else if (std.mem.eql(u8, name, "fast_glob")) {
            self.fast_glob = value;
        } else if (std.mem.eql(u8, name, "ignore_dot")) {
            self.ignore_dot = value;
        } else if (std.mem.eql(u8, name, "ignore_local_sudoers")) {
            self.ignore_local_sudoers = value;
        } else if (std.mem.eql(u8, name, "env_editor")) {
            self.env_editor = value;
        } else if (std.mem.eql(u8, name, "umask_override")) {
            self.umask_override = value;
        } else {
            return error.UnknownSetting;
        }
    }

    /// Set an integer setting
    fn setInteger(self: *Self, name: []const u8, value: i64) !void {
        if (std.mem.eql(u8, name, "passwd_tries")) {
            self.passwd_tries = @intCast(@max(0, value));
        } else if (std.mem.eql(u8, name, "passwd_timeout")) {
            self.passwd_timeout = @intCast(@max(0, value * 60));
        } else if (std.mem.eql(u8, name, "timestamp_timeout")) {
            self.timestamp_timeout = @intCast(@max(0, value * 60));
        } else if (std.mem.eql(u8, name, "command_timeout")) {
            self.command_timeout = @intCast(@max(0, value));
        } else if (std.mem.eql(u8, name, "umask")) {
            self.umask = @intCast(@max(0, value));
        } else if (std.mem.eql(u8, name, "loglinelen")) {
            self.loglinelen = @intCast(@max(0, value));
        } else {
            return error.UnknownSetting;
        }
    }

    /// Add to a list setting
    fn addToList(self: *Self, name: []const u8, value: ast.DefaultValue) !void {
        // For now, we can't dynamically modify the list slices
        // This would require allocator support
        _ = self;
        _ = name;
        _ = value;
    }

    /// Remove from a list setting
    fn removeFromList(self: *Self, name: []const u8, value: ast.DefaultValue) !void {
        _ = self;
        _ = name;
        _ = value;
    }

    /// Apply a setting by name (string value)
    pub fn set(self: *Self, name: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, name, "use_pty")) {
            self.use_pty = parseBool(value);
        } else if (std.mem.eql(u8, name, "pwfeedback")) {
            self.pwfeedback = parseBool(value);
        } else if (std.mem.eql(u8, name, "env_reset")) {
            self.env_reset = parseBool(value);
        } else if (std.mem.eql(u8, name, "passwd_tries")) {
            self.passwd_tries = std.fmt.parseInt(u32, value, 10) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, name, "passwd_timeout")) {
            self.passwd_timeout = parseTimeout(value) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, name, "timestamp_timeout")) {
            self.timestamp_timeout = parseTimeout(value) catch return error.InvalidValue;
        } else if (std.mem.eql(u8, name, "secure_path")) {
            self.secure_path = value;
        } else if (std.mem.eql(u8, name, "editor")) {
            self.editor = value;
        } else if (std.mem.eql(u8, name, "badpass_message")) {
            self.badpass_message = value;
        } else if (std.mem.eql(u8, name, "passprompt")) {
            self.passprompt = value;
        } else if (std.mem.eql(u8, name, "mailsub")) {
            self.mailsub = value;
        } else if (std.mem.eql(u8, name, "mailfrom")) {
            self.mailfrom = value;
        } else if (std.mem.eql(u8, name, "mailto")) {
            self.mailto = value;
        } else if (std.mem.eql(u8, name, "sudoers_locale")) {
            self.sudoers_locale = value;
        } else if (std.mem.eql(u8, name, "timestampdir")) {
            self.timestampdir = value;
        } else if (std.mem.eql(u8, name, "timestampowner")) {
            self.timestampowner = value;
        } else if (std.mem.eql(u8, name, "lecture_file")) {
            self.lecture_file = value;
        } else if (std.mem.eql(u8, name, "apparmor_profile")) {
            self.apparmor_profile = value;
        } else {
            return error.UnknownSetting;
        }
    }

    /// Negate a boolean setting
    pub fn negate(self: *Self, name: []const u8) !void {
        try self.setBoolean(name, false);
    }

    fn parseBool(value: []const u8) bool {
        if (value.len == 0) return true;
        return std.mem.eql(u8, value, "true") or
            std.mem.eql(u8, value, "yes") or
            std.mem.eql(u8, value, "1");
    }

    fn parseTimeout(value: []const u8) !u64 {
        // Parse as fractional minutes
        if (std.mem.indexOf(u8, value, ".")) |dot_pos| {
            const integral = std.fmt.parseInt(u64, value[0..dot_pos], 10) catch return error.InvalidValue;
            const fractional_str = value[dot_pos + 1 ..];
            const fractional = std.fmt.parseInt(u64, fractional_str, 10) catch return error.InvalidValue;
            const shift = std.math.pow(u64, 10, @intCast(fractional_str.len));
            return integral * 60 + (fractional * 60) / shift;
        } else {
            const minutes = std.fmt.parseInt(u64, value, 10) catch return error.InvalidValue;
            return minutes * 60;
        }
    }
};

/// Timestamp type for credential caching
pub const TimestampType = enum {
    global, // One timestamp for all ttys
    tty, // Per-tty timestamps (default)
    ppid, // Per parent process ID
    kernel, // Use kernel-based timestamps
};

const default_env_keep = [_][]const u8{
    "COLORS",
    "DISPLAY",
    "HOSTNAME",
    "KRB5CCNAME",
    "LS_COLORS",
    "PATH",
    "PS1",
    "PS2",
    "XAUTHORITY",
    "XAUTHORIZATION",
    "XDG_CURRENT_DESKTOP",
};

const default_env_check = [_][]const u8{
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "LINGUAS",
    "TERM",
    "TZ",
};

const default_env_delete = [_][]const u8{
    "IFS",
    "CDPATH",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "LD_*",
    "_RLD*",
    "TERMINFO",
    "TERMINFO_DIRS",
    "TERMPATH",
    "TERMCAP",
    "ENV",
    "BASH_ENV",
    "PS4",
    "GLOBIGNORE",
    "BASHOPTS",
    "SHELLOPTS",
    "JAVA_TOOL_OPTIONS",
    "PERLIO_DEBUG",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PERL5DB",
    "FPATH",
    "NULLCMD",
    "READNULLCMD",
    "ZDOTDIR",
    "TMPPREFIX",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "RUBYLIB",
    "RUBYOPT",
};

test {
    std.testing.refAllDecls(@This());
}

test "Settings defaults" {
    const settings = Settings{};
    try std.testing.expectEqual(true, settings.use_pty);
    try std.testing.expectEqual(false, settings.pwfeedback);
    try std.testing.expectEqual(@as(u32, 3), settings.passwd_tries);
    try std.testing.expectEqual(@as(u64, 300), settings.passwd_timeout);
}

test "Settings.set" {
    var settings = Settings{};

    try settings.set("passwd_tries", "5");
    try std.testing.expectEqual(@as(u32, 5), settings.passwd_tries);

    try settings.set("secure_path", "/usr/bin:/bin");
    try std.testing.expectEqualStrings("/usr/bin:/bin", settings.secure_path.?);
}
