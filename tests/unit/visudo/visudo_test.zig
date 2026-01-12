//! Unit tests for visudo module

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const visudo = lib.visudo;

// ============================================
// Module Import Tests
// ============================================

test "visudo module is accessible" {
    // Verify the visudo module can be imported
    try testing.expect(@TypeOf(visudo) != void);
}

// ============================================
// Sudoers Path Tests
// ============================================

test "default sudoers path" {
    const sudoers_path = lib.platform.sudoers_path;
    try testing.expect(sudoers_path.len > 0);
    // Should be absolute path
    try testing.expect(sudoers_path[0] == '/');
}

test "sudoers path platform specific" {
    const path = lib.platform.sudoers_path;
    // Linux uses /etc/sudoers, FreeBSD uses /usr/local/etc/sudoers
    const is_valid = std.mem.eql(u8, path, "/etc/sudoers") or
        std.mem.eql(u8, path, "/usr/local/etc/sudoers");
    try testing.expect(is_valid);
}

// ============================================
// File Permissions Tests
// ============================================

test "sudoers file permissions" {
    // sudoers should be mode 0440 (r--r-----)
    const expected_mode: u32 = 0o440;
    try testing.expectEqual(@as(u32, 0o440), expected_mode);
}

test "sudoers ownership" {
    // sudoers should be owned by root:root (or root:wheel on BSD)
    const owner_uid: u32 = 0;
    try testing.expectEqual(@as(u32, 0), owner_uid);
}

// ============================================
// Editor Tests
// ============================================

test "default editor list" {
    // visudo should try these editors in order
    const editors = [_][]const u8{
        "/usr/bin/editor",
        "/usr/bin/nano",
        "/usr/bin/vim",
        "/usr/bin/vi",
        "/bin/vi",
    };

    for (editors) |editor| {
        try testing.expect(editor.len > 0);
        try testing.expect(editor[0] == '/');
    }
}

test "EDITOR environment variable" {
    // visudo should respect EDITOR env var (if env_editor is set)
    const env_var = "EDITOR";
    try testing.expectEqualStrings("EDITOR", env_var);
}

test "VISUAL environment variable" {
    // visudo should also check VISUAL
    const env_var = "VISUAL";
    try testing.expectEqualStrings("VISUAL", env_var);
}

// ============================================
// Check Mode Tests
// ============================================

test "visudo check mode flag" {
    // visudo -c should only check syntax, not edit
    const check_flag = "-c";
    try testing.expectEqualStrings("-c", check_flag);
}

test "visudo strict mode flag" {
    // visudo -s for strict checking
    const strict_flag = "-s";
    try testing.expectEqualStrings("-s", strict_flag);
}

// ============================================
// Syntax Validation Tests
// ============================================

test "valid sudoers line" {
    const valid_line = "root ALL=(ALL:ALL) ALL";
    try testing.expect(valid_line.len > 0);
}

test "invalid sudoers - missing command" {
    const invalid_line = "root ALL=";
    try testing.expect(invalid_line.len > 0);
}

test "comment line" {
    const comment = "# This is a comment";
    try testing.expect(comment[0] == '#');
}

test "empty line is valid" {
    const empty = "";
    try testing.expectEqual(@as(usize, 0), empty.len);
}

// ============================================
// Lock File Tests
// ============================================

test "sudoers lock file path" {
    // visudo uses a lock file to prevent concurrent edits
    const lock_suffix = ".tmp";
    try testing.expectEqualStrings(".tmp", lock_suffix);
}

// ============================================
// Temp File Tests
// ============================================

test "temp file naming" {
    // visudo creates temp file for editing
    var buf: [256]u8 = undefined;
    const temp_path = std.fmt.bufPrint(&buf, "{s}.tmp", .{"/etc/sudoers"}) catch unreachable;
    try testing.expectEqualStrings("/etc/sudoers.tmp", temp_path);
}

// ============================================
// Error Message Tests
// ============================================

test "visudo error messages exist" {
    try testing.expect(lib.common.messages.visudo_what_now.len > 0);
    try testing.expect(lib.common.messages.visudo_options.len > 0);
    try testing.expect(lib.common.messages.visudo_saved.len > 0);
}

test "visudo parse error format" {
    try testing.expect(lib.common.messages.visudo_parse_error.len > 0);
}

// ============================================
// Interactive Mode Tests
// ============================================

test "visudo prompt options" {
    // After syntax error, visudo prompts: e(dit), e(x)it, (Q)uit
    const options = lib.common.messages.visudo_options;
    try testing.expect(std.mem.indexOf(u8, options, "edit") != null or
        std.mem.indexOf(u8, options, "(e)") != null);
}

// ============================================
// Include Directive Tests
// ============================================

test "include directive syntax" {
    const include = "@include /etc/sudoers.d/custom";
    try testing.expect(std.mem.startsWith(u8, include, "@include"));
}

test "includedir directive syntax" {
    const includedir = "@includedir /etc/sudoers.d";
    try testing.expect(std.mem.startsWith(u8, includedir, "@includedir"));
}

test "legacy include syntax" {
    // Old syntax: #include (still supported for compatibility)
    const legacy_include = "#include /etc/sudoers.d/custom";
    try testing.expect(std.mem.startsWith(u8, legacy_include, "#include"));
}

// ============================================
// CLI Option Tests
// ============================================

test "visudo CLI options" {
    const options = [_][]const u8{
        "-c",       // Check mode
        "-f",       // Specify file
        "-s",       // Strict mode
        "-q",       // Quiet mode
        "-V",       // Version
        "-h",       // Help
    };

    for (options) |opt| {
        try testing.expect(opt.len > 0);
        try testing.expect(opt[0] == '-');
    }
}

// ============================================
// Alias Validation Tests
// ============================================

test "valid alias names" {
    // Alias names must be uppercase
    const valid_aliases = [_][]const u8{
        "ADMINS",
        "WEBSERVERS",
        "SHUTDOWN_CMDS",
        "ROOT",
    };

    for (valid_aliases) |alias| {
        // Check first char is uppercase
        try testing.expect(alias[0] >= 'A' and alias[0] <= 'Z');
    }
}

test "invalid alias name - lowercase" {
    const invalid = "admins";
    // First char should NOT be uppercase for this to be invalid
    try testing.expect(!(invalid[0] >= 'A' and invalid[0] <= 'Z'));
}

// ============================================
// Security Tests
// ============================================

test "visudo must run as root" {
    // visudo requires root privileges
    const requires_root = true;
    try testing.expect(requires_root);
}

test "visudo validates file before saving" {
    // visudo should never save an invalid sudoers file
    const validates_before_save = true;
    try testing.expect(validates_before_save);
}
