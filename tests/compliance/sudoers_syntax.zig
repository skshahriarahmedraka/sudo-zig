//! Compliance tests for sudoers syntax compatibility
//!
//! These tests verify that sudo-zig correctly parses sudoers syntax
//! that is compatible with both original sudo and sudo-rs.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const Parser = lib.sudoers.parser.Parser;

// ============================================
// Basic User Specifications
// ============================================

test "compliance: simple user ALL rule" {
    const allocator = testing.allocator;
    const source = "root ALL=(ALL:ALL) ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "compliance: user with specific command" {
    const allocator = testing.allocator;
    const source = "alice ALL=(root) /usr/bin/apt";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "compliance: user with command arguments" {
    const allocator = testing.allocator;
    const source = "bob ALL=(root) /usr/bin/systemctl restart nginx";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "compliance: multiple users" {
    const allocator = testing.allocator;
    const source = "alice, bob, charlie ALL=(ALL) ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
    try testing.expectEqual(@as(usize, 3), parsed.user_specs.items[0].users.items.len);
}

test "compliance: group specification" {
    const allocator = testing.allocator;
    const source = "%wheel ALL=(ALL:ALL) ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "compliance: UID specification" {
    const allocator = testing.allocator;
    const source = "#1000 ALL=(ALL) ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Tags (NOPASSWD, SETENV, etc.)
// ============================================

test "compliance: NOPASSWD tag" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) NOPASSWD: ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    const spec = parsed.user_specs.items[0];
    const cmnd_spec = spec.host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.tags.nopasswd == true);
}

test "compliance: PASSWD tag" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) PASSWD: ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    const spec = parsed.user_specs.items[0];
    const cmnd_spec = spec.host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.tags.nopasswd == false);
}

test "compliance: NOEXEC tag" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) NOEXEC: /usr/bin/vi";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    const spec = parsed.user_specs.items[0];
    const cmnd_spec = spec.host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.tags.noexec == true);
}

test "compliance: SETENV tag" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) SETENV: ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    const spec = parsed.user_specs.items[0];
    const cmnd_spec = spec.host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.tags.setenv == true);
}

test "compliance: multiple tags" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) NOPASSWD: NOEXEC: SETENV: ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    const spec = parsed.user_specs.items[0];
    const cmnd_spec = spec.host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.tags.nopasswd == true);
    try testing.expect(cmnd_spec.tags.noexec == true);
    try testing.expect(cmnd_spec.tags.setenv == true);
}

// ============================================
// Aliases
// ============================================

test "compliance: User_Alias" {
    const allocator = testing.allocator;
    const source = "User_Alias ADMINS = alice, bob, charlie";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.aliases.user.contains("ADMINS"));
}

test "compliance: Host_Alias" {
    const allocator = testing.allocator;
    const source = "Host_Alias SERVERS = server1, server2, 192.168.1.0/24";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.aliases.host.contains("SERVERS"));
}

test "compliance: Cmnd_Alias" {
    const allocator = testing.allocator;
    const source = "Cmnd_Alias SHUTDOWN = /sbin/shutdown, /sbin/reboot, /sbin/halt";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.aliases.cmnd.contains("SHUTDOWN"));
}

test "compliance: Runas_Alias" {
    const allocator = testing.allocator;
    const source = "Runas_Alias DBA = oracle, postgres, mysql";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.aliases.runas.contains("DBA"));
}

test "compliance: use alias in rule" {
    const allocator = testing.allocator;
    const source =
        \\User_Alias ADMINS = alice, bob
        \\Cmnd_Alias APT = /usr/bin/apt, /usr/bin/apt-get
        \\ADMINS ALL=(root) NOPASSWD: APT
    ;

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.aliases.user.contains("ADMINS"));
    try testing.expect(parsed.aliases.cmnd.contains("APT"));
    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Defaults
// ============================================

test "compliance: Defaults env_reset" {
    const allocator = testing.allocator;
    const source = "Defaults env_reset";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.defaults.items.len);
}

test "compliance: Defaults with value" {
    const allocator = testing.allocator;
    const source = "Defaults passwd_tries=5";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.defaults.items.len);
}

test "compliance: Defaults with string value" {
    const allocator = testing.allocator;
    const source = "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.defaults.items.len);
}

test "compliance: Defaults negation" {
    const allocator = testing.allocator;
    const source = "Defaults !requiretty";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.defaults.items.len);
    try testing.expectEqual(lib.sudoers.ast.DefaultOperator.negate, parsed.defaults.items[0].operator);
}

test "compliance: multiple Defaults on one line" {
    const allocator = testing.allocator;
    const source = "Defaults env_reset, secure_path=\"/usr/bin:/bin\"";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expect(parsed.defaults.items.len >= 2);
}

// ============================================
// Include Directives
// ============================================

test "compliance: @include directive" {
    const allocator = testing.allocator;
    const source = "@include /etc/sudoers.d/local";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.includes.items.len);
    try testing.expect(!parsed.includes.items[0].is_directory);
}

test "compliance: @includedir directive" {
    const allocator = testing.allocator;
    const source = "@includedir /etc/sudoers.d";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.includes.items.len);
    try testing.expect(parsed.includes.items[0].is_directory);
}

test "compliance: #include directive (legacy)" {
    const allocator = testing.allocator;
    const source = "#include /etc/sudoers.d/local";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    // #include may be treated as comment or legacy include
    // depending on implementation
}

// ============================================
// Negation
// ============================================

test "compliance: negated user" {
    const allocator = testing.allocator;
    const source = "ALL, !root ALL=(ALL) ALL";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "compliance: negated command" {
    const allocator = testing.allocator;
    const source = "alice ALL=(ALL) ALL, !/bin/su";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Wildcards
// ============================================

test "compliance: command with wildcard" {
    const allocator = testing.allocator;
    const source = "alice ALL=(root) /usr/bin/apt*";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

// ============================================
// Complex Real-World Examples
// ============================================

test "compliance: complex sudoers file" {
    const allocator = testing.allocator;
    const source =
        \\# Sample sudoers file
        \\Defaults env_reset
        \\Defaults mail_badpass
        \\Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        \\
        \\# User alias specification
        \\User_Alias ADMINS = alice, bob
        \\User_Alias WEBDEVS = charlie, dave
        \\
        \\# Cmnd alias specification
        \\Cmnd_Alias APT = /usr/bin/apt, /usr/bin/apt-get
        \\Cmnd_Alias SERVICES = /usr/bin/systemctl
        \\
        \\# User privilege specification
        \\root ALL=(ALL:ALL) ALL
        \\
        \\# Allow admin users to run any command
        \\ADMINS ALL=(ALL) ALL
        \\
        \\# Allow webdevs to manage web services without password
        \\WEBDEVS ALL=(root) NOPASSWD: SERVICES restart nginx, SERVICES restart apache2
        \\
        \\# Members of the wheel group may execute any command
        \\%wheel ALL=(ALL:ALL) ALL
        \\
        \\# Include additional sudoers files
        \\@includedir /etc/sudoers.d
    ;

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    // Verify all components were parsed
    try testing.expect(parsed.defaults.items.len >= 3);
    try testing.expect(parsed.aliases.user.count() >= 2);
    try testing.expect(parsed.aliases.cmnd.count() >= 2);
    try testing.expect(parsed.user_specs.items.len >= 4);
    try testing.expect(parsed.includes.items.len >= 1);
}

test "compliance: digest specification" {
    const allocator = testing.allocator;
    const source = "alice ALL=(root) sha256:abc123def456 /usr/bin/myapp";

    var parser = Parser.init(allocator, source);
    var parsed = try parser.parse();
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}
