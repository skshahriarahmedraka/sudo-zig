//! Unit tests for sudoers parser
//!
//! These tests cover comprehensive parsing scenarios for sudoers files.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const parser = lib.sudoers.parser;
const ast = lib.sudoers.ast;

// ============================================
// Basic Parsing Tests
// ============================================

test "parse empty input returns empty sudoers" {
    var sudoers = try parser.parse(testing.allocator, "");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
    try testing.expectEqual(@as(usize, 0), sudoers.defaults.items.len);
    try testing.expectEqual(@as(usize, 0), sudoers.includes.items.len);
}

test "parse whitespace only" {
    var sudoers = try parser.parse(testing.allocator, "   \t\n\n   ");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
}

test "parse comments only" {
    var sudoers = try parser.parse(testing.allocator,
        \\# This is a comment
        \\# Another comment
        \\    # Indented comment
    );
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
}

// ============================================
// User Spec Tests
// ============================================

test "parse minimal user spec" {
    var sudoers = try parser.parse(testing.allocator, "root ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.user_specs.items.len);
    
    const spec = sudoers.user_specs.items[0];
    try testing.expectEqual(@as(usize, 1), spec.users.items.items.len);
}

test "parse user spec with username" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    try testing.expectEqual(false, user_item.negated);
    switch (user_item.value) {
        .username => |name| try testing.expectEqualStrings("alice", name),
        else => try testing.expect(false),
    }
}

test "parse user spec with group" {
    var sudoers = try parser.parse(testing.allocator, "%wheel ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .groupname => |name| try testing.expectEqualStrings("wheel", name),
        else => try testing.expect(false),
    }
}

test "parse user spec with UID" {
    var sudoers = try parser.parse(testing.allocator, "#1000 ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .uid => |uid| try testing.expectEqual(@as(u32, 1000), uid),
        else => try testing.expect(false),
    }
}

test "parse user spec with negated user" {
    var sudoers = try parser.parse(testing.allocator, "!baduser ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    try testing.expectEqual(true, user_item.negated);
}

test "parse user spec with netgroup" {
    var sudoers = try parser.parse(testing.allocator, "+admins ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .netgroup => |ng| try testing.expectEqualStrings("admins", ng),
        else => try testing.expect(false),
    }
}

test "parse user spec with non-unix group" {
    var sudoers = try parser.parse(testing.allocator, "%:domain_admins ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const user_item = sudoers.user_specs.items[0].users.items.items[0];
    switch (user_item.value) {
        .non_unix_group => |g| try testing.expectEqualStrings("domain_admins", g),
        else => try testing.expect(false),
    }
}

// ============================================
// Runas Spec Tests
// ============================================

test "parse runas with user only" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(root) ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.runas != null);
    try testing.expect(cmnd_spec.runas.?.users != null);
}

test "parse runas with user and group" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(root:wheel) ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.runas != null);
    try testing.expect(cmnd_spec.runas.?.users != null);
    try testing.expect(cmnd_spec.runas.?.groups != null);
}

test "parse runas with group only" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(:wheel) ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expect(cmnd_spec.runas != null);
    // Users should be null or empty when only group specified
}

// ============================================
// Tag Tests
// ============================================

test "parse NOPASSWD tag" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) NOPASSWD: ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expectEqual(false, cmnd_spec.tags.passwd.?);
}

test "parse PASSWD tag" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) PASSWD: ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expectEqual(true, cmnd_spec.tags.passwd.?);
}

test "parse NOEXEC tag" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) NOEXEC: /usr/bin/vim");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expectEqual(true, cmnd_spec.tags.noexec.?);
}

test "parse multiple tags" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) NOPASSWD: NOEXEC: /usr/bin/vim");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expectEqual(false, cmnd_spec.tags.passwd.?);
    try testing.expectEqual(true, cmnd_spec.tags.noexec.?);
}

test "parse SETENV tag" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) SETENV: ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    try testing.expectEqual(true, cmnd_spec.tags.setenv.?);
}

// ============================================
// Command Tests
// ============================================

test "parse command path" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) /usr/bin/apt");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    const cmnd_item = cmnd_spec.commands.items.items[0];
    switch (cmnd_item.value) {
        .command => |cmd| try testing.expectEqualStrings("/usr/bin/apt", cmd.path),
        else => try testing.expect(false),
    }
}

test "parse command with arguments" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) /usr/bin/apt update");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    const cmnd_item = cmnd_spec.commands.items.items[0];
    switch (cmnd_item.value) {
        .command => |cmd| {
            try testing.expectEqualStrings("/usr/bin/apt", cmd.path);
            try testing.expectEqualStrings("update", cmd.args.?);
        },
        else => try testing.expect(false),
    }
}

test "parse ALL command" {
    var sudoers = try parser.parse(testing.allocator, "alice ALL=(ALL) ALL");
    defer sudoers.deinit();
    
    const cmnd_spec = sudoers.user_specs.items[0].host_specs.items[0].cmnd_specs.items[0];
    const cmnd_item = cmnd_spec.commands.items.items[0];
    switch (cmnd_item.value) {
        .all => {},
        else => try testing.expect(false),
    }
}

// ============================================
// Defaults Tests
// ============================================

test "parse simple defaults flag" {
    var sudoers = try parser.parse(testing.allocator, "Defaults env_reset");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try testing.expectEqualStrings("env_reset", sudoers.defaults.items[0].name);
}

test "parse defaults with value" {
    var sudoers = try parser.parse(testing.allocator, "Defaults secure_path=\"/usr/bin:/bin\"");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try testing.expectEqualStrings("secure_path", sudoers.defaults.items[0].name);
}

test "parse negated defaults" {
    var sudoers = try parser.parse(testing.allocator, "Defaults !requiretty");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try testing.expectEqualStrings("requiretty", sudoers.defaults.items[0].name);
    try testing.expectEqual(ast.DefaultOperator.negate, sudoers.defaults.items[0].operator);
}

test "parse defaults with += operator" {
    var sudoers = try parser.parse(testing.allocator, "Defaults env_keep+=\"HOME\"");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try testing.expectEqual(ast.DefaultOperator.add, sudoers.defaults.items[0].operator);
}

test "parse defaults with -= operator" {
    var sudoers = try parser.parse(testing.allocator, "Defaults env_keep-=\"LD_PRELOAD\"");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    try testing.expectEqual(ast.DefaultOperator.remove, sudoers.defaults.items[0].operator);
}

test "parse scoped defaults for user" {
    var sudoers = try parser.parse(testing.allocator, "Defaults:alice !requiretty");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.defaults.items.len);
    switch (sudoers.defaults.items[0].scope) {
        .user_list => |user_list| try testing.expectEqual(@as(usize, 1), user_list.len()),
        else => try testing.expect(false),
    }
}

test "parse multiple defaults on same line" {
    var sudoers = try parser.parse(testing.allocator, "Defaults env_reset, mail_badpass");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 2), sudoers.defaults.items.len);
}

// ============================================
// Alias Tests
// ============================================

test "parse User_Alias" {
    var sudoers = try parser.parse(testing.allocator, "User_Alias ADMINS = alice, bob, charlie");
    defer sudoers.deinit();
    
    try testing.expect(sudoers.aliases.user.contains("ADMINS"));
    const user_list = sudoers.aliases.user.get("ADMINS").?;
    try testing.expectEqual(@as(usize, 3), user_list.len());
}

test "parse Host_Alias" {
    var sudoers = try parser.parse(testing.allocator, "Host_Alias SERVERS = web1, web2, db1");
    defer sudoers.deinit();
    
    try testing.expect(sudoers.aliases.host.contains("SERVERS"));
    const host_list = sudoers.aliases.host.get("SERVERS").?;
    try testing.expectEqual(@as(usize, 3), host_list.len());
}

test "parse Cmnd_Alias" {
    var sudoers = try parser.parse(testing.allocator, "Cmnd_Alias SHUTDOWN = /sbin/halt, /sbin/reboot");
    defer sudoers.deinit();
    
    try testing.expect(sudoers.aliases.cmnd.contains("SHUTDOWN"));
    const cmnd_list = sudoers.aliases.cmnd.get("SHUTDOWN").?;
    try testing.expectEqual(@as(usize, 2), cmnd_list.len());
}

test "parse Runas_Alias" {
    var sudoers = try parser.parse(testing.allocator, "Runas_Alias DB = oracle, mysql");
    defer sudoers.deinit();
    
    try testing.expect(sudoers.aliases.runas.contains("DB"));
}

// ============================================
// Include Directive Tests
// ============================================

test "parse @include directive" {
    var sudoers = try parser.parse(testing.allocator, "@include /etc/sudoers.d/local");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
    try testing.expectEqualStrings("/etc/sudoers.d/local", sudoers.includes.items[0].path);
    try testing.expectEqual(false, sudoers.includes.items[0].is_directory);
}

test "parse @includedir directive" {
    var sudoers = try parser.parse(testing.allocator, "@includedir /etc/sudoers.d");
    defer sudoers.deinit();
    
    try testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
    try testing.expectEqualStrings("/etc/sudoers.d", sudoers.includes.items[0].path);
    try testing.expectEqual(true, sudoers.includes.items[0].is_directory);
}

// ============================================
// Complex Sudoers File Tests
// ============================================

test "parse complete sudoers file" {
    const source =
        \\# Sample sudoers file
        \\Defaults env_reset
        \\Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        \\
        \\# Aliases
        \\User_Alias ADMINS = alice, bob
        \\Host_Alias SERVERS = web1, web2
        \\Cmnd_Alias SERVICES = /usr/bin/systemctl
        \\
        \\# Rules
        \\root ALL=(ALL:ALL) ALL
        \\%wheel ALL=(ALL) ALL
        \\ADMINS SERVERS=(ALL) NOPASSWD: SERVICES
        \\
        \\@includedir /etc/sudoers.d
    ;
    
    var sudoers = try parser.parse(testing.allocator, source);
    defer sudoers.deinit();
    
    // Verify all components
    try testing.expectEqual(@as(usize, 2), sudoers.defaults.items.len);
    try testing.expect(sudoers.aliases.user.contains("ADMINS"));
    try testing.expect(sudoers.aliases.host.contains("SERVERS"));
    try testing.expect(sudoers.aliases.cmnd.contains("SERVICES"));
    try testing.expectEqual(@as(usize, 3), sudoers.user_specs.items.len);
    try testing.expectEqual(@as(usize, 1), sudoers.includes.items.len);
}

// ============================================
// Error Handling Tests
// ============================================

test "parse error has line and column info" {
    var parser_instance = parser.Parser.init(testing.allocator, "alice ALL = @@invalid");
    defer parser_instance.deinit();
    
    _ = parser_instance.parse() catch |err| {
        if (err == error.ParseError) {
            const errors = parser_instance.getErrors();
            try testing.expect(errors.len > 0);
            try testing.expect(errors[0].line >= 1);
            return;
        }
        return err;
    };
    // If parse succeeds, that's unexpected for invalid input
    try testing.expect(false);
}

test "ParseError format" {
    const err = parser.ParseError{
        .message = "unexpected token",
        .line = 5,
        .column = 10,
        .token_lexeme = "@@",
    };
    var buf: [256]u8 = undefined;
    const result = err.toString(&buf);
    try testing.expect(std.mem.indexOf(u8, result, "5:10") != null);
    try testing.expect(std.mem.indexOf(u8, result, "unexpected token") != null);
}
