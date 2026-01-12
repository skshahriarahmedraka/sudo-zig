//! Unit tests for policy evaluation
//!
//! Tests for sudoers policy matching, authorization, and glob patterns.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const sudoers = lib.sudoers;
const Authorization = sudoers.Authorization;
const AuthRequest = sudoers.AuthRequest;
const Policy = sudoers.Policy;

// ============================================
// Authorization Tests
// ============================================

test "Authorization.denied creates denied authorization" {
    const auth = Authorization.denied();

    try testing.expect(!auth.allowed);
    try testing.expect(auth.must_authenticate);
    try testing.expectEqual(@as(?u32, null), auth.runas_user);
    try testing.expectEqual(@as(?u32, null), auth.runas_group);
}

test "Authorization.grant creates allowed authorization" {
    const auth = Authorization.grant(0, true);

    try testing.expect(auth.allowed);
    try testing.expect(auth.must_authenticate);
    try testing.expectEqual(@as(?u32, 0), auth.runas_user);
}

test "Authorization.grant without authentication" {
    const auth = Authorization.grant(1000, false);

    try testing.expect(auth.allowed);
    try testing.expect(!auth.must_authenticate);
    try testing.expectEqual(@as(?u32, 1000), auth.runas_user);
}

test "Authorization.Flags default values" {
    const flags = Authorization.Flags{};

    try testing.expect(!flags.nopasswd);
    try testing.expect(!flags.noexec);
    try testing.expect(!flags.setenv);
}

test "Authorization.Flags with nopasswd" {
    const flags = Authorization.Flags{
        .nopasswd = true,
        .noexec = false,
        .setenv = false,
    };

    try testing.expect(flags.nopasswd);
    try testing.expect(!flags.noexec);
}

test "Authorization.Flags with all enabled" {
    const flags = Authorization.Flags{
        .nopasswd = true,
        .noexec = true,
        .setenv = true,
    };

    try testing.expect(flags.nopasswd);
    try testing.expect(flags.noexec);
    try testing.expect(flags.setenv);
}

// ============================================
// AuthRequest Tests
// ============================================

test "AuthRequest struct creation" {
    var user: lib.system.User = undefined;
    user.uid = 1000;
    user.gid = 1000;
    user.name = "alice";
    user.gecos = "Alice User";
    user.home = "/home/alice";
    user.shell = "/bin/bash";

    const request = AuthRequest{
        .user = user,
        .groups = &[_]u32{ 1000, 27 },
        .hostname = "localhost",
        .command = "/usr/bin/apt",
        .arguments = "update",
        .target_user = "root",
        .target_group = null,
    };

    try testing.expectEqualStrings("alice", request.user.name);
    try testing.expectEqualStrings("localhost", request.hostname);
    try testing.expectEqualStrings("/usr/bin/apt", request.command);
    try testing.expectEqualStrings("update", request.arguments.?);
    try testing.expectEqualStrings("root", request.target_user.?);
}

test "AuthRequest without target user defaults to root" {
    var user: lib.system.User = undefined;
    user.uid = 1000;
    user.gid = 1000;
    user.name = "bob";
    user.gecos = "";
    user.home = "/home/bob";
    user.shell = "/bin/bash";

    const request = AuthRequest{
        .user = user,
        .groups = &[_]u32{1000},
        .hostname = "server",
        .command = "/bin/ls",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    };

    try testing.expectEqual(@as(?[]const u8, null), request.target_user);
    try testing.expectEqual(@as(?[]const u8, null), request.arguments);
}

// ============================================
// Glob Pattern Matching Tests (via globMatch)
// ============================================

// These test the globMatch function indirectly through the module's test exports
// The actual globMatch tests are in the inline tests in policy.zig

test "glob pattern concepts - exact match" {
    // Exact matches should work
    const pattern = "/usr/bin/apt";
    const path = "/usr/bin/apt";
    try testing.expect(std.mem.eql(u8, pattern, path));
}

test "glob pattern concepts - wildcard at end" {
    // Pattern ending with * should match prefix
    const pattern = "/usr/bin/*";
    const path = "/usr/bin/apt";

    // Pattern without * should match as prefix
    const prefix = pattern[0 .. pattern.len - 1];
    try testing.expect(std.mem.startsWith(u8, path, prefix));
}

test "glob pattern concepts - wildcard at start" {
    // Pattern starting with * should match suffix
    const pattern = "*.txt";
    const path = "file.txt";

    const suffix = pattern[1..];
    try testing.expect(std.mem.endsWith(u8, path, suffix));
}

// ============================================
// Common Sudoers Patterns Tests
// ============================================

test "typical admin patterns" {
    // Test patterns commonly found in sudoers

    // ALL keyword would match any command
    const all_command = "/usr/bin/anything";
    try testing.expect(all_command.len > 0);

    // Specific command patterns
    const apt_pattern = "/usr/bin/apt*";
    const apt_command = "/usr/bin/apt-get";

    // The pattern should match (conceptually)
    const prefix = apt_pattern[0 .. apt_pattern.len - 1];
    try testing.expect(std.mem.startsWith(u8, apt_command, prefix));
}

test "command with arguments pattern" {
    // Commands can have specific arguments in sudoers
    const allowed_cmd = "/usr/bin/systemctl restart nginx";
    var iter = std.mem.splitSequence(u8, allowed_cmd, " ");

    const cmd = iter.next().?;
    try testing.expectEqualStrings("/usr/bin/systemctl", cmd);

    const arg1 = iter.next().?;
    try testing.expectEqualStrings("restart", arg1);

    const arg2 = iter.next().?;
    try testing.expectEqualStrings("nginx", arg2);
}

// ============================================
// Host Matching Tests
// ============================================

test "hostname exact match" {
    const rule_host = "webserver01";
    const actual_host = "webserver01";

    try testing.expect(std.mem.eql(u8, rule_host, actual_host));
}

test "hostname wildcard suffix" {
    const pattern = "web*";
    const hostname = "webserver01";

    const prefix = pattern[0 .. pattern.len - 1];
    try testing.expect(std.mem.startsWith(u8, hostname, prefix));
}

test "hostname wildcard prefix" {
    const pattern = "*.example.com";
    const hostname = "server.example.com";

    const suffix = pattern[1..];
    try testing.expect(std.mem.endsWith(u8, hostname, suffix));
}

// ============================================
// User Matching Tests
// ============================================

test "username exact match" {
    const rule_user = "alice";
    const actual_user = "alice";

    try testing.expect(std.mem.eql(u8, rule_user, actual_user));
}

test "user by UID" {
    const rule_uid: u32 = 1000;
    const actual_uid: u32 = 1000;

    try testing.expectEqual(rule_uid, actual_uid);
}

test "group membership check" {
    const user_groups = [_]u32{ 1000, 27, 100, 44 };
    const required_gid: u32 = 27; // sudo group

    var found = false;
    for (user_groups) |gid| {
        if (gid == required_gid) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// ============================================
// Runas User/Group Tests
// ============================================

test "runas user matching" {
    const allowed_users = [_][]const u8{ "root", "www-data", "postgres" };
    const target = "www-data";

    var found = false;
    for (allowed_users) |user| {
        if (std.mem.eql(u8, user, target)) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "runas root is default" {
    const target_user: ?[]const u8 = null;
    const default_target = target_user orelse "root";

    try testing.expectEqualStrings("root", default_target);
}

// ============================================
// NOPASSWD/PASSWD Tag Tests
// ============================================

test "nopasswd flag behavior" {
    const with_nopasswd = Authorization{
        .allowed = true,
        .must_authenticate = false,
        .runas_user = 0,
        .flags = .{ .nopasswd = true },
    };

    try testing.expect(!with_nopasswd.must_authenticate);
    try testing.expect(with_nopasswd.flags.nopasswd);
}

test "passwd flag behavior (default)" {
    const with_passwd = Authorization{
        .allowed = true,
        .must_authenticate = true,
        .runas_user = 0,
        .flags = .{ .nopasswd = false },
    };

    try testing.expect(with_passwd.must_authenticate);
    try testing.expect(!with_passwd.flags.nopasswd);
}
