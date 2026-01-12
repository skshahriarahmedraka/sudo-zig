//! Unit tests for sudoers tokenizer
//!
//! These tests cover edge cases and comprehensive scenarios for the tokenizer.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const tokens = lib.sudoers.tokens;
const Tokenizer = tokens.Tokenizer;
const TokenType = tokens.TokenType;

// ============================================
// Basic Token Tests
// ============================================

test "tokenize empty input" {
    var tokenizer = Tokenizer.init("");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.eof, t.type);
}

test "tokenize whitespace only" {
    var tokenizer = Tokenizer.init("   \t  ");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.eof, t.type);
}

test "tokenize single comment" {
    var tokenizer = Tokenizer.init("# this is a comment");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.comment, t.type);
}

test "tokenize newline" {
    var tokenizer = Tokenizer.init("\n");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.newline, t.type);
}

// ============================================
// Keyword Tests
// ============================================

test "tokenize Defaults keyword" {
    var tokenizer = Tokenizer.init("Defaults");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_defaults, t.type);
    try testing.expectEqualStrings("Defaults", t.lexeme);
}

test "tokenize User_Alias keyword" {
    var tokenizer = Tokenizer.init("User_Alias");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_user_alias, t.type);
}

test "tokenize Host_Alias keyword" {
    var tokenizer = Tokenizer.init("Host_Alias");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_host_alias, t.type);
}

test "tokenize Cmnd_Alias keyword" {
    var tokenizer = Tokenizer.init("Cmnd_Alias");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_cmnd_alias, t.type);
}

test "tokenize Runas_Alias keyword" {
    var tokenizer = Tokenizer.init("Runas_Alias");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_runas_alias, t.type);
}

test "tokenize @include directive" {
    var tokenizer = Tokenizer.init("@include");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_include, t.type);
}

test "tokenize @includedir directive" {
    var tokenizer = Tokenizer.init("@includedir");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_includedir, t.type);
}

// ============================================
// Operator Tests
// ============================================

test "tokenize equals operator" {
    var tokenizer = Tokenizer.init("=");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.equals, t.type);
}

test "tokenize plus_equals operator" {
    var tokenizer = Tokenizer.init("+=");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.plus_equals, t.type);
}

test "tokenize minus_equals operator" {
    var tokenizer = Tokenizer.init("-=");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.minus_equals, t.type);
}

test "tokenize bang operator" {
    var tokenizer = Tokenizer.init("!");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.bang, t.type);
}

test "tokenize colon operator" {
    var tokenizer = Tokenizer.init(":");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.colon, t.type);
}

test "tokenize comma operator" {
    var tokenizer = Tokenizer.init(",");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.comma, t.type);
}

test "tokenize parentheses" {
    var tokenizer = Tokenizer.init("()");
    const t1 = tokenizer.next();
    try testing.expectEqual(TokenType.open_paren, t1.type);
    const t2 = tokenizer.next();
    try testing.expectEqual(TokenType.close_paren, t2.type);
}

// ============================================
// Identifier and Value Tests
// ============================================

test "tokenize ALL keyword" {
    var tokenizer = Tokenizer.init("ALL");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.all, t.type);
}

test "tokenize simple identifier" {
    var tokenizer = Tokenizer.init("alice");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t.type);
    try testing.expectEqualStrings("alice", t.lexeme);
}

test "tokenize identifier with underscore" {
    var tokenizer = Tokenizer.init("my_user");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t.type);
    try testing.expectEqualStrings("my_user", t.lexeme);
}

test "tokenize identifier with numbers" {
    var tokenizer = Tokenizer.init("user123");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t.type);
    try testing.expectEqualStrings("user123", t.lexeme);
}

test "tokenize group name" {
    var tokenizer = Tokenizer.init("%wheel");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.groupname, t.type);
    try testing.expectEqualStrings("%wheel", t.lexeme);
}

test "tokenize uid" {
    var tokenizer = Tokenizer.init("#1000");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.uid, t.type);
    try testing.expectEqualStrings("#1000", t.lexeme);
}

test "tokenize gid" {
    var tokenizer = Tokenizer.init("%#100");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.gid, t.type);
    try testing.expectEqualStrings("%#100", t.lexeme);
}

test "tokenize netgroup" {
    var tokenizer = Tokenizer.init("+admins");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.netgroup, t.type);
    try testing.expectEqualStrings("+admins", t.lexeme);
}

test "tokenize non-unix group" {
    var tokenizer = Tokenizer.init("%:domain_admins");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.non_unix_group, t.type);
}

test "tokenize non-unix gid" {
    var tokenizer = Tokenizer.init("%:#500");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.non_unix_gid, t.type);
}

// ============================================
// Command Path Tests
// ============================================

test "tokenize absolute command path" {
    var tokenizer = Tokenizer.init("/usr/bin/apt");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.command_path, t.type);
    try testing.expectEqualStrings("/usr/bin/apt", t.lexeme);
}

test "tokenize command path with hyphen" {
    var tokenizer = Tokenizer.init("/usr/bin/apt-get");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.command_path, t.type);
    try testing.expectEqualStrings("/usr/bin/apt-get", t.lexeme);
}

// ============================================
// Tag Tests
// ============================================

test "tokenize PASSWD tag" {
    var tokenizer = Tokenizer.init("PASSWD");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_passwd, t.type);
}

test "tokenize NOPASSWD tag" {
    var tokenizer = Tokenizer.init("NOPASSWD");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_nopasswd, t.type);
}

test "tokenize SETENV tag" {
    var tokenizer = Tokenizer.init("SETENV");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_setenv, t.type);
}

test "tokenize NOSETENV tag" {
    var tokenizer = Tokenizer.init("NOSETENV");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_nosetenv, t.type);
}

test "tokenize NOEXEC tag" {
    var tokenizer = Tokenizer.init("NOEXEC");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_noexec, t.type);
}

test "tokenize EXEC tag" {
    var tokenizer = Tokenizer.init("EXEC");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.tag_exec, t.type);
}

// ============================================
// Quoted String Tests
// ============================================

test "tokenize double-quoted string" {
    var tokenizer = Tokenizer.init("\"hello world\"");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.quoted_string, t.type);
    try testing.expectEqualStrings("\"hello world\"", t.lexeme);
}

test "tokenize quoted string with path" {
    var tokenizer = Tokenizer.init("\"/usr/local/bin:/usr/bin\"");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.quoted_string, t.type);
}

// ============================================
// Line Continuation Tests
// ============================================

test "tokenize line continuation" {
    var tokenizer = Tokenizer.init("alice \\\nALL");
    _ = tokenizer.next(); // alice
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.all, t.type);
}

// ============================================
// Complex Token Sequences
// ============================================

test "tokenize simple user spec" {
    var tokenizer = Tokenizer.init("root ALL=(ALL) ALL");

    const t1 = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t1.type);
    try testing.expectEqualStrings("root", t1.lexeme);

    const t2 = tokenizer.next();
    try testing.expectEqual(TokenType.all, t2.type);

    const t3 = tokenizer.next();
    try testing.expectEqual(TokenType.equals, t3.type);

    const t4 = tokenizer.next();
    try testing.expectEqual(TokenType.open_paren, t4.type);

    const t5 = tokenizer.next();
    try testing.expectEqual(TokenType.all, t5.type);

    const t6 = tokenizer.next();
    try testing.expectEqual(TokenType.close_paren, t6.type);

    const t7 = tokenizer.next();
    try testing.expectEqual(TokenType.all, t7.type);
}

test "tokenize defaults line" {
    var tokenizer = Tokenizer.init("Defaults env_reset");

    const t1 = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_defaults, t1.type);

    const t2 = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t2.type);
    try testing.expectEqualStrings("env_reset", t2.lexeme);
}

test "tokenize user alias definition" {
    var tokenizer = Tokenizer.init("User_Alias ADMINS = alice, bob");

    const t1 = tokenizer.next();
    try testing.expectEqual(TokenType.keyword_user_alias, t1.type);

    const t2 = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t2.type);
    try testing.expectEqualStrings("ADMINS", t2.lexeme);

    const t3 = tokenizer.next();
    try testing.expectEqual(TokenType.equals, t3.type);

    const t4 = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t4.type);
    try testing.expectEqualStrings("alice", t4.lexeme);

    const t5 = tokenizer.next();
    try testing.expectEqual(TokenType.comma, t5.type);

    const t6 = tokenizer.next();
    try testing.expectEqual(TokenType.identifier, t6.type);
    try testing.expectEqualStrings("bob", t6.lexeme);
}

test "tokenize rule with NOPASSWD tag" {
    var tokenizer = Tokenizer.init("alice ALL=(root) NOPASSWD: /usr/bin/apt");

    _ = tokenizer.next(); // alice
    _ = tokenizer.next(); // ALL
    _ = tokenizer.next(); // =
    _ = tokenizer.next(); // (
    _ = tokenizer.next(); // root
    _ = tokenizer.next(); // )

    const tag = tokenizer.next();
    try testing.expectEqual(TokenType.tag_nopasswd, tag.type);

    const colon = tokenizer.next();
    try testing.expectEqual(TokenType.colon, colon.type);

    const cmd = tokenizer.next();
    try testing.expectEqual(TokenType.command_path, cmd.type);
    try testing.expectEqualStrings("/usr/bin/apt", cmd.lexeme);
}

// ============================================
// Token Position Tests
// ============================================

test "token line and column tracking" {
    var tokenizer = Tokenizer.init("alice\nbob");

    const t1 = tokenizer.next();
    try testing.expectEqual(@as(u32, 1), t1.line);
    try testing.expectEqual(@as(u32, 1), t1.column);

    _ = tokenizer.next(); // newline

    const t2 = tokenizer.next();
    try testing.expectEqual(@as(u32, 2), t2.line);
    try testing.expectEqual(@as(u32, 1), t2.column);
}

// ============================================
// Digest Algorithm Tests
// ============================================

test "tokenize sha256 digest prefix" {
    var tokenizer = Tokenizer.init("sha256");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.sha256, t.type);
}

test "tokenize sha512 digest prefix" {
    var tokenizer = Tokenizer.init("sha512");
    const t = tokenizer.next();
    try testing.expectEqual(TokenType.sha512, t.type);
}
