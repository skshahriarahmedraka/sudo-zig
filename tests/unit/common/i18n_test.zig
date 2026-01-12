//! Unit tests for internationalization (i18n) module

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const i18n = lib.common.i18n;

// ============================================
// Basic Translation Tests
// ============================================

test "gettext passthrough" {
    const msg = i18n.gettext("Hello, World!");
    try testing.expectEqualStrings("Hello, World!", msg);
}

test "_ shorthand function" {
    const msg = i18n.@"_"("Test message");
    try testing.expectEqualStrings("Test message", msg);
}

test "translation preserves string" {
    const original = "This is a test string with special chars: !@#$%^&*()";
    const translated = i18n.@"_"(original);
    try testing.expectEqualStrings(original, translated);
}

// ============================================
// Plural Forms Tests
// ============================================

test "ngettext singular" {
    const msg = i18n.ngettext("1 file", "{d} files", 1);
    try testing.expectEqualStrings("1 file", msg);
}

test "ngettext plural" {
    const msg = i18n.ngettext("1 file", "{d} files", 2);
    try testing.expectEqualStrings("{d} files", msg);
}

test "ngettext zero" {
    const msg = i18n.ngettext("1 item", "{d} items", 0);
    try testing.expectEqualStrings("{d} items", msg);
}

test "ngettext large number" {
    const msg = i18n.ngettext("1 error", "{d} errors", 1000000);
    try testing.expectEqualStrings("{d} errors", msg);
}

// ============================================
// Context Translation Tests
// ============================================

test "pgettext with context" {
    const msg = i18n.pgettext("menu", "File");
    try testing.expectEqualStrings("File", msg);
}

test "pgettext different contexts same string" {
    const menu_open = i18n.pgettext("menu", "Open");
    const button_open = i18n.pgettext("button", "Open");

    // Without translations loaded, both should return the same
    try testing.expectEqualStrings("Open", menu_open);
    try testing.expectEqualStrings("Open", button_open);
}

// ============================================
// Locale Tests
// ============================================

test "getCurrentLocale returns string" {
    const locale = i18n.getCurrentLocale();
    try testing.expect(locale.len > 0);
}

test "setLocale C locale" {
    const result = i18n.setLocale("C");
    // Should succeed or fail gracefully
    _ = result;
}

test "setLocale null resets to environment" {
    const result = i18n.setLocale(null);
    _ = result;
}

// ============================================
// Initialization Tests
// ============================================

test "init with domain" {
    i18n.init("test-domain", null);
}

test "init with locale directory" {
    i18n.init("test-domain", "/usr/share/locale");
}

test "initDefault" {
    i18n.initDefault();
}

test "multiple init calls" {
    // Should be safe to call init multiple times
    i18n.init("domain1", null);
    i18n.init("domain2", "/some/path");
    i18n.initDefault();
}

// ============================================
// Message Constants Tests
// ============================================

test "messages.password_prompt" {
    try testing.expect(i18n.messages.password_prompt.len > 0);
    try testing.expectEqualStrings("Password: ", i18n.messages.password_prompt);
}

test "messages.lecture" {
    try testing.expect(i18n.messages.lecture.len > 0);
    // Should contain the classic sudo lecture text
    try testing.expect(std.mem.indexOf(u8, i18n.messages.lecture, "great power") != null);
}

test "messages.not_allowed" {
    try testing.expect(i18n.messages.not_allowed.len > 0);
}

test "messages.command_not_found" {
    try testing.expect(i18n.messages.command_not_found.len > 0);
}

test "messages.unknown_user" {
    try testing.expect(i18n.messages.unknown_user.len > 0);
}

test "messages.visudo strings" {
    try testing.expect(i18n.messages.visudo_what_now.len > 0);
    try testing.expect(i18n.messages.visudo_options.len > 0);
    try testing.expect(i18n.messages.visudo_saved.len > 0);
}

test "messages.su strings" {
    try testing.expect(i18n.messages.su_auth_failure.len > 0);
    try testing.expect(i18n.messages.su_incorrect_password.len > 0);
}

// ============================================
// Domain Constant Tests
// ============================================

test "DOMAIN constant" {
    try testing.expectEqualStrings("sudo-zig", i18n.DOMAIN);
}

test "DEFAULT_LOCALE_DIR constant" {
    try testing.expectEqualStrings("/usr/share/locale", i18n.DEFAULT_LOCALE_DIR);
}

// ============================================
// Edge Cases
// ============================================

test "empty string translation" {
    const msg = i18n.@"_"("");
    try testing.expectEqualStrings("", msg);
}

test "whitespace only translation" {
    const msg = i18n.@"_"("   ");
    try testing.expectEqualStrings("   ", msg);
}

test "unicode string translation" {
    const msg = i18n.@"_"("こんにちは世界");
    try testing.expectEqualStrings("こんにちは世界", msg);
}

test "string with newlines" {
    const msg = i18n.@"_"("line1\nline2\nline3");
    try testing.expectEqualStrings("line1\nline2\nline3", msg);
}

test "string with format specifiers" {
    // Format specifiers should be preserved
    const msg = i18n.@"_"("User {s} not found");
    try testing.expectEqualStrings("User {s} not found", msg);
}

// ============================================
// Format Buffer Tests
// ============================================

test "formatBuf basic" {
    var buf: [256]u8 = undefined;
    const result = i18n.formatBuf(&buf, "Hello, {s}!", .{"World"}) catch unreachable;
    try testing.expectEqualStrings("Hello, World!", result);
}

test "formatBuf with number" {
    var buf: [256]u8 = undefined;
    const result = i18n.formatBuf(&buf, "Count: {d}", .{42}) catch unreachable;
    try testing.expectEqualStrings("Count: 42", result);
}

// ============================================
// Re-export Tests
// ============================================

test "common module re-exports _" {
    const msg = lib.common.@"_"("test");
    try testing.expectEqualStrings("test", msg);
}

test "common module re-exports gettext" {
    const msg = lib.common.gettext("test");
    try testing.expectEqualStrings("test", msg);
}

test "common module re-exports ngettext" {
    const msg = lib.common.ngettext("one", "many", 5);
    try testing.expectEqualStrings("many", msg);
}

test "common module re-exports messages" {
    try testing.expect(lib.common.messages.lecture.len > 0);
}
