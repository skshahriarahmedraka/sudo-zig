//! Internationalization (i18n) support for sudo-zig
//!
//! This module provides localization support using gettext when available,
//! with a fallback to English strings when gettext is not compiled in.
//!
//! ## Usage
//!
//! ```zig
//! const i18n = @import("i18n.zig");
//!
//! // Initialize localization
//! i18n.init("sudo-zig", "/usr/share/locale");
//!
//! // Get translated string
//! const msg = i18n._("Permission denied");
//! ```

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

/// Message catalog domain
pub const DOMAIN = "sudo-zig";

/// Default locale directory
pub const DEFAULT_LOCALE_DIR = "/usr/share/locale";

// ============================================
// Gettext FFI (when enabled)
// ============================================

const UseGettext = build_options.gettext;

const c = if (UseGettext) @cImport({
    @cInclude("libintl.h");
    @cInclude("locale.h");
}) else struct {
    // Stub definitions when gettext is disabled
    pub const LC_ALL: c_int = 0;
    pub const LC_MESSAGES: c_int = 5;
};

// ============================================
// Public API
// ============================================

/// Initialize the internationalization system
/// Should be called early in main() before any translated strings are used
pub fn init(domain: []const u8, locale_dir: ?[]const u8) void {
    if (UseGettext) {
        initGettext(domain, locale_dir);
    }
    // When gettext is disabled, no initialization is needed
}

/// Initialize using default settings
pub fn initDefault() void {
    init(DOMAIN, DEFAULT_LOCALE_DIR);
}

/// Translate a string (main translation function)
/// Use the _ function for brevity
pub fn gettext(msgid: []const u8) []const u8 {
    if (UseGettext) {
        return gettextImpl(msgid);
    }
    return msgid;
}

/// Short alias for gettext - use this in code
pub fn @"_"(msgid: []const u8) []const u8 {
    return gettext(msgid);
}

/// Translate with context disambiguation
/// Use when the same English string needs different translations in different contexts
pub fn pgettext(context: []const u8, msgid: []const u8) []const u8 {
    if (UseGettext) {
        return pgettextImpl(context, msgid);
    }
    return msgid;
}

/// Translate with plural forms
/// Returns singular or plural based on count
pub fn ngettext(msgid_singular: []const u8, msgid_plural: []const u8, n: usize) []const u8 {
    if (UseGettext) {
        return ngettextImpl(msgid_singular, msgid_plural, n);
    }
    return if (n == 1) msgid_singular else msgid_plural;
}

/// Get the current locale
pub fn getCurrentLocale() []const u8 {
    if (UseGettext) {
        return getCurrentLocaleImpl();
    }
    return "C";
}

/// Set the locale explicitly
pub fn setLocale(locale: ?[]const u8) bool {
    if (UseGettext) {
        return setLocaleImpl(locale);
    }
    return true;
}

// ============================================
// Gettext Implementation
// ============================================

fn initGettext(domain: []const u8, locale_dir: ?[]const u8) void {
    // Set locale from environment
    _ = c.setlocale(c.LC_ALL, "");

    // Set text domain
    var domain_buf: [256]u8 = undefined;
    const domain_z = std.fmt.bufPrintZ(&domain_buf, "{s}", .{domain}) catch return;
    _ = c.textdomain(domain_z);

    // Set locale directory if provided
    if (locale_dir) |dir| {
        var dir_buf: [4096]u8 = undefined;
        const dir_z = std.fmt.bufPrintZ(&dir_buf, "{s}", .{dir}) catch return;
        _ = c.bindtextdomain(domain_z, dir_z);
    }

    // Set character encoding to UTF-8
    _ = c.bind_textdomain_codeset(domain_z, "UTF-8");
}

fn gettextImpl(msgid: []const u8) []const u8 {
    var buf: [4096]u8 = undefined;
    const msgid_z = std.fmt.bufPrintZ(&buf, "{s}", .{msgid}) catch return msgid;
    const result = c.gettext(msgid_z);
    if (result) |r| {
        return std.mem.sliceTo(r, 0);
    }
    return msgid;
}

fn pgettextImpl(context: []const u8, msgid: []const u8) []const u8 {
    // Gettext context format: "context\x04msgid"
    var buf: [8192]u8 = undefined;
    const ctx_msgid = std.fmt.bufPrintZ(&buf, "{s}\x04{s}", .{ context, msgid }) catch return msgid;
    const result = c.gettext(ctx_msgid);
    if (result) |r| {
        const translated = std.mem.sliceTo(r, 0);
        // If translation contains \x04, it wasn't translated - return original msgid
        if (std.mem.indexOf(u8, translated, "\x04")) |_| {
            return msgid;
        }
        return translated;
    }
    return msgid;
}

fn ngettextImpl(msgid_singular: []const u8, msgid_plural: []const u8, n: usize) []const u8 {
    var singular_buf: [4096]u8 = undefined;
    var plural_buf: [4096]u8 = undefined;

    const singular_z = std.fmt.bufPrintZ(&singular_buf, "{s}", .{msgid_singular}) catch
        return if (n == 1) msgid_singular else msgid_plural;
    const plural_z = std.fmt.bufPrintZ(&plural_buf, "{s}", .{msgid_plural}) catch
        return if (n == 1) msgid_singular else msgid_plural;

    const result = c.ngettext(singular_z, plural_z, @intCast(n));
    if (result) |r| {
        return std.mem.sliceTo(r, 0);
    }
    return if (n == 1) msgid_singular else msgid_plural;
}

fn getCurrentLocaleImpl() []const u8 {
    const locale = c.setlocale(c.LC_MESSAGES, null);
    if (locale) |l| {
        return std.mem.sliceTo(l, 0);
    }
    return "C";
}

fn setLocaleImpl(locale: ?[]const u8) bool {
    if (locale) |l| {
        var buf: [256]u8 = undefined;
        const locale_z = std.fmt.bufPrintZ(&buf, "{s}", .{l}) catch return false;
        return c.setlocale(c.LC_ALL, locale_z) != null;
    } else {
        return c.setlocale(c.LC_ALL, "") != null;
    }
}

// ============================================
// Common sudo messages (for translation)
// ============================================

/// Standard sudo messages that should be translated
pub const messages = struct {
    // Authentication messages
    pub const password_prompt = "Password: ";
    pub const password_prompt_user = "[sudo] password for {s}: ";
    pub const sorry_try_again = "Sorry, try again.";
    pub const sudo_password_attempts = "{d} incorrect password attempt";
    pub const sudo_password_attempts_plural = "{d} incorrect password attempts";

    // Permission messages
    pub const not_allowed = "{s} is not allowed to run sudo on {s}.";
    pub const not_allowed_as_user = "{s} is not allowed to execute '{s}' as {s} on {s}.";
    pub const must_be_root = "sudo must be owned by uid 0 and have the setuid bit set";

    // Error messages
    pub const command_not_found = "{s}: command not found";
    pub const permission_denied = "{s}: Permission denied";
    pub const unknown_user = "unknown user: {s}";
    pub const unknown_group = "unknown group: {s}";
    pub const invalid_sudoers = ">>> /etc/sudoers: syntax error near line {d} <<<";

    // Lecture message
    pub const lecture = 
        \\We trust you have received the usual lecture from the local System
        \\Administrator. It usually boils down to these three things:
        \\
        \\    #1) Respect the privacy of others.
        \\    #2) Think before you type.
        \\    #3) With great power comes great responsibility.
        \\
    ;

    // Status messages
    pub const session_opened = "session opened for user {s}";
    pub const session_closed = "session closed for user {s}";
    pub const auth_success = "{s} : TTY={s} ; PWD={s} ; USER={s} ; COMMAND={s}";

    // visudo messages
    pub const visudo_what_now = "What now? ";
    pub const visudo_options = "Options are:\n  (e)dit sudoers file again\n  e(x)it without saving changes\n  (Q)uit and save changes\n";
    pub const visudo_parse_error = ">>> {s}: syntax error near line {d} <<<";
    pub const visudo_saved = "sudoers file saved";

    // su messages
    pub const su_auth_failure = "su: Authentication failure";
    pub const su_incorrect_password = "su: incorrect password";
    pub const su_no_shell = "su: failed to execute {s}: {s}";
};

// ============================================
// Formatting helpers
// ============================================

/// Format a translated message with arguments
pub fn format(comptime fmt: []const u8, args: anytype) []const u8 {
    // Note: In actual use, this would need an allocator
    // This is a simplified version for demonstration
    _ = args;
    return gettext(fmt);
}

/// Format translated message into a buffer
/// Note: Since Zig requires comptime format strings, we use the original format
/// and rely on gettext being applied to the format string at the call site
pub fn formatBuf(buf: []u8, comptime fmt: []const u8, args: anytype) ![]const u8 {
    // In production, the translated string would be used via gettext() before calling this
    // For now, we use the original format string since Zig requires comptime fmt
    return std.fmt.bufPrint(buf, fmt, args);
}

// ============================================
// Tests
// ============================================

test "gettext passthrough when disabled" {
    const msg = gettext("Hello, World!");
    try std.testing.expectEqualStrings("Hello, World!", msg);
}

test "ngettext singular" {
    const msg = ngettext("1 file", "{d} files", 1);
    try std.testing.expectEqualStrings("1 file", msg);
}

test "ngettext plural" {
    const msg = ngettext("1 file", "{d} files", 5);
    try std.testing.expectEqualStrings("{d} files", msg);
}

test "pgettext passthrough" {
    const msg = pgettext("menu", "File");
    try std.testing.expectEqualStrings("File", msg);
}

test "getCurrentLocale returns valid string" {
    const locale = getCurrentLocale();
    try std.testing.expect(locale.len > 0);
}

test "messages are defined" {
    try std.testing.expect(messages.password_prompt.len > 0);
    try std.testing.expect(messages.lecture.len > 0);
    try std.testing.expect(messages.not_allowed.len > 0);
}

test "init does not crash" {
    init("test-domain", null);
    initDefault();
}

test "setLocale" {
    // This should not crash even if it fails
    _ = setLocale("C");
    _ = setLocale(null);
}
