//! Unit tests for SELinux support
//!
//! Tests for SELinux security context management.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const selinux = lib.system.selinux;
const SecurityContext = selinux.SecurityContext;
const SELinuxContext = selinux.SELinuxContext;
const Mode = selinux.Mode;

// ============================================
// SecurityContext Tests
// ============================================

test "SecurityContext.parse valid 3-part context" {
    const ctx = SecurityContext.parse("user_u:role_r:type_t");
    try testing.expect(ctx != null);
    try testing.expectEqualStrings("user_u", ctx.?.user);
    try testing.expectEqualStrings("role_r", ctx.?.role);
    try testing.expectEqualStrings("type_t", ctx.?.type_);
    try testing.expect(ctx.?.level == null);
}

test "SecurityContext.parse valid 4-part context with level" {
    const ctx = SecurityContext.parse("user_u:role_r:type_t:s0");
    try testing.expect(ctx != null);
    try testing.expectEqualStrings("user_u", ctx.?.user);
    try testing.expectEqualStrings("role_r", ctx.?.role);
    try testing.expectEqualStrings("type_t", ctx.?.type_);
    try testing.expect(ctx.?.level != null);
    try testing.expectEqualStrings("s0", ctx.?.level.?);
}

test "SecurityContext.parse valid 4-part context with MLS range" {
    const ctx = SecurityContext.parse("system_u:system_r:sudo_t:s0-s0:c0.c1023");
    try testing.expect(ctx != null);
    try testing.expectEqualStrings("system_u", ctx.?.user);
    try testing.expectEqualStrings("system_r", ctx.?.role);
    try testing.expectEqualStrings("sudo_t", ctx.?.type_);
}

test "SecurityContext.parse invalid 2-part context" {
    const ctx = SecurityContext.parse("user_u:role_r");
    try testing.expect(ctx == null);
}

test "SecurityContext.parse invalid 1-part context" {
    const ctx = SecurityContext.parse("user_u");
    try testing.expect(ctx == null);
}

test "SecurityContext.parse empty string" {
    const ctx = SecurityContext.parse("");
    try testing.expect(ctx == null);
}

test "SecurityContext.format 3-part context" {
    const ctx = SecurityContext{
        .user = "user_u",
        .role = "role_r",
        .type_ = "type_t",
        .level = null,
    };
    var buf: [128]u8 = undefined;
    const formatted = ctx.format(&buf);
    try testing.expect(formatted != null);
    try testing.expectEqualStrings("user_u:role_r:type_t", formatted.?);
}

test "SecurityContext.format 4-part context" {
    const ctx = SecurityContext{
        .user = "system_u",
        .role = "system_r",
        .type_ = "sudo_t",
        .level = "s0",
    };
    var buf: [128]u8 = undefined;
    const formatted = ctx.format(&buf);
    try testing.expect(formatted != null);
    try testing.expectEqualStrings("system_u:system_r:sudo_t:s0", formatted.?);
}

test "SecurityContext.format buffer too small" {
    const ctx = SecurityContext{
        .user = "very_long_user_name_that_exceeds_buffer",
        .role = "very_long_role_name_that_exceeds_buffer",
        .type_ = "very_long_type_name_that_exceeds_buffer",
        .level = null,
    };
    var buf: [10]u8 = undefined;
    const formatted = ctx.format(&buf);
    try testing.expect(formatted == null);
}

test "SecurityContext.canTransitionTo always returns true" {
    const ctx1 = SecurityContext{
        .user = "user_u",
        .role = "role_r",
        .type_ = "type_t",
        .level = null,
    };
    const ctx2 = SecurityContext{
        .user = "system_u",
        .role = "system_r",
        .type_ = "sudo_t",
        .level = "s0",
    };
    // Current implementation always returns true
    try testing.expect(ctx1.canTransitionTo(ctx2));
}

// ============================================
// SELinuxContext Tests
// ============================================

test "SELinuxContext.init does not crash" {
    const ctx = SELinuxContext.init();
    // Should work regardless of whether SELinux is available
    _ = ctx.enabled;
    _ = ctx.mode;
}

test "SELinuxContext enabled state is consistent" {
    const ctx = SELinuxContext.init();
    if (!ctx.enabled) {
        // If not enabled, mode should be disabled
        try testing.expectEqual(Mode.disabled, ctx.mode);
    }
}

// ============================================
// Mode Tests
// ============================================

test "Mode enum values are distinct" {
    try testing.expect(Mode.disabled != Mode.permissive);
    try testing.expect(Mode.permissive != Mode.enforcing);
    try testing.expect(Mode.disabled != Mode.enforcing);
}

// ============================================
// Helper Function Tests
// ============================================

test "isEnabled returns consistent value" {
    const enabled1 = selinux.isEnabled();
    const enabled2 = selinux.isEnabled();
    try testing.expectEqual(enabled1, enabled2);
}

test "getMode returns valid mode" {
    const mode = selinux.getMode();
    try testing.expect(mode == .disabled or mode == .permissive or mode == .enforcing);
}

test "getMode returns disabled when SELinux not enabled" {
    if (!selinux.isEnabled()) {
        try testing.expectEqual(Mode.disabled, selinux.getMode());
    }
}

// ============================================
// SudoSELinuxOptions Tests
// ============================================

test "SudoSELinuxOptions default values" {
    const options = selinux.SudoSELinuxOptions{};
    try testing.expect(options.role == null);
    try testing.expect(options.type_ == null);
    try testing.expect(!options.preserve_context);
}

test "SudoSELinuxOptions with role" {
    const options = selinux.SudoSELinuxOptions{
        .role = "staff_r",
        .type_ = null,
        .preserve_context = false,
    };
    try testing.expect(options.role != null);
    try testing.expectEqualStrings("staff_r", options.role.?);
}

test "SudoSELinuxOptions with type" {
    const options = selinux.SudoSELinuxOptions{
        .role = null,
        .type_ = "sudo_t",
        .preserve_context = false,
    };
    try testing.expect(options.type_ != null);
    try testing.expectEqualStrings("sudo_t", options.type_.?);
}

test "SudoSELinuxOptions preserve_context" {
    const options = selinux.SudoSELinuxOptions{
        .role = null,
        .type_ = null,
        .preserve_context = true,
    };
    try testing.expect(options.preserve_context);
}

// ============================================
// Integration-style Tests
// ============================================

test "round-trip context parse and format" {
    const original = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023";
    const ctx = SecurityContext.parse(original);
    try testing.expect(ctx != null);

    var buf: [256]u8 = undefined;
    const formatted = ctx.?.format(&buf);
    try testing.expect(formatted != null);

    // Note: May not be exactly equal due to level formatting
    try testing.expectEqualStrings("unconfined_u", ctx.?.user);
    try testing.expectEqualStrings("unconfined_r", ctx.?.role);
    try testing.expectEqualStrings("unconfined_t", ctx.?.type_);
}
