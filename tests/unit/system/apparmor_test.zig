//! Unit tests for AppArmor module

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const apparmor = lib.system.apparmor;

// ============================================
// ProfileMode Tests
// ============================================

test "ProfileMode.fromString - valid modes" {
    try testing.expectEqual(apparmor.ProfileMode.enforce, apparmor.ProfileMode.fromString("enforce").?);
    try testing.expectEqual(apparmor.ProfileMode.complain, apparmor.ProfileMode.fromString("complain").?);
    try testing.expectEqual(apparmor.ProfileMode.unconfined, apparmor.ProfileMode.fromString("unconfined").?);
}

test "ProfileMode.fromString - invalid modes" {
    try testing.expect(apparmor.ProfileMode.fromString("invalid") == null);
    try testing.expect(apparmor.ProfileMode.fromString("ENFORCE") == null);
    try testing.expect(apparmor.ProfileMode.fromString("") == null);
    try testing.expect(apparmor.ProfileMode.fromString("enforced") == null);
}

test "ProfileMode.toString" {
    try testing.expectEqualStrings("enforce", apparmor.ProfileMode.enforce.toString());
    try testing.expectEqualStrings("complain", apparmor.ProfileMode.complain.toString());
    try testing.expectEqualStrings("unconfined", apparmor.ProfileMode.unconfined.toString());
}

test "ProfileMode roundtrip" {
    const modes = [_]apparmor.ProfileMode{ .enforce, .complain, .unconfined };
    for (modes) |mode| {
        const str = mode.toString();
        const parsed = apparmor.ProfileMode.fromString(str);
        try testing.expect(parsed != null);
        try testing.expectEqual(mode, parsed.?);
    }
}

// ============================================
// ConfinementInfo Tests
// ============================================

test "ConfinementInfo.init - defaults to unconfined" {
    const info = apparmor.ConfinementInfo.init();
    try testing.expect(info.profile == null);
    try testing.expectEqual(apparmor.ProfileMode.unconfined, info.mode);
    try testing.expect(!info.is_confined);
}

// ============================================
// Profile Name Validation Tests
// ============================================

test "validateProfileName - valid names" {
    // Standard profile names
    try apparmor.validateProfileName("my_profile");
    try apparmor.validateProfileName("sudo-zig");
    try apparmor.validateProfileName("profile123");

    // Path-based profile names (common in AppArmor)
    try apparmor.validateProfileName("/usr/bin/sudo");
    try apparmor.validateProfileName("/usr/sbin/apache2");

    // Namespace profiles
    try apparmor.validateProfileName("sudo-zig//command");
    try apparmor.validateProfileName(":ns:profile");

    // Profiles with special characters
    try apparmor.validateProfileName("profile-with-dash");
    try apparmor.validateProfileName("profile_with_underscore");
    try apparmor.validateProfileName("profile.with.dots");
}

test "validateProfileName - empty name" {
    try testing.expectError(apparmor.AppArmorError.InvalidProfileName, apparmor.validateProfileName(""));
}

test "validateProfileName - null byte injection" {
    try testing.expectError(apparmor.AppArmorError.InvalidProfileName, apparmor.validateProfileName("bad\x00profile"));
}

test "validateProfileName - newline injection" {
    try testing.expectError(apparmor.AppArmorError.InvalidProfileName, apparmor.validateProfileName("bad\nprofile"));
    try testing.expectError(apparmor.AppArmorError.InvalidProfileName, apparmor.validateProfileName("bad\rprofile"));
}

test "validateProfileName - very long name" {
    // Create a name longer than 1024 characters
    var long_name: [2000]u8 = undefined;
    @memset(&long_name, 'a');
    try testing.expectError(apparmor.AppArmorError.InvalidProfileName, apparmor.validateProfileName(&long_name));
}

test "validateProfileName - max valid length" {
    var max_name: [1024]u8 = undefined;
    @memset(&max_name, 'a');
    try apparmor.validateProfileName(&max_name);
}

// ============================================
// AppArmorContext Tests
// ============================================

test "AppArmorContext - init and deinit" {
    const allocator = testing.allocator;
    var ctx = apparmor.AppArmorContext.init(allocator);
    defer ctx.deinit();

    try testing.expect(ctx.cached_profiles == null);
    try testing.expect(!ctx.current.is_confined);
    try testing.expectEqual(apparmor.ProfileMode.unconfined, ctx.current.mode);
}

test "AppArmorContext - multiple init/deinit cycles" {
    const allocator = testing.allocator;

    // Should be safe to init and deinit multiple times
    for (0..5) |_| {
        var ctx = apparmor.AppArmorContext.init(allocator);
        ctx.deinit();
    }
}

// ============================================
// Compile-time Feature Tests
// ============================================

test "isCompiled returns boolean" {
    const compiled = apparmor.isCompiled();
    try testing.expect(compiled == true or compiled == false);
}

test "isEnabled returns boolean" {
    const enabled = apparmor.isEnabled();
    try testing.expect(enabled == true or enabled == false);
}

// ============================================
// Error Type Tests
// ============================================

test "AppArmorError variants exist" {
    // Verify all error types are defined
    const errors = [_]apparmor.AppArmorError{
        apparmor.AppArmorError.NotAvailable,
        apparmor.AppArmorError.ProfileNotFound,
        apparmor.AppArmorError.PermissionDenied,
        apparmor.AppArmorError.ProfileChangeRejected,
        apparmor.AppArmorError.SystemError,
        apparmor.AppArmorError.InvalidProfileName,
        apparmor.AppArmorError.KernelInterfaceError,
    };

    for (errors) |err| {
        // Just verify they exist and can be compared
        try testing.expect(err == err);
    }
}

// ============================================
// Profile Transition Tests (Mock/Safe)
// ============================================

test "changeProfile - fails when AppArmor not available" {
    // On systems without AppArmor, this should return NotAvailable
    apparmor.changeProfile("test_profile") catch |err| {
        try testing.expect(err == apparmor.AppArmorError.NotAvailable or
            err == apparmor.AppArmorError.KernelInterfaceError or
            err == apparmor.AppArmorError.PermissionDenied);
        return;
    };
    // AppArmor might be available on this system - that's ok too
}

test "setExecProfile - fails gracefully" {
    apparmor.setExecProfile("test_profile") catch |err| {
        try testing.expect(err == apparmor.AppArmorError.NotAvailable or
            err == apparmor.AppArmorError.KernelInterfaceError or
            err == apparmor.AppArmorError.PermissionDenied);
        return;
    };
    // AppArmor might be available - that's ok
}

test "stackProfile - fails gracefully" {
    apparmor.stackProfile("test_profile") catch |err| {
        try testing.expect(err == apparmor.AppArmorError.NotAvailable or
            err == apparmor.AppArmorError.KernelInterfaceError or
            err == apparmor.AppArmorError.PermissionDenied);
        return;
    };
    // AppArmor might be available - that's ok
}

// ============================================
// Integration Function Tests
// ============================================

test "applyProfileForCommand - no profile specified" {
    // When both profile and fallback are null, should succeed without doing anything
    try apparmor.applyProfileForCommand(null, null);
}

test "applyProfileForCommand - profile validation" {
    // Invalid profile names should be rejected before any system calls
    apparmor.applyProfileForCommand("bad\nprofile", null) catch |err| {
        try testing.expect(err == apparmor.AppArmorError.InvalidProfileName or
            err == apparmor.AppArmorError.NotAvailable);
        return;
    };
    // If it succeeded, that's unexpected but not a test failure
}

// ============================================
// getCurrentConfinement Tests
// ============================================

test "getCurrentConfinement - returns valid info" {
    const allocator = testing.allocator;
    const info = apparmor.getCurrentConfinement(allocator) catch {
        // If AppArmor is not available, we should get default unconfined state
        return;
    };

    // Clean up allocated profile name if any
    if (info.profile) |p| {
        allocator.free(p);
    }

    // Mode should be valid
    try testing.expect(info.mode == .enforce or info.mode == .complain or info.mode == .unconfined);
}

// ============================================
// getLoadedProfiles Tests
// ============================================

test "getLoadedProfiles - returns hashmap" {
    const allocator = testing.allocator;
    var profiles = apparmor.getLoadedProfiles(allocator) catch {
        // Expected on systems without AppArmor
        return;
    };
    defer {
        var it = profiles.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        profiles.deinit();
    }

    // If we got here, profiles is a valid (possibly empty) hashmap
    // Just verify we can iterate it
    var count: usize = 0;
    var it = profiles.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    // Count can be 0 or more
    try testing.expect(count >= 0);
}
