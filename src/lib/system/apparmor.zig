//! AppArmor profile enforcement for sudo-zig
//!
//! This module provides AppArmor integration for confining executed commands
//! to specific security profiles. AppArmor is a Linux Security Module that
//! allows restricting programs' capabilities with per-program profiles.
//!
//! ## Usage
//!
//! ```zig
//! const apparmor = @import("apparmor.zig");
//!
//! // Check if AppArmor is available on the system
//! if (apparmor.isEnabled()) {
//!     // Change to a specific profile before exec
//!     try apparmor.changeProfile("sudo_command_profile");
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

/// AppArmor error types
pub const AppArmorError = error{
    /// AppArmor is not available on this system
    NotAvailable,
    /// The specified profile does not exist
    ProfileNotFound,
    /// Permission denied when changing profile
    PermissionDenied,
    /// The profile change was rejected by the kernel
    ProfileChangeRejected,
    /// Generic system error
    SystemError,
    /// Invalid profile name (contains invalid characters)
    InvalidProfileName,
    /// AppArmor kernel interface not accessible
    KernelInterfaceError,
};

/// AppArmor profile mode
pub const ProfileMode = enum {
    /// Enforce mode - violations are blocked and logged
    enforce,
    /// Complain mode - violations are logged but not blocked
    complain,
    /// Unconfined - no restrictions
    unconfined,

    pub fn fromString(s: []const u8) ?ProfileMode {
        if (std.mem.eql(u8, s, "enforce")) return .enforce;
        if (std.mem.eql(u8, s, "complain")) return .complain;
        if (std.mem.eql(u8, s, "unconfined")) return .unconfined;
        return null;
    }

    pub fn toString(self: ProfileMode) []const u8 {
        return switch (self) {
            .enforce => "enforce",
            .complain => "complain",
            .unconfined => "unconfined",
        };
    }
};

/// Information about the current AppArmor confinement
pub const ConfinementInfo = struct {
    /// The current profile name (null if unconfined)
    profile: ?[]const u8,
    /// The current mode
    mode: ProfileMode,
    /// Whether the process is confined
    is_confined: bool,

    pub fn init() ConfinementInfo {
        return .{
            .profile = null,
            .mode = .unconfined,
            .is_confined = false,
        };
    }
};

/// AppArmor context for managing profile transitions
pub const AppArmorContext = struct {
    allocator: std.mem.Allocator,
    /// Cache of available profiles
    cached_profiles: ?std.StringHashMap(ProfileMode),
    /// Current confinement info
    current: ConfinementInfo,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .cached_profiles = null,
            .current = ConfinementInfo.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.cached_profiles) |*profiles| {
            profiles.deinit();
        }
    }

    /// Refresh the current confinement info
    pub fn refresh(self: *Self) !void {
        self.current = try getCurrentConfinement(self.allocator);
    }

    /// Check if a specific profile is loaded
    pub fn isProfileLoaded(self: *Self, profile_name: []const u8) !bool {
        if (self.cached_profiles == null) {
            self.cached_profiles = try getLoadedProfiles(self.allocator);
        }
        return self.cached_profiles.?.contains(profile_name);
    }
};

// ============================================
// AppArmor Kernel Interface Paths
// ============================================

const APPARMOR_PROFILES_PATH = "/sys/kernel/security/apparmor/profiles";
const APPARMOR_CURRENT_PATH = "/proc/self/attr/apparmor/current";
const APPARMOR_CURRENT_FALLBACK = "/proc/self/attr/current";
const APPARMOR_EXEC_PATH = "/proc/self/attr/apparmor/exec";
const APPARMOR_EXEC_FALLBACK = "/proc/self/attr/exec";

// ============================================
// Public API
// ============================================

/// Check if AppArmor support is compiled in
pub fn isCompiled() bool {
    return build_options.apparmor;
}

/// Check if AppArmor is enabled on this system
pub fn isEnabled() bool {
    if (!isCompiled()) return false;

    // Check if AppArmor filesystem is mounted
    if (std.fs.openFileAbsolute(APPARMOR_PROFILES_PATH, .{})) |file| {
        file.close();
        return true;
    } else |_| {
        return false;
    }
}

/// Get the current AppArmor confinement status
pub fn getCurrentConfinement(allocator: std.mem.Allocator) !ConfinementInfo {
    if (!isEnabled()) {
        return ConfinementInfo.init();
    }

    // Try new path first, then fallback
    const paths = [_][]const u8{ APPARMOR_CURRENT_PATH, APPARMOR_CURRENT_FALLBACK };

    for (paths) |path| {
        if (std.fs.openFileAbsolute(path, .{})) |file| {
            defer file.close();

            var buf: [4096]u8 = undefined;
            const bytes_read = file.read(&buf) catch continue;
            if (bytes_read == 0) continue;

            const content = std.mem.trim(u8, buf[0..bytes_read], &[_]u8{ '\n', '\r', ' ', '\t', 0 });
            return parseConfinementString(allocator, content);
        } else |_| {
            continue;
        }
    }

    return ConfinementInfo.init();
}

/// Parse the confinement string from /proc/self/attr/current
/// Format: "profile_name (mode)" or "unconfined"
fn parseConfinementString(allocator: std.mem.Allocator, content: []const u8) !ConfinementInfo {
    if (std.mem.eql(u8, content, "unconfined")) {
        return ConfinementInfo.init();
    }

    var info = ConfinementInfo{
        .profile = null,
        .mode = .enforce,
        .is_confined = true,
    };

    // Parse "profile_name (mode)"
    if (std.mem.lastIndexOf(u8, content, " (")) |paren_start| {
        const profile_name = content[0..paren_start];
        info.profile = try allocator.dupe(u8, profile_name);

        // Extract mode
        if (paren_start + 2 < content.len) {
            const mode_start = paren_start + 2;
            if (std.mem.indexOf(u8, content[mode_start..], ")")) |paren_end| {
                const mode_str = content[mode_start .. mode_start + paren_end];
                info.mode = ProfileMode.fromString(mode_str) orelse .enforce;
            }
        }
    } else {
        // No mode specified, just profile name
        info.profile = try allocator.dupe(u8, content);
    }

    return info;
}

/// Get list of loaded AppArmor profiles
pub fn getLoadedProfiles(allocator: std.mem.Allocator) !std.StringHashMap(ProfileMode) {
    var profiles = std.StringHashMap(ProfileMode).init(allocator);
    errdefer profiles.deinit();

    if (!isEnabled()) {
        return profiles;
    }

    const file = std.fs.openFileAbsolute(APPARMOR_PROFILES_PATH, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound, error.AccessDenied => profiles,
            else => error.KernelInterfaceError,
        };
    };
    defer file.close();

    // Read file content
    var buf: [65536]u8 = undefined;
    const bytes_read = file.read(&buf) catch return profiles;
    if (bytes_read == 0) return profiles;

    var lines = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // Format: "profile_name (mode)"
        if (std.mem.lastIndexOf(u8, line, " (")) |paren_start| {
            const profile_name = line[0..paren_start];

            var mode: ProfileMode = .enforce;
            if (paren_start + 2 < line.len) {
                const mode_start = paren_start + 2;
                if (std.mem.indexOf(u8, line[mode_start..], ")")) |paren_end| {
                    const mode_str = line[mode_start .. mode_start + paren_end];
                    mode = ProfileMode.fromString(mode_str) orelse .enforce;
                }
            }

            const name_copy = try allocator.dupe(u8, profile_name);
            try profiles.put(name_copy, mode);
        }
    }

    return profiles;
}

/// Validate that a profile name is safe to use
pub fn validateProfileName(name: []const u8) AppArmorError!void {
    if (name.len == 0) return error.InvalidProfileName;
    if (name.len > 1024) return error.InvalidProfileName;

    // Profile names should not contain certain characters
    for (name) |c| {
        if (c == 0) return error.InvalidProfileName;
        // Newlines could be used for injection attacks
        if (c == '\n' or c == '\r') return error.InvalidProfileName;
    }
}

/// Change to a new AppArmor profile for the current process
/// This is typically called just before exec() to confine the command
pub fn changeProfile(profile_name: []const u8) AppArmorError!void {
    if (!isCompiled()) return error.NotAvailable;
    if (!isEnabled()) return error.NotAvailable;

    try validateProfileName(profile_name);

    // Try new path first, then fallback
    const paths = [_][]const u8{ APPARMOR_CURRENT_PATH, APPARMOR_CURRENT_FALLBACK };

    for (paths) |path| {
        if (std.fs.openFileAbsolute(path, .{ .mode = .write_only })) |file| {
            defer file.close();

            // Write "changeprofile profile_name"
            var buf: [1100]u8 = undefined;
            const content = std.fmt.bufPrint(&buf, "changeprofile {s}", .{profile_name}) catch
                return error.InvalidProfileName;

            file.writeAll(content) catch |err| {
                return switch (err) {
                    error.AccessDenied => error.PermissionDenied,
                    else => error.ProfileChangeRejected,
                };
            };
            return;
        } else |_| {
            continue;
        }
    }

    return error.KernelInterfaceError;
}

/// Set the profile that will be applied on the next exec()
/// This is the preferred method for confining commands
pub fn setExecProfile(profile_name: []const u8) AppArmorError!void {
    if (!isCompiled()) return error.NotAvailable;
    if (!isEnabled()) return error.NotAvailable;

    try validateProfileName(profile_name);

    // Try new path first, then fallback
    const paths = [_][]const u8{ APPARMOR_EXEC_PATH, APPARMOR_EXEC_FALLBACK };

    for (paths) |path| {
        if (std.fs.openFileAbsolute(path, .{ .mode = .write_only })) |file| {
            defer file.close();

            // Write "exec profile_name"
            var buf: [1100]u8 = undefined;
            const content = std.fmt.bufPrint(&buf, "exec {s}", .{profile_name}) catch
                return error.InvalidProfileName;

            file.writeAll(content) catch |err| {
                return switch (err) {
                    error.AccessDenied => error.PermissionDenied,
                    else => error.ProfileChangeRejected,
                };
            };
            return;
        } else |_| {
            continue;
        }
    }

    return error.KernelInterfaceError;
}

/// Change to a profile with a specific mode (if supported)
pub fn changeProfileWithMode(profile_name: []const u8, mode: ProfileMode) AppArmorError!void {
    // Most systems don't support changing mode dynamically
    // This would require the profile to be loaded in the target mode
    _ = mode;
    return changeProfile(profile_name);
}

/// Stack a new profile on top of the current confinement
/// This creates a more restrictive confinement combining both profiles
pub fn stackProfile(profile_name: []const u8) AppArmorError!void {
    if (!isCompiled()) return error.NotAvailable;
    if (!isEnabled()) return error.NotAvailable;

    try validateProfileName(profile_name);

    const paths = [_][]const u8{ APPARMOR_CURRENT_PATH, APPARMOR_CURRENT_FALLBACK };

    for (paths) |path| {
        if (std.fs.openFileAbsolute(path, .{ .mode = .write_only })) |file| {
            defer file.close();

            // Write "stack profile_name"
            var buf: [1100]u8 = undefined;
            const content = std.fmt.bufPrint(&buf, "stack {s}", .{profile_name}) catch
                return error.InvalidProfileName;

            file.writeAll(content) catch |err| {
                return switch (err) {
                    error.AccessDenied => error.PermissionDenied,
                    else => error.ProfileChangeRejected,
                };
            };
            return;
        } else |_| {
            continue;
        }
    }

    return error.KernelInterfaceError;
}

// ============================================
// Integration with sudo execution
// ============================================

/// Apply AppArmor profile based on sudoers configuration
/// Called from the exec module before running the command
pub fn applyProfileForCommand(
    profile: ?[]const u8,
    fallback_profile: ?[]const u8,
) AppArmorError!void {
    // If no profile specified, don't change anything
    const target_profile = profile orelse fallback_profile orelse return;

    if (!isEnabled()) {
        // If AppArmor is configured but not available, this is an error
        return error.NotAvailable;
    }

    // Use exec transition - profile will be applied when command is exec'd
    setExecProfile(target_profile) catch |err| {
        // If profile doesn't exist, try a fallback
        if (err == error.ProfileChangeRejected and profile != null and fallback_profile != null) {
            return setExecProfile(fallback_profile.?);
        }
        return err;
    };
}

// ============================================
// FFI for libapparmor (optional)
// ============================================

/// When linking against libapparmor, we can use its functions for better integration
pub const LibAppArmor = struct {
    // These would be populated by @cImport when apparmor is enabled
    // For now, we use the /proc interface which works without libapparmor

    pub fn aa_change_profile(profile: [*:0]const u8) c_int {
        // Stub - would call actual libapparmor function
        _ = profile;
        return -1;
    }

    pub fn aa_change_onexec(profile: [*:0]const u8) c_int {
        // Stub - would call actual libapparmor function
        _ = profile;
        return -1;
    }

    pub fn aa_is_enabled() c_int {
        // Stub - would call actual libapparmor function
        return 0;
    }
};

// ============================================
// Tests
// ============================================

test "ProfileMode conversion" {
    try std.testing.expectEqual(ProfileMode.enforce, ProfileMode.fromString("enforce").?);
    try std.testing.expectEqual(ProfileMode.complain, ProfileMode.fromString("complain").?);
    try std.testing.expectEqual(ProfileMode.unconfined, ProfileMode.fromString("unconfined").?);
    try std.testing.expect(ProfileMode.fromString("invalid") == null);
}

test "ProfileMode toString" {
    try std.testing.expectEqualStrings("enforce", ProfileMode.enforce.toString());
    try std.testing.expectEqualStrings("complain", ProfileMode.complain.toString());
    try std.testing.expectEqualStrings("unconfined", ProfileMode.unconfined.toString());
}

test "validateProfileName" {
    // Valid names
    try validateProfileName("my_profile");
    try validateProfileName("/usr/bin/myapp");
    try validateProfileName("sudo-zig//command");

    // Invalid names
    try std.testing.expectError(error.InvalidProfileName, validateProfileName(""));
    try std.testing.expectError(error.InvalidProfileName, validateProfileName("bad\nprofile"));
    try std.testing.expectError(error.InvalidProfileName, validateProfileName("bad\rprofile"));
}

test "ConfinementInfo init" {
    const info = ConfinementInfo.init();
    try std.testing.expect(info.profile == null);
    try std.testing.expectEqual(ProfileMode.unconfined, info.mode);
    try std.testing.expect(!info.is_confined);
}

test "isCompiled" {
    // This test verifies the function exists and returns a boolean
    const compiled = isCompiled();
    try std.testing.expect(compiled == true or compiled == false);
}

test "parseConfinementString unconfined" {
    const allocator = std.testing.allocator;
    const info = try parseConfinementString(allocator, "unconfined");
    try std.testing.expect(info.profile == null);
    try std.testing.expectEqual(ProfileMode.unconfined, info.mode);
    try std.testing.expect(!info.is_confined);
}

test "parseConfinementString with profile" {
    const allocator = std.testing.allocator;
    const info = try parseConfinementString(allocator, "/usr/bin/sudo (enforce)");
    defer if (info.profile) |p| allocator.free(p);

    try std.testing.expect(info.profile != null);
    try std.testing.expectEqualStrings("/usr/bin/sudo", info.profile.?);
    try std.testing.expectEqual(ProfileMode.enforce, info.mode);
    try std.testing.expect(info.is_confined);
}

test "parseConfinementString complain mode" {
    const allocator = std.testing.allocator;
    const info = try parseConfinementString(allocator, "test_profile (complain)");
    defer if (info.profile) |p| allocator.free(p);

    try std.testing.expect(info.profile != null);
    try std.testing.expectEqualStrings("test_profile", info.profile.?);
    try std.testing.expectEqual(ProfileMode.complain, info.mode);
}

test "AppArmorContext init and deinit" {
    const allocator = std.testing.allocator;
    var ctx = AppArmorContext.init(allocator);
    defer ctx.deinit();

    try std.testing.expect(ctx.cached_profiles == null);
    try std.testing.expect(!ctx.current.is_confined);
}
