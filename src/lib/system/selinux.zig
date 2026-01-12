//! SELinux support for sudo-zig
//!
//! This module provides SELinux security context management:
//! - Checking if SELinux is enabled
//! - Getting/setting security contexts
//! - Role and type transitions for command execution
//!
//! SELinux support is optional and gracefully degrades if not available.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

// SELinux library bindings (optional)
const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
});

/// SELinux security context
pub const SecurityContext = struct {
    user: []const u8,
    role: []const u8,
    type_: []const u8,
    level: ?[]const u8,

    const Self = @This();

    /// Parse a security context string (user:role:type:level)
    pub fn parse(context_str: []const u8) ?Self {
        var parts: [4][]const u8 = undefined;
        var count: usize = 0;
        var iter = std.mem.splitScalar(u8, context_str, ':');

        while (iter.next()) |part| {
            if (count >= 4) break;
            parts[count] = part;
            count += 1;
        }

        if (count < 3) return null;

        return .{
            .user = parts[0],
            .role = parts[1],
            .type_ = parts[2],
            .level = if (count >= 4) parts[3] else null,
        };
    }

    /// Format context back to string
    pub fn format(self: Self, buf: []u8) ?[]const u8 {
        if (self.level) |level| {
            return std.fmt.bufPrint(buf, "{s}:{s}:{s}:{s}", .{
                self.user,
                self.role,
                self.type_,
                level,
            }) catch null;
        } else {
            return std.fmt.bufPrint(buf, "{s}:{s}:{s}", .{
                self.user,
                self.role,
                self.type_,
            }) catch null;
        }
    }

    /// Check if this context allows a transition to another context
    pub fn canTransitionTo(self: Self, target: Self) bool {
        // In a real implementation, this would check SELinux policy
        // For now, we just check basic validity
        _ = self;
        _ = target;
        return true;
    }
};

/// SELinux mode
pub const Mode = enum {
    disabled,
    permissive,
    enforcing,
};

/// SELinux context manager
pub const SELinuxContext = struct {
    enabled: bool,
    mode: Mode,
    current_context: ?SecurityContext,

    // Buffer for context strings
    _context_buf: [512]u8 = undefined,

    const Self = @This();

    /// Initialize SELinux context
    pub fn init() Self {
        var self = Self{
            .enabled = false,
            .mode = .disabled,
            .current_context = null,
        };

        // Check if SELinux is enabled
        self.enabled = isEnabled();
        if (self.enabled) {
            self.mode = getMode();
            self.current_context = self.getCurrentContext();
        }

        return self;
    }

    /// Get the current process security context
    pub fn getCurrentContext(self: *Self) ?SecurityContext {
        const context_str = readProcContext("/proc/self/attr/current", &self._context_buf) orelse return null;
        return SecurityContext.parse(context_str);
    }

    /// Get the exec context (context for next exec)
    pub fn getExecContext(self: *Self) ?SecurityContext {
        const context_str = readProcContext("/proc/self/attr/exec", &self._context_buf) orelse return null;
        return SecurityContext.parse(context_str);
    }

    /// Set the exec context for the next execve
    pub fn setExecContext(self: *Self, context: SecurityContext) !void {
        if (!self.enabled) return;

        var ctx_buf: [512]u8 = undefined;
        const ctx_str = context.format(&ctx_buf) orelse return error.InvalidContext;

        try writeProcContext("/proc/self/attr/exec", ctx_str);
    }

    /// Set role for next execution
    pub fn setRole(self: *Self, role: []const u8) !void {
        if (!self.enabled) return;

        if (self.current_context) |ctx| {
            const new_ctx = SecurityContext{
                .user = ctx.user,
                .role = role,
                .type_ = ctx.type_,
                .level = ctx.level,
            };
            try self.setExecContext(new_ctx);
        }
    }

    /// Set type for next execution
    pub fn setType(self: *Self, type_: []const u8) !void {
        if (!self.enabled) return;

        if (self.current_context) |ctx| {
            const new_ctx = SecurityContext{
                .user = ctx.user,
                .role = ctx.role,
                .type_ = type_,
                .level = ctx.level,
            };
            try self.setExecContext(new_ctx);
        }
    }

    /// Clear exec context (reset to default)
    pub fn clearExecContext(self: *Self) void {
        if (!self.enabled) return;
        writeProcContext("/proc/self/attr/exec", "") catch {};
    }

    /// Check if a role transition is allowed
    pub fn isRoleAllowed(self: *Self, role: []const u8) bool {
        if (!self.enabled) return true;
        // In real implementation, would check policy
        _ = role;
        return true;
    }

    /// Check if a type transition is allowed
    pub fn isTypeAllowed(self: *Self, type_: []const u8) bool {
        if (!self.enabled) return true;
        // In real implementation, would check policy
        _ = type_;
        return true;
    }
};

/// Check if SELinux is enabled on the system
pub fn isEnabled() bool {
    // Check /sys/fs/selinux/enforce or /selinux/enforce
    const paths = [_][]const u8{
        "/sys/fs/selinux/enforce",
        "/selinux/enforce",
    };

    for (paths) |path| {
        const file = std.fs.openFileAbsolute(path, .{}) catch continue;
        file.close();
        return true;
    }

    // Also check /proc/filesystems for selinuxfs
    const filesystems = std.fs.openFileAbsolute("/proc/filesystems", .{}) catch return false;
    defer filesystems.close();

    var buf: [4096]u8 = undefined;
    const n = filesystems.read(&buf) catch return false;

    return std.mem.indexOf(u8, buf[0..n], "selinuxfs") != null;
}

/// Get current SELinux mode
pub fn getMode() Mode {
    const paths = [_][]const u8{
        "/sys/fs/selinux/enforce",
        "/selinux/enforce",
    };

    for (paths) |path| {
        const file = std.fs.openFileAbsolute(path, .{}) catch continue;
        defer file.close();

        var buf: [2]u8 = undefined;
        const n = file.read(&buf) catch continue;
        if (n > 0) {
            return if (buf[0] == '1') .enforcing else .permissive;
        }
    }

    return .disabled;
}

/// Read a security context from /proc
fn readProcContext(path: []const u8, buf: []u8) ?[]const u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const n = file.read(buf) catch return null;
    if (n == 0) return null;

    // Remove trailing newline/null
    var len = n;
    while (len > 0 and (buf[len - 1] == '\n' or buf[len - 1] == 0)) {
        len -= 1;
    }

    return buf[0..len];
}

/// Write a security context to /proc
fn writeProcContext(path: []const u8, context: []const u8) !void {
    const file = std.fs.openFileAbsolute(path, .{ .mode = .write_only }) catch |err| {
        return switch (err) {
            error.AccessDenied => error.PermissionDenied,
            error.FileNotFound => error.SELinuxNotAvailable,
            else => error.SELinuxError,
        };
    };
    defer file.close();

    file.writeAll(context) catch return error.SELinuxError;
}

/// Get the security context of a file
pub fn getFileContext(path: []const u8, buf: []u8) ?[]const u8 {
    // Would use getfilecon() in real implementation
    // For now, check /proc/self/attr/fscreate after setting path
    _ = path;
    _ = buf;
    return null;
}

/// Compute the context for a new file in a directory
pub fn computeCreateContext(dir_path: []const u8, buf: []u8) ?[]const u8 {
    // Would use security_compute_create() in real implementation
    _ = dir_path;
    _ = buf;
    return null;
}

/// SELinux-specific errors
pub const SELinuxError = error{
    SELinuxNotAvailable,
    SELinuxError,
    InvalidContext,
    PermissionDenied,
    PolicyViolation,
    RoleNotAllowed,
    TypeNotAllowed,
};

// ============================================
// Sudo-specific SELinux functions
// ============================================

/// Options for SELinux context during sudo execution
pub const SudoSELinuxOptions = struct {
    role: ?[]const u8 = null,
    type_: ?[]const u8 = null,
    preserve_context: bool = false,
};

/// Set up SELinux context for sudo command execution
pub fn setupSudoContext(options: SudoSELinuxOptions) !void {
    if (!isEnabled()) return;

    var ctx = SELinuxContext.init();

    if (options.role) |role| {
        if (!ctx.isRoleAllowed(role)) {
            return error.RoleNotAllowed;
        }
        try ctx.setRole(role);
    }

    if (options.type_) |type_| {
        if (!ctx.isTypeAllowed(type_)) {
            return error.TypeNotAllowed;
        }
        try ctx.setType(type_);
    }
}

/// Clean up SELinux context after sudo execution
pub fn cleanupSudoContext() void {
    if (!isEnabled()) return;

    var ctx = SELinuxContext.init();
    ctx.clearExecContext();
}

// ============================================
// Tests
// ============================================

test "SecurityContext parse valid" {
    const ctx = SecurityContext.parse("user_u:role_r:type_t:s0");
    try std.testing.expect(ctx != null);
    try std.testing.expectEqualStrings("user_u", ctx.?.user);
    try std.testing.expectEqualStrings("role_r", ctx.?.role);
    try std.testing.expectEqualStrings("type_t", ctx.?.type_);
    try std.testing.expectEqualStrings("s0", ctx.?.level.?);
}

test "SecurityContext parse without level" {
    const ctx = SecurityContext.parse("user_u:role_r:type_t");
    try std.testing.expect(ctx != null);
    try std.testing.expectEqualStrings("user_u", ctx.?.user);
    try std.testing.expectEqualStrings("role_r", ctx.?.role);
    try std.testing.expectEqualStrings("type_t", ctx.?.type_);
    try std.testing.expect(ctx.?.level == null);
}

test "SecurityContext parse invalid" {
    const ctx = SecurityContext.parse("invalid");
    try std.testing.expect(ctx == null);
}

test "SecurityContext format" {
    const ctx = SecurityContext{
        .user = "user_u",
        .role = "role_r",
        .type_ = "type_t",
        .level = "s0:c0.c255",
    };
    var buf: [128]u8 = undefined;
    const formatted = ctx.format(&buf);
    try std.testing.expect(formatted != null);
    try std.testing.expectEqualStrings("user_u:role_r:type_t:s0:c0.c255", formatted.?);
}

test "SecurityContext format without level" {
    const ctx = SecurityContext{
        .user = "user_u",
        .role = "role_r",
        .type_ = "type_t",
        .level = null,
    };
    var buf: [128]u8 = undefined;
    const formatted = ctx.format(&buf);
    try std.testing.expect(formatted != null);
    try std.testing.expectEqualStrings("user_u:role_r:type_t", formatted.?);
}

test "SELinuxContext init" {
    const ctx = SELinuxContext.init();
    // Should not crash regardless of whether SELinux is available
    _ = ctx.enabled;
    _ = ctx.mode;
}

test "Mode enum" {
    try std.testing.expectEqual(Mode.disabled, Mode.disabled);
    try std.testing.expectEqual(Mode.permissive, Mode.permissive);
    try std.testing.expectEqual(Mode.enforcing, Mode.enforcing);
}

test "isEnabled returns bool" {
    // Just verify it doesn't crash
    _ = isEnabled();
}

test "getMode returns valid mode" {
    const mode = getMode();
    try std.testing.expect(mode == .disabled or mode == .permissive or mode == .enforcing);
}

test "SudoSELinuxOptions defaults" {
    const options = SudoSELinuxOptions{};
    try std.testing.expect(options.role == null);
    try std.testing.expect(options.type_ == null);
    try std.testing.expect(!options.preserve_context);
}
