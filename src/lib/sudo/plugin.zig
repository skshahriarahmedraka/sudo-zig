//! Plugin API for sudo-zig
//!
//! This module provides an extensibility system for sudo, allowing custom:
//! - Authentication methods
//! - Policy decision modules
//! - I/O logging backends
//! - Audit event handlers
//!
//! The plugin API is inspired by sudo's native plugin interface but simplified
//! for Zig's type system.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Plugin API version
pub const API_VERSION = struct {
    pub const MAJOR: u32 = 1;
    pub const MINOR: u32 = 0;
    pub const PATCH: u32 = 0;

    pub fn asU32() u32 {
        return (MAJOR << 16) | (MINOR << 8) | PATCH;
    }
};

/// Plugin type enumeration
pub const PluginType = enum(u8) {
    /// Policy decision plugin
    policy = 1,
    /// I/O logging plugin
    io_log = 2,
    /// Audit event plugin
    audit = 3,
    /// Authentication plugin
    auth = 4,
    /// Approval plugin (for multi-factor workflows)
    approval = 5,
};

/// Plugin capability flags
pub const Capabilities = packed struct {
    /// Plugin supports async operations
    async_ops: bool = false,
    /// Plugin supports configuration reload
    hot_reload: bool = false,
    /// Plugin is thread-safe
    thread_safe: bool = false,
    /// Plugin supports session tracking
    session_aware: bool = false,
    /// Reserved for future use
    _reserved: u28 = 0,
};

/// Plugin information structure
pub const PluginInfo = struct {
    /// Plugin name
    name: []const u8,
    /// Plugin version string
    version: []const u8,
    /// Plugin description
    description: []const u8,
    /// Plugin author
    author: []const u8,
    /// Plugin type
    plugin_type: PluginType,
    /// API version this plugin was built for
    api_version: u32,
    /// Plugin capabilities
    capabilities: Capabilities,
};

/// Command context passed to plugins
pub const CommandContext = struct {
    /// User invoking sudo
    submit_user: []const u8,
    /// User ID
    submit_uid: u32,
    /// Group ID
    submit_gid: u32,
    /// Groups
    submit_groups: []const u32,
    /// Target user
    runas_user: []const u8,
    /// Target user ID
    runas_uid: u32,
    /// Target group
    runas_group: ?[]const u8,
    /// Target group ID
    runas_gid: ?u32,
    /// Command to execute
    command: []const u8,
    /// Command arguments
    arguments: []const []const u8,
    /// Working directory
    cwd: []const u8,
    /// TTY device
    tty: ?[]const u8,
    /// Hostname
    host: []const u8,
    /// Environment variables
    environment: std.StringHashMap([]const u8),
};

/// Policy decision result
pub const PolicyResult = struct {
    /// Whether the command is allowed
    allowed: bool,
    /// Reason for decision
    reason: ?[]const u8 = null,
    /// Modified command (if plugin wants to change it)
    modified_command: ?[]const u8 = null,
    /// Modified arguments
    modified_arguments: ?[]const []const u8 = null,
    /// Additional environment variables to set
    extra_env: ?std.StringHashMap([]const u8) = null,
    /// Require authentication
    require_auth: bool = true,
    /// Custom error code
    error_code: ?i32 = null,
};

/// Authentication result
pub const AuthResult = enum {
    /// Authentication successful
    success,
    /// Authentication failed
    failure,
    /// Authentication requires more input
    continue_auth,
    /// Authentication error (internal)
    error_internal,
    /// Authentication not applicable (try next plugin)
    not_applicable,
};

/// Audit event types
pub const AuditEvent = enum {
    /// Session start
    session_start,
    /// Session end
    session_end,
    /// Command accepted
    command_accept,
    /// Command rejected
    command_reject,
    /// Authentication success
    auth_success,
    /// Authentication failure
    auth_failure,
    /// I/O event (stdin/stdout/stderr)
    io_event,
    /// Error occurred
    error_event,
};

/// Audit event data
pub const AuditEventData = struct {
    /// Event type
    event_type: AuditEvent,
    /// Timestamp
    timestamp: i64,
    /// Command context (if applicable)
    context: ?*const CommandContext,
    /// Additional message
    message: ?[]const u8,
    /// Result code
    result_code: i32,
};

// ============================================
// Plugin Interface Definitions
// ============================================

/// Policy plugin interface
pub const PolicyPlugin = struct {
    /// Plugin information
    info: PluginInfo,

    /// Initialize the plugin
    initFn: *const fn (allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque,

    /// Check if command is allowed
    checkFn: *const fn (self: *anyopaque, ctx: *const CommandContext) anyerror!PolicyResult,

    /// List user privileges (for sudo -l)
    listFn: ?*const fn (self: *anyopaque, user: []const u8, host: []const u8) anyerror![]const []const u8,

    /// Validate configuration
    validateFn: ?*const fn (self: *anyopaque) anyerror!bool,

    /// Close/cleanup
    closeFn: *const fn (self: *anyopaque) void,

    const Self = @This();

    /// Create policy plugin wrapper
    pub fn create(comptime T: type) Self {
        return .{
            .info = T.plugin_info,
            .initFn = struct {
                fn init(allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque {
                    const instance = try T.init(allocator, config);
                    return @ptrCast(instance);
                }
            }.init,
            .checkFn = struct {
                fn check(self: *anyopaque, ctx: *const CommandContext) anyerror!PolicyResult {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.check(ctx);
                }
            }.check,
            .listFn = if (@hasDecl(T, "list")) struct {
                fn list(self: *anyopaque, user: []const u8, host: []const u8) anyerror![]const []const u8 {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.list(user, host);
                }
            }.list else null,
            .validateFn = if (@hasDecl(T, "validate")) struct {
                fn validate(self: *anyopaque) anyerror!bool {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.validate();
                }
            }.validate else null,
            .closeFn = struct {
                fn close(self: *anyopaque) void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    typed.close();
                }
            }.close,
        };
    }
};

/// I/O Log plugin interface
pub const IoLogPlugin = struct {
    info: PluginInfo,

    initFn: *const fn (allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque,
    openFn: *const fn (self: *anyopaque, ctx: *const CommandContext) anyerror!void,
    logStdinFn: ?*const fn (self: *anyopaque, data: []const u8) anyerror!void,
    logStdoutFn: ?*const fn (self: *anyopaque, data: []const u8) anyerror!void,
    logStderrFn: ?*const fn (self: *anyopaque, data: []const u8) anyerror!void,
    logTtyinFn: ?*const fn (self: *anyopaque, data: []const u8) anyerror!void,
    logTtyoutFn: ?*const fn (self: *anyopaque, data: []const u8) anyerror!void,
    closeFn: *const fn (self: *anyopaque, exit_status: i32, error_msg: ?[]const u8) void,

    const Self = @This();

    pub fn create(comptime T: type) Self {
        return .{
            .info = T.plugin_info,
            .initFn = struct {
                fn init(allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque {
                    const instance = try T.init(allocator, config);
                    return @ptrCast(instance);
                }
            }.init,
            .openFn = struct {
                fn open(self: *anyopaque, ctx: *const CommandContext) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.open(ctx);
                }
            }.open,
            .logStdinFn = if (@hasDecl(T, "logStdin")) struct {
                fn logStdin(self: *anyopaque, data: []const u8) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.logStdin(data);
                }
            }.logStdin else null,
            .logStdoutFn = if (@hasDecl(T, "logStdout")) struct {
                fn logStdout(self: *anyopaque, data: []const u8) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.logStdout(data);
                }
            }.logStdout else null,
            .logStderrFn = if (@hasDecl(T, "logStderr")) struct {
                fn logStderr(self: *anyopaque, data: []const u8) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.logStderr(data);
                }
            }.logStderr else null,
            .logTtyinFn = if (@hasDecl(T, "logTtyin")) struct {
                fn logTtyin(self: *anyopaque, data: []const u8) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.logTtyin(data);
                }
            }.logTtyin else null,
            .logTtyoutFn = if (@hasDecl(T, "logTtyout")) struct {
                fn logTtyout(self: *anyopaque, data: []const u8) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.logTtyout(data);
                }
            }.logTtyout else null,
            .closeFn = struct {
                fn close(self: *anyopaque, exit_status: i32, error_msg: ?[]const u8) void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    typed.close(exit_status, error_msg);
                }
            }.close,
        };
    }
};

/// Audit plugin interface
pub const AuditPlugin = struct {
    info: PluginInfo,

    initFn: *const fn (allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque,
    eventFn: *const fn (self: *anyopaque, event: *const AuditEventData) anyerror!void,
    closeFn: *const fn (self: *anyopaque) void,

    const Self = @This();

    pub fn create(comptime T: type) Self {
        return .{
            .info = T.plugin_info,
            .initFn = struct {
                fn init(allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque {
                    const instance = try T.init(allocator, config);
                    return @ptrCast(instance);
                }
            }.init,
            .eventFn = struct {
                fn event(self: *anyopaque, ev: *const AuditEventData) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.event(ev);
                }
            }.event,
            .closeFn = struct {
                fn close(self: *anyopaque) void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    typed.close();
                }
            }.close,
        };
    }
};

/// Authentication plugin interface
pub const AuthPlugin = struct {
    info: PluginInfo,

    initFn: *const fn (allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque,
    authenticateFn: *const fn (self: *anyopaque, user: []const u8, password: ?[]const u8) anyerror!AuthResult,
    beginSessionFn: ?*const fn (self: *anyopaque, ctx: *const CommandContext) anyerror!void,
    endSessionFn: ?*const fn (self: *anyopaque) void,
    closeFn: *const fn (self: *anyopaque) void,

    const Self = @This();

    pub fn create(comptime T: type) Self {
        return .{
            .info = T.plugin_info,
            .initFn = struct {
                fn init(allocator: Allocator, config: ?[]const u8) anyerror!*anyopaque {
                    const instance = try T.init(allocator, config);
                    return @ptrCast(instance);
                }
            }.init,
            .authenticateFn = struct {
                fn authenticate(self: *anyopaque, user: []const u8, password: ?[]const u8) anyerror!AuthResult {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.authenticate(user, password);
                }
            }.authenticate,
            .beginSessionFn = if (@hasDecl(T, "beginSession")) struct {
                fn beginSession(self: *anyopaque, ctx: *const CommandContext) anyerror!void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    return typed.beginSession(ctx);
                }
            }.beginSession else null,
            .endSessionFn = if (@hasDecl(T, "endSession")) struct {
                fn endSession(self: *anyopaque) void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    typed.endSession();
                }
            }.endSession else null,
            .closeFn = struct {
                fn close(self: *anyopaque) void {
                    const typed: *T = @ptrCast(@alignCast(self));
                    typed.close();
                }
            }.close,
        };
    }
};

// ============================================
// Plugin Registry
// ============================================

/// Plugin registry for managing loaded plugins
pub const PluginRegistry = struct {
    allocator: Allocator,
    policy_plugins: std.ArrayList(LoadedPlugin(PolicyPlugin)),
    io_log_plugins: std.ArrayList(LoadedPlugin(IoLogPlugin)),
    audit_plugins: std.ArrayList(LoadedPlugin(AuditPlugin)),
    auth_plugins: std.ArrayList(LoadedPlugin(AuthPlugin)),

    const Self = @This();

    fn LoadedPlugin(comptime T: type) type {
        return struct {
            plugin: T,
            instance: *anyopaque,
            enabled: bool,
        };
    }

    /// Create a new plugin registry
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy_plugins = std.ArrayList(LoadedPlugin(PolicyPlugin)).init(allocator),
            .io_log_plugins = std.ArrayList(LoadedPlugin(IoLogPlugin)).init(allocator),
            .audit_plugins = std.ArrayList(LoadedPlugin(AuditPlugin)).init(allocator),
            .auth_plugins = std.ArrayList(LoadedPlugin(AuthPlugin)).init(allocator),
        };
    }

    /// Register a policy plugin
    pub fn registerPolicy(self: *Self, plugin: PolicyPlugin, config: ?[]const u8) !void {
        const instance = try plugin.initFn(self.allocator, config);
        try self.policy_plugins.append(.{
            .plugin = plugin,
            .instance = instance,
            .enabled = true,
        });
    }

    /// Register an I/O log plugin
    pub fn registerIoLog(self: *Self, plugin: IoLogPlugin, config: ?[]const u8) !void {
        const instance = try plugin.initFn(self.allocator, config);
        try self.io_log_plugins.append(.{
            .plugin = plugin,
            .instance = instance,
            .enabled = true,
        });
    }

    /// Register an audit plugin
    pub fn registerAudit(self: *Self, plugin: AuditPlugin, config: ?[]const u8) !void {
        const instance = try plugin.initFn(self.allocator, config);
        try self.audit_plugins.append(.{
            .plugin = plugin,
            .instance = instance,
            .enabled = true,
        });
    }

    /// Register an authentication plugin
    pub fn registerAuth(self: *Self, plugin: AuthPlugin, config: ?[]const u8) !void {
        const instance = try plugin.initFn(self.allocator, config);
        try self.auth_plugins.append(.{
            .plugin = plugin,
            .instance = instance,
            .enabled = true,
        });
    }

    /// Check policy using all registered policy plugins
    pub fn checkPolicy(self: *Self, ctx: *const CommandContext) !PolicyResult {
        for (self.policy_plugins.items) |*loaded| {
            if (!loaded.enabled) continue;

            const result = try loaded.plugin.checkFn(loaded.instance, ctx);
            if (!result.allowed) {
                return result;
            }
        }

        // All plugins allowed, return success
        return PolicyResult{ .allowed = true };
    }

    /// Authenticate using registered auth plugins
    pub fn authenticate(self: *Self, user: []const u8, password: ?[]const u8) !AuthResult {
        for (self.auth_plugins.items) |*loaded| {
            if (!loaded.enabled) continue;

            const result = try loaded.plugin.authenticateFn(loaded.instance, user, password);
            switch (result) {
                .success => return .success,
                .failure => return .failure,
                .not_applicable => continue,
                .continue_auth => continue,
                .error_internal => return .error_internal,
            }
        }

        // No plugin handled authentication
        return .not_applicable;
    }

    /// Send audit event to all audit plugins
    pub fn audit(self: *Self, event: *const AuditEventData) !void {
        for (self.audit_plugins.items) |*loaded| {
            if (!loaded.enabled) continue;
            try loaded.plugin.eventFn(loaded.instance, event);
        }
    }

    /// Log I/O to all I/O log plugins
    pub fn logStdout(self: *Self, data: []const u8) !void {
        for (self.io_log_plugins.items) |*loaded| {
            if (!loaded.enabled) continue;
            if (loaded.plugin.logStdoutFn) |logFn| {
                try logFn(loaded.instance, data);
            }
        }
    }

    /// Clean up all plugins
    pub fn deinit(self: *Self) void {
        for (self.policy_plugins.items) |*loaded| {
            loaded.plugin.closeFn(loaded.instance);
        }
        for (self.io_log_plugins.items) |*loaded| {
            loaded.plugin.closeFn(loaded.instance, 0, null);
        }
        for (self.audit_plugins.items) |*loaded| {
            loaded.plugin.closeFn(loaded.instance);
        }
        for (self.auth_plugins.items) |*loaded| {
            loaded.plugin.closeFn(loaded.instance);
        }

        self.policy_plugins.deinit();
        self.io_log_plugins.deinit();
        self.audit_plugins.deinit();
        self.auth_plugins.deinit();
    }
};

// ============================================
// Example Plugin Implementations
// ============================================

/// Example: Simple allow-all policy plugin
pub const AllowAllPolicy = struct {
    allocator: Allocator,

    pub const plugin_info = PluginInfo{
        .name = "allow_all",
        .version = "1.0.0",
        .description = "Simple policy that allows all commands",
        .author = "sudo-zig",
        .plugin_type = .policy,
        .api_version = API_VERSION.asU32(),
        .capabilities = .{},
    };

    pub fn init(allocator: Allocator, config: ?[]const u8) !*AllowAllPolicy {
        _ = config;
        const self = try allocator.create(AllowAllPolicy);
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn check(self: *AllowAllPolicy, ctx: *const CommandContext) !PolicyResult {
        _ = self;
        _ = ctx;
        return PolicyResult{ .allowed = true, .require_auth = false };
    }

    pub fn close(self: *AllowAllPolicy) void {
        self.allocator.destroy(self);
    }
};

/// Example: Simple logging audit plugin
pub const LoggingAudit = struct {
    allocator: Allocator,
    log_file: ?std.fs.File,

    pub const plugin_info = PluginInfo{
        .name = "logging_audit",
        .version = "1.0.0",
        .description = "Audit plugin that logs events to a file",
        .author = "sudo-zig",
        .plugin_type = .audit,
        .api_version = API_VERSION.asU32(),
        .capabilities = .{},
    };

    pub fn init(allocator: Allocator, config: ?[]const u8) !*LoggingAudit {
        const self = try allocator.create(LoggingAudit);
        self.* = .{
            .allocator = allocator,
            .log_file = if (config) |path|
                std.fs.cwd().createFile(path, .{ .truncate = false }) catch null
            else
                null,
        };
        return self;
    }

    pub fn event(self: *LoggingAudit, ev: *const AuditEventData) !void {
        if (self.log_file) |file| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[{d}] {s}: {s}\n", .{
                ev.timestamp,
                @tagName(ev.event_type),
                ev.message orelse "",
            }) catch return;
            _ = file.write(msg) catch {};
        }
    }

    pub fn close(self: *LoggingAudit) void {
        if (self.log_file) |file| file.close();
        self.allocator.destroy(self);
    }
};

// ============================================
// Tests
// ============================================

test "API_VERSION" {
    const version = API_VERSION.asU32();
    try std.testing.expect(version > 0);
    try std.testing.expectEqual(@as(u32, 1), API_VERSION.MAJOR);
}

test "PluginType values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(PluginType.policy));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(PluginType.auth));
}

test "Capabilities default" {
    const caps = Capabilities{};
    try std.testing.expect(!caps.async_ops);
    try std.testing.expect(!caps.thread_safe);
}

test "PolicyResult default" {
    const result = PolicyResult{ .allowed = true };
    try std.testing.expect(result.allowed);
    try std.testing.expect(result.require_auth);
    try std.testing.expect(result.reason == null);
}

test "AuthResult values" {
    try std.testing.expect(AuthResult.success != AuthResult.failure);
}

test "AuditEvent values" {
    try std.testing.expect(AuditEvent.session_start != AuditEvent.session_end);
}

test "PluginRegistry init and deinit" {
    var registry = PluginRegistry.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expectEqual(@as(usize, 0), registry.policy_plugins.items.len);
}

test "AllowAllPolicy plugin" {
    const plugin = PolicyPlugin.create(AllowAllPolicy);

    try std.testing.expectEqualStrings("allow_all", plugin.info.name);
    try std.testing.expectEqual(PluginType.policy, plugin.info.plugin_type);
}

test "LoggingAudit plugin" {
    const plugin = AuditPlugin.create(LoggingAudit);

    try std.testing.expectEqualStrings("logging_audit", plugin.info.name);
    try std.testing.expectEqual(PluginType.audit, plugin.info.plugin_type);
}

test "PluginRegistry registerPolicy" {
    var registry = PluginRegistry.init(std.testing.allocator);
    defer registry.deinit();

    const plugin = PolicyPlugin.create(AllowAllPolicy);
    try registry.registerPolicy(plugin, null);

    try std.testing.expectEqual(@as(usize, 1), registry.policy_plugins.items.len);
}
