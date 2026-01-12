//! Unit tests for error handling
//!
//! Tests for Error types and ErrorContext.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const common = lib.common;
const error_mod = common.error_mod;
const Error = common.Error;
const ErrorContext = error_mod.ErrorContext;
const errCtx = error_mod.errCtx;
const errMsg = error_mod.errMsg;
const errPath = error_mod.errPath;

// ============================================
// Error Enum Tests
// ============================================

test "Error enum contains all expected values" {
    // Verify key errors exist
    const errors = [_]Error{
        error.Silent,
        error.NotAllowed,
        error.SelfCheck,
        error.CommandNotFound,
        error.InvalidCommand,
        error.ChDirNotAllowed,
        error.UserNotFound,
        error.GroupNotFound,
        error.AuthorizationFailed,
        error.InteractionRequired,
        error.EnvironmentVarForbidden,
        error.Configuration,
        error.Options,
        error.PamError,
        error.IoError,
        error.MaxAuthAttempts,
        error.PathValidation,
        error.StringValidation,
        error.AppArmorError,
        error.SystemError,
        error.OutOfMemory,
        error.WouldBlock,
        error.PermissionDenied,
        error.FileNotFound,
        error.InvalidArgument,
    };

    // Verify all are distinct
    for (errors, 0..) |e1, i| {
        for (errors[i + 1 ..]) |e2| {
            try testing.expect(e1 != e2);
        }
    }
}

// ============================================
// ErrorContext Tests
// ============================================

test "ErrorContext creation with error only" {
    const ctx = ErrorContext{ .err = Error.CommandNotFound };

    try testing.expectEqual(Error.CommandNotFound, ctx.err);
    try testing.expectEqual(@as(?[]const u8, null), ctx.message);
    try testing.expectEqual(@as(?[]const u8, null), ctx.path);
    try testing.expectEqual(@as(?[]const u8, null), ctx.username);
    try testing.expectEqual(@as(?[]const u8, null), ctx.hostname);
}

test "ErrorContext with all fields" {
    const ctx = ErrorContext{
        .err = Error.NotAllowed,
        .message = "Permission denied for this command",
        .path = "/usr/bin/restricted",
        .username = "alice",
        .hostname = "server1",
    };

    try testing.expectEqual(Error.NotAllowed, ctx.err);
    try testing.expectEqualStrings("Permission denied for this command", ctx.message.?);
    try testing.expectEqualStrings("/usr/bin/restricted", ctx.path.?);
    try testing.expectEqualStrings("alice", ctx.username.?);
    try testing.expectEqualStrings("server1", ctx.hostname.?);
}

test "ErrorContext.isSilent returns true for Silent error" {
    const silent = ErrorContext{ .err = Error.Silent };
    try testing.expect(silent.isSilent());
}

test "ErrorContext.isSilent returns false for other errors" {
    const not_silent_errors = [_]Error{
        error.CommandNotFound,
        error.NotAllowed,
        error.AuthorizationFailed,
        error.UserNotFound,
        error.Configuration,
    };

    for (not_silent_errors) |err| {
        const ctx = ErrorContext{ .err = err };
        try testing.expect(!ctx.isSilent());
    }
}

// ============================================
// Error Context Helper Functions Tests
// ============================================

test "errCtx creates context from error" {
    const ctx = errCtx(Error.UserNotFound);

    try testing.expectEqual(Error.UserNotFound, ctx.err);
    try testing.expectEqual(@as(?[]const u8, null), ctx.message);
    try testing.expectEqual(@as(?[]const u8, null), ctx.path);
}

test "errMsg creates context with message" {
    const ctx = errMsg(Error.AuthorizationFailed, "Too many failed attempts");

    try testing.expectEqual(Error.AuthorizationFailed, ctx.err);
    try testing.expectEqualStrings("Too many failed attempts", ctx.message.?);
    try testing.expectEqual(@as(?[]const u8, null), ctx.path);
}

test "errPath creates context with path" {
    const ctx = errPath(Error.CommandNotFound, "/nonexistent/command");

    try testing.expectEqual(Error.CommandNotFound, ctx.err);
    try testing.expectEqualStrings("/nonexistent/command", ctx.path.?);
    try testing.expectEqual(@as(?[]const u8, null), ctx.message);
}

// ============================================
// Common Error Scenarios Tests
// ============================================

test "authentication error scenario" {
    const ctx = ErrorContext{
        .err = Error.AuthorizationFailed,
        .message = "3 incorrect password attempts",
        .username = "mallory",
        .hostname = "secure-server",
    };

    try testing.expect(!ctx.isSilent());
    try testing.expectEqual(Error.AuthorizationFailed, ctx.err);
    try testing.expectEqualStrings("mallory", ctx.username.?);
}

test "command not found scenario" {
    const ctx = errPath(Error.CommandNotFound, "/usr/local/bin/nonexistent");

    try testing.expect(!ctx.isSilent());
    try testing.expectEqual(Error.CommandNotFound, ctx.err);
    try testing.expect(std.mem.startsWith(u8, ctx.path.?, "/usr/local/bin/"));
}

test "permission denied scenario" {
    const ctx = ErrorContext{
        .err = Error.NotAllowed,
        .message = "user not in sudoers",
        .username = "guest",
        .path = "/etc/shadow",
    };

    try testing.expectEqual(Error.NotAllowed, ctx.err);
    try testing.expectEqualStrings("guest", ctx.username.?);
    try testing.expectEqualStrings("/etc/shadow", ctx.path.?);
}

test "configuration error scenario" {
    const ctx = errMsg(Error.Configuration, "syntax error in /etc/sudoers line 42");

    try testing.expectEqual(Error.Configuration, ctx.err);
    try testing.expect(std.mem.indexOf(u8, ctx.message.?, "sudoers") != null);
}

test "PAM error scenario" {
    const ctx = ErrorContext{
        .err = Error.PamError,
        .message = "PAM authentication failure",
    };

    try testing.expectEqual(Error.PamError, ctx.err);
}

// ============================================
// Error Classification Tests
// ============================================

test "user-related errors" {
    const user_errors = [_]Error{
        error.UserNotFound,
        error.GroupNotFound,
        error.NotAllowed,
        error.AuthorizationFailed,
    };

    for (user_errors) |err| {
        const ctx = errCtx(err);
        try testing.expect(!ctx.isSilent());
    }
}

test "system-related errors" {
    const system_errors = [_]Error{
        error.SystemError,
        error.IoError,
        error.OutOfMemory,
        error.WouldBlock,
        error.PermissionDenied,
        error.FileNotFound,
    };

    for (system_errors) |err| {
        const ctx = errCtx(err);
        try testing.expect(!ctx.isSilent());
    }
}

test "validation errors" {
    const validation_errors = [_]Error{
        error.InvalidCommand,
        error.InvalidArgument,
        error.PathValidation,
        error.StringValidation,
    };

    for (validation_errors) |err| {
        const ctx = errCtx(err);
        try testing.expect(!ctx.isSilent());
    }
}

test "security-related errors" {
    const security_errors = [_]Error{
        error.NotAllowed,
        error.AuthorizationFailed,
        error.MaxAuthAttempts,
        error.EnvironmentVarForbidden,
        error.AppArmorError,
    };

    for (security_errors) |err| {
        const ctx = errCtx(err);
        try testing.expect(!ctx.isSilent());
    }
}
