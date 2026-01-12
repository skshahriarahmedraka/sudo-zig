//! Error types for sudo-zig
//!
//! Provides comprehensive error handling for all sudo operations.

const std = @import("std");

/// Main error type for sudo-zig operations
pub const Error = error{
    Silent,
    NotAllowed,
    SelfCheck,
    CommandNotFound,
    InvalidCommand,
    ChDirNotAllowed,
    UserNotFound,
    GroupNotFound,
    AuthorizationFailed,
    InteractionRequired,
    EnvironmentVarForbidden,
    Configuration,
    Options,
    PamError,
    IoError,
    MaxAuthAttempts,
    PathValidation,
    StringValidation,
    AppArmorError,
    SystemError,
    OutOfMemory,
    WouldBlock,
    PermissionDenied,
    FileNotFound,
    InvalidArgument,
};

/// Extended error information with context
pub const ErrorContext = struct {
    err: Error,
    message: ?[]const u8 = null,
    path: ?[]const u8 = null,
    username: ?[]const u8 = null,
    hostname: ?[]const u8 = null,

    const Self = @This();

    /// Check if this error should be silent (no message printed)
    pub fn isSilent(self: Self) bool {
        return self.err == Error.Silent;
    }
};

/// Create an error context from an error
pub fn errCtx(err: Error) ErrorContext {
    return .{ .err = err };
}

/// Create an error context with a message
pub fn errMsg(err: Error, message: []const u8) ErrorContext {
    return .{ .err = err, .message = message };
}

/// Create an error context with a path
pub fn errPath(err: Error, err_path: []const u8) ErrorContext {
    return .{ .err = err, .path = err_path };
}

// ============================================
// Tests
// ============================================

test "error context silent check" {
    const testing = std.testing;

    const silent = ErrorContext{ .err = Error.Silent };
    try testing.expect(silent.isSilent());

    const not_silent = ErrorContext{ .err = Error.CommandNotFound };
    try testing.expect(!not_silent.isSilent());
}
