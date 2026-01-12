//! IO utilities for Zig 0.15+ compatibility
//!
//! Provides buffered writers for stdout/stderr

const std = @import("std");

/// Get a buffered writer for stderr
pub fn getStdErr() StdErrWriter {
    return .{};
}

/// Get a buffered writer for stdout  
pub fn getStdOut() StdOutWriter {
    return .{};
}

pub const StdErrWriter = struct {
    var buffer: [4096]u8 = undefined;

    pub fn writer(self: *StdErrWriter) std.fs.File.Writer {
        _ = self;
        var file = std.fs.File{ .handle = std.posix.STDERR_FILENO };
        return file.writer(&buffer);
    }

    pub fn print(_: *StdErrWriter, comptime fmt: []const u8, args: anytype) !void {
        var file = std.fs.File{ .handle = std.posix.STDERR_FILENO };
        const w = file.writer(&buffer);
        try w.print(fmt, args);
    }

    pub fn writeAll(self: *StdErrWriter, bytes: []const u8) !void {
        _ = self;
        _ = std.posix.write(std.posix.STDERR_FILENO, bytes) catch return error.WriteError;
    }

    pub fn writeByte(self: *StdErrWriter, byte: u8) !void {
        _ = self;
        var buf = [1]u8{byte};
        _ = std.posix.write(std.posix.STDERR_FILENO, &buf) catch return error.WriteError;
    }
};

pub const StdOutWriter = struct {
    var buffer: [4096]u8 = undefined;

    pub fn writer(self: *StdOutWriter) std.fs.File.Writer {
        _ = self;
        var file = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
        return file.writer(&buffer);
    }

    pub fn print(_: *StdOutWriter, comptime fmt: []const u8, args: anytype) !void {
        var file = std.fs.File{ .handle = std.posix.STDOUT_FILENO };
        const w = file.writer(&buffer);
        try w.print(fmt, args);
    }

    pub fn writeAll(self: *StdOutWriter, bytes: []const u8) !void {
        _ = self;
        _ = std.posix.write(std.posix.STDOUT_FILENO, bytes) catch return error.WriteError;
    }

    pub fn writeByte(self: *StdOutWriter, byte: u8) !void {
        _ = self;
        var buf = [1]u8{byte};
        _ = std.posix.write(std.posix.STDOUT_FILENO, &buf) catch return error.WriteError;
    }
};
