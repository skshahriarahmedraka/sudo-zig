//! C utility wrappers
//!
//! Provides safe wrappers around C library functions.

const std = @import("std");
const c = std.c;

pub const io = @import("io.zig");

/// Convert a Zig slice to a null-terminated C string.
/// Returns error if the slice contains null bytes.
pub fn toCString(allocator: std.mem.Allocator, slice: []const u8) ![:0]u8 {
    if (std.mem.indexOfScalar(u8, slice, 0) != null) {
        return error.EmbeddedNull;
    }
    return allocator.dupeZ(u8, slice);
}

/// Convert a null-terminated C string to a Zig slice.
pub fn fromCString(cstr: [*:0]const u8) []const u8 {
    return std.mem.span(cstr);
}

/// Convert a C string that may be null.
pub fn fromCStringOptional(cstr: ?[*:0]const u8) ?[]const u8 {
    if (cstr) |s| {
        return std.mem.span(s);
    }
    return null;
}

/// Safe wrapper for strerror
pub fn strerror(errno: c_int) []const u8 {
    const msg = c.strerror(errno);
    if (msg) |m| {
        return std.mem.span(m);
    }
    return "Unknown error";
}

test "toCString" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = try toCString(allocator, "hello");
    defer allocator.free(result);
    try testing.expectEqualStrings("hello", result);

    // Should fail with embedded null
    const bad = toCString(allocator, "hel\x00lo");
    try testing.expectError(error.EmbeddedNull, bad);
}

test "fromCString" {
    const cstr: [*:0]const u8 = "test";
    const slice = fromCString(cstr);
    try std.testing.expectEqualStrings("test", slice);
}
