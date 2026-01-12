//! Safe string handling for sudo-zig
//!
//! Provides string types that validate against null bytes and other
//! potentially dangerous content.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A validated string that cannot contain null bytes.
/// This is important for security when passing strings to C functions.
pub const SudoString = struct {
    data: []const u8,

    const Self = @This();

    /// Initialize a SudoString, validating that it contains no null bytes.
    pub fn init(data: []const u8) error{StringValidation}!Self {
        if (std.mem.indexOfScalar(u8, data, 0) != null) {
            return error.StringValidation;
        }
        return .{ .data = data };
    }

    /// Create from a null-terminated C string.
    /// Safe because C strings are guaranteed to have no embedded nulls.
    pub fn fromCstr(cstr: [*:0]const u8) Self {
        return .{ .data = std.mem.span(cstr) };
    }

    /// Convert to a null-terminated string for C interop.
    /// Caller owns the returned memory.
    pub fn toCstr(self: Self, allocator: Allocator) ![:0]u8 {
        return allocator.dupeZ(u8, self.data);
    }

    /// Get the underlying slice.
    pub fn slice(self: Self) []const u8 {
        return self.data;
    }

    /// Get the length of the string.
    pub fn len(self: Self) usize {
        return self.data.len;
    }

    /// Check if empty.
    pub fn isEmpty(self: Self) bool {
        return self.data.len == 0;
    }

    /// Format for printing.
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(self.data);
    }

    /// Check equality with another SudoString.
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.data, other.data);
    }

    /// Check equality with a regular string slice.
    pub fn eqlSlice(self: Self, other: []const u8) bool {
        return std.mem.eql(u8, self.data, other);
    }
};

/// Secure memory handling for sensitive strings (like passwords).
/// Automatically clears memory on deinitialization.
pub const SecureString = struct {
    data: []u8,
    allocator: Allocator,

    const Self = @This();

    /// Create a new secure string by copying data.
    pub fn init(allocator: Allocator, data: []const u8) !Self {
        const copy = try allocator.alloc(u8, data.len);
        @memcpy(copy, data);
        return .{
            .data = copy,
            .allocator = allocator,
        };
    }

    /// Create with a specific capacity (for reading passwords).
    pub fn initCapacity(allocator: Allocator, capacity: usize) !Self {
        const data = try allocator.alloc(u8, capacity);
        @memset(data, 0);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    /// Securely clear and free the memory.
    pub fn deinit(self: *Self) void {
        secureClear(self.data);
        self.allocator.free(self.data);
        self.data = &.{};
    }

    /// Get the underlying slice (use with caution).
    pub fn slice(self: Self) []const u8 {
        return self.data;
    }

    /// Get the length.
    pub fn len(self: Self) usize {
        return self.data.len;
    }
};

/// Securely clear a buffer to prevent sensitive data from lingering in memory.
/// Uses volatile operations to prevent compiler optimization.
pub fn secureClear(buffer: []u8) void {
    @memset(buffer, 0);
    // Prevent the compiler from optimizing away the memset
    std.mem.doNotOptimizeAway(buffer.ptr);
}

/// Check if a string contains any null bytes.
pub fn containsNull(data: []const u8) bool {
    return std.mem.indexOfScalar(u8, data, 0) != null;
}

/// Split a string by a delimiter, returning an iterator.
pub fn split(data: []const u8, delimiter: u8) std.mem.SplitIterator(u8, .scalar) {
    return std.mem.splitScalar(u8, data, delimiter);
}

/// Join strings with a separator.
pub fn join(allocator: Allocator, strings: []const []const u8, separator: []const u8) ![]u8 {
    return std.mem.join(allocator, separator, strings);
}

// ============================================
// Tests
// ============================================

test "SudoString validation" {
    const testing = std.testing;

    // Valid string
    const valid = try SudoString.init("hello world");
    try testing.expectEqualStrings("hello world", valid.slice());

    // String with null byte should fail
    const invalid = SudoString.init("hello\x00world");
    try testing.expectError(error.StringValidation, invalid);

    // Empty string is valid
    const empty = try SudoString.init("");
    try testing.expect(empty.isEmpty());
}

test "SudoString from C string" {
    const testing = std.testing;

    const cstr: [*:0]const u8 = "test string";
    const sudo_str = SudoString.fromCstr(cstr);
    try testing.expectEqualStrings("test string", sudo_str.slice());
}

test "SecureString clear on deinit" {
    const testing = std.testing;

    var secure = try SecureString.init(testing.allocator, "secret password");
    const ptr = secure.data.ptr;

    // Verify the password is there
    try testing.expectEqualStrings("secret password", secure.slice());

    // Deinit should clear memory
    secure.deinit();

    // After deinit, the data slice should be empty
    try testing.expectEqual(@as(usize, 0), secure.data.len);

    // Note: We can't reliably test that the memory was zeroed because
    // the allocator may have already reused it. But the secureClear
    // function is called.
    _ = ptr;
}

test "secureClear" {
    var buffer = [_]u8{ 'a', 'b', 'c', 'd' };
    secureClear(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "containsNull" {
    const testing = std.testing;

    try testing.expect(!containsNull("hello"));
    try testing.expect(containsNull("hel\x00lo"));
    try testing.expect(!containsNull(""));
}
