//! Unit tests for common string utilities
//!
//! Tests for safe string handling, including null byte validation
//! and secure string operations.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const string = lib.common.string;
const SudoString = string.SudoString;
const SecureString = string.SecureString;

// ============================================
// SudoString Tests
// ============================================

test "SudoString.init valid string" {
    const s = try SudoString.init("hello world");
    try testing.expectEqualStrings("hello world", s.slice());
    try testing.expectEqual(@as(usize, 11), s.len());
}

test "SudoString.init empty string" {
    const s = try SudoString.init("");
    try testing.expect(s.isEmpty());
    try testing.expectEqual(@as(usize, 0), s.len());
}

test "SudoString.init rejects null bytes" {
    const result = SudoString.init("hello\x00world");
    try testing.expectError(error.StringValidation, result);
}

test "SudoString.init rejects embedded null at start" {
    const result = SudoString.init("\x00hello");
    try testing.expectError(error.StringValidation, result);
}

test "SudoString.init rejects embedded null at end" {
    const result = SudoString.init("hello\x00");
    try testing.expectError(error.StringValidation, result);
}

test "SudoString.fromCstr" {
    const cstr: [*:0]const u8 = "test string";
    const s = SudoString.fromCstr(cstr);
    try testing.expectEqualStrings("test string", s.slice());
}

test "SudoString.toCstr" {
    const s = try SudoString.init("hello");
    const cstr = try s.toCstr(testing.allocator);
    defer testing.allocator.free(cstr);
    
    try testing.expectEqualStrings("hello", cstr);
    try testing.expectEqual(@as(u8, 0), cstr[5]); // null terminator
}

test "SudoString.eql" {
    const s1 = try SudoString.init("hello");
    const s2 = try SudoString.init("hello");
    const s3 = try SudoString.init("world");
    
    try testing.expect(s1.eql(s2));
    try testing.expect(!s1.eql(s3));
}

test "SudoString.eqlSlice" {
    const s = try SudoString.init("hello");
    
    try testing.expect(s.eqlSlice("hello"));
    try testing.expect(!s.eqlSlice("world"));
    try testing.expect(!s.eqlSlice("hell"));
}

// ============================================
// SecureString Tests
// ============================================

test "SecureString.init copies data" {
    const original = "secret password";
    var secure = try SecureString.init(testing.allocator, original);
    defer secure.deinit();
    
    try testing.expectEqualStrings(original, secure.slice());
    try testing.expectEqual(@as(usize, 15), secure.len());
}

test "SecureString.initCapacity creates zeroed buffer" {
    var secure = try SecureString.initCapacity(testing.allocator, 32);
    defer secure.deinit();
    
    try testing.expectEqual(@as(usize, 32), secure.len());
    for (secure.data) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "SecureString.deinit clears data" {
    var secure = try SecureString.init(testing.allocator, "secret");
    
    // Verify data is there before deinit
    try testing.expectEqualStrings("secret", secure.slice());
    
    secure.deinit();
    
    // After deinit, the slice should be empty
    try testing.expectEqual(@as(usize, 0), secure.data.len);
}

// ============================================
// Utility Function Tests
// ============================================

test "secureClear zeros buffer" {
    var buffer = [_]u8{ 'a', 'b', 'c', 'd', 'e' };
    string.secureClear(&buffer);
    
    for (buffer) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "containsNull detects null byte" {
    try testing.expect(!string.containsNull("hello"));
    try testing.expect(string.containsNull("hel\x00lo"));
    try testing.expect(string.containsNull("\x00"));
    try testing.expect(!string.containsNull(""));
}

test "split by delimiter" {
    const data = "one:two:three";
    var it = string.split(data, ':');
    
    try testing.expectEqualStrings("one", it.next().?);
    try testing.expectEqualStrings("two", it.next().?);
    try testing.expectEqualStrings("three", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "join strings" {
    const strings = [_][]const u8{ "one", "two", "three" };
    const result = try string.join(testing.allocator, &strings, ", ");
    defer testing.allocator.free(result);
    
    try testing.expectEqualStrings("one, two, three", result);
}

test "join single string" {
    const strings = [_][]const u8{"alone"};
    const result = try string.join(testing.allocator, &strings, ", ");
    defer testing.allocator.free(result);
    
    try testing.expectEqualStrings("alone", result);
}

test "join empty array" {
    const strings = [_][]const u8{};
    const result = try string.join(testing.allocator, &strings, ", ");
    defer testing.allocator.free(result);
    
    try testing.expectEqualStrings("", result);
}
