//! Test to prevent regression of parse API misuse
//!
//! This test ensures that:
//! 1. parse() is used with content strings
//! 2. parseFile() is used with file paths
//! 3. Memory is properly freed on parse errors

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const sudoers = lib.sudoers;

test "parse() works with valid content string" {
    const allocator = testing.allocator;
    
    const content = "root ALL=(ALL:ALL) ALL\n";
    var parsed = try sudoers.parse(allocator, content);
    defer parsed.deinit();
    
    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "parse() handles parse errors without leaking memory" {
    const allocator = testing.allocator;
    
    // This content has invalid syntax (missing closing paren)
    const invalid_content = "root ALL=(INVALID\n";
    
    const result = sudoers.parse(allocator, invalid_content);
    
    // Should return an error
    try testing.expectError(error.ParseError, result);
    
    // No memory should be leaked (verified by testing.allocator)
}

test "parse() handles complex parse error without memory leak" {
    const allocator = testing.allocator;
    
    // Content that will fail during RunAs parsing
    const invalid_content = "alice ALL=(root:wheel NOPASSWD: ALL\n";
    
    const result = sudoers.parse(allocator, invalid_content);
    try testing.expectError(error.ParseError, result);
}

test "parseFile() works with valid file" {
    const allocator = testing.allocator;
    
    // Create a temporary test file
    const test_content = "# Test sudoers\nroot ALL=(ALL:ALL) ALL\n";
    const temp_file = "tmp_test_sudoers_file";
    
    // Write test file
    {
        const file = try std.fs.cwd().createFile(temp_file, .{});
        defer file.close();
        try file.writeAll(test_content);
    }
    defer std.fs.cwd().deleteFile(temp_file) catch {};
    
    // Parse the file
    var parsed = try sudoers.parseFile(allocator, temp_file);
    defer parsed.deinit();
    
    try testing.expectEqual(@as(usize, 1), parsed.user_specs.items.len);
}

test "parseFile() handles missing file gracefully" {
    const allocator = testing.allocator;
    
    const result = sudoers.parseFile(allocator, "/nonexistent/file/path");
    
    // Should return a file error, not crash
    try testing.expectError(error.FileNotFound, result);
}

test "parseFile() handles parse error in file without memory leak" {
    const allocator = testing.allocator;
    
    // Create a temporary file with invalid syntax
    const invalid_content = "root ALL=(BROKEN SYNTAX\n";
    const temp_file = "tmp_test_invalid_sudoers";
    
    {
        const file = try std.fs.cwd().createFile(temp_file, .{});
        defer file.close();
        try file.writeAll(invalid_content);
    }
    defer std.fs.cwd().deleteFile(temp_file) catch {};
    
    const result = sudoers.parseFile(allocator, temp_file);
    try testing.expectError(error.ParseError, result);
}

test "multiple parse errors don't accumulate memory leaks" {
    const allocator = testing.allocator;
    
    const invalid_contents = [_][]const u8{
        "root ALL=(BROKEN\n",
        "alice ALL=(root:wheel\n",
        "bob ALL=(ALL MISSING_COLON ALL\n",
        "%wheel ALL=(INCOMPLETE\n",
    };
    
    for (invalid_contents) |content| {
        const result = sudoers.parse(allocator, content);
        try testing.expectError(error.ParseError, result);
    }
    
    // testing.allocator will detect any leaks
}

test "parse vs parseFile API contract" {
    const allocator = testing.allocator;
    
    // Demonstrate correct usage patterns
    
    // 1. parse() expects content strings (in-memory data)
    const content = "root ALL=(ALL:ALL) ALL\n";
    var parsed1 = try sudoers.parse(allocator, content);
    defer parsed1.deinit();
    
    // 2. parseFile() expects file paths
    const temp_file = "tmp_test_api_contract";
    {
        const file = try std.fs.cwd().createFile(temp_file, .{});
        defer file.close();
        try file.writeAll(content);
    }
    defer std.fs.cwd().deleteFile(temp_file) catch {};
    
    var parsed2 = try sudoers.parseFile(allocator, temp_file);
    defer parsed2.deinit();
    
    // Both should produce the same result
    try testing.expectEqual(parsed1.user_specs.items.len, parsed2.user_specs.items.len);
}

test "errdefer cleanup in parseRunAs" {
    const allocator = testing.allocator;
    
    // This specific syntax triggers error during RunAs parsing
    // after users list has been allocated
    const content = "alice ALL=(root, bob, charlie\n"; // missing closing paren
    
    const result = sudoers.parse(allocator, content);
    try testing.expectError(error.ParseError, result);
    
    // Memory should be properly freed by errdefer
}

test "errdefer cleanup in nested parse functions" {
    const allocator = testing.allocator;
    
    // Various error scenarios that should all clean up properly
    const error_cases = [_][]const u8{
        "root ALL=(ALL", // incomplete RunAs
        "root ALL=(ALL:", // incomplete group list
        "root ALL=(ALL:wheel", // missing close paren
        "alice ALL=(root:admin,wheel", // missing close paren after comma
    };
    
    for (error_cases) |content| {
        const result = sudoers.parse(allocator, content);
        // All should fail with ParseError and clean up memory
        try testing.expectError(error.ParseError, result);
    }
}
