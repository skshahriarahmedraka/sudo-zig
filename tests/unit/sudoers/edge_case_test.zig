//! Edge case tests for memory safety and crash prevention
const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const sudoers = lib.sudoers;
const system = lib.system;

// Test 1: Multiple sequential parse errors don't accumulate leaks
test "edge case: sequential parse errors" {
    const allocator = testing.allocator;
    
    const error_cases = [_][]const u8{
        "root ALL=(BROKEN\n",
        "alice ALL=(\n",
        "bob ALL=(root:\n",
        "%wheel ALL=(ALL:wheel\n",
        "user ALL=(ALL:ALL) NOPASSWD: \n",
        "test ALL=(root,alice,bob,charlie,dave,eve\n",
    };
    
    // Run multiple times to check for leak accumulation
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        for (error_cases) |content| {
            const result = sudoers.parse(allocator, content);
            try testing.expectError(error.ParseError, result);
        }
    }
}

// Test 2: Very long user lists in RunAs
test "edge case: long RunAs user list" {
    const allocator = testing.allocator;
    
    // Create a user list with many users, but missing closing paren (parse error)
    const content = "alice ALL=(root,user1,user2,user3,user4,user5,user6,user7,user8,user9,user10\n";
    
    const result = sudoers.parse(allocator, content);
    try testing.expectError(error.ParseError, result);
    // Should not leak memory for the user list
}

// Test 3: Empty and minimal files
test "edge case: empty and minimal files" {
    const allocator = testing.allocator;
    
    // Empty file
    var parsed1 = try sudoers.parse(allocator, "");
    defer parsed1.deinit();
    try testing.expectEqual(@as(usize, 0), parsed1.user_specs.items.len);
    
    // Only comments
    var parsed2 = try sudoers.parse(allocator, "# Just a comment\n");
    defer parsed2.deinit();
    try testing.expectEqual(@as(usize, 0), parsed2.user_specs.items.len);
    
    // Only whitespace
    var parsed3 = try sudoers.parse(allocator, "   \n\n  \t\n");
    defer parsed3.deinit();
    try testing.expectEqual(@as(usize, 0), parsed3.user_specs.items.len);
}

// Test 4: Multiple user specs
test "edge case: multiple user specs" {
    const allocator = testing.allocator;
    
    const content = 
        \\user1 ALL=(ALL:ALL) ALL
        \\user2 ALL=(ALL:ALL) ALL
        \\user3 ALL=(ALL:ALL) ALL
        \\user4 ALL=(ALL:ALL) ALL
        \\user5 ALL=(ALL:ALL) ALL
    ;
    
    var parsed = try sudoers.parse(allocator, content);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 5), parsed.user_specs.items.len);
}

// Test 5: User struct pointer safety - ensure no dangling pointers
test "edge case: User pointer lifetime" {
    const allocator = testing.allocator;
    
    const content = "alice ALL=(ALL:ALL) ALL\n";
    var parsed = try sudoers.parse(allocator, content);
    defer parsed.deinit();
    
    var policy = sudoers.Policy.init(allocator, &parsed);
    
    // Create user in a separate scope
    {
        var user = system.User{
            .uid = 1000,
            .gid = 1000,
            ._name_len = 5,
            ._home_len = 11,
            ._shell_len = 9,
            ._gecos_len = 10,
        };
        @memcpy(user._name_buf[0..5], "alice");
        @memcpy(user._home_buf[0..11], "/home/alice");
        @memcpy(user._shell_buf[0..9], "/bin/bash");
        @memcpy(user._gecos_buf[0..10], "Alice User");
        
        const request = sudoers.AuthRequest{
            .user = &user,
            .groups = &[_]u32{1000},
            .hostname = "localhost",
            .command = "/bin/ls",
            .arguments = null,
            .target_user = null,
            .target_group = null,
        };
        
        // This should not crash
        const auth = policy.check(request);
        try testing.expect(auth.allowed);
    }
    // User goes out of scope here - any dangling pointers would cause issues
}

// Test 6: Interleaved parse and parseFile calls
test "edge case: mixed parse and parseFile calls" {
    const allocator = testing.allocator;
    
    // Create temp file
    const temp_file = "tmp_edge_case_test";
    const file_content = "root ALL=(ALL:ALL) ALL\n";
    
    {
        const file = try std.fs.cwd().createFile(temp_file, .{});
        defer file.close();
        try file.writeAll(file_content);
    }
    defer std.fs.cwd().deleteFile(temp_file) catch {};
    
    // Interleave calls
    var parsed1 = try sudoers.parse(allocator, file_content);
    defer parsed1.deinit();
    
    var parsed2 = try sudoers.parseFile(allocator, temp_file);
    defer parsed2.deinit();
    
    var parsed3 = try sudoers.parse(allocator, file_content);
    defer parsed3.deinit();
    
    var parsed4 = try sudoers.parseFile(allocator, temp_file);
    defer parsed4.deinit();
    
    // All should produce the same result
    try testing.expectEqual(parsed1.user_specs.items.len, parsed2.user_specs.items.len);
    try testing.expectEqual(parsed2.user_specs.items.len, parsed3.user_specs.items.len);
    try testing.expectEqual(parsed3.user_specs.items.len, parsed4.user_specs.items.len);
}

// Test 7: Parse errors at different stages
test "edge case: errors at different parsing stages" {
    const allocator = testing.allocator;
    
    const error_stages = [_][]const u8{
        // Error in user parsing
        "@ ALL=(ALL:ALL) ALL\n",
        // Error after RunAs open
        "root ALL=(\n",
        // Error in RunAs user list
        "root ALL=(root,@bad\n",
        // Error in RunAs group list after colon
        "root ALL=(root:@bad\n",
        // Error missing close paren
        "root ALL=(root:wheel NOPASSWD: ALL\n",
    };
    
    for (error_stages) |content| {
        const result = sudoers.parse(allocator, content);
        // All should fail gracefully without leaks
        try testing.expectError(error.ParseError, result);
    }
}

// Test 8: Non-existent file paths
test "edge case: non-existent file" {
    const allocator = testing.allocator;
    
    const result = sudoers.parseFile(allocator, "/nonexistent/path/to/sudoers/file/that/does/not/exist");
    // Should fail with FileNotFound, not crash
    try testing.expectError(error.FileNotFound, result);
}

// Test 9: Rapid allocation and deallocation
test "edge case: rapid alloc/dealloc cycles" {
    const allocator = testing.allocator;
    const content = "alice ALL=(ALL:ALL) NOPASSWD: ALL\n";
    
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var parsed = try sudoers.parse(allocator, content);
        parsed.deinit();
    }
    // Should not leak memory across iterations
}

// Test 10: Multiple Policy instances with same parsed data
test "edge case: multiple Policy instances" {
    const allocator = testing.allocator;
    const content = "bob ALL=(ALL:ALL) ALL\n";
    
    var parsed = try sudoers.parse(allocator, content);
    defer parsed.deinit();
    
    var policy1 = sudoers.Policy.init(allocator, &parsed);
    var policy2 = sudoers.Policy.init(allocator, &parsed);
    
    // Both should work independently
    var user = system.User{
        .uid = 1001,
        .gid = 1001,
        ._name_len = 3,
        ._home_len = 9,
        ._shell_len = 9,
        ._gecos_len = 8,
    };
    @memcpy(user._name_buf[0..3], "bob");
    @memcpy(user._home_buf[0..9], "/home/bob");
    @memcpy(user._shell_buf[0..9], "/bin/bash");
    @memcpy(user._gecos_buf[0..8], "Bob User");
    
    const request = sudoers.AuthRequest{
        .user = &user,
        .groups = &[_]u32{1001},
        .hostname = "localhost",
        .command = "/bin/ls",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    };
    
    const auth1 = policy1.check(request);
    const auth2 = policy2.check(request);
    
    try testing.expectEqual(auth1.allowed, auth2.allowed);
}
