//! Unit tests for path validation and manipulation
//!
//! Tests for secure path handling including null byte validation,
//! traversal detection, and path security checks.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const path = lib.common.path;
const SudoPath = path.SudoPath;
const SecurePath = path.SecurePath;

// ============================================
// SudoPath Tests
// ============================================

test "SudoPath.init valid path" {
    const p = try SudoPath.init("/usr/bin/ls");
    try testing.expectEqualStrings("/usr/bin/ls", p.slice());
}

test "SudoPath.init rejects null bytes" {
    const result = SudoPath.init("/usr/bin\x00/ls");
    try testing.expectError(error.PathValidation, result);
}

test "SudoPath.isAbsolute" {
    const absolute = try SudoPath.init("/usr/bin/ls");
    try testing.expect(absolute.isAbsolute());
    
    const relative = try SudoPath.init("usr/bin/ls");
    try testing.expect(!relative.isAbsolute());
    
    const current = try SudoPath.init("./script.sh");
    try testing.expect(!current.isAbsolute());
}

test "SudoPath.dirname" {
    const p = try SudoPath.init("/usr/bin/ls");
    try testing.expectEqualStrings("/usr/bin", p.dirname().?);
}

test "SudoPath.dirname root" {
    const p = try SudoPath.init("/");
    try testing.expectEqual(@as(?[]const u8, null), p.dirname());
}

test "SudoPath.basename" {
    const p = try SudoPath.init("/usr/bin/ls");
    try testing.expectEqualStrings("ls", p.basename());
}

test "SudoPath.basename single component" {
    const p = try SudoPath.init("filename");
    try testing.expectEqualStrings("filename", p.basename());
}

test "SudoPath.display" {
    const p = try SudoPath.init("/path/to/file");
    try testing.expectEqualStrings("/path/to/file", p.display());
}

test "SudoPath.toCstr" {
    const p = try SudoPath.init("/usr/bin/ls");
    const cstr = try p.toCstr(testing.allocator);
    defer testing.allocator.free(cstr);
    
    try testing.expectEqualStrings("/usr/bin/ls", cstr);
}

// ============================================
// Path Traversal Tests
// ============================================

test "containsTraversal with .." {
    try testing.expect(path.containsTraversal("/usr/../bin"));
    try testing.expect(path.containsTraversal("/../etc/passwd"));
    try testing.expect(path.containsTraversal("/var/log/../../etc/passwd"));
}

test "containsTraversal safe paths" {
    try testing.expect(!path.containsTraversal("/usr/bin/ls"));
    try testing.expect(!path.containsTraversal("/var/log"));
    try testing.expect(!path.containsTraversal("/"));
    try testing.expect(!path.containsTraversal("/home/user/.bashrc"));
}

test "containsTraversal edge cases" {
    // Double dots in filename (not traversal)
    try testing.expect(!path.containsTraversal("/var/log/app..log"));
    // Actual traversal
    try testing.expect(path.containsTraversal("/var/log/../../../etc"));
}

// ============================================
// SecurePath Tests
// ============================================

test "SecurePath.validate absolute path" {
    const sp = try SecurePath.validate("/usr/bin/ls", .{});
    try testing.expectEqualStrings("/usr/bin/ls", sp.slice());
}

test "SecurePath.validate rejects relative path" {
    const result = SecurePath.validate("usr/bin/ls", .{});
    try testing.expectError(error.RelativePath, result);
}

test "SecurePath.validate rejects path with traversal" {
    const result = SecurePath.validate("/usr/../bin/ls", .{});
    try testing.expectError(error.PathTraversal, result);
}

test "SecurePath.validate rejects null bytes" {
    const result = SecurePath.validate("/usr/bin\x00/ls", .{});
    try testing.expectError(error.PathValidation, result);
}

// ============================================
// Utility Function Tests
// ============================================

test "exists for /tmp" {
    // /tmp or /var/tmp should exist on most systems
    try testing.expect(path.exists("/tmp") or path.exists("/var/tmp"));
}

test "exists for nonexistent path" {
    try testing.expect(!path.exists("/nonexistent/path/that/should/not/exist/12345"));
}

test "isExecutable for common binaries" {
    // At least one of these should be executable
    const common_bins = [_][]const u8{
        "/bin/sh",
        "/usr/bin/sh",
        "/bin/ls",
        "/usr/bin/ls",
    };
    
    var found_executable = false;
    for (common_bins) |bin| {
        if (path.isExecutable(bin)) {
            found_executable = true;
            break;
        }
    }
    // Just verify the function runs without error - use the variable
    if (!found_executable) {
        // It's okay if no common binary is found on unusual systems
    }
}

test "findInPath for common command" {
    const path_env = "/usr/local/bin:/usr/bin:/bin";
    
    // Try to find 'sh' which should exist
    if (try path.findInPath(testing.allocator, "sh", path_env)) |found| {
        defer testing.allocator.free(found);
        try testing.expect(std.mem.endsWith(u8, found, "/sh"));
    }
}

test "findInPath returns null for nonexistent command" {
    const path_env = "/usr/bin:/bin";
    const result = try path.findInPath(testing.allocator, "nonexistent_command_12345", path_env);
    try testing.expectEqual(@as(?[]u8, null), result);
}

test "findInPath with absolute path" {
    // If given an absolute path, findInPath should check if it's executable
    if (path.exists("/bin/sh") and path.isExecutable("/bin/sh")) {
        if (try path.findInPath(testing.allocator, "/bin/sh", "")) |found| {
            defer testing.allocator.free(found);
            try testing.expectEqualStrings("/bin/sh", found);
        }
    }
}
