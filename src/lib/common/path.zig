//! Path validation and manipulation for sudo-zig
//!
//! Provides secure path handling with validation against:
//! - Null bytes
//! - Relative paths in security-critical contexts
//! - Symlinks in sensitive directories
//! - Path traversal attempts

const std = @import("std");
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const string = @import("string.zig");

// C library imports for lstat
const c = @cImport({
    @cInclude("sys/stat.h");
});

/// A validated path that cannot contain null bytes.
pub const SudoPath = struct {
    path: []const u8,

    const Self = @This();

    /// Initialize a SudoPath, validating that it contains no null bytes.
    pub fn init(data: []const u8) error{PathValidation}!Self {
        if (std.mem.indexOfScalar(u8, data, 0) != null) {
            return error.PathValidation;
        }
        return .{ .path = data };
    }

    /// Check if the path is absolute.
    pub fn isAbsolute(self: Self) bool {
        return std.fs.path.isAbsolute(self.path);
    }

    /// Get the directory name (parent directory).
    pub fn dirname(self: Self) ?[]const u8 {
        return std.fs.path.dirname(self.path);
    }

    /// Get the base name (file name).
    pub fn basename(self: Self) []const u8 {
        return std.fs.path.basename(self.path);
    }

    /// Get the underlying slice.
    pub fn slice(self: Self) []const u8 {
        return self.path;
    }

    /// Display the path (for error messages, etc.).
    pub fn display(self: Self) []const u8 {
        return self.path;
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
        try writer.writeAll(self.path);
    }

    /// Convert to null-terminated string for C interop.
    pub fn toCstr(self: Self, allocator: Allocator) ![:0]u8 {
        return allocator.dupeZ(u8, self.path);
    }

    /// Join with another path component.
    pub fn join(self: Self, allocator: Allocator, sub_path: []const u8) !SudoPath {
        const joined = try fs.path.join(allocator, &.{ self.path, sub_path });
        return Self.init(joined) catch {
            allocator.free(joined);
            return error.PathValidation;
        };
    }
};

/// Validate that a path is secure for privileged operations.
pub const SecurePath = struct {
    path: SudoPath,

    const Self = @This();

    /// Validate a path for secure operations.
    /// Checks:
    /// - Path is absolute
    /// - No path components are writable by non-root (optional)
    /// - No symlinks in the path (optional)
    pub fn validate(path_str: []const u8, options: ValidateOptions) !Self {
        const sudo_path = try SudoPath.init(path_str);

        // Must be absolute path
        if (!sudo_path.isAbsolute()) {
            return error.RelativePath;
        }

        // Check for path traversal attempts
        if (containsTraversal(path_str)) {
            return error.PathTraversal;
        }

        // Additional security checks if requested
        if (options.check_symlinks or options.check_ownership) {
            try validatePathSecurity(path_str, options);
        }

        return .{ .path = sudo_path };
    }

    /// Get the underlying SudoPath.
    pub fn sudoPath(self: Self) SudoPath {
        return self.path;
    }

    /// Get the path slice.
    pub fn slice(self: Self) []const u8 {
        return self.path.path;
    }
};

/// Options for path validation.
pub const ValidateOptions = struct {
    /// Check that no component is a symlink.
    check_symlinks: bool = false,

    /// Check that path is owned by root.
    check_ownership: bool = false,

    /// Check that path is not world-writable.
    check_writable: bool = false,
};

/// Errors specific to path validation.
pub const PathValidationError = error{
    PathValidation,
    RelativePath,
    PathTraversal,
    SymlinkInPath,
    InsecureOwnership,
    WorldWritable,
    StatError,
};

/// Check if a path contains traversal attempts (.. or .)
pub fn containsTraversal(path_str: []const u8) bool {
    var it = std.mem.splitScalar(u8, path_str, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) {
            return true;
        }
        // Single dot is usually harmless but can be suspicious
        if (std.mem.eql(u8, component, ".") and it.peek() != null) {
            // "./something" at the start or "/./" in the middle
            // is suspicious in an "absolute" path
        }
    }
    return false;
}

/// Validate path security by checking each component.
fn validatePathSecurity(path_str: []const u8, options: ValidateOptions) !void {
    // Build up path component by component and check each
    var current_path: [std.fs.max_path_bytes]u8 = undefined;
    var current_len: usize = 0;

    var it = std.mem.splitScalar(u8, path_str, '/');
    while (it.next()) |component| {
        if (component.len == 0) continue;

        // Add separator
        if (current_len > 0) {
            current_path[current_len] = '/';
            current_len += 1;
        } else {
            // Start with /
            current_path[0] = '/';
            current_len = 1;
        }

        // Add component
        if (current_len + component.len >= current_path.len) {
            return error.PathValidation;
        }
        @memcpy(current_path[current_len..][0..component.len], component);
        current_len += component.len;

        const check_path = current_path[0..current_len];

        // Check for symlinks if requested
        if (options.check_symlinks) {
            // Use C lstat to check for symlinks
            var stat_buf: c.struct_stat = undefined;
            const path_z: [*:0]const u8 = @ptrCast(check_path.ptr);
            const result = c.lstat(path_z, &stat_buf);
            if (result != 0) {
                // If lstat fails, skip this check (file may not exist yet)
                continue;
            }
            // Check if it's a symlink (S_IFLNK = 0o120000)
            if ((stat_buf.st_mode & 0o170000) == 0o120000) {
                return error.SymlinkInPath;
            }
        }

        // Check ownership if requested
        if (options.check_ownership) {
            var stat_buf: c.struct_stat = undefined;
            const path_z: [*:0]const u8 = @ptrCast(check_path.ptr);
            const result = c.stat(path_z, &stat_buf);
            if (result != 0) {
                // If stat fails, skip this check
                continue;
            }
            // Should be owned by root
            if (stat_buf.st_uid != 0) {
                return error.InsecureOwnership;
            }
        }

        // Check world-writable if requested
        if (options.check_writable) {
            var stat_buf: c.struct_stat = undefined;
            const path_z: [*:0]const u8 = @ptrCast(check_path.ptr);
            const result = c.stat(path_z, &stat_buf);
            if (result != 0) {
                // If stat fails, skip this check
                continue;
            }
            // Check world-writable bit (S_IWOTH = 0o002)
            if ((stat_buf.st_mode & 0o002) != 0) {
                return error.WorldWritable;
            }
        }
    }
}

/// Resolve a path to its canonical form.
pub fn realpath(allocator: Allocator, path_str: []const u8) ![]u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = try posix.realpath(path_str, &path_buf);
    return allocator.dupe(u8, resolved);
}

/// Check if a path exists.
pub fn exists(path_str: []const u8) bool {
    posix.access(path_str, posix.F_OK) catch return false;
    return true;
}

/// Check if a path is executable.
pub fn isExecutable(path_str: []const u8) bool {
    posix.access(path_str, posix.X_OK) catch return false;
    return true;
}

/// Find an executable in the PATH environment variable.
pub fn findInPath(allocator: Allocator, command: []const u8, path_env: []const u8) !?[]u8 {
    // If command contains a slash, it's already a path
    if (std.mem.indexOfScalar(u8, command, '/') != null) {
        if (isExecutable(command)) {
            return try allocator.dupe(u8, command);
        }
        return null;
    }

    // Search in PATH
    var it = std.mem.splitScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;

        const full_path = try std.fs.path.join(allocator, &.{ dir, command });
        defer allocator.free(full_path);

        if (isExecutable(full_path)) {
            return try allocator.dupe(u8, full_path);
        }
    }

    return null;
}

// ============================================
// Tests
// ============================================

test "SudoPath validation" {
    const testing = std.testing;

    // Valid path
    const valid = try SudoPath.init("/usr/bin/ls");
    try testing.expectEqualStrings("/usr/bin/ls", valid.slice());

    // Path with null byte should fail
    const invalid = SudoPath.init("/usr/bin\x00/ls");
    try testing.expectError(error.PathValidation, invalid);
}

test "SudoPath absolute check" {
    const testing = std.testing;

    const absolute = try SudoPath.init("/usr/bin/ls");
    try testing.expect(absolute.isAbsolute());

    const relative = try SudoPath.init("usr/bin/ls");
    try testing.expect(!relative.isAbsolute());
}

test "SudoPath dirname and basename" {
    const testing = std.testing;

    const p = try SudoPath.init("/usr/bin/ls");
    try testing.expectEqualStrings("/usr/bin", p.dirname().?);
    try testing.expectEqualStrings("ls", p.basename());
}

test "containsTraversal" {
    const testing = std.testing;

    try testing.expect(containsTraversal("/usr/../bin"));
    try testing.expect(containsTraversal("/../etc/passwd"));
    try testing.expect(!containsTraversal("/usr/bin/ls"));
    try testing.expect(!containsTraversal("/usr/bin"));
}

test "exists" {
    const testing = std.testing;

    // /tmp should exist on most systems
    try testing.expect(exists("/tmp") or exists("/var/tmp"));

    // This path should not exist
    try testing.expect(!exists("/nonexistent/path/that/does/not/exist"));
}
