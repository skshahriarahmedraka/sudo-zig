//! Secure memory handling for sensitive data
//!
//! This module provides secure memory operations for handling sensitive data
//! like passwords and cryptographic keys. It ensures that:
//! - Memory is zeroed before deallocation
//! - Memory cannot be swapped to disk (where possible)
//! - Comparisons are constant-time to prevent timing attacks

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const c = @cImport({
    @cInclude("string.h");
    @cInclude("sys/mman.h");
    @cInclude("unistd.h");
    @cInclude("termios.h");
});

/// A secure buffer that automatically zeros memory on deallocation
/// and optionally locks memory to prevent swapping
pub fn SecureBuffer(comptime T: type, comptime size: usize) type {
    return struct {
        data: [size]T = undefined,
        len: usize = 0,
        locked: bool = false,

        const Self = @This();

        /// Initialize an empty secure buffer
        pub fn init() Self {
            var self = Self{};
            @memset(&self.data, 0);
            return self;
        }

        /// Initialize with data
        pub fn initWithData(source: []const T) Self {
            var self = Self{};
            const copy_len = @min(source.len, size);
            @memcpy(self.data[0..copy_len], source[0..copy_len]);
            self.len = copy_len;
            return self;
        }

        /// Lock memory to prevent swapping (requires elevated privileges)
        pub fn lock(self: *Self) bool {
            if (self.locked) return true;

            if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
                const result = c.mlock(@ptrCast(&self.data), size * @sizeOf(T));
                if (result == 0) {
                    self.locked = true;
                    return true;
                }
            }
            return false;
        }

        /// Unlock memory
        pub fn unlock(self: *Self) void {
            if (!self.locked) return;

            if (builtin.os.tag == .linux or builtin.os.tag == .freebsd) {
                _ = c.munlock(@ptrCast(&self.data), size * @sizeOf(T));
                self.locked = false;
            }
        }

        /// Get a slice of the valid data
        pub fn slice(self: *const Self) []const T {
            return self.data[0..self.len];
        }

        /// Get a mutable slice of the valid data
        pub fn sliceMut(self: *Self) []T {
            return self.data[0..self.len];
        }

        /// Securely clear all data using volatile writes
        pub fn clear(self: *Self) void {
            secureZero(T, &self.data);
            self.len = 0;
        }

        /// Deinitialize - securely clears and unlocks memory
        pub fn deinit(self: *Self) void {
            self.clear();
            self.unlock();
        }

        /// Append data to the buffer
        pub fn append(self: *Self, item: T) bool {
            if (self.len >= size) return false;
            self.data[self.len] = item;
            self.len += 1;
            return true;
        }

        /// Remove and return the last item
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            self.len -= 1;
            const item = self.data[self.len];
            self.data[self.len] = 0;
            return item;
        }
    };
}

/// Secure password buffer - 256 bytes should be enough for any password
pub const SecurePassword = SecureBuffer(u8, 256);

/// Secure key buffer for cryptographic keys
pub const SecureKey = SecureBuffer(u8, 64);

/// Securely zero memory using volatile operations to prevent optimization
pub fn secureZero(comptime T: type, buffer: []T) void {
    // Use volatile pointer to prevent compiler from optimizing away the zeroing
    const ptr: [*]volatile T = @ptrCast(buffer.ptr);
    for (0..buffer.len) |i| {
        ptr[i] = 0;
    }
    // The volatile pointer access above ensures the compiler won't optimize away
    // the writes. No additional barrier needed as volatile semantics handle this.
}

/// Securely zero a byte slice
pub fn secureZeroBytes(buffer: []u8) void {
    secureZero(u8, buffer);
}

/// Constant-time comparison to prevent timing attacks
/// Returns true if the slices are equal
pub fn secureCompare(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }

    return result == 0;
}

/// Constant-time comparison that also hides length differences
/// Uses the length of the first argument as the comparison length
pub fn secureCompareConstantTime(a: []const u8, b: []const u8) bool {
    // Always compare up to a's length to avoid early termination leaking info
    var result: u8 = 0;

    // XOR lengths - if different, result will be non-zero
    result |= @as(u8, @truncate(a.len ^ b.len));

    for (0..a.len) |i| {
        const byte_a = a[i];
        const byte_b = if (i < b.len) b[i] else 0;
        result |= byte_a ^ byte_b;
    }

    return result == 0;
}

/// Allocator wrapper that securely zeros memory on free
pub const SecureAllocator = struct {
    backing_allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(backing: std.mem.Allocator) Self {
        return .{ .backing_allocator = backing };
    }

    /// Get an allocator that wraps the backing allocator with secure zeroing
    /// Note: This returns the backing allocator directly for simplicity.
    /// For production use, implement proper VTable-based wrapping.
    pub fn allocator(self: *Self) std.mem.Allocator {
        return self.backing_allocator;
    }

    /// Securely free memory by zeroing before deallocation
    pub fn secureFree(self: *Self, buf: []u8) void {
        secureZeroBytes(buf);
        self.backing_allocator.free(buf);
    }
};

/// Read a password securely from terminal
/// Returns a SecurePassword that will be zeroed on deinit
pub fn readSecurePassword(prompt: []const u8, use_stdin: bool, show_asterisks: bool) !SecurePassword {
    const fd = if (use_stdin) std.posix.STDIN_FILENO else blk: {
        const tty_fd = std.posix.open("/dev/tty", .{ .ACCMODE = .RDWR }, 0) catch {
            break :blk std.posix.STDIN_FILENO;
        };
        break :blk tty_fd;
    };
    defer if (fd != std.posix.STDIN_FILENO) std.posix.close(fd);

    const output_fd = if (use_stdin) std.posix.STDERR_FILENO else fd;

    // Write prompt
    _ = std.posix.write(output_fd, prompt) catch {};

    // Save and modify terminal settings
    var orig_termios: c.termios = undefined;
    const have_termios = c.tcgetattr(fd, &orig_termios) == 0;

    if (have_termios) {
        var new_termios = orig_termios;
        new_termios.c_lflag &= ~@as(c_uint, c.ECHO);
        if (!show_asterisks) {
            new_termios.c_lflag &= ~@as(c_uint, c.ICANON);
        }
        _ = c.tcsetattr(fd, c.TCSANOW, &new_termios);
    }

    defer {
        if (have_termios) {
            _ = c.tcsetattr(fd, c.TCSANOW, &orig_termios);
        }
        _ = std.posix.write(output_fd, "\n") catch {};
    }

    // Read password into secure buffer
    var password = SecurePassword.init();
    _ = password.lock(); // Try to lock, ignore failure

    if (show_asterisks and have_termios) {
        // Character-by-character with asterisk feedback
        while (password.len < password.data.len - 1) {
            var char_buf: [1]u8 = undefined;
            const n = std.posix.read(fd, &char_buf) catch break;
            if (n == 0) break;

            const char = char_buf[0];
            if (char == '\n' or char == '\r') break;
            if (char == 127 or char == 8) { // Backspace
                if (password.len > 0) {
                    _ = password.pop();
                    _ = std.posix.write(output_fd, "\x08 \x08") catch {};
                }
                continue;
            }
            if (char < 32) continue; // Ignore control chars

            if (password.append(char)) {
                _ = std.posix.write(output_fd, "*") catch {};
            }
        }
    } else {
        // Line-by-line reading
        while (password.len < password.data.len - 1) {
            var char_buf: [1]u8 = undefined;
            const n = std.posix.read(fd, &char_buf) catch break;
            if (n == 0) break;
            if (char_buf[0] == '\n') break;
            _ = password.append(char_buf[0]);
        }
    }

    return password;
}

// ============================================
// Tests
// ============================================

test "SecureBuffer init and clear" {
    var buf = SecurePassword.init();
    defer buf.deinit();

    try std.testing.expectEqual(@as(usize, 0), buf.len);

    _ = buf.append('t');
    _ = buf.append('e');
    _ = buf.append('s');
    _ = buf.append('t');

    try std.testing.expectEqual(@as(usize, 4), buf.len);
    try std.testing.expectEqualStrings("test", buf.slice());

    buf.clear();
    try std.testing.expectEqual(@as(usize, 0), buf.len);

    // Verify memory is zeroed
    for (buf.data[0..4]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "SecureBuffer initWithData" {
    const data = "password123";
    var buf = SecurePassword.initWithData(data);
    defer buf.deinit();

    try std.testing.expectEqualStrings(data, buf.slice());
}

test "secureCompare equal" {
    const a = "password";
    const b = "password";
    try std.testing.expect(secureCompare(a, b));
}

test "secureCompare not equal" {
    const a = "password";
    const b = "different";
    try std.testing.expect(!secureCompare(a, b));
}

test "secureCompare different lengths" {
    const a = "short";
    const b = "longer_string";
    try std.testing.expect(!secureCompare(a, b));
}

test "secureCompareConstantTime" {
    try std.testing.expect(secureCompareConstantTime("test", "test"));
    try std.testing.expect(!secureCompareConstantTime("test", "TEST"));
    try std.testing.expect(!secureCompareConstantTime("test", "testing"));
}

test "secureZero" {
    var buffer: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    secureZeroBytes(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "SecureAllocator" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var secure_alloc = SecureAllocator.init(gpa.allocator());
    const allocator = secure_alloc.allocator();

    const buf = try allocator.alloc(u8, 32);
    @memset(buf, 0xAA);

    // Securely zero and free the memory
    secure_alloc.secureFree(buf);
}

test "SecureBuffer pop" {
    var buf = SecurePassword.init();
    defer buf.deinit();

    _ = buf.append('a');
    _ = buf.append('b');
    _ = buf.append('c');

    try std.testing.expectEqual(@as(?u8, 'c'), buf.pop());
    try std.testing.expectEqual(@as(usize, 2), buf.len);
    try std.testing.expectEqualStrings("ab", buf.slice());
}
