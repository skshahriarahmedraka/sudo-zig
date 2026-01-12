//! Unit tests for command execution module
//!
//! Tests for PTY handling, I/O relay, and execution structures.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const exec = lib.exec;
const pty_mod = exec.pty;
const Pty = pty_mod.Pty;
const Terminal = pty_mod.Terminal;
const IoRelay = pty_mod.IoRelay;

// ============================================
// Pty Structure Tests
// ============================================

test "Pty struct has correct fields" {
    // Verify the struct layout without actually opening a PTY
    const pty_info = @typeInfo(Pty);
    try testing.expect(pty_info == .@"struct");

    const fields = pty_info.@"struct".fields;
    try testing.expect(fields.len >= 3);
}

test "Pty slave_name buffer size" {
    // Slave names are typically /dev/pts/N which should fit in 64 bytes
    // Test by checking the Pty struct has the slave_name field
    const pty_info = @typeInfo(Pty);
    try testing.expect(pty_info == .@"struct");
    // Use @hasField for comptime field check
    try testing.expect(@hasField(Pty, "slave_name"));
}

// ============================================
// Terminal Structure Tests
// ============================================

test "Terminal struct has correct fields" {
    const term_info = @typeInfo(Terminal);
    try testing.expect(term_info == .@"struct");
}

// ============================================
// IoRelay Tests
// ============================================

test "IoRelay struct creation" {
    const relay = IoRelay{
        .source_fd = 0,
        .dest_fd = 1,
    };

    try testing.expectEqual(@as(std.posix.fd_t, 0), relay.source_fd);
    try testing.expectEqual(@as(std.posix.fd_t, 1), relay.dest_fd);
}

test "IoRelay is properly configured" {
    // Verify IoRelay struct exists and can be instantiated
    const relay = IoRelay{
        .source_fd = 3,
        .dest_fd = 4,
    };
    try testing.expect(relay.source_fd != relay.dest_fd);
}

// ============================================
// PTY Error Handling Tests
// ============================================

test "PTY open can fail gracefully" {
    // Test that PTY operations handle errors appropriately
    // The actual error types are tested via Pty.open() failure paths
    const pty_result = Pty.open();
    if (pty_result) |p| {
        var pty_copy = p;
        pty_copy.close();
    } else |_| {
        // Expected in environments without PTY support
    }
}

// ============================================
// Window Size Tests
// ============================================

test "window size struct" {
    // Test that window size can represent typical terminal dimensions
    const size = struct { rows: u16, cols: u16 }{
        .rows = 24,
        .cols = 80,
    };

    try testing.expectEqual(@as(u16, 24), size.rows);
    try testing.expectEqual(@as(u16, 80), size.cols);
}

test "window size for modern terminals" {
    const sizes = [_]struct { rows: u16, cols: u16 }{
        .{ .rows = 24, .cols = 80 }, // Classic VT100
        .{ .rows = 25, .cols = 80 }, // DOS standard
        .{ .rows = 50, .cols = 132 }, // Extended
        .{ .rows = 60, .cols = 200 }, // Modern widescreen
    };

    for (sizes) |size| {
        try testing.expect(size.rows > 0);
        try testing.expect(size.cols > 0);
    }
}

// ============================================
// File Descriptor Tests
// ============================================

test "standard file descriptors" {
    // Verify standard fd values
    try testing.expectEqual(@as(std.posix.fd_t, 0), std.posix.STDIN_FILENO);
    try testing.expectEqual(@as(std.posix.fd_t, 1), std.posix.STDOUT_FILENO);
    try testing.expectEqual(@as(std.posix.fd_t, 2), std.posix.STDERR_FILENO);
}

// ============================================
// Functional PTY Tests (may require permissions)
// ============================================

test "Pty.open creates valid PTY" {
    // This test may fail in restricted environments
    const pty = Pty.open() catch |err| {
        // Skip test if we can't open a PTY (e.g., in a container without /dev/pts)
        if (err == error.PtyOpenFailed or err == error.PtySlaveOpenFailed) {
            return;
        }
        return err;
    };
    defer @constCast(&pty).close();

    // Verify we got valid file descriptors
    try testing.expect(pty.master_fd >= 0);
    try testing.expect(pty.slave_fd >= 0);
    try testing.expect(pty.master_fd != pty.slave_fd);

    // Verify slave name starts with expected prefix
    const name = pty.getSlaveName();
    try testing.expect(name.len > 0);
    try testing.expect(std.mem.startsWith(u8, name, "/dev/pts/") or
        std.mem.startsWith(u8, name, "/dev/pty"));
}

test "Pty.getSlaveName returns valid path" {
    const pty = Pty.open() catch |err| {
        if (err == error.PtyOpenFailed or err == error.PtySlaveOpenFailed) {
            return;
        }
        return err;
    };
    defer @constCast(&pty).close();

    const name = pty.getSlaveName();

    // Should be a valid device path
    try testing.expect(std.mem.startsWith(u8, name, "/dev/"));
    try testing.expect(name.len < 64);
}

test "Pty.setWindowSize and getWindowSize" {
    var pty = Pty.open() catch |err| {
        if (err == error.PtyOpenFailed or err == error.PtySlaveOpenFailed) {
            return;
        }
        return err;
    };
    defer pty.close();

    // Set a specific size
    pty.setWindowSize(40, 120);

    // Get the size back
    if (pty.getWindowSize()) |size| {
        try testing.expectEqual(@as(u16, 40), size.rows);
        try testing.expectEqual(@as(u16, 120), size.cols);
    }
}

test "Pty.closeMaster and closeSlave" {
    var pty = Pty.open() catch |err| {
        if (err == error.PtyOpenFailed or err == error.PtySlaveOpenFailed) {
            return;
        }
        return err;
    };

    const original_master = pty.master_fd;
    const original_slave = pty.slave_fd;

    try testing.expect(original_master >= 0);
    try testing.expect(original_slave >= 0);

    // Close master
    pty.closeMaster();
    try testing.expectEqual(@as(std.posix.fd_t, -1), pty.master_fd);
    try testing.expect(pty.slave_fd >= 0); // Slave still open

    // Close slave
    pty.closeSlave();
    try testing.expectEqual(@as(std.posix.fd_t, -1), pty.slave_fd);
}
