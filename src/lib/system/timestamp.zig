//! Timestamp/Credential caching
//!
//! Manages credential caching to avoid repeated password prompts.
//! Timestamps are stored in /run/sudo/ts/<username>
//!
//! Security considerations:
//! - Timestamp files are owned by root:root with mode 0600
//! - Records include boot time to invalidate across reboots
//! - Records include parent PID to limit scope
//! - Files are stored on tmpfs (/run) which is cleared on reboot

const std = @import("std");
const posix = std.posix;
const root = @import("../root.zig");
const user_mod = @import("user.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/types.h");
    @cInclude("fcntl.h");
    @cInclude("time.h");
});

/// Default timestamp directory
pub const TIMESTAMP_DIR = "/run/sudo/ts";

/// Magic number for timestamp file format
const TIMESTAMP_MAGIC: u32 = 0x53554454; // "SUDT"

/// Timestamp file format version
const TIMESTAMP_VERSION: u16 = 1;

/// Record type
pub const RecordType = enum(u8) {
    /// Global timestamp (applies to all ttys)
    global = 1,
    /// Per-TTY timestamp
    tty = 2,
    /// Per-parent-PID timestamp
    ppid = 3,
};

/// A single timestamp record in the file
pub const TimestampRecord = struct {
    /// Record type
    record_type: RecordType,
    /// User ID this record is for
    uid: user_mod.UserId,
    /// Boot time when record was created (to invalidate across reboots)
    boot_time: i64,
    /// Parent process ID (for PPID scope)
    ppid: i32,
    /// TTY device number (for TTY scope)
    tty_dev: u64,
    /// Session ID
    sid: i32,
    /// Timestamp when authentication succeeded
    auth_time: i64,
    /// Reserved for future use
    _reserved: [16]u8 = [_]u8{0} ** 16,

    const Self = @This();

    /// Size of a serialized record
    pub const SERIALIZED_SIZE = 64;

    /// Create a new record for the current session
    pub fn create(record_type: RecordType, uid: user_mod.UserId) Self {
        const now = std.time.timestamp();
        const boot = getBootTime() catch 0;
        const ppid = c.getppid();
        const sid = c.getsid(0);
        const tty = getTtyDev() catch 0;

        return .{
            .record_type = record_type,
            .uid = uid,
            .boot_time = boot,
            .ppid = ppid,
            .tty_dev = tty,
            .sid = sid,
            .auth_time = now,
        };
    }

    /// Check if record is valid (not expired)
    pub fn isValid(self: Self, timeout_seconds: u64) bool {
        // Check boot time
        const current_boot = getBootTime() catch return false;
        if (self.boot_time != current_boot) return false;

        // Check expiration
        const now = std.time.timestamp();
        const expiry = self.auth_time + @as(i64, @intCast(timeout_seconds));
        if (now > expiry) return false;

        return true;
    }

    /// Check if record matches current session scope
    pub fn matchesScope(self: Self, scope: RecordScope) bool {
        switch (self.record_type) {
            .global => return true,
            .tty => {
                if (scope.tty_dev) |dev| {
                    return self.tty_dev == dev;
                }
                return false;
            },
            .ppid => {
                return self.ppid == scope.ppid and self.sid == scope.sid;
            },
        }
    }

    /// Serialize record to bytes
    pub fn serialize(self: Self) [SERIALIZED_SIZE]u8 {
        var buf: [SERIALIZED_SIZE]u8 = [_]u8{0} ** SERIALIZED_SIZE;

        // Record type (1 byte)
        buf[0] = @intFromEnum(self.record_type);

        // UID (4 bytes)
        const uid_bytes = std.mem.toBytes(self.uid);
        @memcpy(buf[4..8], &uid_bytes);

        // Boot time (8 bytes)
        const boot_bytes = std.mem.toBytes(self.boot_time);
        @memcpy(buf[8..16], &boot_bytes);

        // PPID (4 bytes)
        const ppid_bytes = std.mem.toBytes(self.ppid);
        @memcpy(buf[16..20], &ppid_bytes);

        // TTY dev (8 bytes)
        const tty_bytes = std.mem.toBytes(self.tty_dev);
        @memcpy(buf[20..28], &tty_bytes);

        // SID (4 bytes)
        const sid_bytes = std.mem.toBytes(self.sid);
        @memcpy(buf[28..32], &sid_bytes);

        // Auth time (8 bytes)
        const auth_bytes = std.mem.toBytes(self.auth_time);
        @memcpy(buf[32..40], &auth_bytes);

        // Reserved (remaining bytes already zero)

        return buf;
    }

    /// Deserialize record from bytes
    pub fn deserialize(buf: *const [SERIALIZED_SIZE]u8) ?Self {
        const record_type_raw = buf[0];
        const record_type: RecordType = std.meta.intToEnum(RecordType, record_type_raw) catch return null;

        return .{
            .record_type = record_type,
            .uid = std.mem.bytesToValue(user_mod.UserId, buf[4..8]),
            .boot_time = std.mem.bytesToValue(i64, buf[8..16]),
            .ppid = std.mem.bytesToValue(i32, buf[16..20]),
            .tty_dev = std.mem.bytesToValue(u64, buf[20..28]),
            .sid = std.mem.bytesToValue(i32, buf[28..32]),
            .auth_time = std.mem.bytesToValue(i64, buf[32..40]),
        };
    }
};

/// Scope for timestamp matching
pub const RecordScope = struct {
    tty_dev: ?u64,
    ppid: i32,
    sid: i32,

    /// Get scope for current process
    pub fn current() RecordScope {
        return .{
            .tty_dev = getTtyDev() catch null,
            .ppid = c.getppid(),
            .sid = c.getsid(0),
        };
    }
};

/// Timestamp file header
const TimestampHeader = struct {
    magic: u32 = TIMESTAMP_MAGIC,
    version: u16 = TIMESTAMP_VERSION,
    flags: u16 = 0,
    _reserved: [8]u8 = [_]u8{0} ** 8,

    const SERIALIZED_SIZE = 16;

    fn serialize(self: TimestampHeader) [SERIALIZED_SIZE]u8 {
        var buf: [SERIALIZED_SIZE]u8 = [_]u8{0} ** SERIALIZED_SIZE;
        const magic_bytes = std.mem.toBytes(self.magic);
        @memcpy(buf[0..4], &magic_bytes);
        const version_bytes = std.mem.toBytes(self.version);
        @memcpy(buf[4..6], &version_bytes);
        const flags_bytes = std.mem.toBytes(self.flags);
        @memcpy(buf[6..8], &flags_bytes);
        return buf;
    }

    fn deserialize(buf: *const [SERIALIZED_SIZE]u8) ?TimestampHeader {
        const magic = std.mem.bytesToValue(u32, buf[0..4]);
        if (magic != TIMESTAMP_MAGIC) return null;

        const version = std.mem.bytesToValue(u16, buf[4..6]);
        if (version != TIMESTAMP_VERSION) return null;

        return .{
            .magic = magic,
            .version = version,
            .flags = std.mem.bytesToValue(u16, buf[6..8]),
        };
    }
};

/// Timestamp file manager
pub const TimestampFile = struct {
    fd: posix.fd_t,
    uid: user_mod.UserId,
    username: []const u8,
    path_buf: [256]u8,
    path_len: usize,

    const Self = @This();

    /// Open or create timestamp file for a user
    pub fn open(username: []const u8, uid: user_mod.UserId) !Self {
        // Ensure timestamp directory exists
        try ensureTimestampDir();

        // Build path
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ TIMESTAMP_DIR, username }) catch return error.PathTooLong;
        path_buf[path.len] = 0;

        // Open or create file (root-only access)
        const fd = posix.open(
            path_buf[0..path.len :0],
            .{ .ACCMODE = .RDWR, .CREAT = true },
            0o600,
        ) catch |err| {
            return switch (err) {
                error.AccessDenied => error.PermissionDenied,
                else => error.OpenFailed,
            };
        };

        // Verify file ownership (must be root) using C fstat
        var stat_buf: c.struct_stat = undefined;
        if (c.fstat(fd, &stat_buf) == 0) {
            if (stat_buf.st_uid != 0 or stat_buf.st_gid != 0) {
                posix.close(fd);
                return error.InvalidOwnership;
            }
        }

        return .{
            .fd = fd,
            .uid = uid,
            .username = username,
            .path_buf = path_buf,
            .path_len = path.len,
        };
    }

    /// Check if user has a valid cached credential
    pub fn check(self: *Self, timeout_seconds: u64) !bool {
        const scope = RecordScope.current();
        return self.checkWithScope(scope, timeout_seconds);
    }

    /// Check with specific scope
    pub fn checkWithScope(self: *Self, scope: RecordScope, timeout_seconds: u64) !bool {
        // Seek to beginning
        _ = c.lseek(self.fd, 0, c.SEEK_SET);

        // Read and validate header
        var header_buf: [TimestampHeader.SERIALIZED_SIZE]u8 = undefined;
        const header_read = posix.read(self.fd, &header_buf) catch return false;
        if (header_read < TimestampHeader.SERIALIZED_SIZE) return false;

        const header = TimestampHeader.deserialize(&header_buf) orelse return false;
        _ = header;

        // Read records
        while (true) {
            var record_buf: [TimestampRecord.SERIALIZED_SIZE]u8 = undefined;
            const n = posix.read(self.fd, &record_buf) catch break;
            if (n < TimestampRecord.SERIALIZED_SIZE) break;

            const record = TimestampRecord.deserialize(&record_buf) orelse continue;

            // Check if record matches our user, scope, and is valid
            if (record.uid == self.uid and record.matchesScope(scope) and record.isValid(timeout_seconds)) {
                return true;
            }
        }

        return false;
    }

    /// Update timestamp after successful authentication
    pub fn update(self: *Self, record_type: RecordType) !void {
        const record = TimestampRecord.create(record_type, self.uid);

        // Check if we need to write header
        var stat_buf: c.struct_stat = undefined;
        const file_size: i64 = if (c.fstat(self.fd, &stat_buf) == 0) stat_buf.st_size else 0;

        if (file_size == 0) {
            // Write header
            const header = TimestampHeader{};
            const header_bytes = header.serialize();
            _ = try posix.write(self.fd, &header_bytes);
        }

        // Find existing record to update or append
        const scope = RecordScope.current();
        _ = c.lseek(self.fd, TimestampHeader.SERIALIZED_SIZE, c.SEEK_SET);

        var found_offset: ?i64 = null;
        var offset: i64 = TimestampHeader.SERIALIZED_SIZE;

        while (true) {
            var record_buf: [TimestampRecord.SERIALIZED_SIZE]u8 = undefined;
            const n = posix.read(self.fd, &record_buf) catch break;
            if (n < TimestampRecord.SERIALIZED_SIZE) break;

            if (TimestampRecord.deserialize(&record_buf)) |existing| {
                if (existing.uid == self.uid and
                    existing.record_type == record_type and
                    existing.matchesScope(scope))
                {
                    found_offset = offset;
                    break;
                }
            }
            offset += TimestampRecord.SERIALIZED_SIZE;
        }

        // Write record
        if (found_offset) |off| {
            _ = c.lseek(self.fd, off, c.SEEK_SET);
        } else {
            _ = c.lseek(self.fd, 0, c.SEEK_END);
        }

        const record_bytes = record.serialize();
        _ = try posix.write(self.fd, &record_bytes);
    }

    /// Invalidate all timestamps for this user (like sudo -k)
    pub fn reset(self: *Self) !void {
        // Truncate file to just header
        const header = TimestampHeader{};
        const header_bytes = header.serialize();

        _ = c.lseek(self.fd, 0, c.SEEK_SET);
        _ = try posix.write(self.fd, &header_bytes);
        _ = c.ftruncate(self.fd, TimestampHeader.SERIALIZED_SIZE);
    }

    /// Remove timestamp file entirely (like sudo -K)
    pub fn remove(self: *Self) void {
        posix.close(self.fd);
        self.fd = -1;

        const path = self.path_buf[0..self.path_len :0];
        posix.unlink(path) catch {};
    }

    /// Close the timestamp file
    pub fn close(self: *Self) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
            self.fd = -1;
        }
    }
};

/// Ensure timestamp directory exists with correct permissions
fn ensureTimestampDir() !void {
    // Create /run/sudo if it doesn't exist
    posix.mkdir("/run/sudo", 0o711) catch |err| {
        if (err != error.PathAlreadyExists) {
            // Try to continue anyway
        }
    };

    // Create /run/sudo/ts
    posix.mkdir(TIMESTAMP_DIR, 0o700) catch |err| {
        if (err != error.PathAlreadyExists) {
            return error.CreateDirFailed;
        }
    };

    // Verify ownership using C stat
    var stat_buf: c.struct_stat = undefined;
    var path_buf: [128:0]u8 = undefined;
    @memcpy(path_buf[0..TIMESTAMP_DIR.len], TIMESTAMP_DIR);
    path_buf[TIMESTAMP_DIR.len] = 0;
    
    if (c.stat(&path_buf, &stat_buf) == 0) {
        if (stat_buf.st_uid != 0) {
            return error.InvalidOwnership;
        }
    } else {
        return error.StatFailed;
    }
}

/// Get system boot time (for invalidating timestamps across reboots)
fn getBootTime() !i64 {
    // Read from /proc/stat on Linux
    const file = std.fs.openFileAbsolute("/proc/stat", .{}) catch return error.BootTimeUnavailable;
    defer file.close();

    var buf: [4096]u8 = undefined;
    const n = file.read(&buf) catch return error.BootTimeUnavailable;

    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "btime ")) {
            const time_str = std.mem.trimLeft(u8, line[6..], " ");
            const time_end = std.mem.indexOfScalar(u8, time_str, ' ') orelse time_str.len;
            return std.fmt.parseInt(i64, time_str[0..time_end], 10) catch return error.BootTimeUnavailable;
        }
    }

    return error.BootTimeUnavailable;
}

/// Get TTY device number for current process
fn getTtyDev() !u64 {
    // Try to stat the controlling terminal
    var stat_buf: c.struct_stat = undefined;
    if (c.stat("/dev/tty", &stat_buf) == 0) {
        return stat_buf.st_rdev;
    }

    // Try stdin if /dev/tty fails
    if (c.fstat(posix.STDIN_FILENO, &stat_buf) == 0) {
        if (c.isatty(posix.STDIN_FILENO) == 1) {
            return stat_buf.st_rdev;
        }
    }

    return error.NoTty;
}

/// High-level functions for sudo integration

/// Check if credentials are cached for a user
pub fn checkCredentials(username: []const u8, uid: user_mod.UserId, timeout_seconds: u64) bool {
    var ts_file = TimestampFile.open(username, uid) catch return false;
    defer ts_file.close();

    return ts_file.check(timeout_seconds) catch false;
}

/// Update cached credentials after successful authentication
pub fn updateCredentials(username: []const u8, uid: user_mod.UserId) !void {
    var ts_file = try TimestampFile.open(username, uid);
    defer ts_file.close();

    try ts_file.update(.tty);
}

/// Reset (invalidate) cached credentials (sudo -k)
pub fn resetCredentials(username: []const u8, uid: user_mod.UserId) !void {
    var ts_file = TimestampFile.open(username, uid) catch return;
    defer ts_file.close();

    try ts_file.reset();
}

/// Remove timestamp file entirely (sudo -K)
pub fn removeCredentials(username: []const u8, uid: user_mod.UserId) void {
    var ts_file = TimestampFile.open(username, uid) catch return;
    ts_file.remove();
}

// ============================================
// Tests
// ============================================

test "TimestampRecord serialization" {
    const record = TimestampRecord{
        .record_type = .tty,
        .uid = 1000,
        .boot_time = 1234567890,
        .ppid = 12345,
        .tty_dev = 0x8801,
        .sid = 1234,
        .auth_time = 1234567900,
    };

    const bytes = record.serialize();
    const decoded = TimestampRecord.deserialize(&bytes).?;

    try std.testing.expectEqual(record.record_type, decoded.record_type);
    try std.testing.expectEqual(record.uid, decoded.uid);
    try std.testing.expectEqual(record.boot_time, decoded.boot_time);
    try std.testing.expectEqual(record.ppid, decoded.ppid);
    try std.testing.expectEqual(record.tty_dev, decoded.tty_dev);
    try std.testing.expectEqual(record.auth_time, decoded.auth_time);
}

test "TimestampHeader serialization" {
    const header = TimestampHeader{};
    const bytes = header.serialize();
    const decoded = TimestampHeader.deserialize(&bytes).?;

    try std.testing.expectEqual(TIMESTAMP_MAGIC, decoded.magic);
    try std.testing.expectEqual(TIMESTAMP_VERSION, decoded.version);
}

test "RecordScope" {
    const scope = RecordScope.current();
    _ = scope.ppid;
    _ = scope.sid;
}
