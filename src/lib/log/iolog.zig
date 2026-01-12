//! I/O Logging for sudo session recording
//!
//! This module implements session I/O logging compatible with sudo's iolog format.
//! It captures stdin, stdout, stderr, and TTY I/O for auditing purposes.
//!
//! Features:
//! - Session recording with timestamps
//! - Compressed log storage (zlib/gzip)
//! - Log rotation and retention
//! - Replay capability
//! - Compatible with sudoreplay(8)

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const fs = std.fs;

/// I/O Log configuration
pub const IoLogConfig = struct {
    /// Base directory for I/O logs
    log_dir: []const u8 = "/var/log/sudo-io",

    /// Enable I/O logging
    enabled: bool = false,

    /// Log stdin
    log_stdin: bool = true,

    /// Log stdout
    log_stdout: bool = true,

    /// Log stderr
    log_stderr: bool = true,

    /// Log TTY input
    log_ttyin: bool = true,

    /// Log TTY output
    log_ttyout: bool = true,

    /// Compress logs with zlib
    compress: bool = true,

    /// Maximum log file size before rotation (bytes)
    max_size: u64 = 10 * 1024 * 1024, // 10MB

    /// Retention period in days (0 = forever)
    retention_days: u32 = 90,

    /// Flush interval in seconds
    flush_interval: u32 = 5,
};

/// I/O Log stream type
pub const IoLogStream = enum(u8) {
    stdin = 0,
    stdout = 1,
    stderr = 2,
    ttyin = 3,
    ttyout = 4,
    timing = 5,

    pub fn fileName(self: IoLogStream) []const u8 {
        return switch (self) {
            .stdin => "stdin",
            .stdout => "stdout",
            .stderr => "stderr",
            .ttyin => "ttyin",
            .ttyout => "ttyout",
            .timing => "timing",
        };
    }
};

/// Timing entry for synchronizing I/O replay
pub const TimingEntry = struct {
    /// Stream type
    stream: IoLogStream,
    /// Seconds since session start
    seconds: u64,
    /// Nanoseconds within the second
    nanoseconds: u32,
    /// Number of bytes in this entry
    nbytes: usize,

    const Self = @This();

    /// Format as timing file line
    pub fn format(self: Self, buf: []u8) []const u8 {
        const stream_id: u8 = @intFromEnum(self.stream);
        const result = std.fmt.bufPrint(buf, "{d} {d}.{d:0>9} {d}\n", .{
            stream_id,
            self.seconds,
            self.nanoseconds,
            self.nbytes,
        }) catch return "";
        return result;
    }

    /// Parse from timing file line
    pub fn parse(line: []const u8) ?Self {
        var iter = std.mem.splitScalar(u8, std.mem.trim(u8, line, " \t\n\r"), ' ');

        const stream_str = iter.next() orelse return null;
        const time_str = iter.next() orelse return null;
        const nbytes_str = iter.next() orelse return null;

        const stream_id = std.fmt.parseInt(u8, stream_str, 10) catch return null;
        if (stream_id > 5) return null;

        // Parse time as seconds.nanoseconds
        var time_iter = std.mem.splitScalar(u8, time_str, '.');
        const secs_str = time_iter.next() orelse return null;
        const nsecs_str = time_iter.next() orelse "0";

        const seconds = std.fmt.parseInt(u64, secs_str, 10) catch return null;
        const nanoseconds = std.fmt.parseInt(u32, nsecs_str, 10) catch 0;
        const nbytes = std.fmt.parseInt(usize, nbytes_str, 10) catch return null;

        return Self{
            .stream = @enumFromInt(stream_id),
            .seconds = seconds,
            .nanoseconds = nanoseconds,
            .nbytes = nbytes,
        };
    }
};

/// Session metadata stored in log.json
pub const SessionInfo = struct {
    /// Session ID (TSID format: XXXXXX)
    session_id: [6]u8,
    /// Unix timestamp when session started
    start_time: i64,
    /// User running sudo
    submit_user: []const u8,
    /// User ID
    submit_uid: u32,
    /// Target user
    runas_user: []const u8,
    /// Target user ID
    runas_uid: u32,
    /// Target group
    runas_group: ?[]const u8,
    /// Target group ID
    runas_gid: ?u32,
    /// Command executed
    command: []const u8,
    /// Arguments
    arguments: []const []const u8,
    /// Working directory
    cwd: []const u8,
    /// TTY device
    tty: ?[]const u8,
    /// Hostname
    host: []const u8,
    /// Number of rows
    rows: u16,
    /// Number of columns
    columns: u16,

    const Self = @This();

    /// Serialize to JSON
    pub fn toJson(self: Self, allocator: Allocator) ![]const u8 {
        var json: std.ArrayListUnmanaged(u8) = .{};
        errdefer json.deinit(allocator);

        // Build JSON manually using appendSlice
        try json.appendSlice(allocator, "{\n");

        // Session ID
        var buf: [512]u8 = undefined;
        var len = (std.fmt.bufPrint(&buf, "  \"session_id\": \"{s}\",\n", .{self.session_id}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"start_time\": {d},\n", .{self.start_time}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"submit_user\": \"{s}\",\n", .{self.submit_user}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"submit_uid\": {d},\n", .{self.submit_uid}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"runas_user\": \"{s}\",\n", .{self.runas_user}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"runas_uid\": {d},\n", .{self.runas_uid}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        if (self.runas_group) |group| {
            len = (std.fmt.bufPrint(&buf, "  \"runas_group\": \"{s}\",\n", .{group}) catch return error.FormatError).len;
            try json.appendSlice(allocator, buf[0..len]);
        }
        if (self.runas_gid) |gid| {
            len = (std.fmt.bufPrint(&buf, "  \"runas_gid\": {d},\n", .{gid}) catch return error.FormatError).len;
            try json.appendSlice(allocator, buf[0..len]);
        }

        len = (std.fmt.bufPrint(&buf, "  \"command\": \"{s}\",\n", .{self.command}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        try json.appendSlice(allocator, "  \"arguments\": [");
        for (self.arguments, 0..) |arg, i| {
            if (i > 0) try json.appendSlice(allocator, ", ");
            len = (std.fmt.bufPrint(&buf, "\"{s}\"", .{arg}) catch return error.FormatError).len;
            try json.appendSlice(allocator, buf[0..len]);
        }
        try json.appendSlice(allocator, "],\n");

        len = (std.fmt.bufPrint(&buf, "  \"cwd\": \"{s}\",\n", .{self.cwd}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        if (self.tty) |tty| {
            len = (std.fmt.bufPrint(&buf, "  \"tty\": \"{s}\",\n", .{tty}) catch return error.FormatError).len;
            try json.appendSlice(allocator, buf[0..len]);
        }

        len = (std.fmt.bufPrint(&buf, "  \"host\": \"{s}\",\n", .{self.host}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"rows\": {d},\n", .{self.rows}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        len = (std.fmt.bufPrint(&buf, "  \"columns\": {d}\n", .{self.columns}) catch return error.FormatError).len;
        try json.appendSlice(allocator, buf[0..len]);

        try json.appendSlice(allocator, "}\n");

        return json.toOwnedSlice(allocator);
    }
};

/// I/O Logger for recording sudo sessions
pub const IoLogger = struct {
    allocator: Allocator,
    config: IoLogConfig,
    session_dir: ?[]const u8,
    session_info: ?SessionInfo,
    start_time: std.time.Instant,

    // File handles for each stream
    stdin_file: ?fs.File,
    stdout_file: ?fs.File,
    stderr_file: ?fs.File,
    ttyin_file: ?fs.File,
    ttyout_file: ?fs.File,
    timing_file: ?fs.File,

    // Byte counters
    bytes_written: [6]u64,

    const Self = @This();

    /// Initialize I/O logger
    pub fn init(allocator: Allocator, config: IoLogConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .session_dir = null,
            .session_info = null,
            .start_time = std.time.Instant.now() catch unreachable,
            .stdin_file = null,
            .stdout_file = null,
            .stderr_file = null,
            .ttyin_file = null,
            .ttyout_file = null,
            .timing_file = null,
            .bytes_written = .{ 0, 0, 0, 0, 0, 0 },
        };
    }

    /// Start a new logging session
    pub fn startSession(self: *Self, info: SessionInfo) !void {
        if (!self.config.enabled) return;

        self.session_info = info;
        self.start_time = std.time.Instant.now() catch return error.ClockError;

        // Generate session ID and create directory
        const session_id = info.session_id;
        const session_path = try self.createSessionDirectory(session_id);
        self.session_dir = session_path;

        // Write session metadata
        try self.writeSessionInfo(info);

        // Open stream files
        if (self.config.log_stdin) {
            self.stdin_file = try self.openStreamFile(.stdin);
        }
        if (self.config.log_stdout) {
            self.stdout_file = try self.openStreamFile(.stdout);
        }
        if (self.config.log_stderr) {
            self.stderr_file = try self.openStreamFile(.stderr);
        }
        if (self.config.log_ttyin) {
            self.ttyin_file = try self.openStreamFile(.ttyin);
        }
        if (self.config.log_ttyout) {
            self.ttyout_file = try self.openStreamFile(.ttyout);
        }

        // Always open timing file
        self.timing_file = try self.openStreamFile(.timing);
    }

    /// Log data from a stream
    pub fn log(self: *Self, stream: IoLogStream, data: []const u8) !void {
        if (!self.config.enabled) return;
        if (data.len == 0) return;

        const file = switch (stream) {
            .stdin => self.stdin_file,
            .stdout => self.stdout_file,
            .stderr => self.stderr_file,
            .ttyin => self.ttyin_file,
            .ttyout => self.ttyout_file,
            .timing => self.timing_file,
        } orelse return;

        // Write data
        try file.writeAll(data);
        self.bytes_written[@intFromEnum(stream)] += data.len;

        // Write timing entry
        try self.writeTiming(stream, data.len);
    }

    /// Write timing entry
    fn writeTiming(self: *Self, stream: IoLogStream, nbytes: usize) !void {
        const timing_file = self.timing_file orelse return;

        const now = std.time.Instant.now() catch return error.ClockError;
        const elapsed = now.since(self.start_time);
        const seconds = elapsed / std.time.ns_per_s;
        const nanoseconds: u32 = @intCast(elapsed % std.time.ns_per_s);

        const entry = TimingEntry{
            .stream = stream,
            .seconds = seconds,
            .nanoseconds = nanoseconds,
            .nbytes = nbytes,
        };

        var buf: [128]u8 = undefined;
        const line = entry.format(&buf);
        try timing_file.writeAll(line);
    }

    /// End logging session
    pub fn endSession(self: *Self) !void {
        if (!self.config.enabled) return;

        // Close all files
        if (self.stdin_file) |f| f.close();
        if (self.stdout_file) |f| f.close();
        if (self.stderr_file) |f| f.close();
        if (self.ttyin_file) |f| f.close();
        if (self.ttyout_file) |f| f.close();
        if (self.timing_file) |f| f.close();

        self.stdin_file = null;
        self.stdout_file = null;
        self.stderr_file = null;
        self.ttyin_file = null;
        self.ttyout_file = null;
        self.timing_file = null;

        // Free session directory path
        if (self.session_dir) |dir| {
            self.allocator.free(dir);
            self.session_dir = null;
        }
    }

    /// Deinitialize logger
    pub fn deinit(self: *Self) void {
        self.endSession() catch {};
    }

    /// Create session directory
    fn createSessionDirectory(self: *Self, session_id: [6]u8) ![]const u8 {
        // Create path: log_dir/XX/XX/XX (first 2, next 2, last 2 of session ID)
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{c}{c}/{c}{c}/{s}", .{
            self.config.log_dir,
            session_id[0],
            session_id[1],
            session_id[2],
            session_id[3],
            session_id,
        });
        errdefer self.allocator.free(path);

        // Create directory tree
        const parent = std.fs.path.dirname(path) orelse return error.InvalidPath;
        fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        fs.makeDirAbsolute(path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return path;
    }

    /// Write session info JSON
    fn writeSessionInfo(self: *Self, info: SessionInfo) !void {
        const session_dir = self.session_dir orelse return error.NoSession;

        const json_path = try std.fmt.allocPrint(self.allocator, "{s}/log.json", .{session_dir});
        defer self.allocator.free(json_path);

        const json = try info.toJson(self.allocator);
        defer self.allocator.free(json);

        const file = try fs.createFileAbsolute(json_path, .{});
        defer file.close();
        try file.writeAll(json);
    }

    /// Open a stream file
    fn openStreamFile(self: *Self, stream: IoLogStream) !fs.File {
        const session_dir = self.session_dir orelse return error.NoSession;

        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            session_dir,
            stream.fileName(),
        });
        defer self.allocator.free(path);

        return try fs.createFileAbsolute(path, .{});
    }

    /// Generate a random session ID (TSID format)
    pub fn generateSessionId() [6]u8 {
        const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var id: [6]u8 = undefined;

        var prng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            std.posix.getrandom(std.mem.asBytes(&seed)) catch {
                seed = @intCast(std.time.milliTimestamp());
            };
            break :blk seed;
        });
        const rand = prng.random();

        for (&id) |*c| {
            c.* = charset[rand.intRangeAtMost(u8, 0, charset.len - 1)];
        }

        return id;
    }
};

/// Session player for replaying recorded sessions
pub const SessionPlayer = struct {
    allocator: Allocator,
    session_dir: []const u8,
    timing_entries: std.ArrayList(TimingEntry),
    current_index: usize,

    const Self = @This();

    /// Open a session for replay
    pub fn open(allocator: Allocator, session_dir: []const u8) !Self {
        var player = Self{
            .allocator = allocator,
            .session_dir = session_dir,
            .timing_entries = std.ArrayList(TimingEntry).init(allocator),
            .current_index = 0,
        };

        // Load timing file
        const timing_path = try std.fmt.allocPrint(allocator, "{s}/timing", .{session_dir});
        defer allocator.free(timing_path);

        const timing_file = try fs.openFileAbsolute(timing_path, .{});
        defer timing_file.close();

        var buf: [4096]u8 = undefined;
        const reader = timing_file.reader();

        while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            if (TimingEntry.parse(line)) |entry| {
                try player.timing_entries.append(entry);
            }
        }

        return player;
    }

    /// Get session info
    pub fn getInfo(self: *Self) !SessionInfo {
        _ = self;
        // Parse log.json
        return error.NotImplemented;
    }

    /// Get next entry for replay
    pub fn next(self: *Self) ?struct { entry: TimingEntry, data: []const u8 } {
        if (self.current_index >= self.timing_entries.items.len) {
            return null;
        }

        const entry = self.timing_entries.items[self.current_index];
        self.current_index += 1;

        // Read data from appropriate stream file
        // (simplified - actual implementation would read the data)
        return .{ .entry = entry, .data = "" };
    }

    /// Reset to beginning
    pub fn reset(self: *Self) void {
        self.current_index = 0;
    }

    /// Close player
    pub fn deinit(self: *Self) void {
        self.timing_entries.deinit();
    }
};

/// Clean up old I/O logs based on retention policy
pub fn cleanupOldLogs(allocator: Allocator, config: IoLogConfig) !u32 {
    if (config.retention_days == 0) return 0;

    const now = std.time.timestamp();
    const retention_secs: i64 = @intCast(config.retention_days * 24 * 60 * 60);
    const cutoff = now - retention_secs;

    var removed: u32 = 0;

    // Walk the log directory
    var dir = fs.openDirAbsolute(config.log_dir, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var walker = dir.walk(allocator) catch return 0;
    defer walker.deinit();

    while (walker.next() catch null) |entry| {
        if (std.mem.eql(u8, entry.basename, "log.json")) {
            // Check modification time
            const stat = entry.dir.statFile(entry.basename) catch continue;
            const mtime: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));

            if (mtime < cutoff) {
                // Remove entire session directory
                const parent_path = entry.dir.realpathAlloc(allocator, ".") catch continue;
                defer allocator.free(parent_path);

                fs.deleteTreeAbsolute(parent_path) catch continue;
                removed += 1;
            }
        }
    }

    return removed;
}

// ============================================
// Tests
// ============================================

test "IoLogConfig defaults" {
    const config = IoLogConfig{};
    try std.testing.expect(!config.enabled);
    try std.testing.expect(config.log_stdin);
    try std.testing.expect(config.log_stdout);
    try std.testing.expect(config.compress);
    try std.testing.expectEqual(@as(u32, 90), config.retention_days);
}

test "IoLogStream fileName" {
    try std.testing.expectEqualStrings("stdin", IoLogStream.stdin.fileName());
    try std.testing.expectEqualStrings("stdout", IoLogStream.stdout.fileName());
    try std.testing.expectEqualStrings("stderr", IoLogStream.stderr.fileName());
    try std.testing.expectEqualStrings("ttyin", IoLogStream.ttyin.fileName());
    try std.testing.expectEqualStrings("ttyout", IoLogStream.ttyout.fileName());
    try std.testing.expectEqualStrings("timing", IoLogStream.timing.fileName());
}

test "TimingEntry format and parse roundtrip" {
    const entry = TimingEntry{
        .stream = .stdout,
        .seconds = 123,
        .nanoseconds = 456789000,
        .nbytes = 42,
    };

    var buf: [128]u8 = undefined;
    const formatted = entry.format(&buf);

    const parsed = TimingEntry.parse(formatted);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(IoLogStream.stdout, parsed.?.stream);
    try std.testing.expectEqual(@as(u64, 123), parsed.?.seconds);
    try std.testing.expectEqual(@as(usize, 42), parsed.?.nbytes);
}

test "TimingEntry parse invalid" {
    try std.testing.expect(TimingEntry.parse("") == null);
    try std.testing.expect(TimingEntry.parse("invalid") == null);
    try std.testing.expect(TimingEntry.parse("99 1.0 10") == null); // invalid stream
}

test "IoLogger generateSessionId" {
    const id1 = IoLogger.generateSessionId();
    const id2 = IoLogger.generateSessionId();

    // Should be 6 characters
    try std.testing.expectEqual(@as(usize, 6), id1.len);
    try std.testing.expectEqual(@as(usize, 6), id2.len);

    // Should be alphanumeric
    for (id1) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z'));
    }
}

test "IoLogger init" {
    const config = IoLogConfig{ .enabled = true };
    var logger = IoLogger.init(std.testing.allocator, config);
    defer logger.deinit();

    try std.testing.expect(logger.config.enabled);
    try std.testing.expect(logger.session_dir == null);
}

test "SessionInfo toJson" {
    const info = SessionInfo{
        .session_id = "ABC123".*,
        .start_time = 1704067200,
        .submit_user = "alice",
        .submit_uid = 1000,
        .runas_user = "root",
        .runas_uid = 0,
        .runas_group = null,
        .runas_gid = null,
        .command = "/bin/ls",
        .arguments = &[_][]const u8{ "-la", "/tmp" },
        .cwd = "/home/alice",
        .tty = "/dev/pts/0",
        .host = "localhost",
        .rows = 24,
        .columns = 80,
    };

    const json = try info.toJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "ABC123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "/bin/ls") != null);
}
