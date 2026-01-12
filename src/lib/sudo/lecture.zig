//! First-use lecture for sudo
//!
//! Displays a lecture message on first sudo use to educate users
//! about the responsibilities of using sudo.

const std = @import("std");
const posix = std.posix;
const system = @import("../system/mod.zig");

/// Default lecture message (from sudo-rs)
pub const DEFAULT_LECTURE =
    \\
    \\We trust you have received the usual lecture from the local System
    \\Administrator. It usually boils down to these three things:
    \\
    \\    #1) Respect the privacy of others.
    \\    #2) Think before you type.
    \\    #3) With great power comes great responsibility.
    \\
    \\
;

/// Lecture display modes
pub const LectureMode = enum {
    never, // Never show lecture
    once, // Show once per user (default)
    always, // Show every time
};

/// Check if lecture should be shown and display it if needed
pub fn maybeShowLecture(
    username: []const u8,
    uid: system.UserId,
    mode: LectureMode,
    custom_lecture_file: ?[]const u8,
) void {
    switch (mode) {
        .never => return,
        .always => showLecture(custom_lecture_file),
        .once => {
            if (!hasSeenLecture(username, uid)) {
                showLecture(custom_lecture_file);
                markLectureSeen(username, uid);
            }
        },
    }
}

/// Check if user has already seen the lecture
fn hasSeenLecture(username: []const u8, uid: system.UserId) bool {
    _ = username;
    
    // Check for lecture file in /var/db/sudo/lectured/ or /var/lib/sudo/lectured/
    const paths = [_][]const u8{
        "/var/db/sudo/lectured",
        "/var/lib/sudo/lectured",
    };

    var uid_buf: [32]u8 = undefined;
    const uid_str = std.fmt.bufPrint(&uid_buf, "{d}", .{uid}) catch return false;

    for (paths) |base_path| {
        var path_buf: [256]u8 = undefined;
        const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ base_path, uid_str }) catch continue;

        // Check if file exists
        if (std.fs.accessAbsolute(full_path, .{})) {
            return true;
        } else |_| {}
    }

    return false;
}

/// Mark that user has seen the lecture
fn markLectureSeen(username: []const u8, uid: system.UserId) void {
    _ = username;
    
    // Try to create lecture marker file
    const base_paths = [_][]const u8{
        "/var/db/sudo/lectured",
        "/var/lib/sudo/lectured",
    };

    var uid_buf: [32]u8 = undefined;
    const uid_str = std.fmt.bufPrint(&uid_buf, "{d}", .{uid}) catch return;

    for (base_paths) |base_path| {
        // Try to create the directory if it doesn't exist
        std.fs.makeDirAbsolute(base_path) catch {};

        var path_buf: [256]u8 = undefined;
        const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ base_path, uid_str }) catch continue;

        // Create an empty file as marker
        if (std.fs.createFileAbsolute(full_path, .{})) |file| {
            file.close();
            return; // Success
        } else |_| {}
    }
}

/// Display the lecture to the user
fn showLecture(custom_lecture_file: ?[]const u8) void {
    // Try to read custom lecture file if specified
    if (custom_lecture_file) |lecture_path| {
        if (readAndShowLectureFile(lecture_path)) return;
    }

    // Show default lecture
    _ = posix.write(posix.STDERR_FILENO, DEFAULT_LECTURE) catch {};
}

fn readAndShowLectureFile(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = file.read(&buf) catch break;
        if (n == 0) break;
        _ = posix.write(posix.STDERR_FILENO, buf[0..n]) catch break;
    }

    return true;
}

// ============================================
// Tests
// ============================================

test "LectureMode enum" {
    const testing = std.testing;
    try testing.expectEqual(LectureMode.once, LectureMode.once);
    try testing.expectEqual(LectureMode.never, LectureMode.never);
    try testing.expectEqual(LectureMode.always, LectureMode.always);
}

test "DEFAULT_LECTURE contains key phrases" {
    const testing = std.testing;
    try testing.expect(std.mem.indexOf(u8, DEFAULT_LECTURE, "great power") != null);
    try testing.expect(std.mem.indexOf(u8, DEFAULT_LECTURE, "responsibility") != null);
}
