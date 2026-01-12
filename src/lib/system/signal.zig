//! Signal handling
//!
//! Provides signal management including blocking, handling, and forwarding.

const std = @import("std");
const posix = std.posix;

/// Common Unix signals.
pub const Signal = enum(u6) {
    HUP = 1,
    INT = 2,
    QUIT = 3,
    ILL = 4,
    TRAP = 5,
    ABRT = 6,
    BUS = 7,
    FPE = 8,
    KILL = 9,
    USR1 = 10,
    SEGV = 11,
    USR2 = 12,
    PIPE = 13,
    ALRM = 14,
    TERM = 15,
    CHLD = 17,
    CONT = 18,
    STOP = 19,
    TSTP = 20,
    TTIN = 21,
    TTOU = 22,
    URG = 23,
    XCPU = 24,
    XFSZ = 25,
    VTALRM = 26,
    PROF = 27,
    WINCH = 28,
    IO = 29,
    PWR = 30,
    SYS = 31,

    pub fn toInt(self: Signal) u6 {
        return @intFromEnum(self);
    }

    pub fn fromInt(sig: u32) ?Signal {
        if (sig > 31 or sig == 0) return null;
        return @enumFromInt(@as(u6, @truncate(sig)));
    }
};

/// Signal set for blocking/unblocking multiple signals.
pub const SignalSet = struct {
    set: posix.sigset_t,

    const Self = @This();

    /// Create an empty signal set.
    pub fn empty() Self {
        var set: posix.sigset_t = undefined;
        _ = posix.system.sigemptyset(&set);
        return .{ .set = set };
    }

    /// Create a signal set with all signals.
    pub fn full() Self {
        var set: posix.sigset_t = undefined;
        _ = posix.system.sigfillset(&set);
        return .{ .set = set };
    }

    /// Add a signal to the set.
    pub fn add(self: *Self, sig: Signal) void {
        _ = posix.system.sigaddset(&self.set, sig.toInt());
    }

    /// Remove a signal from the set.
    pub fn remove(self: *Self, sig: Signal) void {
        _ = posix.system.sigdelset(&self.set, sig.toInt());
    }

    /// Check if a signal is in the set.
    pub fn contains(self: Self, sig: Signal) bool {
        return posix.system.sigismember(&self.set, sig.toInt()) == 1;
    }

    /// Block signals in this set.
    pub fn block(self: Self) !Self {
        var old_set: posix.sigset_t = undefined;
        const rc = posix.system.sigprocmask(posix.SIG.BLOCK, &self.set, &old_set);
        if (rc != 0) return error.SystemError;
        return .{ .set = old_set };
    }

    /// Unblock signals in this set.
    pub fn unblock(self: Self) !void {
        const rc = posix.system.sigprocmask(posix.SIG.UNBLOCK, &self.set, null);
        if (rc != 0) return error.SystemError;
    }

    /// Set the signal mask to this set.
    pub fn setMask(self: Self) !Self {
        var old_set: posix.sigset_t = undefined;
        const rc = posix.system.sigprocmask(posix.SIG.SETMASK, &self.set, &old_set);
        if (rc != 0) return error.SystemError;
        return .{ .set = old_set };
    }
};

/// Signal handler function type.
pub const SignalHandler = union(enum) {
    default: void,
    ignore: void,
    handler: *const fn (c_int) callconv(.C) void,
};

/// Install a signal handler.
pub fn installHandler(sig: Signal, handler: SignalHandler) !void {
    var sa: posix.Sigaction = .{
        .handler = switch (handler) {
            .default => .{ .handler = posix.SIG.DFL },
            .ignore => .{ .handler = posix.SIG.IGN },
            .handler => |h| .{ .handler = h },
        },
        .mask = SignalSet.empty().set,
        .flags = 0,
    };

    try posix.sigaction(sig.toInt(), &sa, null);
}

/// Block a single signal.
pub fn blockSignal(sig: Signal) !void {
    var set = SignalSet.empty();
    set.add(sig);
    _ = try set.block();
}

/// Unblock a single signal.
pub fn unblockSignal(sig: Signal) !void {
    var set = SignalSet.empty();
    set.add(sig);
    try set.unblock();
}

// ============================================
// Tests
// ============================================

test "Signal enum" {
    const testing = std.testing;

    try testing.expectEqual(@as(u6, 15), Signal.TERM.toInt());
    try testing.expectEqual(Signal.TERM, Signal.fromInt(15).?);
    try testing.expectEqual(@as(?Signal, null), Signal.fromInt(100));
}

test "SignalSet operations" {
    const testing = std.testing;

    var set = SignalSet.empty();
    try testing.expect(!set.contains(.TERM));

    set.add(.TERM);
    try testing.expect(set.contains(.TERM));

    set.remove(.TERM);
    try testing.expect(!set.contains(.TERM));
}

test "SignalSet full" {
    const set = SignalSet.full();
    try std.testing.expect(set.contains(.TERM));
    try std.testing.expect(set.contains(.INT));
}
