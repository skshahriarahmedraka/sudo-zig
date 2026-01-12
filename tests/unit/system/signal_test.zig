//! Unit tests for signal handling
//!
//! Tests for signal types, signal sets, and signal operations.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const signal = lib.system.signal;
const Signal = signal.Signal;
const SignalSet = signal.SignalSet;

// ============================================
// Signal Enum Tests
// ============================================

test "Signal.toInt returns correct values" {
    try testing.expectEqual(@as(u6, 1), Signal.HUP.toInt());
    try testing.expectEqual(@as(u6, 2), Signal.INT.toInt());
    try testing.expectEqual(@as(u6, 3), Signal.QUIT.toInt());
    try testing.expectEqual(@as(u6, 9), Signal.KILL.toInt());
    try testing.expectEqual(@as(u6, 15), Signal.TERM.toInt());
    try testing.expectEqual(@as(u6, 17), Signal.CHLD.toInt());
    try testing.expectEqual(@as(u6, 19), Signal.STOP.toInt());
    try testing.expectEqual(@as(u6, 20), Signal.TSTP.toInt());
}

test "Signal.fromInt returns correct signals" {
    try testing.expectEqual(Signal.HUP, Signal.fromInt(1).?);
    try testing.expectEqual(Signal.INT, Signal.fromInt(2).?);
    try testing.expectEqual(Signal.QUIT, Signal.fromInt(3).?);
    try testing.expectEqual(Signal.KILL, Signal.fromInt(9).?);
    try testing.expectEqual(Signal.TERM, Signal.fromInt(15).?);
    try testing.expectEqual(Signal.CHLD, Signal.fromInt(17).?);
}

test "Signal.fromInt returns null for invalid signals" {
    try testing.expectEqual(@as(?Signal, null), Signal.fromInt(0));
    try testing.expectEqual(@as(?Signal, null), Signal.fromInt(32));
    try testing.expectEqual(@as(?Signal, null), Signal.fromInt(100));
    try testing.expectEqual(@as(?Signal, null), Signal.fromInt(255));
}

test "Signal roundtrip conversion" {
    const signals = [_]Signal{
        .HUP,  .INT,  .QUIT, .ILL,   .TRAP, .ABRT,
        .BUS,  .FPE,  .KILL, .USR1,  .SEGV, .USR2,
        .PIPE, .ALRM, .TERM, .CHLD,  .CONT, .STOP,
        .TSTP, .TTIN, .TTOU, .URG,   .XCPU, .XFSZ,
        .VTALRM, .PROF, .WINCH, .IO, .PWR,  .SYS,
    };

    for (signals) |sig| {
        const as_int = sig.toInt();
        const back = Signal.fromInt(as_int).?;
        try testing.expectEqual(sig, back);
    }
}

// ============================================
// SignalSet Tests
// ============================================

test "SignalSet.empty creates empty set" {
    const set = SignalSet.empty();

    // No signals should be in an empty set
    try testing.expect(!set.contains(.HUP));
    try testing.expect(!set.contains(.INT));
    try testing.expect(!set.contains(.TERM));
    try testing.expect(!set.contains(.KILL));
}

test "SignalSet.full creates full set" {
    const set = SignalSet.full();

    // All signals should be in a full set
    try testing.expect(set.contains(.HUP));
    try testing.expect(set.contains(.INT));
    try testing.expect(set.contains(.TERM));
    try testing.expect(set.contains(.KILL));
    try testing.expect(set.contains(.CHLD));
    try testing.expect(set.contains(.USR1));
    try testing.expect(set.contains(.USR2));
}

test "SignalSet.add adds signals" {
    var set = SignalSet.empty();

    try testing.expect(!set.contains(.TERM));
    set.add(.TERM);
    try testing.expect(set.contains(.TERM));

    try testing.expect(!set.contains(.INT));
    set.add(.INT);
    try testing.expect(set.contains(.INT));

    // TERM should still be there
    try testing.expect(set.contains(.TERM));
}

test "SignalSet.remove removes signals" {
    var set = SignalSet.full();

    try testing.expect(set.contains(.TERM));
    set.remove(.TERM);
    try testing.expect(!set.contains(.TERM));

    try testing.expect(set.contains(.INT));
    set.remove(.INT);
    try testing.expect(!set.contains(.INT));

    // Other signals should still be there
    try testing.expect(set.contains(.HUP));
    try testing.expect(set.contains(.KILL));
}

test "SignalSet add and remove are idempotent" {
    var set = SignalSet.empty();

    // Adding twice should be same as adding once
    set.add(.TERM);
    set.add(.TERM);
    try testing.expect(set.contains(.TERM));

    // Removing twice should be same as removing once
    set.remove(.TERM);
    set.remove(.TERM);
    try testing.expect(!set.contains(.TERM));
}

test "SignalSet multiple signals" {
    var set = SignalSet.empty();

    // Add multiple signals
    set.add(.HUP);
    set.add(.INT);
    set.add(.QUIT);
    set.add(.TERM);

    try testing.expect(set.contains(.HUP));
    try testing.expect(set.contains(.INT));
    try testing.expect(set.contains(.QUIT));
    try testing.expect(set.contains(.TERM));

    // These should not be in the set
    try testing.expect(!set.contains(.KILL));
    try testing.expect(!set.contains(.USR1));
    try testing.expect(!set.contains(.CHLD));
}

// ============================================
// Common Signal Patterns Tests
// ============================================

test "typical sudo signal set" {
    // sudo typically blocks these signals during critical sections
    var set = SignalSet.empty();
    set.add(.INT);
    set.add(.QUIT);
    set.add(.TSTP);
    set.add(.TERM);
    set.add(.HUP);

    try testing.expect(set.contains(.INT));
    try testing.expect(set.contains(.QUIT));
    try testing.expect(set.contains(.TSTP));
    try testing.expect(set.contains(.TERM));
    try testing.expect(set.contains(.HUP));

    // CHLD should not be blocked (need to wait for children)
    try testing.expect(!set.contains(.CHLD));
}

test "job control signals" {
    var set = SignalSet.empty();
    set.add(.TSTP);
    set.add(.TTIN);
    set.add(.TTOU);
    set.add(.CONT);

    try testing.expect(set.contains(.TSTP));
    try testing.expect(set.contains(.TTIN));
    try testing.expect(set.contains(.TTOU));
    try testing.expect(set.contains(.CONT));
}
