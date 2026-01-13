//! Regression tests for sudoers policy evaluation crashes

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");

const sudoers = lib.sudoers;
const Policy = sudoers.Policy;
const AuthRequest = sudoers.AuthRequest;

// This test exercises user matching with a User obtained from the system database.
// Previously this could segfault due to dangling slice pointers in `User.name`.
test "Policy.check does not segfault when matching username" {
    const allocator = testing.allocator;

    // Minimal sudoers content permitting root on all hosts to run all commands.
    // We only care that policy evaluation reaches username matching safely.
    var parsed = try sudoers.parse(
        allocator,
        "root ALL=(ALL:ALL) ALL\n",
    );
    defer parsed.deinit();

    var policy = Policy.init(allocator, &parsed);

    // Use a real user from the system database.
    var root_user: lib.system.User = undefined;
    try testing.expect(lib.system.User.fromUidInto(0, &root_user));

    const req = AuthRequest{
        .user = &root_user,
        .groups = &[_]u32{0},
        .hostname = "localhost",
        .command = "/usr/bin/whoami",
        .arguments = null,
        .target_user = null,
        .target_group = null,
    };

    // Should not crash; result depends on sudoers.
    const auth = policy.check(req);
    try testing.expect(auth.allowed);
}
