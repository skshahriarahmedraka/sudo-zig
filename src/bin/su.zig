//! su - switch user
//!
//! su allows commands to be run with a substitute user and group ID.
//! When called with no user specified, su defaults to running an interactive
//! shell as root.

const std = @import("std");
const lib = @import("sudo-zig-lib");

pub fn main() void {
    lib.su.main();
}
