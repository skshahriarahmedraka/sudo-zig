//! sudo - execute a command as another user
//!
//! sudo allows a permitted user to execute a command as the superuser or
//! another user, as specified by the security policy configured in /etc/sudoers.

const std = @import("std");
const lib = @import("sudo-zig-lib");

pub fn main() void {
    lib.sudo.main();
}
