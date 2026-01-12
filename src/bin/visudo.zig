//! visudo - edit the sudoers file safely
//!
//! visudo edits the sudoers file in a safe fashion, locking the file and
//! checking for syntax errors before saving.

const std = @import("std");
const lib = @import("sudo-zig-lib");

pub fn main() void {
    lib.visudo.main();
}
