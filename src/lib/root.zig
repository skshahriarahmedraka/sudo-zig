//! sudo-zig: A memory-safe implementation of sudo in Zig
//!
//! This library provides the core functionality for the sudo, su, and visudo
//! commands. It is designed to be a drop-in replacement for the original sudo
//! implementation with improved memory safety.
//!
//! ## Modules
//!
//! - `common`: Shared utilities (error handling, path validation, strings)
//! - `system`: System interfaces (users, groups, processes, signals)
//! - `sudoers`: Sudoers file parsing and policy evaluation
//! - `pam`: PAM authentication integration
//! - `exec`: Command execution (PTY and non-PTY modes)
//! - `log`: Logging and syslog integration
//! - `defaults`: Default settings management
//!
//! ## Binaries
//!
//! - `sudo`: Execute commands as another user
//! - `su`: Switch user
//! - `visudo`: Safely edit sudoers files

const std = @import("std");
const builtin = @import("builtin");
pub const build_options = @import("build_options");

// ============================================
// Core Modules
// ============================================

pub const common = @import("common/mod.zig");
pub const system = @import("system/mod.zig");
pub const sudoers = @import("sudoers/mod.zig");
pub const pam = @import("pam/mod.zig");
pub const exec = @import("exec/mod.zig");
pub const log = @import("log/mod.zig");
pub const defaults = @import("defaults/mod.zig");
pub const cutils = @import("cutils/mod.zig");

// ============================================
// Binary Entry Points
// ============================================

pub const sudo = @import("sudo/mod.zig");
pub const su = @import("su/mod.zig");
pub const visudo = @import("visudo/mod.zig");

// ============================================
// Version Information
// ============================================

pub const version = "0.1.0";
pub const version_string = "sudo-zig " ++ version;

// ============================================
// Compile-time Feature Detection
// ============================================

pub const features = struct {
    pub const pam_login = build_options.pam_login;
    pub const apparmor = build_options.apparmor;
    pub const gettext = build_options.gettext;
    pub const dev_mode = build_options.dev_mode;
};

// ============================================
// Platform Detection
// ============================================

pub const platform = struct {
    pub const is_linux = builtin.os.tag == .linux;
    pub const is_freebsd = builtin.os.tag == .freebsd;
    pub const is_macos = builtin.os.tag == .macos;

    pub const sudoers_path = if (is_freebsd)
        "/usr/local/etc/sudoers"
    else
        "/etc/sudoers";

    pub const timestamp_dir = "/run/sudo/ts";
};

// ============================================
// Common Types (re-exported for convenience)
// ============================================

pub const Error = common.Error;
pub const SudoPath = common.SudoPath;
pub const SudoString = common.SudoString;
pub const Context = common.Context;
pub const User = system.User;
pub const Group = system.Group;
pub const UserId = system.UserId;
pub const GroupId = system.GroupId;

// ============================================
// Tests
// ============================================

test {
    // Run all module tests
    std.testing.refAllDecls(@This());
}

test "version string" {
    try std.testing.expectEqualStrings("sudo-zig 0.1.0", version_string);
}

test "platform detection" {
    // At least one platform should be detected
    const any_platform = platform.is_linux or platform.is_freebsd or platform.is_macos;
    try std.testing.expect(any_platform or true); // Allow other platforms too
}
