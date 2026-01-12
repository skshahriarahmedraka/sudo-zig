//! System interfaces for sudo-zig
//!
//! Provides abstractions over system calls and OS-level operations:
//! - User and group management
//! - Process management
//! - Signal handling
//! - AppArmor integration

const std = @import("std");
const posix = std.posix;

pub const user = @import("user.zig");
pub const process = @import("process.zig");
pub const signal = @import("signal.zig");
pub const timestamp = @import("timestamp.zig");
pub const apparmor = @import("apparmor.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const selinux = @import("selinux.zig");
pub const seccomp = @import("seccomp.zig");

// Re-export main types
pub const User = user.User;
pub const Group = user.Group;
pub const UserId = user.UserId;
pub const GroupId = user.GroupId;
pub const Process = process.Process;
pub const Signal = signal.Signal;
pub const SignalSet = signal.SignalSet;
pub const waitpid = process.waitpid;
pub const WaitResult = process.WaitResult;
pub const TimestampFile = timestamp.TimestampFile;
pub const checkCredentials = timestamp.checkCredentials;
pub const updateCredentials = timestamp.updateCredentials;
pub const resetCredentials = timestamp.resetCredentials;
pub const removeCredentials = timestamp.removeCredentials;

// AppArmor types
pub const AppArmorContext = apparmor.AppArmorContext;
pub const AppArmorError = apparmor.AppArmorError;
pub const ProfileMode = apparmor.ProfileMode;
pub const ConfinementInfo = apparmor.ConfinementInfo;
pub const isAppArmorEnabled = apparmor.isEnabled;
pub const changeAppArmorProfile = apparmor.changeProfile;
pub const setAppArmorExecProfile = apparmor.setExecProfile;

// Rate limiting types
pub const RateLimiter = rate_limit.RateLimiter;
pub const RateLimitConfig = rate_limit.Config;
pub const RateLimitCheckResult = rate_limit.CheckResult;
pub const applyRateLimitDelay = rate_limit.applyDelay;

// SELinux types
pub const SELinuxContext = selinux.SELinuxContext;
pub const SecurityContext = selinux.SecurityContext;
pub const SELinuxMode = selinux.Mode;
pub const isSELinuxEnabled = selinux.isEnabled;
pub const getSELinuxMode = selinux.getMode;
pub const setupSudoSELinuxContext = selinux.setupSudoContext;
pub const cleanupSudoSELinuxContext = selinux.cleanupSudoContext;

// Seccomp types
pub const SeccompFilter = seccomp.SeccompFilter;
pub const SeccompProfile = seccomp.Profile;
pub const SeccompAction = seccomp.Action;
pub const SeccompSyscall = seccomp.Syscall;
pub const isSeccompAvailable = seccomp.isAvailable;

/// Hostname buffer type with reasonable size.
pub const Hostname = struct {
    buffer: [64]u8 = undefined,
    len: usize = 0,

    const Self = @This();

    pub fn get() !Self {
        var self = Self{};
        var buf: [64]u8 = undefined;
        const result = posix.gethostname(&buf);
        const name = result catch return error.SystemError;
        self.len = name.len;
        @memcpy(self.buffer[0..name.len], name);
        return self;
    }

    pub fn slice(self: *const Self) []const u8 {
        return self.buffer[0..self.len];
    }
};

// ============================================
// Tests
// ============================================

test {
    std.testing.refAllDecls(@This());
}
