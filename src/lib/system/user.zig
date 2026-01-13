//! User and group management
//!
//! Provides interfaces for looking up users and groups from the system
//! password and group databases.
//!
//! IMPORTANT: The User struct stores string data in fixed internal buffers.
//! The public slice fields (name, home, shell, gecos) are computed on-demand
//! via getter methods to avoid dangling pointer issues when the struct is copied.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

// C library imports for passwd/group database access
const c = @cImport({
    @cInclude("pwd.h");
    @cInclude("grp.h");
    @cInclude("unistd.h");
});

/// User ID type (uid_t equivalent)
pub const UserId = u32;

/// Group ID type (gid_t equivalent)
pub const GroupId = u32;

/// Root user ID
pub const ROOT_UID: UserId = 0;

/// Root group ID
pub const ROOT_GID: GroupId = 0;

/// Maximum number of supplementary groups
pub const MAX_GROUPS: usize = 64;

/// User information from passwd database.
/// 
/// This struct stores all string data in fixed-size internal buffers.
/// Use the getter methods (getName(), getHome(), etc.) to safely access
/// string data - these always return valid slices into this struct's own buffers.
pub const User = struct {
    uid: UserId,
    gid: GroupId,

    // Storage for string data with lengths
    _name_buf: [256]u8 = undefined,
    _home_buf: [256]u8 = undefined,
    _shell_buf: [256]u8 = undefined,
    _gecos_buf: [256]u8 = undefined,
    _name_len: usize = 0,
    _home_len: usize = 0,
    _shell_len: usize = 0,
    _gecos_len: usize = 0,

    const Self = @This();

    /// Get the user's name. Always returns a valid slice into this struct's buffer.
    pub fn getName(self: *const Self) []const u8 {
        return self._name_buf[0..self._name_len];
    }

    /// Get the user's home directory. Always returns a valid slice into this struct's buffer.
    pub fn getHome(self: *const Self) []const u8 {
        return self._home_buf[0..self._home_len];
    }

    /// Get the user's shell. Always returns a valid slice into this struct's buffer.
    pub fn getShell(self: *const Self) []const u8 {
        return self._shell_buf[0..self._shell_len];
    }

    /// Get the user's GECOS field. Always returns a valid slice into this struct's buffer.
    pub fn getGecos(self: *const Self) []const u8 {
        return self._gecos_buf[0..self._gecos_len];
    }


    /// Get the effective user ID of the current process.
    pub fn effectiveUid() UserId {
        return posix.geteuid();
    }

    /// Get the real user ID of the current process.
    pub fn realUid() UserId {
        return posix.getuid();
    }

    /// Check if this user is root.
    pub fn isRoot(self: *const Self) bool {
        return self.uid == ROOT_UID;
    }

    /// Look up a user by UID from the passwd database.
    /// Returns null if user not found.
    pub fn fromUid(uid: UserId) ?Self {
        const pwd = c.getpwuid(uid);
        if (pwd == null) return null;
        return fromPasswd(pwd);
    }

    /// Look up a user by UID and write it into `out`.
    /// Returns true on success, false if user not found.
    pub fn fromUidInto(uid: UserId, out: *Self) bool {
        const pwd = c.getpwuid(uid);
        if (pwd == null) return false;
        out.* = fromPasswd(pwd);
        return true;
    }

    /// Look up a user by name from the passwd database.
    /// Returns null if user not found.
    pub fn fromName(lookup_name: []const u8) ?Self {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (lookup_name.len >= name_buf.len) return null;
        @memcpy(name_buf[0..lookup_name.len], lookup_name);
        name_buf[lookup_name.len] = 0;

        const pwd = c.getpwnam(&name_buf);
        if (pwd == null) return null;
        return fromPasswd(pwd);
    }

    /// Look up a user by name and write it into `out`.
    /// Returns true on success, false if user not found.
    pub fn fromNameInto(lookup_name: []const u8, out: *Self) bool {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (lookup_name.len >= name_buf.len) return false;
        @memcpy(name_buf[0..lookup_name.len], lookup_name);
        name_buf[lookup_name.len] = 0;

        const pwd = c.getpwnam(&name_buf);
        if (pwd == null) return false;
        out.* = fromPasswd(pwd);
        return true;
    }

    /// Create a User from a C passwd struct, copying strings into internal buffers.
    fn fromPasswd(pwd: *const c.struct_passwd) Self {
        var user = Self{
            .uid = @intCast(pwd.pw_uid),
            .gid = @intCast(pwd.pw_gid),
            ._name_len = 0,
            ._home_len = 0,
            ._shell_len = 0,
            ._gecos_len = 0,
        };

        // Copy name
        if (pwd.pw_name) |name_ptr| {
            const src = std.mem.span(name_ptr);
            const len = @min(src.len, user._name_buf.len - 1);
            @memcpy(user._name_buf[0..len], src[0..len]);
            user._name_len = len;
        }

        // Copy home directory
        if (pwd.pw_dir) |dir_ptr| {
            const src = std.mem.span(dir_ptr);
            const len = @min(src.len, user._home_buf.len - 1);
            @memcpy(user._home_buf[0..len], src[0..len]);
            user._home_len = len;
        }

        // Copy shell
        if (pwd.pw_shell) |shell_ptr| {
            const src = std.mem.span(shell_ptr);
            const len = @min(src.len, user._shell_buf.len - 1);
            @memcpy(user._shell_buf[0..len], src[0..len]);
            user._shell_len = len;
        }

        // Copy gecos
        if (pwd.pw_gecos) |gecos_ptr| {
            const src = std.mem.span(gecos_ptr);
            const len = @min(src.len, user._gecos_buf.len - 1);
            @memcpy(user._gecos_buf[0..len], src[0..len]);
            user._gecos_len = len;
        }

        return user;
    }

    /// Get supplementary groups for this user.
    pub fn getGroups(self: *const Self, groups_buf: []GroupId) ![]GroupId {
        var ngroups: c_int = @intCast(groups_buf.len);

        // Create null-terminated name
        var name_buf: [256:0]u8 = undefined;
        const user_name = self.getName();
        if (user_name.len >= name_buf.len) return error.NameTooLong;
        @memcpy(name_buf[0..user_name.len], user_name);
        name_buf[user_name.len] = 0;

        // getgrouplist wants a pointer to c_int array
        var c_groups: [MAX_GROUPS]c.gid_t = undefined;

        const result = c.getgrouplist(
            &name_buf,
            @intCast(self.gid),
            &c_groups,
            &ngroups,
        );

        if (result < 0) {
            // Buffer too small, ngroups now contains required size
            return error.BufferTooSmall;
        }

        // Copy to output buffer
        const count: usize = @intCast(ngroups);
        const actual_count = @min(count, groups_buf.len);
        for (0..actual_count) |i| {
            groups_buf[i] = @intCast(c_groups[i]);
        }

        return groups_buf[0..actual_count];
    }
};

/// Group information from group database.
/// 
/// This struct stores string data in fixed-size internal buffers.
/// Use the getter method (getName()) to safely access string data.
pub const Group = struct {
    gid: GroupId,

    // Storage for string data with length
    _name_buf: [256]u8 = undefined,
    _name_len: usize = 0,

    const Self = @This();

    /// Get the group's name. Always returns a valid slice into this struct's buffer.
    pub fn getName(self: *const Self) []const u8 {
        return self._name_buf[0..self._name_len];
    }

    /// Get the effective group ID of the current process.
    pub fn effectiveGid() GroupId {
        return @intCast(c.getegid());
    }

    /// Get the real group ID of the current process.
    pub fn realGid() GroupId {
        return @intCast(c.getgid());
    }

    /// Look up a group by GID from the group database.
    pub fn fromGid(gid: GroupId) ?Self {
        const grp = c.getgrgid(gid);
        if (grp == null) return null;
        return fromGrp(grp);
    }

    pub fn fromGidInto(gid: GroupId, out: *Self) bool {
        const grp = c.getgrgid(gid);
        if (grp == null) return false;
        out.* = fromGrp(grp);
        return true;
    }

    /// Look up a group by name from the group database.
    pub fn fromName(lookup_name: []const u8) ?Self {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (lookup_name.len >= name_buf.len) return null;
        @memcpy(name_buf[0..lookup_name.len], lookup_name);
        name_buf[lookup_name.len] = 0;

        const grp = c.getgrnam(&name_buf);
        if (grp == null) return null;
        return fromGrp(grp);
    }

    pub fn fromNameInto(lookup_name: []const u8, out: *Self) bool {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (lookup_name.len >= name_buf.len) return false;
        @memcpy(name_buf[0..lookup_name.len], lookup_name);
        name_buf[lookup_name.len] = 0;

        const grp = c.getgrnam(&name_buf);
        if (grp == null) return false;
        out.* = fromGrp(grp);
        return true;
    }

    /// Create a Group from a C group struct.
    fn fromGrp(grp: *const c.struct_group) Self {
        var group = Self{
            .gid = @intCast(grp.gr_gid),
            ._name_len = 0,
        };

        // Copy name
        if (grp.gr_name) |name_ptr| {
            const src = std.mem.span(name_ptr);
            const len = @min(src.len, group._name_buf.len - 1);
            @memcpy(group._name_buf[0..len], src[0..len]);
            group._name_len = len;
        }

        return group;
    }

    /// Check if a user is a member of this group.
    pub fn hasMember(self: *const Self, username: []const u8) bool {
        // Look up group again to get member list
        var name_buf: [256:0]u8 = undefined;
        const group_name = self.getName();
        if (group_name.len >= name_buf.len) return false;
        @memcpy(name_buf[0..group_name.len], group_name);
        name_buf[group_name.len] = 0;

        const grp = c.getgrnam(&name_buf);
        if (grp == null) return false;

        // Check members
        if (grp.*.gr_mem) |members| {
            var i: usize = 0;
            while (members[i] != null) : (i += 1) {
                const member = std.mem.span(members[i].?);
                if (std.mem.eql(u8, member, username)) {
                    return true;
                }
            }
        }

        return false;
    }
};

// ============================================
// Tests
// ============================================

test "User.effectiveUid" {
    const uid = User.effectiveUid();
    // Should return something (we can't know what without root)
    _ = uid;
}

test "User.realUid" {
    const uid = User.realUid();
    _ = uid;
}

test "User.fromUid root" {
    // Root user should always exist
    if (User.fromUid(0)) |root_user| {
        try std.testing.expectEqual(@as(UserId, 0), root_user.uid);
        try std.testing.expectEqualStrings("root", root_user.getName());
    }
}

test "User.fromName root" {
    if (User.fromName("root")) |root_user| {
        try std.testing.expectEqual(@as(UserId, 0), root_user.uid);
        try std.testing.expectEqualStrings("root", root_user.getName());
    }
}

test "User.fromName nonexistent" {
    const user = User.fromName("this_user_should_not_exist_12345");
    try std.testing.expectEqual(@as(?User, null), user);
}

test "Group.effectiveGid" {
    const gid = Group.effectiveGid();
    _ = gid;
}

test "Group.fromGid root" {
    // Root group (gid 0) should always exist
    if (Group.fromGid(0)) |root_group| {
        try std.testing.expectEqual(@as(GroupId, 0), root_group.gid);
    }
}

test "Group.fromName" {
    // Try to look up "root" group (common on most systems)
    if (Group.fromName("root")) |root_group| {
        try std.testing.expectEqual(@as(GroupId, 0), root_group.gid);
    }
}
