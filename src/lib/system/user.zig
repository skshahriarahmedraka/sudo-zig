//! User and group management
//!
//! Provides interfaces for looking up users and groups from the system
//! password and group databases.

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
pub const User = struct {
    uid: UserId,
    gid: GroupId,
    name: []const u8,
    home: []const u8,
    shell: []const u8,
    gecos: []const u8,
    
    // Storage for string data (when looked up from system)
    _name_buf: [256]u8 = undefined,
    _home_buf: [256]u8 = undefined,
    _shell_buf: [256]u8 = undefined,
    _gecos_buf: [256]u8 = undefined,

    const Self = @This();

    /// Get the effective user ID of the current process.
    pub fn effectiveUid() UserId {
        return posix.geteuid();
    }

    /// Get the real user ID of the current process.
    pub fn realUid() UserId {
        return posix.getuid();
    }

    /// Check if this user is root.
    pub fn isRoot(self: Self) bool {
        return self.uid == ROOT_UID;
    }

    /// Look up a user by UID from the passwd database.
    pub fn fromUid(uid: UserId) ?Self {
        const pwd = c.getpwuid(uid);
        if (pwd == null) return null;
        return fromPasswd(pwd);
    }

    /// Look up a user by name from the passwd database.
    pub fn fromName(name: []const u8) ?Self {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (name.len >= name_buf.len) return null;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;

        const pwd = c.getpwnam(&name_buf);
        if (pwd == null) return null;
        return fromPasswd(pwd);
    }

    /// Create a User from a C passwd struct, copying strings into internal buffers.
    fn fromPasswd(pwd: *const c.struct_passwd) Self {
        var user = Self{
            .uid = @intCast(pwd.pw_uid),
            .gid = @intCast(pwd.pw_gid),
            .name = "",
            .home = "",
            .shell = "",
            .gecos = "",
        };

        // Copy name
        if (pwd.pw_name) |name_ptr| {
            const name = std.mem.span(name_ptr);
            const len = @min(name.len, user._name_buf.len - 1);
            @memcpy(user._name_buf[0..len], name[0..len]);
            user.name = user._name_buf[0..len];
        }

        // Copy home directory
        if (pwd.pw_dir) |dir_ptr| {
            const dir = std.mem.span(dir_ptr);
            const len = @min(dir.len, user._home_buf.len - 1);
            @memcpy(user._home_buf[0..len], dir[0..len]);
            user.home = user._home_buf[0..len];
        }

        // Copy shell
        if (pwd.pw_shell) |shell_ptr| {
            const shell = std.mem.span(shell_ptr);
            const len = @min(shell.len, user._shell_buf.len - 1);
            @memcpy(user._shell_buf[0..len], shell[0..len]);
            user.shell = user._shell_buf[0..len];
        }

        // Copy gecos
        if (pwd.pw_gecos) |gecos_ptr| {
            const gecos = std.mem.span(gecos_ptr);
            const len = @min(gecos.len, user._gecos_buf.len - 1);
            @memcpy(user._gecos_buf[0..len], gecos[0..len]);
            user.gecos = user._gecos_buf[0..len];
        }

        return user;
    }

    /// Get supplementary groups for this user.
    pub fn getGroups(self: Self, groups_buf: []GroupId) ![]GroupId {
        var ngroups: c_int = @intCast(groups_buf.len);
        
        // Create null-terminated name
        var name_buf: [256:0]u8 = undefined;
        if (self.name.len >= name_buf.len) return error.NameTooLong;
        @memcpy(name_buf[0..self.name.len], self.name);
        name_buf[self.name.len] = 0;

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
pub const Group = struct {
    gid: GroupId,
    name: []const u8,
    
    // Storage for string data
    _name_buf: [256]u8 = undefined,

    const Self = @This();

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

    /// Look up a group by name from the group database.
    pub fn fromName(name: []const u8) ?Self {
        // Create null-terminated string
        var name_buf: [256:0]u8 = undefined;
        if (name.len >= name_buf.len) return null;
        @memcpy(name_buf[0..name.len], name);
        name_buf[name.len] = 0;

        const grp = c.getgrnam(&name_buf);
        if (grp == null) return null;
        return fromGrp(grp);
    }

    /// Create a Group from a C group struct.
    fn fromGrp(grp: *const c.struct_group) Self {
        var group = Self{
            .gid = @intCast(grp.gr_gid),
            .name = "",
        };

        // Copy name
        if (grp.gr_name) |name_ptr| {
            const name = std.mem.span(name_ptr);
            const len = @min(name.len, group._name_buf.len - 1);
            @memcpy(group._name_buf[0..len], name[0..len]);
            group.name = group._name_buf[0..len];
        }

        return group;
    }

    /// Check if a user is a member of this group.
    pub fn hasMember(self: Self, username: []const u8) bool {
        // Look up group again to get member list
        var name_buf: [256:0]u8 = undefined;
        if (self.name.len >= name_buf.len) return false;
        @memcpy(name_buf[0..self.name.len], self.name);
        name_buf[self.name.len] = 0;

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
        try std.testing.expectEqualStrings("root", root_user.name);
    }
}

test "User.fromName root" {
    if (User.fromName("root")) |root_user| {
        try std.testing.expectEqual(@as(UserId, 0), root_user.uid);
        try std.testing.expectEqualStrings("root", root_user.name);
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
