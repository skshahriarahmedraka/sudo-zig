//! Unit tests for system user and group management
//!
//! Tests for user/group lookup and related functionality.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const system = lib.system;
const User = system.User;
const Group = system.Group;
const UserId = system.UserId;
const GroupId = system.GroupId;

// ============================================
// User Tests
// ============================================

test "User.effectiveUid returns a valid uid" {
    const uid = User.effectiveUid();
    // Just verify it returns without error
    _ = uid;
}

test "User.realUid returns a valid uid" {
    const uid = User.realUid();
    _ = uid;
}

test "User.fromUid for root (uid 0)" {
    // Root user should always exist
    if (User.fromUid(0)) |root_user| {
        try testing.expectEqual(@as(UserId, 0), root_user.uid);
        try testing.expectEqualStrings("root", root_user.getName());
        try testing.expect(root_user.isRoot());
    }
}

test "User.fromUid for nonexistent uid" {
    // Very high UID that probably doesn't exist
    const result = User.fromUid(999999);
    // May or may not exist depending on system
    _ = result;
}

test "User.fromName for root" {
    if (User.fromName("root")) |root_user| {
        try testing.expectEqual(@as(UserId, 0), root_user.uid);
        try testing.expectEqualStrings("root", root_user.getName());
        try testing.expect(root_user.getHome().len > 0);
        try testing.expect(root_user.getShell().len > 0);
    }
}

test "User.fromName for nonexistent user" {
    const result = User.fromName("this_user_definitely_does_not_exist_12345");
    try testing.expectEqual(@as(?User, null), result);
}

test "User.fromName with empty string" {
    const result = User.fromName("");
    try testing.expectEqual(@as(?User, null), result);
}

test "User.isRoot" {
    if (User.fromUid(0)) |root_user| {
        try testing.expect(root_user.isRoot());
    }
    
    // Non-root user (if we're not running as root)
    const current_uid = User.realUid();
    if (current_uid != 0) {
        if (User.fromUid(current_uid)) |current_user| {
            try testing.expect(!current_user.isRoot());
        }
    }
}

test "User has home directory" {
    if (User.fromName("root")) |root_user| {
        try testing.expect(root_user.getHome().len > 0);
        // Root's home is typically /root or /var/root
        try testing.expect(root_user.getHome()[0] == '/');
    }
}

test "User has shell" {
    if (User.fromName("root")) |root_user| {
        try testing.expect(root_user.getShell().len > 0);
        try testing.expect(root_user.getShell()[0] == '/');
    }
}

// ============================================
// Group Tests
// ============================================

test "Group.effectiveGid returns a valid gid" {
    const gid = Group.effectiveGid();
    _ = gid;
}

test "Group.realGid returns a valid gid" {
    const gid = Group.realGid();
    _ = gid;
}

test "Group.fromGid for root group (gid 0)" {
    if (Group.fromGid(0)) |root_group| {
        try testing.expectEqual(@as(GroupId, 0), root_group.gid);
        // Name might be "root" or "wheel" depending on system
        try testing.expect(root_group.getName().len > 0);
    }
}

test "Group.fromGid for nonexistent gid" {
    const result = Group.fromGid(999999);
    // May or may not exist depending on system
    _ = result;
}

test "Group.fromName for root" {
    // Try both "root" and "wheel" as different systems use different names
    if (Group.fromName("root")) |group| {
        try testing.expectEqual(@as(GroupId, 0), group.gid);
    } else if (Group.fromName("wheel")) |group| {
        // wheel is often gid 0 on BSD systems
        _ = group;
    }
}

test "Group.fromName for nonexistent group" {
    const result = Group.fromName("this_group_definitely_does_not_exist_12345");
    try testing.expectEqual(@as(?Group, null), result);
}

// ============================================
// User Groups Tests
// ============================================

test "User.getGroups returns at least primary group" {
    if (User.fromName("root")) |root_user| {
        var groups_buf: [64]GroupId = undefined;
        if (root_user.getGroups(&groups_buf)) |groups| {
            try testing.expect(groups.len >= 1);
            // Primary group should be included
            var found_primary = false;
            for (groups) |gid| {
                if (gid == root_user.gid) {
                    found_primary = true;
                    break;
                }
            }
            try testing.expect(found_primary);
        } else |_| {
            // getGroups might fail on some systems
        }
    }
}

// ============================================
// Constants Tests
// ============================================

test "ROOT_UID is 0" {
    try testing.expectEqual(@as(UserId, 0), system.user.ROOT_UID);
}

test "ROOT_GID is 0" {
    try testing.expectEqual(@as(GroupId, 0), system.user.ROOT_GID);
}

test "MAX_GROUPS is reasonable" {
    try testing.expect(system.user.MAX_GROUPS >= 16);
    try testing.expect(system.user.MAX_GROUPS <= 256);
}
