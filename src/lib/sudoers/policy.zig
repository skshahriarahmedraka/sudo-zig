//! Policy evaluation for sudoers
//!
//! This module checks if a user is authorized to run a command based on
//! the parsed sudoers rules.

const std = @import("std");
const ast = @import("ast.zig");
const system = @import("../system/mod.zig");
const common = @import("../common/mod.zig");

const Allocator = std.mem.Allocator;
const User = system.User;
const Group = system.Group;
const UserId = system.UserId;
const GroupId = system.GroupId;

// Network types for IP matching
const IPAddress = common.IPAddress;
const IPv4Address = common.IPv4Address;
const IPv4Network = common.IPv4Network;
const IPv6Network = common.IPv6Network;

// Digest verification
const DigestAlgorithm = common.DigestAlgorithm;
const Digest = common.Digest;
const verifyFileDigest = common.verifyFileDigest;

/// Authorization result from policy check
pub const Authorization = struct {
    allowed: bool = false,
    must_authenticate: bool = true,
    runas_user: ?UserId = null,
    runas_group: ?GroupId = null,
    flags: Flags = .{},

    pub const Flags = struct {
        nopasswd: bool = false,
        noexec: bool = false,
        setenv: bool = false,
    };

    /// Create a denied authorization
    pub fn denied() Authorization {
        return .{ .allowed = false };
    }

    /// Create an allowed authorization
    pub fn grant(runas_uid: UserId, require_auth: bool) Authorization {
        return .{
            .allowed = true,
            .must_authenticate = require_auth,
            .runas_user = runas_uid,
        };
    }
};

/// Request for authorization check
pub const AuthRequest = struct {
    /// User requesting sudo
    user: User,
    /// User's groups
    groups: []const GroupId,
    /// Hostname
    hostname: []const u8,
    /// Command to run (full path)
    command: []const u8,
    /// Command arguments (joined)
    arguments: ?[]const u8,
    /// Target user (default: root)
    target_user: ?[]const u8,
    /// Target group
    target_group: ?[]const u8,
};

/// Policy engine for checking sudoers permissions
pub const Policy = struct {
    sudoers: *const ast.Sudoers,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, sudoers: *const ast.Sudoers) Self {
        return .{
            .allocator = allocator,
            .sudoers = sudoers,
        };
    }

    /// Check if a request is authorized
    pub fn check(self: *Self, request: AuthRequest) Authorization {
        // Iterate through user specs in order (last match wins in sudo)
        var last_auth: ?Authorization = null;

        for (self.sudoers.user_specs.items) |*user_spec| {
            // Check if user matches
            if (!self.matchesUserList(&user_spec.users, request.user, request.groups)) {
                continue;
            }

            // Check host specs
            for (user_spec.host_specs.items) |*host_spec| {
                if (!self.matchesHostList(&host_spec.hosts, request.hostname)) {
                    continue;
                }

                // Check command specs
                for (host_spec.cmnd_specs.items) |*cmnd_spec| {
                    // Check runas user if specified
                    if (request.target_user) |target| {
                        if (!self.matchesRunasUser(cmnd_spec, target)) {
                            continue;
                        }
                    }

                    // Check runas group if specified
                    if (request.target_group) |target| {
                        if (!self.matchesRunasGroup(cmnd_spec, target)) {
                            continue;
                        }
                    }

                    // Check command
                    if (self.matchesCmndList(&cmnd_spec.commands, request.command, request.arguments)) |match| {
                        if (match.negated) {
                            // Negated match = explicit deny
                            last_auth = Authorization.denied();
                        } else {
                            // Positive match
                            const target_uid = self.resolveTargetUser(request.target_user);
                            last_auth = .{
                                .allowed = true,
                                .must_authenticate = cmnd_spec.tags.requiresPassword(),
                                .runas_user = target_uid,
                                .runas_group = self.resolveTargetGroup(request.target_group),
                                .flags = .{
                                    .nopasswd = !cmnd_spec.tags.requiresPassword(),
                                    .noexec = cmnd_spec.tags.isNoexec(),
                                    .setenv = cmnd_spec.tags.allowsSetenv(),
                                },
                            };
                        }
                    }
                }
            }
        }

        return last_auth orelse Authorization.denied();
    }

    /// Check if a user matches a user list
    fn matchesUserList(self: *Self, list: *const ast.UserList, user: User, groups: []const GroupId) bool {
        var matched = false;
        var negated = false;

        for (list.items.items) |item| {
            const item_matches = self.matchesUserItem(&item, user, groups);
            if (item_matches) {
                matched = true;
                negated = item.negated;
            }
        }

        // If last match was negated, user is excluded
        return matched and !negated;
    }

    /// Check if a user matches a single user item
    fn matchesUserItem(self: *Self, item: *const ast.UserItem, user: User, groups: []const GroupId) bool {
        return switch (item.value) {
            .all => true,
            .username => |name| std.mem.eql(u8, name, user.name),
            .uid => |uid| uid == user.uid,
            .groupname => |name| self.userInGroup(user, groups, name),
            .gid => |gid| self.userInGid(groups, gid),
            .alias => |alias_name| self.matchesUserAlias(alias_name, user, groups),
            .netgroup, .non_unix_group, .non_unix_gid => false, // Not implemented
        };
    }

    /// Check if user is in a named group
    fn userInGroup(self: *Self, user: User, user_groups: []const GroupId, groupname: []const u8) bool {
        _ = self;
        // Look up group by name
        if (Group.fromName(groupname)) |group| {
            // Check primary group
            if (user.gid == group.gid) return true;

            // Check supplementary groups
            for (user_groups) |gid| {
                if (gid == group.gid) return true;
            }
        }
        return false;
    }

    /// Check if user is in a group by GID
    fn userInGid(self: *Self, user_groups: []const GroupId, gid: GroupId) bool {
        _ = self;
        for (user_groups) |g| {
            if (g == gid) return true;
        }
        return false;
    }

    /// Check if user matches a User_Alias
    fn matchesUserAlias(self: *Self, alias_name: []const u8, user: User, groups: []const GroupId) bool {
        if (self.sudoers.aliases.user.get(alias_name)) |alias_list| {
            return self.matchesUserList(&alias_list, user, groups);
        }
        return false;
    }

    /// Check if hostname matches a host list
    fn matchesHostList(self: *Self, list: *const ast.HostList, hostname: []const u8) bool {
        var matched = false;
        var negated = false;

        for (list.items.items) |item| {
            const item_matches = self.matchesHostItem(&item, hostname);
            if (item_matches) {
                matched = true;
                negated = item.negated;
            }
        }

        return matched and !negated;
    }

    /// Check if hostname matches a single host item
    fn matchesHostItem(self: *Self, item: *const ast.HostItem, hostname: []const u8) bool {
        return switch (item.value) {
            .all => true,
            .hostname => |pattern| self.matchesHostname(pattern, hostname),
            .alias => |alias_name| self.matchesHostAlias(alias_name, hostname),
            .ip_addr => |ip_str| self.matchesIPAddress(ip_str, hostname),
            .ip_network => |net_str| self.matchesIPNetwork(net_str, hostname),
            .netgroup => false, // Netgroups not implemented (require NIS)
        };
    }

    /// Check if host matches an IP address
    fn matchesIPAddress(self: *Self, ip_str: []const u8, hostname: []const u8) bool {
        _ = self;
        // Parse the IP address from the rule
        const rule_ip = IPAddress.parse(ip_str) orelse return false;

        // First, try to parse hostname as an IP address directly
        if (IPAddress.parse(hostname)) |host_ip| {
            return rule_ip.eql(host_ip);
        }

        // Otherwise, need to resolve hostname to IP addresses
        // For now, try to get local addresses and match
        if (getLocalIPForHost(hostname)) |local_ip| {
            return rule_ip.eql(local_ip);
        }

        return false;
    }

    /// Check if host matches an IP network (CIDR)
    fn matchesIPNetwork(self: *Self, net_str: []const u8, hostname: []const u8) bool {
        _ = self;
        // Try IPv4 network first
        if (IPv4Network.parse(net_str)) |net| {
            // Try to parse hostname as IP
            if (IPAddress.parse(hostname)) |host_ip| {
                if (host_ip == .v4) {
                    return net.contains(host_ip.v4);
                }
            }
            // Try local addresses
            if (getLocalIPForHost(hostname)) |local_ip| {
                if (local_ip == .v4) {
                    return net.contains(local_ip.v4);
                }
            }
        }

        // Try IPv6 network
        if (IPv6Network.parse(net_str)) |net| {
            if (IPAddress.parse(hostname)) |host_ip| {
                if (host_ip == .v6) {
                    return net.contains(host_ip.v6);
                }
            }
            if (getLocalIPForHost(hostname)) |local_ip| {
                if (local_ip == .v6) {
                    return net.contains(local_ip.v6);
                }
            }
        }

        return false;
    }

    /// Match hostname with wildcard support
    fn matchesHostname(self: *Self, pattern: []const u8, hostname: []const u8) bool {
        _ = self;
        // Simple exact match or wildcard
        if (std.mem.eql(u8, pattern, hostname)) return true;

        // Support simple * wildcard at start/end
        if (pattern.len > 0 and pattern[0] == '*') {
            return std.mem.endsWith(u8, hostname, pattern[1..]);
        }
        if (pattern.len > 0 and pattern[pattern.len - 1] == '*') {
            return std.mem.startsWith(u8, hostname, pattern[0 .. pattern.len - 1]);
        }

        return false;
    }

    /// Check if hostname matches a Host_Alias
    fn matchesHostAlias(self: *Self, alias_name: []const u8, hostname: []const u8) bool {
        if (self.sudoers.aliases.host.get(alias_name)) |alias_list| {
            return self.matchesHostList(&alias_list, hostname);
        }
        return false;
    }

    /// Check if runas user is allowed
    fn matchesRunasUser(self: *Self, cmnd_spec: *const ast.CmndSpec, target_user: []const u8) bool {
        if (cmnd_spec.runas) |runas| {
            if (runas.users) |users| {
                for (users.items.items) |item| {
                    const matches = switch (item.value) {
                        .all => true,
                        .username => |name| std.mem.eql(u8, name, target_user),
                        .uid => |uid| blk: {
                            if (User.fromName(target_user)) |user| {
                                break :blk uid == user.uid;
                            }
                            break :blk false;
                        },
                        .alias => |alias_name| self.matchesRunasUserAlias(alias_name, target_user),
                        else => false,
                    };
                    if (matches and !item.negated) return true;
                    if (matches and item.negated) return false;
                }
                return false;
            }
        }
        // No runas specified means root only
        return std.mem.eql(u8, target_user, "root");
    }

    fn matchesRunasUserAlias(self: *Self, alias_name: []const u8, target_user: []const u8) bool {
        if (self.sudoers.aliases.runas.get(alias_name)) |alias_list| {
            for (alias_list.items.items) |item| {
                const matches = switch (item.value) {
                    .all => true,
                    .username => |name| std.mem.eql(u8, name, target_user),
                    else => false,
                };
                if (matches and !item.negated) return true;
            }
        }
        return false;
    }

    /// Check if runas group is allowed
    fn matchesRunasGroup(_: *Self, cmnd_spec: *const ast.CmndSpec, target_group: []const u8) bool {
        if (cmnd_spec.runas) |runas| {
            if (runas.groups) |groups| {
                for (groups.items.items) |item| {
                    const matches = switch (item.value) {
                        .all => true,
                        .groupname => |name| std.mem.eql(u8, name, target_group),
                        .gid => |gid| blk: {
                            if (Group.fromName(target_group)) |group| {
                                break :blk gid == group.gid;
                            }
                            break :blk false;
                        },
                        else => false,
                    };
                    if (matches and !item.negated) return true;
                    if (matches and item.negated) return false;
                }
                return false;
            }
        }
        // No group specified = not allowed to specify a group
        return false;
    }

    /// Match result for command list
    const CmndMatch = struct {
        negated: bool,
    };

    /// Check if command matches a command list
    fn matchesCmndList(self: *Self, list: *const ast.CmndList, command: []const u8, arguments: ?[]const u8) ?CmndMatch {
        var last_match: ?CmndMatch = null;

        for (list.items.items) |item| {
            if (self.matchesCmndItem(&item, command, arguments)) {
                last_match = .{ .negated = item.negated };
            }
        }

        return last_match;
    }

    /// Check if command matches a single command item
    fn matchesCmndItem(self: *Self, item: *const ast.CmndItem, command: []const u8, arguments: ?[]const u8) bool {
        return switch (item.value) {
            .all => true,
            .command => |cmd| self.matchesCommand(&cmd, command, arguments),
            .alias => |alias_name| self.matchesCmndAlias(alias_name, command, arguments),
            .sudoedit => false, // Handle separately
        };
    }

    /// Check if a command matches a command pattern
    fn matchesCommand(self: *Self, cmd: *const ast.Command, command: []const u8, arguments: ?[]const u8) bool {
        _ = self;
        // Check path (support wildcards)
        if (!matchPath(cmd.path, command)) {
            return false;
        }

        // Verify digest if specified in the rule
        if (cmd.digest) |digest| {
            // Convert ast.DigestAlgorithm to common.digest.DigestAlgorithm
            const algo: common.DigestAlgorithm = switch (digest.algorithm) {
                .sha224 => .sha224,
                .sha256 => .sha256,
                .sha384 => .sha384,
                .sha512 => .sha512,
            };
            const digest_valid = verifyFileDigest(command, .{
                .algorithm = algo,
                .hash = digest.hash,
            }) catch false;

            if (!digest_valid) {
                // Digest mismatch - command binary has been modified
                return false;
            }
        }

        // Check arguments if specified in rule
        if (cmd.args) |rule_args| {
            if (rule_args.len == 0) {
                // Empty args in rule means NO arguments allowed
                return arguments == null or arguments.?.len == 0;
            }
            // Rule specifies arguments - must match
            const actual_args = arguments orelse "";
            return matchArgs(rule_args, actual_args);
        }

        // No args specified in rule means any arguments allowed
        return true;
    }

    fn matchesCmndAlias(self: *Self, alias_name: []const u8, command: []const u8, arguments: ?[]const u8) bool {
        if (self.sudoers.aliases.cmnd.get(alias_name)) |alias_list| {
            if (self.matchesCmndList(&alias_list, command, arguments)) |_| {
                return true;
            }
        }
        return false;
    }

    /// Resolve target user to UID
    fn resolveTargetUser(self: *Self, target_user: ?[]const u8) ?UserId {
        _ = self;
        const username = target_user orelse "root";
        if (User.fromName(username)) |user| {
            return user.uid;
        }
        // Could be a UID directly
        if (std.fmt.parseInt(UserId, username, 10)) |uid| {
            return uid;
        } else |_| {}
        return null;
    }

    /// Resolve target group to GID
    fn resolveTargetGroup(self: *Self, target_group: ?[]const u8) ?GroupId {
        _ = self;
        const groupname = target_group orelse return null;
        if (Group.fromName(groupname)) |group| {
            return group.gid;
        }
        // Could be a GID directly
        if (std.fmt.parseInt(GroupId, groupname, 10)) |gid| {
            return gid;
        } else |_| {}
        return null;
    }
};

/// Try to get a local IP address for hostname matching
/// This is a simplified version - in production would use getaddrinfo
fn getLocalIPForHost(hostname: []const u8) ?IPAddress {
    _ = hostname;
    // In a real implementation, this would:
    // 1. Check if hostname matches the local hostname
    // 2. If so, return one of the local IP addresses
    // 3. Otherwise, resolve hostname via DNS
    // For now, return null and rely on direct IP matching
    return null;
}

/// Match a command path with wildcard support
fn matchPath(pattern: []const u8, path: []const u8) bool {
    // Exact match
    if (std.mem.eql(u8, pattern, path)) return true;

    // Wildcard matching
    return globMatch(pattern, path);
}

/// Match arguments with wildcard support
fn matchArgs(pattern: []const u8, args: []const u8) bool {
    if (std.mem.eql(u8, pattern, args)) return true;
    if (std.mem.eql(u8, pattern, "*")) return true;
    return globMatch(pattern, args);
}

/// Simple glob matching (* and ?)
fn globMatch(pattern: []const u8, string: []const u8) bool {
    var p_idx: usize = 0;
    var s_idx: usize = 0;
    var star_idx: ?usize = null;
    var match_idx: usize = 0;

    while (s_idx < string.len) {
        if (p_idx < pattern.len and (pattern[p_idx] == '?' or pattern[p_idx] == string[s_idx])) {
            p_idx += 1;
            s_idx += 1;
        } else if (p_idx < pattern.len and pattern[p_idx] == '*') {
            star_idx = p_idx;
            match_idx = s_idx;
            p_idx += 1;
        } else if (star_idx != null) {
            p_idx = star_idx.? + 1;
            match_idx += 1;
            s_idx = match_idx;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.len and pattern[p_idx] == '*') {
        p_idx += 1;
    }

    return p_idx == pattern.len;
}

// ============================================
// Tests
// ============================================

test "globMatch exact" {
    try std.testing.expect(globMatch("hello", "hello"));
    try std.testing.expect(!globMatch("hello", "world"));
}

test "globMatch wildcard star" {
    try std.testing.expect(globMatch("*", "anything"));
    try std.testing.expect(globMatch("hello*", "hello world"));
    try std.testing.expect(globMatch("*world", "hello world"));
    try std.testing.expect(globMatch("h*d", "hello world"));
    try std.testing.expect(!globMatch("hello*", "goodbye"));
}

test "globMatch wildcard question" {
    try std.testing.expect(globMatch("h?llo", "hello"));
    try std.testing.expect(globMatch("h?llo", "hallo"));
    try std.testing.expect(!globMatch("h?llo", "hllo"));
}

test "Authorization denied" {
    const auth = Authorization.denied();
    try std.testing.expect(!auth.allowed);
}

test "Authorization grant" {
    const auth = Authorization.grant(0, true);
    try std.testing.expect(auth.allowed);
    try std.testing.expect(auth.must_authenticate);
    try std.testing.expectEqual(@as(?UserId, 0), auth.runas_user);
}
