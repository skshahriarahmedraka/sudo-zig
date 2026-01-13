//! Abstract Syntax Tree for sudoers files
//!
//! This module defines the data structures that represent a parsed sudoers file.
//! The AST is designed to closely follow the sudoers grammar.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================
// Top-level Structure
// ============================================

/// Include directive type
pub const IncludeDirective = struct {
    path: []const u8,
    is_directory: bool, // true for @includedir, false for @include
};

/// A complete parsed sudoers file
pub const Sudoers = struct {
    allocator: Allocator,
    defaults: std.ArrayListUnmanaged(Default),
    aliases: Aliases,
    user_specs: std.ArrayListUnmanaged(UserSpec),
    includes: std.ArrayListUnmanaged(IncludeDirective),
    /// Source buffers that back all string slices in the AST.
    /// These must be kept alive for the lifetime of the Sudoers struct.
    source_buffers: std.ArrayListUnmanaged([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .defaults = .{},
            .aliases = Aliases.init(allocator),
            .user_specs = .{},
            .includes = .{},
            .source_buffers = .{},
        };
    }

    /// Add a source buffer to be owned by this Sudoers struct.
    /// The buffer will be freed when Sudoers.deinit() is called.
    pub fn addSourceBuffer(self: *Self, source: []const u8) !void {
        try self.source_buffers.append(self.allocator, source);
    }

    pub fn deinit(self: *Self) void {
        for (self.defaults.items) |*default| {
            default.deinit(self.allocator);
        }
        self.defaults.deinit(self.allocator);

        self.aliases.deinit();

        for (self.user_specs.items) |*spec| {
            spec.deinit(self.allocator);
        }
        self.user_specs.deinit(self.allocator);
        
        self.includes.deinit(self.allocator);

        // Free all source buffers that back string slices in the AST
        for (self.source_buffers.items) |source| {
            self.allocator.free(source);
        }
        self.source_buffers.deinit(self.allocator);
    }

    /// Add a default setting
    pub fn addDefault(self: *Self, default: Default) !void {
        try self.defaults.append(self.allocator, default);
    }

    /// Add a user specification
    pub fn addUserSpec(self: *Self, spec: UserSpec) !void {
        try self.user_specs.append(self.allocator, spec);
    }

    /// Add an include directive
    pub fn addInclude(self: *Self, include: IncludeDirective) !void {
        try self.includes.append(self.allocator, include);
    }
};

/// Container for all alias types
pub const Aliases = struct {
    allocator: Allocator,
    user: std.StringHashMap(UserList),
    host: std.StringHashMap(HostList),
    cmnd: std.StringHashMap(CmndList),
    runas: std.StringHashMap(RunasList),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .user = std.StringHashMap(UserList).init(allocator),
            .host = std.StringHashMap(HostList).init(allocator),
            .cmnd = std.StringHashMap(CmndList).init(allocator),
            .runas = std.StringHashMap(RunasList).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var user_iter = self.user.iterator();
        while (user_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.user.deinit();

        var host_iter = self.host.iterator();
        while (host_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.host.deinit();

        var cmnd_iter = self.cmnd.iterator();
        while (cmnd_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.cmnd.deinit();

        var runas_iter = self.runas.iterator();
        while (runas_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.runas.deinit();
    }

    pub fn addUserAlias(self: *Self, name: []const u8, members: UserList) !void {
        try self.user.put(name, members);
    }

    pub fn addHostAlias(self: *Self, name: []const u8, members: HostList) !void {
        try self.host.put(name, members);
    }

    pub fn addCmndAlias(self: *Self, name: []const u8, members: CmndList) !void {
        try self.cmnd.put(name, members);
    }

    pub fn addRunasAlias(self: *Self, name: []const u8, members: RunasList) !void {
        try self.runas.put(name, members);
    }
};

// ============================================
// User Specification
// ============================================

/// A user specification: who can run what as whom on which hosts
/// Format: user_list host_list = cmnd_spec_list
pub const UserSpec = struct {
    allocator: Allocator,
    users: UserList,
    host_specs: std.ArrayListUnmanaged(HostSpec),

    const Self = @This();

    pub fn init(allocator: Allocator, users: UserList) Self {
        return .{
            .allocator = allocator,
            .users = users,
            .host_specs = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.users.deinit(allocator);
        for (self.host_specs.items) |*spec| {
            spec.deinit(allocator);
        }
        self.host_specs.deinit(allocator);
    }

    pub fn addHostSpec(self: *Self, spec: HostSpec) !void {
        try self.host_specs.append(self.allocator, spec);
    }
};

/// Host specification within a user spec
pub const HostSpec = struct {
    allocator: Allocator,
    hosts: HostList,
    cmnd_specs: std.ArrayListUnmanaged(CmndSpec),

    const Self = @This();

    pub fn init(allocator: Allocator, hosts: HostList) Self {
        return .{
            .allocator = allocator,
            .hosts = hosts,
            .cmnd_specs = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.hosts.deinit(allocator);
        for (self.cmnd_specs.items) |*spec| {
            spec.deinit(allocator);
        }
        self.cmnd_specs.deinit(allocator);
    }

    pub fn addCmndSpec(self: *Self, spec: CmndSpec) !void {
        try self.cmnd_specs.append(self.allocator, spec);
    }
};

/// Command specification: runas + tags + commands
pub const CmndSpec = struct {
    runas: ?RunAs,
    tags: Tags,
    commands: CmndList,

    const Self = @This();

    pub fn init(commands: CmndList) Self {
        return .{
            .runas = null,
            .tags = Tags{},
            .commands = commands,
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.runas) |*runas| {
            runas.deinit(allocator);
        }
        self.commands.deinit(allocator);
    }

    pub fn setRunAs(self: *Self, runas: RunAs) void {
        self.runas = runas;
    }

    pub fn setTags(self: *Self, tags: Tags) void {
        self.tags = tags;
    }
};

/// RunAs specification: (user_list : group_list)
pub const RunAs = struct {
    users: ?UserList,
    groups: ?GroupList,

    const Self = @This();

    pub fn init() Self {
        return .{
            .users = null,
            .groups = null,
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        if (self.users) |*users| {
            users.deinit(allocator);
        }
        if (self.groups) |*groups| {
            groups.deinit(allocator);
        }
    }
};

/// Command tags (NOPASSWD, SETENV, etc.)
pub const Tags = struct {
    passwd: ?bool = null, // PASSWD/NOPASSWD
    setenv: ?bool = null, // SETENV/NOSETENV
    noexec: ?bool = null, // NOEXEC/EXEC
    log_input: ?bool = null, // LOG_INPUT/NOLOG_INPUT
    log_output: ?bool = null, // LOG_OUTPUT/NOLOG_OUTPUT

    const Self = @This();

    /// Merge tags, with other taking precedence
    pub fn merge(self: Self, other: Self) Self {
        return .{
            .passwd = other.passwd orelse self.passwd,
            .setenv = other.setenv orelse self.setenv,
            .noexec = other.noexec orelse self.noexec,
            .log_input = other.log_input orelse self.log_input,
            .log_output = other.log_output orelse self.log_output,
        };
    }

    /// Check if password is required (default is true)
    pub fn requiresPassword(self: Self) bool {
        return self.passwd orelse true;
    }

    /// Check if setenv is allowed (default is false)
    pub fn allowsSetenv(self: Self) bool {
        return self.setenv orelse false;
    }

    /// Check if noexec is enabled (default is false)
    pub fn isNoexec(self: Self) bool {
        return self.noexec orelse false;
    }
};

// ============================================
// Default Settings
// ============================================

/// A Defaults setting
pub const Default = struct {
    scope: DefaultScope,
    name: []const u8,
    operator: DefaultOperator,
    value: ?DefaultValue,

    const Self = @This();

    pub fn init(name: []const u8) Self {
        return .{
            .scope = .{ .global = {} },
            .name = name,
            .operator = .set,
            .value = null,
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        // Clean up scope if it contains allocated lists
        switch (self.scope) {
            .user_list => |*list| {
                var mutable_list = list.*;
                mutable_list.deinit(allocator);
            },
            .host_list => |*list| {
                var mutable_list = list.*;
                mutable_list.deinit(allocator);
            },
            else => {},
        }
        // Strings are typically slices into the source, no deallocation needed
    }
};

/// Scope for Defaults settings
/// Syntax examples:
/// - Defaults                  -> global
/// - Defaults:user             -> user scope
/// - Defaults:User_Alias       -> user alias scope  
/// - Defaults@host             -> host scope
/// - Defaults@Host_Alias       -> host alias scope
/// - Defaults!command          -> command scope
/// - Defaults!Cmnd_Alias       -> command alias scope
/// - Defaults>runas            -> runas scope
/// - Defaults>Runas_Alias      -> runas alias scope
pub const DefaultScope = union(enum) {
    global: void,
    user: []const u8,
    user_list: UserList,
    host: []const u8,
    host_list: HostList,
    command: []const u8,
    runas: []const u8,
};

/// Operator for Defaults settings
pub const DefaultOperator = enum {
    set, // name or name=value
    negate, // !name
    add, // name+=value
    remove, // name-=value
};

/// Value for Defaults settings
pub const DefaultValue = union(enum) {
    boolean: bool,
    string: []const u8,
    integer: i64,
    list: std.ArrayListUnmanaged([]const u8),

    pub fn deinit(self: *DefaultValue, allocator: Allocator) void {
        switch (self.*) {
            .list => |*list| list.deinit(allocator),
            else => {},
        }
    }
};

// ============================================
// List Types with Negation Support
// ============================================

/// A list of user items (can be negated)
pub const UserList = struct {
    items: std.ArrayListUnmanaged(UserItem),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        _ = allocator;
        return .{
            .items = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: Allocator, item: UserItem) !void {
        try self.items.append(allocator, item);
    }

    pub fn len(self: Self) usize {
        return self.items.items.len;
    }
};

/// A single user item in a list
pub const UserItem = struct {
    negated: bool,
    value: UserValue,
};

/// Types of user values
pub const UserValue = union(enum) {
    all: void, // ALL
    username: []const u8, // plain username
    uid: u32, // #uid
    groupname: []const u8, // %group
    gid: u32, // %#gid
    netgroup: []const u8, // +netgroup
    non_unix_group: []const u8, // %:group
    non_unix_gid: u32, // %:#gid
    alias: []const u8, // ALIAS_NAME
};

/// A list of host items
pub const HostList = struct {
    items: std.ArrayListUnmanaged(HostItem),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        _ = allocator;
        return .{
            .items = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: Allocator, item: HostItem) !void {
        try self.items.append(allocator, item);
    }

    pub fn len(self: Self) usize {
        return self.items.items.len;
    }
};

/// A single host item
pub const HostItem = struct {
    negated: bool,
    value: HostValue,
};

/// Types of host values
pub const HostValue = union(enum) {
    all: void, // ALL
    hostname: []const u8, // plain hostname
    ip_addr: []const u8, // IP address
    ip_network: []const u8, // IP network (CIDR)
    netgroup: []const u8, // +netgroup
    alias: []const u8, // ALIAS_NAME
};

/// A list of command items
pub const CmndList = struct {
    items: std.ArrayListUnmanaged(CmndItem),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        _ = allocator;
        return .{
            .items = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: Allocator, item: CmndItem) !void {
        try self.items.append(allocator, item);
    }

    pub fn len(self: Self) usize {
        return self.items.items.len;
    }
};

/// A single command item
pub const CmndItem = struct {
    negated: bool,
    value: CmndValue,
};

/// Types of command values
pub const CmndValue = union(enum) {
    all: void, // ALL
    command: Command, // /path/to/command args
    sudoedit: []const u8, // sudoedit /path/to/file
    alias: []const u8, // ALIAS_NAME
};

/// A command with optional arguments
pub const Command = struct {
    path: []const u8,
    args: ?[]const u8, // null means any args, "" means no args
    digest: ?Digest, // optional SHA digest

    pub fn init(path: []const u8) Command {
        return .{
            .path = path,
            .args = null,
            .digest = null,
        };
    }
};

/// SHA digest for command verification
pub const Digest = struct {
    algorithm: DigestAlgorithm,
    hash: []const u8,
};

pub const DigestAlgorithm = enum {
    sha224,
    sha256,
    sha384,
    sha512,
};

/// A list of group items (for RunAs groups)
pub const GroupList = struct {
    items: std.ArrayListUnmanaged(GroupItem),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        _ = allocator;
        return .{
            .items = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: Allocator, item: GroupItem) !void {
        try self.items.append(allocator, item);
    }

    pub fn len(self: Self) usize {
        return self.items.items.len;
    }
};

/// A single group item
pub const GroupItem = struct {
    negated: bool,
    value: GroupValue,
};

/// Types of group values
pub const GroupValue = union(enum) {
    all: void, // ALL
    groupname: []const u8, // plain group name
    gid: u32, // #gid
    non_unix_group: []const u8, // %:group
    non_unix_gid: u32, // %:#gid
    alias: []const u8, // ALIAS_NAME
};

/// A list for RunAs aliases (can contain both users and groups)
pub const RunasList = struct {
    items: std.ArrayListUnmanaged(RunasItem),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        _ = allocator;
        return .{
            .items = .{},
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: Allocator, item: RunasItem) !void {
        try self.items.append(allocator, item);
    }

    pub fn len(self: Self) usize {
        return self.items.items.len;
    }
};

/// A single RunAs item (can be user or group reference)
pub const RunasItem = struct {
    negated: bool,
    value: RunasValue,
};

/// Types of RunAs values
pub const RunasValue = union(enum) {
    all: void, // ALL
    username: []const u8, // plain username
    uid: u32, // #uid
    groupname: []const u8, // %group
    gid: u32, // %#gid
    netgroup: []const u8, // +netgroup
    alias: []const u8, // ALIAS_NAME
};

// ============================================
// Tests
// ============================================

test "create empty sudoers" {
    const allocator = std.testing.allocator;
    var sudoers = Sudoers.init(allocator);
    defer sudoers.deinit();

    try std.testing.expectEqual(@as(usize, 0), sudoers.defaults.items.len);
    try std.testing.expectEqual(@as(usize, 0), sudoers.user_specs.items.len);
}

test "create user spec" {
    const allocator = std.testing.allocator;

    var users = UserList.init(allocator);
    try users.append(allocator, .{
        .negated = false,
        .value = .{ .username = "alice" },
    });

    var spec = UserSpec.init(allocator, users);
    defer spec.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.users.len());
}

test "create default setting" {
    var default = Default.init("env_reset");
    default.operator = .set;

    try std.testing.expectEqualStrings("env_reset", default.name);
    try std.testing.expectEqual(DefaultOperator.set, default.operator);
}

test "tags merge" {
    const base = Tags{
        .passwd = true,
        .setenv = false,
    };

    const override = Tags{
        .passwd = false,
        .noexec = true,
    };

    const merged = base.merge(override);

    try std.testing.expectEqual(false, merged.passwd.?);
    try std.testing.expectEqual(false, merged.setenv.?);
    try std.testing.expectEqual(true, merged.noexec.?);
}

test "tags defaults" {
    const tags = Tags{};

    try std.testing.expect(tags.requiresPassword());
    try std.testing.expect(!tags.allowsSetenv());
    try std.testing.expect(!tags.isNoexec());
}
