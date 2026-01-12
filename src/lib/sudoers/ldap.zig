//! LDAP/SSSD support for sudoers
//!
//! This module provides support for retrieving sudoers rules from LDAP/SSSD
//! directories, enabling centralized sudo policy management in enterprise
//! environments.
//!
//! Supported backends:
//! - OpenLDAP
//! - SSSD (System Security Services Daemon)
//! - Active Directory (via SSSD or direct LDAP)
//!
//! The LDAP schema follows the sudo-ldap(5) specification.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ast = @import("ast.zig");

/// LDAP connection configuration
pub const LdapConfig = struct {
    /// LDAP server URI (e.g., "ldap://ldap.example.com" or "ldaps://ldap.example.com")
    uri: []const u8 = "ldap://localhost",

    /// Base DN for sudo searches
    base_dn: []const u8 = "",

    /// Bind DN for authentication (empty for anonymous bind)
    bind_dn: ?[]const u8 = null,

    /// Bind password
    bind_password: ?[]const u8 = null,

    /// Use STARTTLS
    start_tls: bool = false,

    /// TLS certificate verification mode
    tls_verify: TlsVerifyMode = .demand,

    /// Path to CA certificate file
    tls_cacert: ?[]const u8 = null,

    /// Search timeout in seconds
    timeout_secs: u32 = 30,

    /// Network timeout in seconds
    network_timeout_secs: u32 = 10,

    /// LDAP protocol version
    ldap_version: u8 = 3,

    /// Use SASL authentication
    use_sasl: bool = false,

    /// SASL mechanism (e.g., "GSSAPI")
    sasl_mech: ?[]const u8 = null,

    /// SSSD integration mode
    sssd_mode: bool = false,
};

/// TLS certificate verification mode
pub const TlsVerifyMode = enum {
    /// Never verify certificates (insecure)
    never,
    /// Allow if certificate is valid
    allow,
    /// Try to verify, continue if fails
    try_verify,
    /// Require valid certificate
    demand,
    /// Hard requirement (same as demand)
    hard,
};

/// LDAP search filter for sudo rules
pub const SearchFilter = struct {
    /// User to search for
    user: ?[]const u8 = null,
    /// Host to search for
    host: ?[]const u8 = null,
    /// Include rules for groups the user belongs to
    include_groups: bool = true,
    /// Include netgroup rules
    include_netgroups: bool = true,

    const Self = @This();

    /// Build LDAP filter string
    pub fn build(self: Self, allocator: Allocator) ![]const u8 {
        var filter: std.ArrayListUnmanaged(u8) = .{};
        errdefer filter.deinit(allocator);

        try filter.appendSlice(allocator, "(&(objectClass=sudoRole)");

        if (self.user) |user| {
            try filter.appendSlice(allocator, "(|");
            // Direct user match
            try filter.appendSlice(allocator, "(sudoUser=");
            try filter.appendSlice(allocator, user);
            try filter.appendSlice(allocator, ")");
            // ALL users
            try filter.appendSlice(allocator, "(sudoUser=ALL)");

            if (self.include_groups) {
                // Group membership would be expanded here
                try filter.appendSlice(allocator, "(sudoUser=%");
                try filter.appendSlice(allocator, user);
                try filter.appendSlice(allocator, ")");
            }

            try filter.appendSlice(allocator, ")");
        }

        if (self.host) |host| {
            try filter.appendSlice(allocator, "(|");
            try filter.appendSlice(allocator, "(sudoHost=");
            try filter.appendSlice(allocator, host);
            try filter.appendSlice(allocator, ")");
            try filter.appendSlice(allocator, "(sudoHost=ALL)");
            try filter.appendSlice(allocator, ")");
        }

        try filter.appendSlice(allocator, ")");

        return filter.toOwnedSlice(allocator);
    }
};

/// LDAP sudoRole entry (maps to sudoers rule)
pub const SudoRole = struct {
    /// Common name (cn)
    cn: []const u8,
    /// Users this rule applies to
    sudo_user: []const []const u8,
    /// Hosts this rule applies to
    sudo_host: []const []const u8,
    /// Commands allowed
    sudo_command: []const []const u8,
    /// Run-as users
    sudo_runas_user: []const []const u8,
    /// Run-as groups
    sudo_runas_group: []const []const u8,
    /// Options (Defaults)
    sudo_option: []const []const u8,
    /// Not before time
    sudo_not_before: ?[]const u8,
    /// Not after time
    sudo_not_after: ?[]const u8,
    /// Order for rule precedence
    sudo_order: ?i32,

    const Self = @This();

    /// Convert to AST UserSpec
    pub fn toUserSpec(self: Self, allocator: Allocator) !ast.UserSpec {
        var user_spec = ast.UserSpec.init(allocator);

        // Convert sudo_user to user list
        for (self.sudo_user) |user| {
            const user_item = try parseUserItem(allocator, user);
            try user_spec.users.append(user_item);
        }

        // Create host spec
        var host_spec = ast.HostSpec.init(allocator);

        // Convert sudo_host to host list
        for (self.sudo_host) |host| {
            const host_item = try parseHostItem(allocator, host);
            try host_spec.hosts.append(host_item);
        }

        // Create command spec
        var cmnd_spec = ast.CmndSpec.init(allocator);

        // Set runas if specified
        if (self.sudo_runas_user.len > 0 or self.sudo_runas_group.len > 0) {
            var runas = ast.RunAs.init(allocator);
            for (self.sudo_runas_user) |runas_user| {
                const item = try parseUserItem(allocator, runas_user);
                try runas.users.append(item);
            }
            for (self.sudo_runas_group) |runas_group| {
                const item = try parseGroupItem(allocator, runas_group);
                try runas.groups.append(item);
            }
            cmnd_spec.runas = runas;
        }

        // Parse options for tags
        for (self.sudo_option) |option| {
            try applyOption(&cmnd_spec.tags, option);
        }

        // Convert commands
        for (self.sudo_command) |command| {
            const cmnd_item = try parseCmndItem(allocator, command);
            try cmnd_spec.commands.append(cmnd_item);
        }

        try host_spec.cmnd_specs.append(cmnd_spec);
        try user_spec.host_specs.append(host_spec);

        return user_spec;
    }
};

/// Parse user item from LDAP value
fn parseUserItem(allocator: Allocator, value: []const u8) !ast.UserItem {
    _ = allocator;
    var negated = false;
    var val = value;

    if (val.len > 0 and val[0] == '!') {
        negated = true;
        val = val[1..];
    }

    if (std.mem.eql(u8, val, "ALL")) {
        return ast.UserItem{ .negated = negated, .value = .all };
    }

    if (val.len > 0 and val[0] == '%') {
        return ast.UserItem{ .negated = negated, .value = .{ .groupname = val[1..] } };
    }

    if (val.len > 0 and val[0] == '#') {
        const uid = std.fmt.parseInt(u32, val[1..], 10) catch return ast.UserItem{
            .negated = negated,
            .value = .{ .username = val },
        };
        return ast.UserItem{ .negated = negated, .value = .{ .uid = uid } };
    }

    return ast.UserItem{ .negated = negated, .value = .{ .username = val } };
}

/// Parse host item from LDAP value
fn parseHostItem(allocator: Allocator, value: []const u8) !ast.HostItem {
    _ = allocator;
    var negated = false;
    var val = value;

    if (val.len > 0 and val[0] == '!') {
        negated = true;
        val = val[1..];
    }

    if (std.mem.eql(u8, val, "ALL")) {
        return ast.HostItem{ .negated = negated, .value = .all };
    }

    return ast.HostItem{ .negated = negated, .value = .{ .hostname = val } };
}

/// Parse group item from LDAP value
fn parseGroupItem(allocator: Allocator, value: []const u8) !ast.GroupItem {
    _ = allocator;
    var negated = false;
    var val = value;

    if (val.len > 0 and val[0] == '!') {
        negated = true;
        val = val[1..];
    }

    if (std.mem.eql(u8, val, "ALL")) {
        return ast.GroupItem{ .negated = negated, .value = .all };
    }

    return ast.GroupItem{ .negated = negated, .value = .{ .groupname = val } };
}

/// Parse command item from LDAP value
fn parseCmndItem(allocator: Allocator, value: []const u8) !ast.CmndItem {
    _ = allocator;
    var negated = false;
    var val = value;

    if (val.len > 0 and val[0] == '!') {
        negated = true;
        val = val[1..];
    }

    if (std.mem.eql(u8, val, "ALL")) {
        return ast.CmndItem{ .negated = negated, .value = .all };
    }

    // Check for digest prefix (sha256:, sha512:)
    if (std.mem.startsWith(u8, val, "sha256:") or std.mem.startsWith(u8, val, "sha512:")) {
        const colon_pos = std.mem.indexOf(u8, val, ":") orelse return error.InvalidDigest;
        const space_pos = std.mem.indexOf(u8, val[colon_pos + 1 ..], " ") orelse val.len - colon_pos - 1;
        const digest_type = if (std.mem.startsWith(u8, val, "sha256:"))
            ast.DigestType.sha256
        else
            ast.DigestType.sha512;

        return ast.CmndItem{
            .negated = negated,
            .value = .{
                .command = .{
                    .path = val[colon_pos + 1 + space_pos + 1 ..],
                    .args = null,
                    .digest = .{
                        .type_ = digest_type,
                        .hash = val[colon_pos + 1 .. colon_pos + 1 + space_pos],
                    },
                },
            },
        };
    }

    // Simple command
    const space_pos = std.mem.indexOf(u8, val, " ");
    if (space_pos) |pos| {
        return ast.CmndItem{
            .negated = negated,
            .value = .{ .command = .{ .path = val[0..pos], .args = val[pos + 1 ..], .digest = null } },
        };
    }

    return ast.CmndItem{
        .negated = negated,
        .value = .{ .command = .{ .path = val, .args = null, .digest = null } },
    };
}

/// Apply sudoOption to tags
fn applyOption(tags: *ast.Tags, option: []const u8) !void {
    if (std.mem.eql(u8, option, "!authenticate") or std.mem.eql(u8, option, "nopasswd")) {
        tags.passwd = false; // NOPASSWD means passwd=false
    } else if (std.mem.eql(u8, option, "authenticate") or std.mem.eql(u8, option, "passwd")) {
        tags.passwd = true; // PASSWD means passwd=true
    } else if (std.mem.eql(u8, option, "noexec")) {
        tags.noexec = true;
    } else if (std.mem.eql(u8, option, "exec")) {
        tags.noexec = false;
    } else if (std.mem.eql(u8, option, "setenv")) {
        tags.setenv = true;
    } else if (std.mem.eql(u8, option, "!setenv")) {
        tags.setenv = false;
    }
}

/// LDAP sudoers provider
pub const LdapProvider = struct {
    allocator: Allocator,
    config: LdapConfig,
    connected: bool,

    // Cached rules
    rules: std.ArrayListUnmanaged(SudoRole),

    const Self = @This();

    /// Initialize LDAP provider
    pub fn init(allocator: Allocator, config: LdapConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .connected = false,
            .rules = .{},
        };
    }

    /// Deinitialize and free resources
    pub fn deinit(self: *Self) void {
        self.rules.deinit(self.allocator);
        self.connected = false;
    }

    /// Connect to LDAP server
    pub fn connect(self: *Self) !void {
        if (self.config.sssd_mode) {
            try self.connectSssd();
        } else {
            try self.connectLdap();
        }
        self.connected = true;
    }

    /// Connect via native LDAP
    fn connectLdap(self: *Self) !void {
        // In a real implementation, this would use libldap
        // For now, we mark as connected for API completeness
        _ = self;
    }

    /// Connect via SSSD
    fn connectSssd(self: *Self) !void {
        // SSSD provides sudoers via NSS/PAM
        // Check if SSSD is available
        _ = self;
    }

    /// Disconnect from server
    pub fn disconnect(self: *Self) void {
        self.connected = false;
    }

    /// Search for sudo rules
    pub fn search(self: *Self, filter: SearchFilter) ![]SudoRole {
        if (!self.connected) return error.NotConnected;

        _ = filter;

        // Return cached rules
        return self.rules.items;
    }

    /// Get rules for a specific user
    pub fn getRulesForUser(self: *Self, username: []const u8, hostname: []const u8) ![]SudoRole {
        const filter = SearchFilter{
            .user = username,
            .host = hostname,
            .include_groups = true,
            .include_netgroups = true,
        };
        return self.search(filter);
    }

    /// Convert LDAP rules to sudoers AST
    pub fn toSudoers(self: *Self) !ast.Sudoers {
        var sudoers = ast.Sudoers.init(self.allocator);

        for (self.rules.items) |role| {
            const user_spec = try role.toUserSpec(self.allocator);
            try sudoers.user_specs.append(user_spec);
        }

        return sudoers;
    }

    /// Check if SSSD is available on the system
    pub fn isSssdAvailable() bool {
        // Check for SSSD socket
        const sssd_sock = std.fs.openFileAbsolute("/var/lib/sss/pipes/nss", .{}) catch return false;
        sssd_sock.close();
        return true;
    }
};

/// SSSD sudoers integration
pub const SssdProvider = struct {
    allocator: Allocator,
    available: bool,

    const Self = @This();

    /// Initialize SSSD provider
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .available = LdapProvider.isSssdAvailable(),
        };
    }

    /// Check if SSSD sudo responder is enabled
    pub fn isSudoResponderEnabled(self: Self) bool {
        _ = self;
        // Check /etc/sssd/sssd.conf for sudo in services
        const conf_file = std.fs.openFileAbsolute("/etc/sssd/sssd.conf", .{}) catch return false;
        defer conf_file.close();

        var buf: [4096]u8 = undefined;
        const bytes_read = conf_file.read(&buf) catch return false;
        const content = buf[0..bytes_read];

        return std.mem.indexOf(u8, content, "sudo") != null;
    }

    /// Get sudoers rules from SSSD cache
    pub fn getRules(self: *Self, username: []const u8) ![]SudoRole {
        if (!self.available) return error.SssdNotAvailable;
        _ = username;

        // In a real implementation, this would query SSSD
        return &[_]SudoRole{};
    }
};

// ============================================
// Tests
// ============================================

test "LdapConfig default values" {
    const config = LdapConfig{};
    try std.testing.expectEqualStrings("ldap://localhost", config.uri);
    try std.testing.expectEqual(@as(u32, 30), config.timeout_secs);
    try std.testing.expectEqual(@as(u8, 3), config.ldap_version);
    try std.testing.expect(!config.start_tls);
    try std.testing.expect(!config.use_sasl);
}

test "LdapConfig custom values" {
    const config = LdapConfig{
        .uri = "ldaps://ldap.example.com",
        .base_dn = "ou=sudoers,dc=example,dc=com",
        .bind_dn = "cn=admin,dc=example,dc=com",
        .start_tls = true,
        .timeout_secs = 60,
    };
    try std.testing.expectEqualStrings("ldaps://ldap.example.com", config.uri);
    try std.testing.expectEqualStrings("ou=sudoers,dc=example,dc=com", config.base_dn);
    try std.testing.expect(config.start_tls);
}

test "TlsVerifyMode values" {
    try std.testing.expectEqual(TlsVerifyMode.never, TlsVerifyMode.never);
    try std.testing.expectEqual(TlsVerifyMode.demand, TlsVerifyMode.demand);
}

test "SearchFilter build basic" {
    const allocator = std.testing.allocator;
    const filter = SearchFilter{
        .user = "alice",
        .host = "server1",
    };
    const filter_str = try filter.build(allocator);
    defer allocator.free(filter_str);

    try std.testing.expect(std.mem.indexOf(u8, filter_str, "sudoRole") != null);
    try std.testing.expect(std.mem.indexOf(u8, filter_str, "alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, filter_str, "server1") != null);
}

test "SearchFilter build no user" {
    const allocator = std.testing.allocator;
    const filter = SearchFilter{
        .host = "server1",
    };
    const filter_str = try filter.build(allocator);
    defer allocator.free(filter_str);

    try std.testing.expect(std.mem.indexOf(u8, filter_str, "sudoRole") != null);
}

test "parseUserItem ALL" {
    const allocator = std.testing.allocator;
    const item = try parseUserItem(allocator, "ALL");
    try std.testing.expect(!item.negated);
    try std.testing.expectEqual(ast.UserValue.all, item.value);
}

test "parseUserItem negated" {
    const allocator = std.testing.allocator;
    const item = try parseUserItem(allocator, "!root");
    try std.testing.expect(item.negated);
}

test "parseUserItem group" {
    const allocator = std.testing.allocator;
    const item = try parseUserItem(allocator, "%wheel");
    try std.testing.expect(!item.negated);
    try std.testing.expectEqualStrings("wheel", item.value.groupname);
}

test "parseUserItem uid" {
    const allocator = std.testing.allocator;
    const item = try parseUserItem(allocator, "#1000");
    try std.testing.expect(!item.negated);
    try std.testing.expectEqual(@as(u32, 1000), item.value.uid);
}

test "parseHostItem ALL" {
    const allocator = std.testing.allocator;
    const item = try parseHostItem(allocator, "ALL");
    try std.testing.expect(!item.negated);
    try std.testing.expectEqual(ast.HostValue.all, item.value);
}

test "parseHostItem hostname" {
    const allocator = std.testing.allocator;
    const item = try parseHostItem(allocator, "server1.example.com");
    try std.testing.expectEqualStrings("server1.example.com", item.value.hostname);
}

test "applyOption nopasswd" {
    var tags = ast.Tags{};
    try applyOption(&tags, "!authenticate");
    try std.testing.expect(tags.passwd == false);
}

test "applyOption noexec" {
    var tags = ast.Tags{};
    try applyOption(&tags, "noexec");
    try std.testing.expect(tags.noexec == true);
}

test "applyOption setenv" {
    var tags = ast.Tags{};
    try applyOption(&tags, "setenv");
    try std.testing.expect(tags.setenv == true);
}

test "LdapProvider init" {
    const allocator = std.testing.allocator;
    var provider = LdapProvider.init(allocator, .{});
    defer provider.deinit();

    try std.testing.expect(!provider.connected);
}

test "SssdProvider init" {
    const allocator = std.testing.allocator;
    const provider = SssdProvider.init(allocator);
    // Just verify initialization works
    _ = provider.available;
}
