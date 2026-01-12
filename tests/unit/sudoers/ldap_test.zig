//! Unit tests for LDAP/SSSD support
//!
//! Tests for LDAP sudoers provider and SSSD integration.

const std = @import("std");
const testing = std.testing;
const lib = @import("sudo-zig-lib");
const ldap = lib.sudoers.ldap;
const LdapConfig = ldap.LdapConfig;
const LdapProvider = ldap.LdapProvider;
const SssdProvider = ldap.SssdProvider;
const SearchFilter = ldap.SearchFilter;
const TlsVerifyMode = ldap.TlsVerifyMode;

// ============================================
// LdapConfig Tests
// ============================================

test "LdapConfig default values" {
    const config = LdapConfig{};
    try testing.expectEqualStrings("ldap://localhost", config.uri);
    try testing.expectEqualStrings("", config.base_dn);
    try testing.expect(config.bind_dn == null);
    try testing.expect(config.bind_password == null);
    try testing.expect(!config.start_tls);
    try testing.expectEqual(TlsVerifyMode.demand, config.tls_verify);
    try testing.expect(config.tls_cacert == null);
    try testing.expectEqual(@as(u32, 30), config.timeout_secs);
    try testing.expectEqual(@as(u32, 10), config.network_timeout_secs);
    try testing.expectEqual(@as(u8, 3), config.ldap_version);
    try testing.expect(!config.use_sasl);
    try testing.expect(config.sasl_mech == null);
    try testing.expect(!config.sssd_mode);
}

test "LdapConfig with LDAPS URI" {
    const config = LdapConfig{
        .uri = "ldaps://ldap.example.com:636",
        .base_dn = "ou=sudoers,dc=example,dc=com",
        .bind_dn = "cn=sudo,ou=services,dc=example,dc=com",
        .bind_password = "secret",
    };
    try testing.expectEqualStrings("ldaps://ldap.example.com:636", config.uri);
    try testing.expectEqualStrings("ou=sudoers,dc=example,dc=com", config.base_dn);
    try testing.expect(config.bind_dn != null);
    try testing.expect(config.bind_password != null);
}

test "LdapConfig with STARTTLS" {
    const config = LdapConfig{
        .uri = "ldap://ldap.example.com",
        .start_tls = true,
        .tls_verify = .demand,
        .tls_cacert = "/etc/ssl/certs/ca-certificates.crt",
    };
    try testing.expect(config.start_tls);
    try testing.expectEqual(TlsVerifyMode.demand, config.tls_verify);
    try testing.expect(config.tls_cacert != null);
}

test "LdapConfig with SASL/GSSAPI" {
    const config = LdapConfig{
        .uri = "ldap://ldap.example.com",
        .use_sasl = true,
        .sasl_mech = "GSSAPI",
    };
    try testing.expect(config.use_sasl);
    try testing.expect(config.sasl_mech != null);
    try testing.expectEqualStrings("GSSAPI", config.sasl_mech.?);
}

test "LdapConfig SSSD mode" {
    const config = LdapConfig{
        .sssd_mode = true,
    };
    try testing.expect(config.sssd_mode);
}

// ============================================
// TlsVerifyMode Tests
// ============================================

test "TlsVerifyMode enum values" {
    try testing.expect(TlsVerifyMode.never != TlsVerifyMode.allow);
    try testing.expect(TlsVerifyMode.allow != TlsVerifyMode.try_verify);
    try testing.expect(TlsVerifyMode.try_verify != TlsVerifyMode.demand);
    try testing.expect(TlsVerifyMode.demand != TlsVerifyMode.hard);
}

// ============================================
// SearchFilter Tests
// ============================================

test "SearchFilter default values" {
    const filter = SearchFilter{};
    try testing.expect(filter.user == null);
    try testing.expect(filter.host == null);
    try testing.expect(filter.include_groups);
    try testing.expect(filter.include_netgroups);
}

test "SearchFilter with user" {
    const filter = SearchFilter{
        .user = "alice",
    };
    try testing.expect(filter.user != null);
    try testing.expectEqualStrings("alice", filter.user.?);
}

test "SearchFilter with host" {
    const filter = SearchFilter{
        .host = "server1.example.com",
    };
    try testing.expect(filter.host != null);
    try testing.expectEqualStrings("server1.example.com", filter.host.?);
}

test "SearchFilter build with user and host" {
    const filter = SearchFilter{
        .user = "bob",
        .host = "webserver",
    };
    const filter_str = try filter.build(testing.allocator);
    defer testing.allocator.free(filter_str);

    // Verify contains expected elements
    try testing.expect(std.mem.indexOf(u8, filter_str, "objectClass=sudoRole") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=bob") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=ALL") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoHost=webserver") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoHost=ALL") != null);
}

test "SearchFilter build user only" {
    const filter = SearchFilter{
        .user = "charlie",
    };
    const filter_str = try filter.build(testing.allocator);
    defer testing.allocator.free(filter_str);

    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=charlie") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoHost=") == null);
}

test "SearchFilter build host only" {
    const filter = SearchFilter{
        .host = "db-server",
    };
    const filter_str = try filter.build(testing.allocator);
    defer testing.allocator.free(filter_str);

    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoHost=db-server") != null);
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=") == null);
}

test "SearchFilter build without groups" {
    const filter = SearchFilter{
        .user = "dave",
        .include_groups = false,
    };
    const filter_str = try filter.build(testing.allocator);
    defer testing.allocator.free(filter_str);

    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=dave") != null);
    // Group pattern uses % prefix
    try testing.expect(std.mem.indexOf(u8, filter_str, "sudoUser=%dave") == null);
}

// ============================================
// LdapProvider Tests
// ============================================

test "LdapProvider initialization" {
    var provider = LdapProvider.init(testing.allocator, .{});
    defer provider.deinit();

    try testing.expect(!provider.connected);
}

test "LdapProvider with custom config" {
    var provider = LdapProvider.init(testing.allocator, .{
        .uri = "ldaps://ldap.corp.example.com",
        .base_dn = "ou=sudo,dc=corp,dc=example,dc=com",
    });
    defer provider.deinit();

    try testing.expectEqualStrings("ldaps://ldap.corp.example.com", provider.config.uri);
    try testing.expectEqualStrings("ou=sudo,dc=corp,dc=example,dc=com", provider.config.base_dn);
}

test "LdapProvider disconnect" {
    var provider = LdapProvider.init(testing.allocator, .{});
    defer provider.deinit();

    provider.disconnect();
    try testing.expect(!provider.connected);
}

test "LdapProvider isSssdAvailable" {
    // This just checks that the function doesn't crash
    _ = LdapProvider.isSssdAvailable();
}

// ============================================
// SssdProvider Tests
// ============================================

test "SssdProvider initialization" {
    const provider = SssdProvider.init(testing.allocator);
    // Just verify it initializes without error
    _ = provider.available;
}

test "SssdProvider isSudoResponderEnabled" {
    const provider = SssdProvider.init(testing.allocator);
    // This should not crash regardless of SSSD availability
    _ = provider.isSudoResponderEnabled();
}
