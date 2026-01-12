//! Sudoers file parsing and policy evaluation
//!
//! This module handles:
//! - Tokenizing sudoers files
//! - Parsing into AST
//! - Evaluating authorization policies
//! - Handling aliases and defaults
//! - LDAP/SSSD integration for enterprise environments

const std = @import("std");

// Submodules
pub const tokens = @import("tokens.zig");
pub const ast = @import("ast.zig");
pub const parser = @import("parser.zig");
pub const policy = @import("policy.zig");
pub const ldap = @import("ldap.zig");

// Re-export commonly used types
pub const Tokenizer = tokens.Tokenizer;
pub const Token = tokens.Token;
pub const TokenType = tokens.TokenType;

pub const Sudoers = ast.Sudoers;
pub const UserSpec = ast.UserSpec;
pub const HostSpec = ast.HostSpec;
pub const CmndSpec = ast.CmndSpec;
pub const RunAs = ast.RunAs;
pub const Tags = ast.Tags;
pub const Default = ast.Default;
pub const DefaultScope = ast.DefaultScope;
pub const DefaultOperator = ast.DefaultOperator;
pub const DefaultValue = ast.DefaultValue;
pub const Aliases = ast.Aliases;
pub const IncludeDirective = ast.IncludeDirective;
pub const Digest = ast.Digest;
pub const DigestAlgorithm = ast.DigestAlgorithm;

pub const UserList = ast.UserList;
pub const UserItem = ast.UserItem;
pub const UserValue = ast.UserValue;
pub const HostList = ast.HostList;
pub const HostItem = ast.HostItem;
pub const HostValue = ast.HostValue;
pub const CmndList = ast.CmndList;
pub const CmndItem = ast.CmndItem;
pub const CmndValue = ast.CmndValue;
pub const Command = ast.Command;
pub const GroupList = ast.GroupList;
pub const GroupItem = ast.GroupItem;
pub const GroupValue = ast.GroupValue;
pub const RunasList = ast.RunasList;
pub const RunasItem = ast.RunasItem;
pub const RunasValue = ast.RunasValue;

pub const Parser = parser.Parser;
pub const ParseError = parser.ParseError;
pub const parse = parser.parse;
pub const parseFile = parser.parseFile;
pub const parseWithIncludes = parser.parseWithIncludes;

// Policy evaluation
pub const Policy = policy.Policy;
pub const Authorization = policy.Authorization;
pub const AuthRequest = policy.AuthRequest;

// LDAP/SSSD integration
pub const LdapProvider = ldap.LdapProvider;
pub const LdapConfig = ldap.LdapConfig;
pub const SssdProvider = ldap.SssdProvider;
pub const SudoRole = ldap.SudoRole;
pub const SearchFilter = ldap.SearchFilter;

test {
    std.testing.refAllDecls(@This());
    _ = tokens;
    _ = ast;
    _ = parser;
    _ = policy;
    _ = ldap;
}
