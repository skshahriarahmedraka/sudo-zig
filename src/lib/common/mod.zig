//! Common utilities shared across all sudo-zig modules
//!
//! This module provides:
//! - Error types and handling
//! - Safe string types (null-byte validation)
//! - Path validation and manipulation
//! - Execution context management
//! - Command parsing

const std = @import("std");

pub const error_mod = @import("error.zig");
pub const string = @import("string.zig");
pub const path = @import("path.zig");
pub const context = @import("context.zig");
pub const command = @import("command.zig");
pub const digest = @import("digest.zig");
pub const network = @import("network.zig");
pub const i18n = @import("i18n.zig");
pub const secure_mem = @import("secure_mem.zig");
pub const env_check = @import("env_check.zig");

// Re-export main types
pub const Error = error_mod.Error;
pub const SudoString = string.SudoString;
pub const SudoPath = path.SudoPath;
pub const Context = context.Context;
pub const CommandAndArguments = command.CommandAndArguments;
pub const DigestAlgorithm = digest.DigestAlgorithm;
pub const Digest = digest.Digest;
pub const verifyFileDigest = digest.verifyFileDigest;

// Network types
pub const IPAddress = network.IPAddress;
pub const IPv4Address = network.IPv4Address;
pub const IPv6Address = network.IPv6Address;
pub const IPNetwork = network.IPNetwork;
pub const IPv4Network = network.IPv4Network;
pub const IPv6Network = network.IPv6Network;

// i18n functions
pub const @"_" = i18n.@"_";
pub const gettext = i18n.gettext;
pub const ngettext = i18n.ngettext;
pub const pgettext = i18n.pgettext;
pub const initLocale = i18n.init;
pub const messages = i18n.messages;

// Secure memory types
pub const SecurePassword = secure_mem.SecurePassword;
pub const SecureKey = secure_mem.SecureKey;
pub const SecureAllocator = secure_mem.SecureAllocator;
pub const secureZero = secure_mem.secureZero;
pub const secureZeroBytes = secure_mem.secureZeroBytes;
pub const secureCompare = secure_mem.secureCompare;
pub const readSecurePassword = secure_mem.readSecurePassword;

// Environment security
pub const EnvValidator = env_check.EnvValidator;
pub const EnvValidationResult = env_check.ValidationResult;
pub const isValidEnvName = env_check.isValidName;
pub const isValidEnvValue = env_check.isValidValue;
pub const isDangerousEnvVar = env_check.isDangerousVariable;

// ============================================
// Hardened Enum Values
// ============================================
// Used for critical enums to mitigate Rowhammer-style attacks
// Values copied from sudo-rs (originally from sudo)

pub const HARDENED_ENUM_VALUE_0: u32 = 0x52a2925;
pub const HARDENED_ENUM_VALUE_1: u32 = 0xad5d6da;
pub const HARDENED_ENUM_VALUE_2: u32 = 0x69d61fc8;
pub const HARDENED_ENUM_VALUE_3: u32 = 0x1629e037;
pub const HARDENED_ENUM_VALUE_4: u32 = 0x1fc8d3ac;

// ============================================
// Tests
// ============================================

test {
    std.testing.refAllDecls(@This());
}
