//! Environment variable security validation
//!
//! This module provides security checks for environment variables to prevent
//! injection attacks and ensure safe environment handling in sudo.
//!
//! Key security features:
//! - Dangerous variable detection (LD_PRELOAD, etc.)
//! - Value format validation (no shell escapes, null bytes)
//! - Pattern-based env_keep/env_check/env_delete matching
//! - Wildcard support for variable names

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Result of environment validation
pub const ValidationResult = enum {
    /// Variable is safe and should be kept
    keep,
    /// Variable should be checked (validate value)
    check,
    /// Variable should be removed (dangerous)
    delete,
    /// Variable name is invalid
    invalid_name,
    /// Variable value is invalid (contains dangerous content)
    invalid_value,
};

/// Environment security validator
pub const EnvValidator = struct {
    /// Variables that should always be kept
    env_keep: []const []const u8,
    /// Variables that need value validation
    env_check: []const []const u8,
    /// Variables that should always be deleted
    env_delete: []const []const u8,
    /// Whether to reset environment (vs preserve)
    env_reset: bool,

    const Self = @This();

    /// Initialize with default security settings
    pub fn initDefault() Self {
        return .{
            .env_keep = &default_env_keep,
            .env_check = &default_env_check,
            .env_delete = &default_env_delete,
            .env_reset = true,
        };
    }

    /// Initialize with custom settings
    pub fn init(
        env_keep: []const []const u8,
        env_check: []const []const u8,
        env_delete: []const []const u8,
        env_reset: bool,
    ) Self {
        return .{
            .env_keep = env_keep,
            .env_check = env_check,
            .env_delete = env_delete,
            .env_reset = env_reset,
        };
    }

    /// Validate an environment variable
    pub fn validate(self: *const Self, name: []const u8, value: []const u8) ValidationResult {
        // Check if name is valid
        if (!isValidName(name)) {
            return .invalid_name;
        }

        // Check against delete list first (highest priority)
        if (self.matchesPatternList(name, self.env_delete)) {
            return .delete;
        }

        // Check if it's an inherently dangerous variable
        if (isDangerousVariable(name)) {
            return .delete;
        }

        // Check if it needs value validation
        if (self.matchesPatternList(name, self.env_check)) {
            if (!isValidValue(name, value)) {
                return .invalid_value;
            }
            return .check;
        }

        // Check if it's explicitly kept
        if (self.matchesPatternList(name, self.env_keep)) {
            // Still validate the value
            if (!isValidValue(name, value)) {
                return .invalid_value;
            }
            return .keep;
        }

        // In env_reset mode, variables not in keep list are deleted
        if (self.env_reset) {
            return .delete;
        }

        // In preserve mode, validate and keep by default
        if (!isValidValue(name, value)) {
            return .invalid_value;
        }
        return .keep;
    }

    /// Check if name matches any pattern in the list
    fn matchesPatternList(self: *const Self, name: []const u8, patterns: []const []const u8) bool {
        _ = self;
        for (patterns) |pattern| {
            if (matchesPattern(pattern, name)) {
                return true;
            }
        }
        return false;
    }

    /// Build a safe environment map from the current environment
    pub fn buildSafeEnvironment(
        self: *const Self,
        allocator: Allocator,
        source_env: std.StringHashMap([]const u8),
    ) !std.StringHashMap([]const u8) {
        var safe_env = std.StringHashMap([]const u8).init(allocator);
        errdefer safe_env.deinit();

        var iter = source_env.iterator();
        while (iter.next()) |entry| {
            const result = self.validate(entry.key_ptr.*, entry.value_ptr.*);
            switch (result) {
                .keep, .check => {
                    try safe_env.put(entry.key_ptr.*, entry.value_ptr.*);
                },
                .delete, .invalid_name, .invalid_value => {
                    // Skip dangerous/invalid variables
                },
            }
        }

        return safe_env;
    }
};

/// Check if a variable name is valid
pub fn isValidName(name: []const u8) bool {
    if (name.len == 0) return false;

    // First character must be letter or underscore
    const first = name[0];
    if (!std.ascii.isAlphabetic(first) and first != '_') {
        return false;
    }

    // Rest must be alphanumeric or underscore
    for (name[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') {
            return false;
        }
    }

    // Check for embedded null bytes
    if (std.mem.indexOf(u8, name, "\x00") != null) {
        return false;
    }

    return true;
}

/// Check if a variable value is safe
pub fn isValidValue(name: []const u8, value: []const u8) bool {
    // Check for null bytes (can be used for injection)
    if (std.mem.indexOf(u8, value, "\x00") != null) {
        return false;
    }

    // PATH-like variables need additional validation
    if (isPathLikeVariable(name)) {
        return isValidPathValue(value);
    }

    // Check for shell function definitions (bash shellshock-style)
    if (std.mem.startsWith(u8, value, "() {")) {
        return false;
    }

    // Check for excessive length (DoS prevention)
    if (value.len > 65536) {
        return false;
    }

    return true;
}

/// Check if this is a PATH-like variable that contains paths
fn isPathLikeVariable(name: []const u8) bool {
    const path_vars = [_][]const u8{
        "PATH",
        "LD_LIBRARY_PATH",
        "MANPATH",
        "INFOPATH",
        "PERL5LIB",
        "PYTHONPATH",
        "RUBYLIB",
        "CLASSPATH",
    };

    for (path_vars) |pv| {
        if (std.ascii.eqlIgnoreCase(name, pv)) {
            return true;
        }
    }
    return false;
}

/// Validate PATH-like values (no relative paths, no ..)
fn isValidPathValue(value: []const u8) bool {
    var iter = std.mem.splitScalar(u8, value, ':');
    while (iter.next()) |path| {
        if (path.len == 0) continue;

        // Relative paths are dangerous
        if (path[0] != '/') {
            return false;
        }

        // No .. components
        if (std.mem.indexOf(u8, path, "..") != null) {
            return false;
        }
    }
    return true;
}

/// Check if a variable is inherently dangerous
pub fn isDangerousVariable(name: []const u8) bool {
    for (dangerous_variables) |dangerous| {
        if (matchesPattern(dangerous, name)) {
            return true;
        }
    }
    return false;
}

/// Match a pattern against a name (supports * wildcard)
pub fn matchesPattern(pattern: []const u8, name: []const u8) bool {
    // Exact match
    if (std.mem.eql(u8, pattern, name)) {
        return true;
    }

    // Wildcard at end (e.g., "LD_*")
    if (pattern.len > 0 and pattern[pattern.len - 1] == '*') {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, name, prefix);
    }

    // Wildcard at start (e.g., "*_DEBUG")
    if (pattern.len > 0 and pattern[0] == '*') {
        const suffix = pattern[1..];
        return std.mem.endsWith(u8, name, suffix);
    }

    // Shell function pattern: *=()*
    if (std.mem.eql(u8, pattern, "*=()*")) {
        // Check if the value (not name) contains function definition
        // This is handled separately in value validation
        return false;
    }

    return false;
}

// ============================================
// Default Lists (from sudo defaults)
// ============================================

/// Variables to always keep
const default_env_keep = [_][]const u8{
    "COLORS",
    "DISPLAY",
    "HOSTNAME",
    "KRB5CCNAME",
    "LS_COLORS",
    "PS1",
    "PS2",
    "XAUTHORITY",
    "XAUTHORIZATION",
    "XDG_CURRENT_DESKTOP",
};

/// Variables to check (validate value before keeping)
const default_env_check = [_][]const u8{
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "LINGUAS",
    "TERM",
    "TZ",
};

/// Variables to always delete
const default_env_delete = [_][]const u8{
    "IFS",
    "CDPATH",
    "LOCALDOMAIN",
    "RES_OPTIONS",
    "HOSTALIASES",
    "NLSPATH",
    "PATH_LOCALE",
    "LD_*",
    "_RLD*",
    "TERMINFO",
    "TERMINFO_DIRS",
    "TERMPATH",
    "TERMCAP",
    "ENV",
    "BASH_ENV",
    "PS4",
    "GLOBIGNORE",
    "BASHOPTS",
    "SHELLOPTS",
    "JAVA_TOOL_OPTIONS",
    "PERLIO_DEBUG",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PERL5DB",
    "FPATH",
    "NULLCMD",
    "READNULLCMD",
    "ZDOTDIR",
    "TMPPREFIX",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "RUBYLIB",
    "RUBYOPT",
};

/// Inherently dangerous variables that should never be passed
const dangerous_variables = [_][]const u8{
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LD_AOUT_LIBRARY_PATH",
    "LD_AOUT_PRELOAD",
    "LD_DYNAMIC_WEAK",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "LD_HWCAP_MASK",
    "LD_ORIGIN_PATH",
    "LD_POINTER_GUARD",
    "GCONV_PATH",
    "GETCONF_DIR",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_TRACE",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TMPDIR", // Can be dangerous if attacker-controlled
    "TZDIR",
};

// ============================================
// Tests
// ============================================

test "isValidName valid" {
    try std.testing.expect(isValidName("PATH"));
    try std.testing.expect(isValidName("HOME"));
    try std.testing.expect(isValidName("_"));
    try std.testing.expect(isValidName("_VAR"));
    try std.testing.expect(isValidName("VAR_123"));
}

test "isValidName invalid" {
    try std.testing.expect(!isValidName(""));
    try std.testing.expect(!isValidName("123VAR"));
    try std.testing.expect(!isValidName("VAR-NAME"));
    try std.testing.expect(!isValidName("VAR.NAME"));
    try std.testing.expect(!isValidName("VAR\x00NAME"));
}

test "isValidValue basic" {
    try std.testing.expect(isValidValue("FOO", "bar"));
    try std.testing.expect(isValidValue("FOO", ""));
    try std.testing.expect(!isValidValue("FOO", "bar\x00baz")); // Null byte
    try std.testing.expect(!isValidValue("FOO", "() { :; };")); // Shell function
}

test "isValidValue PATH" {
    try std.testing.expect(isValidValue("PATH", "/usr/bin:/bin"));
    try std.testing.expect(!isValidValue("PATH", "relative/path:/bin"));
    try std.testing.expect(!isValidValue("PATH", "/usr/../bin"));
}

test "isDangerousVariable" {
    try std.testing.expect(isDangerousVariable("LD_PRELOAD"));
    try std.testing.expect(isDangerousVariable("LD_LIBRARY_PATH"));
    try std.testing.expect(isDangerousVariable("GCONV_PATH"));
    try std.testing.expect(!isDangerousVariable("HOME"));
    try std.testing.expect(!isDangerousVariable("PATH"));
}

test "matchesPattern exact" {
    try std.testing.expect(matchesPattern("PATH", "PATH"));
    try std.testing.expect(!matchesPattern("PATH", "HOME"));
}

test "matchesPattern wildcard suffix" {
    try std.testing.expect(matchesPattern("LD_*", "LD_PRELOAD"));
    try std.testing.expect(matchesPattern("LD_*", "LD_LIBRARY_PATH"));
    try std.testing.expect(!matchesPattern("LD_*", "HOME"));
}

test "matchesPattern wildcard prefix" {
    try std.testing.expect(matchesPattern("*_PATH", "LD_LIBRARY_PATH"));
    try std.testing.expect(matchesPattern("*_PATH", "PYTHON_PATH"));
    try std.testing.expect(!matchesPattern("*_PATH", "HOME"));
}

test "EnvValidator delete dangerous" {
    const validator = EnvValidator.initDefault();
    try std.testing.expectEqual(ValidationResult.delete, validator.validate("LD_PRELOAD", "/evil.so"));
    try std.testing.expectEqual(ValidationResult.delete, validator.validate("LD_LIBRARY_PATH", "/tmp"));
}

test "EnvValidator keep safe" {
    const validator = EnvValidator.initDefault();
    try std.testing.expectEqual(ValidationResult.keep, validator.validate("DISPLAY", ":0"));
    try std.testing.expectEqual(ValidationResult.keep, validator.validate("COLORS", "256"));
}

test "EnvValidator check locale" {
    const validator = EnvValidator.initDefault();
    try std.testing.expectEqual(ValidationResult.check, validator.validate("LANG", "en_US.UTF-8"));
    try std.testing.expectEqual(ValidationResult.check, validator.validate("LC_ALL", "C"));
}

test "EnvValidator invalid value" {
    const validator = EnvValidator.initDefault();
    try std.testing.expectEqual(ValidationResult.invalid_value, validator.validate("DISPLAY", "evil\x00injection"));
}
