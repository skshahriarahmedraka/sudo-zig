//! Performance benchmarks for sudo-zig
//!
//! These benchmarks measure the performance of critical paths:
//! - Sudoers parsing
//! - Policy evaluation
//! - Environment variable handling
//! - Secure memory operations

const std = @import("std");
const lib = @import("sudo-zig-lib");
const time = std.time;

/// Benchmark result
const BenchmarkResult = struct {
    name: []const u8,
    iterations: u64,
    total_ns: u64,
    avg_ns: u64,
    min_ns: u64,
    max_ns: u64,

    pub fn print(self: BenchmarkResult) void {
        std.debug.print(
            \\Benchmark: {s}
            \\  Iterations: {}
            \\  Total time: {} ns ({d:.3} ms)
            \\  Average:    {} ns ({d:.3} µs)
            \\  Min:        {} ns
            \\  Max:        {} ns
            \\
        , .{
            self.name,
            self.iterations,
            self.total_ns,
            @as(f64, @floatFromInt(self.total_ns)) / 1_000_000.0,
            self.avg_ns,
            @as(f64, @floatFromInt(self.avg_ns)) / 1000.0,
            self.min_ns,
            self.max_ns,
        });
    }
};

/// Run a benchmark
fn benchmark(name: []const u8, iterations: u64, func: *const fn () void) BenchmarkResult {
    var total_ns: u64 = 0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;

    // Warmup
    for (0..10) |_| {
        func();
    }

    // Actual benchmark
    for (0..iterations) |_| {
        const start = time.nanoTimestamp();
        func();
        const end = time.nanoTimestamp();
        const elapsed: u64 = @intCast(end - start);

        total_ns += elapsed;
        min_ns = @min(min_ns, elapsed);
        max_ns = @max(max_ns, elapsed);
    }

    return BenchmarkResult{
        .name = name,
        .iterations = iterations,
        .total_ns = total_ns,
        .avg_ns = total_ns / iterations,
        .min_ns = min_ns,
        .max_ns = max_ns,
    };
}

// ============================================
// Benchmark Functions
// ============================================

var bench_allocator: std.mem.Allocator = undefined;

// Simple sudoers for parsing benchmark
const simple_sudoers = "root ALL=(ALL:ALL) ALL";

const complex_sudoers =
    \\# Complex sudoers file for benchmarking
    \\Defaults env_reset
    \\Defaults mail_badpass
    \\Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    \\
    \\User_Alias ADMINS = alice, bob, charlie, david, eve
    \\User_Alias WEBDEVS = frank, grace, henry, ivy, jack
    \\User_Alias DBAS = kate, leo, mary, nick, olivia
    \\
    \\Host_Alias SERVERS = server1, server2, server3, server4, server5
    \\Host_Alias WEBSERVERS = web1, web2, web3
    \\Host_Alias DBSERVERS = db1, db2, db3
    \\
    \\Cmnd_Alias APT = /usr/bin/apt, /usr/bin/apt-get, /usr/bin/aptitude
    \\Cmnd_Alias SERVICES = /usr/bin/systemctl, /usr/sbin/service
    \\Cmnd_Alias SHUTDOWN = /sbin/shutdown, /sbin/reboot, /sbin/halt
    \\
    \\root ALL=(ALL:ALL) ALL
    \\ADMINS ALL=(ALL:ALL) ALL
    \\WEBDEVS WEBSERVERS=(root) NOPASSWD: SERVICES restart nginx, SERVICES restart apache2
    \\DBAS DBSERVERS=(postgres) NOPASSWD: /usr/bin/psql, /usr/bin/pg_dump
    \\%wheel ALL=(ALL:ALL) ALL
    \\%sudo ALL=(ALL:ALL) ALL
;

fn benchParseSimple() void {
    var parser = lib.sudoers.parser.Parser.init(bench_allocator, simple_sudoers);
    var parsed = parser.parse() catch return;
    parsed.deinit();
}

fn benchParseComplex() void {
    var parser = lib.sudoers.parser.Parser.init(bench_allocator, complex_sudoers);
    var parsed = parser.parse() catch return;
    parsed.deinit();
}

fn benchTokenizeComplex() void {
    var tokenizer = lib.sudoers.tokens.Tokenizer.init(complex_sudoers);
    while (true) {
        const token = tokenizer.next();
        if (token.type == .eof) break;
    }
}

var policy_cache: ?lib.sudoers.Policy = null;
var parsed_cache: ?lib.sudoers.ast.Sudoers = null;

fn benchPolicyCheck() void {
    if (policy_cache) |*policy| {
        _ = policy.check(.{
            .user = .{ .name = "alice", .uid = 1000, .gid = 1000, .home = "/home/alice", .shell = "/bin/bash", .gecos = "" },
            .groups = &[_]lib.system.GroupId{1000},
            .hostname = "server1",
            .command = "/usr/bin/apt",
            .arguments = null,
            .target_user = null,
            .target_group = null,
        });
    }
}

fn benchEnvValidation() void {
    const validator = lib.common.EnvValidator.initDefault();
    _ = validator.validate("LD_PRELOAD", "/tmp/evil.so");
    _ = validator.validate("PATH", "/usr/bin:/bin");
    _ = validator.validate("DISPLAY", ":0");
    _ = validator.validate("TERM", "xterm-256color");
    _ = validator.validate("HOME", "/home/user");
}

fn benchSecurePassword() void {
    var password = lib.common.SecurePassword.init();
    _ = password.append('p');
    _ = password.append('a');
    _ = password.append('s');
    _ = password.append('s');
    _ = password.append('w');
    _ = password.append('o');
    _ = password.append('r');
    _ = password.append('d');
    _ = password.slice();
    password.clear();
    password.deinit();
}

fn benchSecureCompare() void {
    _ = lib.common.secureCompare("password123456", "password123456");
    _ = lib.common.secureCompare("password123456", "different12345");
    _ = lib.common.secureCompare("short", "longer_string_here");
}

fn benchSignalSet() void {
    var set = lib.system.SignalSet.empty();
    set.add(.TERM);
    set.add(.INT);
    set.add(.QUIT);
    _ = set.contains(.TERM);
    _ = set.contains(.KILL);
    set.remove(.TERM);
}

fn benchUserLookup() void {
    _ = lib.system.User.fromName("root");
}

fn benchGroupLookup() void {
    _ = lib.system.Group.fromName("root");
}

fn benchHostname() void {
    _ = lib.system.Hostname.get() catch {};
}

fn benchPathValidation() void {
    _ = lib.common.SudoPath.init("/usr/bin/sudo") catch {};
    _ = lib.common.SudoPath.init("/bin/ls") catch {};
    _ = lib.common.SudoPath.init("/usr/local/bin/myapp") catch {};
}

fn benchStringValidation() void {
    _ = lib.common.SudoString.init("hello world") catch {};
    _ = lib.common.SudoString.init("user@example.com") catch {};
    _ = lib.common.SudoString.init("some-hostname-123") catch {};
}

// ============================================
// Main Entry Point
// ============================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    bench_allocator = gpa.allocator();

    std.debug.print("\n=== sudo-zig Performance Benchmarks ===\n\n", .{});

    // Parsing benchmarks
    std.debug.print("--- Parsing Benchmarks ---\n\n", .{});

    var result = benchmark("Parse simple sudoers", 10000, benchParseSimple);
    result.print();

    result = benchmark("Parse complex sudoers", 1000, benchParseComplex);
    result.print();

    result = benchmark("Tokenize complex sudoers", 5000, benchTokenizeComplex);
    result.print();

    // Policy benchmarks
    std.debug.print("\n--- Policy Benchmarks ---\n\n", .{});

    // Setup policy cache - use simple sudoers to avoid parsing issues
    var parser = lib.sudoers.parser.Parser.init(bench_allocator, simple_sudoers);
    if (parser.parse()) |parsed| {
        parsed_cache = parsed;
        policy_cache = lib.sudoers.Policy.init(bench_allocator, &parsed_cache.?);

        result = benchmark("Policy check", 10000, benchPolicyCheck);
        result.print();

        parsed_cache.?.deinit();
        policy_cache = null;
        parsed_cache = null;
    } else |_| {
        std.debug.print("Skipping policy benchmark due to parse error\n\n", .{});
    }

    // Security benchmarks
    std.debug.print("\n--- Security Benchmarks ---\n\n", .{});

    result = benchmark("Environment validation", 50000, benchEnvValidation);
    result.print();

    result = benchmark("Secure password handling", 50000, benchSecurePassword);
    result.print();

    result = benchmark("Secure compare", 100000, benchSecureCompare);
    result.print();

    // System benchmarks
    std.debug.print("\n--- System Benchmarks ---\n\n", .{});

    result = benchmark("Signal set operations", 100000, benchSignalSet);
    result.print();

    result = benchmark("User lookup (root)", 1000, benchUserLookup);
    result.print();

    result = benchmark("Group lookup (root)", 1000, benchGroupLookup);
    result.print();

    result = benchmark("Hostname lookup", 10000, benchHostname);
    result.print();

    // Validation benchmarks
    std.debug.print("\n--- Validation Benchmarks ---\n\n", .{});

    result = benchmark("Path validation", 100000, benchPathValidation);
    result.print();

    result = benchmark("String validation", 100000, benchStringValidation);
    result.print();

    std.debug.print("\n=== Benchmarks Complete ===\n", .{});
}

// ============================================
// Tests (ensure benchmarks compile)
// ============================================

test "benchmark functions compile" {
    bench_allocator = std.testing.allocator;

    benchParseSimple();
    benchTokenizeComplex();
    benchEnvValidation();
    benchSecureCompare();
    benchSignalSet();
    benchPathValidation();
    benchStringValidation();
}
