//! Seccomp sandboxing for sudo
//!
//! This module provides Linux seccomp-bpf (Secure Computing Mode) support
//! for restricting system calls available to executed commands.
//!
//! Features:
//! - Predefined security profiles (strict, standard, permissive)
//! - Custom syscall filtering rules
//! - NOEXEC implementation via seccomp
//! - Audit logging of blocked syscalls

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// Seccomp action for matched syscalls
pub const Action = enum(u32) {
    /// Kill the process
    kill_process = 0x80000000,
    /// Kill the thread
    kill_thread = 0x00000000,
    /// Send SIGSYS signal
    trap = 0x00030000,
    /// Return EPERM (common case)
    errno_perm = 0x00050001,
    /// Return ENOSYS
    errno_nosys = 0x00050026,
    /// Return EACCES
    errno_acces = 0x0005000d,
    /// Log and allow (kernel 4.14+)
    log = 0x7ffc0000,
    /// Allow the syscall
    allow = 0x7fff0000,
    /// Notify userspace (kernel 5.0+)
    user_notif = 0x7fc00000,

    /// Create errno action with specific error code
    pub fn withErrno(err: u16) u32 {
        return 0x00050000 | @as(u32, err);
    }
};

/// Syscall numbers for x86_64
pub const Syscall = enum(u32) {
    read = 0,
    write = 1,
    open = 2,
    close = 3,
    stat = 4,
    fstat = 5,
    lstat = 6,
    poll = 7,
    lseek = 8,
    mmap = 9,
    mprotect = 10,
    munmap = 11,
    brk = 12,
    rt_sigaction = 13,
    rt_sigprocmask = 14,
    rt_sigreturn = 15,
    ioctl = 16,
    pread64 = 17,
    pwrite64 = 18,
    readv = 19,
    writev = 20,
    access = 21,
    pipe = 22,
    select = 23,
    sched_yield = 24,
    mremap = 25,
    msync = 26,
    mincore = 27,
    madvise = 28,
    shmget = 29,
    shmat = 30,
    shmctl = 31,
    dup = 32,
    dup2 = 33,
    pause = 34,
    nanosleep = 35,
    getitimer = 36,
    alarm = 37,
    setitimer = 38,
    getpid = 39,
    sendfile = 40,
    socket = 41,
    connect = 42,
    accept = 43,
    sendto = 44,
    recvfrom = 45,
    sendmsg = 46,
    recvmsg = 47,
    shutdown = 48,
    bind = 49,
    listen = 50,
    getsockname = 51,
    getpeername = 52,
    socketpair = 53,
    setsockopt = 54,
    getsockopt = 55,
    clone = 56,
    fork = 57,
    vfork = 58,
    execve = 59,
    exit = 60,
    wait4 = 61,
    kill = 62,
    uname = 63,
    fcntl = 72,
    flock = 73,
    fsync = 74,
    fdatasync = 75,
    truncate = 76,
    ftruncate = 77,
    getdents = 78,
    getcwd = 79,
    chdir = 80,
    fchdir = 81,
    rename = 82,
    mkdir = 83,
    rmdir = 84,
    creat = 85,
    link = 86,
    unlink = 87,
    symlink = 88,
    readlink = 89,
    chmod = 90,
    fchmod = 91,
    chown = 92,
    fchown = 93,
    lchown = 94,
    umask = 95,
    gettimeofday = 96,
    getrlimit = 97,
    getrusage = 98,
    sysinfo = 99,
    times = 100,
    ptrace = 101,
    getuid = 102,
    syslog = 103,
    getgid = 104,
    setuid = 105,
    setgid = 106,
    geteuid = 107,
    getegid = 108,
    setpgid = 109,
    getppid = 110,
    getpgrp = 111,
    setsid = 112,
    setreuid = 113,
    setregid = 114,
    getgroups = 115,
    setgroups = 116,
    setresuid = 117,
    getresuid = 118,
    setresgid = 119,
    getresgid = 120,
    getpgid = 121,
    setfsuid = 122,
    setfsgid = 123,
    getsid = 124,
    capget = 125,
    capset = 126,
    rt_sigpending = 127,
    rt_sigtimedwait = 128,
    rt_sigqueueinfo = 129,
    rt_sigsuspend = 130,
    sigaltstack = 131,
    utime = 132,
    mknod = 133,
    personality = 135,
    statfs = 137,
    fstatfs = 138,
    getpriority = 140,
    setpriority = 141,
    sched_setparam = 142,
    sched_getparam = 143,
    sched_setscheduler = 144,
    sched_getscheduler = 145,
    sched_get_priority_max = 146,
    sched_get_priority_min = 147,
    sched_rr_get_interval = 148,
    mlock = 149,
    munlock = 150,
    mlockall = 151,
    munlockall = 152,
    vhangup = 153,
    pivot_root = 155,
    prctl = 157,
    arch_prctl = 158,
    adjtimex = 159,
    setrlimit = 160,
    chroot = 161,
    sync = 162,
    acct = 163,
    settimeofday = 164,
    mount = 165,
    umount2 = 166,
    swapon = 167,
    swapoff = 168,
    reboot = 169,
    sethostname = 170,
    setdomainname = 171,
    iopl = 172,
    ioperm = 173,
    init_module = 175,
    delete_module = 176,
    quotactl = 179,
    gettid = 186,
    readahead = 187,
    setxattr = 188,
    lsetxattr = 189,
    fsetxattr = 190,
    getxattr = 191,
    lgetxattr = 192,
    fgetxattr = 193,
    listxattr = 194,
    llistxattr = 195,
    flistxattr = 196,
    removexattr = 197,
    lremovexattr = 198,
    fremovexattr = 199,
    tkill = 200,
    time = 201,
    futex = 202,
    sched_setaffinity = 203,
    sched_getaffinity = 204,
    io_setup = 206,
    io_destroy = 207,
    io_getevents = 208,
    io_submit = 209,
    io_cancel = 210,
    epoll_create = 213,
    getdents64 = 217,
    set_tid_address = 218,
    restart_syscall = 219,
    semtimedop = 220,
    fadvise64 = 221,
    timer_create = 222,
    timer_settime = 223,
    timer_gettime = 224,
    timer_getoverrun = 225,
    timer_delete = 226,
    clock_settime = 227,
    clock_gettime = 228,
    clock_getres = 229,
    clock_nanosleep = 230,
    exit_group = 231,
    epoll_wait = 232,
    epoll_ctl = 233,
    tgkill = 234,
    utimes = 235,
    mbind = 237,
    set_mempolicy = 238,
    get_mempolicy = 239,
    mq_open = 240,
    mq_unlink = 241,
    mq_timedsend = 242,
    mq_timedreceive = 243,
    mq_notify = 244,
    mq_getsetattr = 245,
    kexec_load = 246,
    waitid = 247,
    add_key = 248,
    request_key = 249,
    keyctl = 250,
    ioprio_set = 251,
    ioprio_get = 252,
    inotify_init = 253,
    inotify_add_watch = 254,
    inotify_rm_watch = 255,
    migrate_pages = 256,
    openat = 257,
    mkdirat = 258,
    mknodat = 259,
    fchownat = 260,
    futimesat = 261,
    newfstatat = 262,
    unlinkat = 263,
    renameat = 264,
    linkat = 265,
    symlinkat = 266,
    readlinkat = 267,
    fchmodat = 268,
    faccessat = 269,
    pselect6 = 270,
    ppoll = 271,
    unshare = 272,
    set_robust_list = 273,
    get_robust_list = 274,
    splice = 275,
    tee = 276,
    sync_file_range = 277,
    vmsplice = 278,
    move_pages = 279,
    utimensat = 280,
    epoll_pwait = 281,
    signalfd = 282,
    timerfd_create = 283,
    eventfd = 284,
    fallocate = 285,
    timerfd_settime = 286,
    timerfd_gettime = 287,
    accept4 = 288,
    signalfd4 = 289,
    eventfd2 = 290,
    epoll_create1 = 291,
    dup3 = 292,
    pipe2 = 293,
    inotify_init1 = 294,
    preadv = 295,
    pwritev = 296,
    rt_tgsigqueueinfo = 297,
    perf_event_open = 298,
    recvmmsg = 299,
    fanotify_init = 300,
    fanotify_mark = 301,
    prlimit64 = 302,
    name_to_handle_at = 303,
    open_by_handle_at = 304,
    clock_adjtime = 305,
    syncfs = 306,
    sendmmsg = 307,
    setns = 308,
    getcpu = 309,
    process_vm_readv = 310,
    process_vm_writev = 311,
    kcmp = 312,
    finit_module = 313,
    sched_setattr = 314,
    sched_getattr = 315,
    renameat2 = 316,
    seccomp = 317,
    getrandom = 318,
    memfd_create = 319,
    kexec_file_load = 320,
    bpf = 321,
    execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,

    _,
};

/// Seccomp filter rule
pub const Rule = struct {
    /// Syscall number (or null for default action)
    syscall: ?Syscall,
    /// Action to take
    action: Action,
    /// Optional argument filters (for conditional rules)
    arg_filters: ?[]const ArgFilter = null,
};

/// Argument filter for conditional rules
pub const ArgFilter = struct {
    /// Argument index (0-5)
    arg_index: u3,
    /// Comparison operator
    op: Operator,
    /// Value to compare against
    value: u64,

    pub const Operator = enum {
        eq, // ==
        ne, // !=
        lt, // <
        le, // <=
        gt, // >
        ge, // >=
        masked_eq, // (arg & mask) == value
    };
};

/// Predefined security profiles
pub const Profile = enum {
    /// Block everything except basic I/O and process management
    strict,
    /// Standard profile - block dangerous syscalls
    standard,
    /// Permissive - only block the most dangerous syscalls
    permissive,
    /// NOEXEC mode - prevent exec* syscalls
    noexec,
    /// Custom rules
    custom,

    /// Get rules for this profile
    pub fn getRules(self: Profile) []const Rule {
        return switch (self) {
            .strict => &strict_rules,
            .standard => &standard_rules,
            .permissive => &permissive_rules,
            .noexec => &noexec_rules,
            .custom => &[_]Rule{},
        };
    }
};

/// Strict profile rules - very restrictive
const strict_rules = [_]Rule{
    // Default: deny
    .{ .syscall = null, .action = .kill_process },
    // Allow basic I/O
    .{ .syscall = .read, .action = .allow },
    .{ .syscall = .write, .action = .allow },
    .{ .syscall = .close, .action = .allow },
    .{ .syscall = .fstat, .action = .allow },
    .{ .syscall = .lseek, .action = .allow },
    // Memory management
    .{ .syscall = .mmap, .action = .allow },
    .{ .syscall = .mprotect, .action = .allow },
    .{ .syscall = .munmap, .action = .allow },
    .{ .syscall = .brk, .action = .allow },
    // Signals
    .{ .syscall = .rt_sigaction, .action = .allow },
    .{ .syscall = .rt_sigprocmask, .action = .allow },
    .{ .syscall = .rt_sigreturn, .action = .allow },
    // Exit
    .{ .syscall = .exit, .action = .allow },
    .{ .syscall = .exit_group, .action = .allow },
};

/// Standard profile rules
const standard_rules = [_]Rule{
    // Default: allow most
    .{ .syscall = null, .action = .allow },
    // Block dangerous kernel operations
    .{ .syscall = .init_module, .action = .errno_perm },
    .{ .syscall = .finit_module, .action = .errno_perm },
    .{ .syscall = .delete_module, .action = .errno_perm },
    .{ .syscall = .kexec_load, .action = .errno_perm },
    .{ .syscall = .kexec_file_load, .action = .errno_perm },
    .{ .syscall = .reboot, .action = .errno_perm },
    .{ .syscall = .swapon, .action = .errno_perm },
    .{ .syscall = .swapoff, .action = .errno_perm },
    // Block namespace manipulation
    .{ .syscall = .setns, .action = .errno_perm },
    .{ .syscall = .unshare, .action = .errno_perm },
    // Block debugging
    .{ .syscall = .ptrace, .action = .errno_perm },
    .{ .syscall = .process_vm_readv, .action = .errno_perm },
    .{ .syscall = .process_vm_writev, .action = .errno_perm },
    // Block BPF
    .{ .syscall = .bpf, .action = .errno_perm },
    // Block userfaultfd (can be used for exploits)
    .{ .syscall = .userfaultfd, .action = .errno_perm },
};

/// Permissive profile rules
const permissive_rules = [_]Rule{
    // Default: allow
    .{ .syscall = null, .action = .allow },
    // Only block kernel module loading
    .{ .syscall = .init_module, .action = .errno_perm },
    .{ .syscall = .finit_module, .action = .errno_perm },
    .{ .syscall = .delete_module, .action = .errno_perm },
};

/// NOEXEC profile - prevent executing new programs
const noexec_rules = [_]Rule{
    // Default: allow
    .{ .syscall = null, .action = .allow },
    // Block exec syscalls
    .{ .syscall = .execve, .action = .errno_perm },
    .{ .syscall = .execveat, .action = .errno_perm },
};

/// Seccomp filter context
pub const SeccompFilter = struct {
    allocator: Allocator,
    rules: std.ArrayListUnmanaged(Rule),
    default_action: Action,
    log_blocked: bool,

    const Self = @This();

    /// Create a new seccomp filter
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .rules = .{},
            .default_action = .allow,
            .log_blocked = true,
        };
    }

    /// Create from a predefined profile
    pub fn fromProfile(allocator: Allocator, profile: Profile) !Self {
        var filter = init(allocator);

        const profile_rules = profile.getRules();
        for (profile_rules) |rule| {
            try filter.addRule(rule);
        }

        return filter;
    }

    /// Add a rule to the filter
    pub fn addRule(self: *Self, rule: Rule) !void {
        if (rule.syscall == null) {
            self.default_action = rule.action;
        } else {
            try self.rules.append(self.allocator, rule);
        }
    }

    /// Allow a specific syscall
    pub fn allow(self: *Self, syscall: Syscall) !void {
        try self.addRule(.{ .syscall = syscall, .action = .allow });
    }

    /// Block a specific syscall with EPERM
    pub fn block(self: *Self, syscall: Syscall) !void {
        try self.addRule(.{
            .syscall = syscall,
            .action = .errno_perm,
        });
    }

    /// Block a syscall and kill the process
    pub fn blockFatal(self: *Self, syscall: Syscall) !void {
        try self.addRule(.{ .syscall = syscall, .action = .kill_process });
    }

    /// Apply the filter to the current process
    pub fn apply(self: *Self) !void {
        // First, set no_new_privs to allow unprivileged seccomp
        try setNoNewPrivs();

        // Build BPF program from rules
        const prog = try self.buildBpfProgram();
        defer self.allocator.free(prog);

        // Apply seccomp filter
        try seccompSetModeFilter(prog);
    }

    /// Build BPF program from rules
    fn buildBpfProgram(self: *Self) ![]const BpfInsn {
        var insns: std.ArrayListUnmanaged(BpfInsn) = .{};
        errdefer insns.deinit(self.allocator);

        // Load syscall number: A = syscall_nr
        try insns.append(self.allocator, BpfInsn.load_syscall_nr());

        // Check each rule
        for (self.rules.items) |rule| {
            if (rule.syscall) |syscall| {
                // JEQ syscall, action - use the action's integer value directly
                _ = rule.action;

                // Jump if equal to syscall number
                try insns.append(self.allocator, BpfInsn.jeq(@intFromEnum(syscall), 0, 1));
                try insns.append(self.allocator, BpfInsn.ret(@intFromEnum(rule.action)));
            }
        }

        // Default action
        try insns.append(self.allocator, BpfInsn.ret(@intFromEnum(self.default_action)));

        return insns.toOwnedSlice(self.allocator);
    }

    /// Clean up
    pub fn deinit(self: *Self) void {
        self.rules.deinit(self.allocator);
    }
};

/// BPF instruction structure
const BpfInsn = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,

    // BPF instruction classes
    const BPF_LD: u16 = 0x00;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;

    // BPF sizes
    const BPF_W: u16 = 0x00;

    // BPF modes
    const BPF_ABS: u16 = 0x20;
    const BPF_K: u16 = 0x00;

    // BPF jump operations
    const BPF_JEQ: u16 = 0x10;

    // Seccomp data offsets
    const SECCOMP_DATA_NR: u32 = 0; // offsetof(struct seccomp_data, nr)

    /// Load syscall number
    pub fn load_syscall_nr() BpfInsn {
        return .{
            .code = BPF_LD | BPF_W | BPF_ABS,
            .jt = 0,
            .jf = 0,
            .k = SECCOMP_DATA_NR,
        };
    }

    /// Jump if equal
    pub fn jeq(val: u32, jt: u8, jf: u8) BpfInsn {
        return .{
            .code = BPF_JMP | BPF_JEQ | BPF_K,
            .jt = jt,
            .jf = jf,
            .k = val,
        };
    }

    /// Return action
    pub fn ret(val: u32) BpfInsn {
        return .{
            .code = BPF_RET | BPF_K,
            .jt = 0,
            .jf = 0,
            .k = val,
        };
    }
};

/// Set PR_SET_NO_NEW_PRIVS
fn setNoNewPrivs() !void {
    const PR_SET_NO_NEW_PRIVS: c_int = 38;
    const result = std.os.linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (result != 0) {
        return error.PrctlFailed;
    }
}

/// Apply seccomp filter using SECCOMP_SET_MODE_FILTER
fn seccompSetModeFilter(prog: []const BpfInsn) !void {
    const SockFprog = extern struct {
        len: u16,
        filter: [*]const BpfInsn,
    };

    const fprog = SockFprog{
        .len = @intCast(prog.len),
        .filter = prog.ptr,
    };

    const SECCOMP_SET_MODE_FILTER: c_int = 1;
    const SECCOMP_FILTER_FLAG_LOG: c_int = 2;

    const result = std.os.linux.syscall3(
        .seccomp,
        @intCast(SECCOMP_SET_MODE_FILTER),
        @intCast(SECCOMP_FILTER_FLAG_LOG),
        @intFromPtr(&fprog),
    );

    if (result != 0) {
        return error.SeccompFailed;
    }
}

/// Check if seccomp is available
pub fn isAvailable() bool {
    const PR_GET_SECCOMP: c_int = 21;
    const result = std.os.linux.prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return result >= 0;
}

/// Get current seccomp mode
pub fn getMode() ?u32 {
    const PR_GET_SECCOMP: c_int = 21;
    const result = std.os.linux.prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (result < 0) return null;
    return @intCast(result);
}

// ============================================
// Tests
// ============================================

test "Action values" {
    try std.testing.expectEqual(@as(u32, 0x7fff0000), @intFromEnum(Action.allow));
    try std.testing.expectEqual(@as(u32, 0x80000000), @intFromEnum(Action.kill_process));
}

test "Action.withErrno" {
    const action = Action.withErrno(1); // EPERM
    try std.testing.expectEqual(@as(u32, 0x00050001), action);
}

test "Profile.getRules returns non-empty for standard" {
    const rules = Profile.standard.getRules();
    try std.testing.expect(rules.len > 0);
}

test "Profile.getRules returns noexec rules" {
    const rules = Profile.noexec.getRules();
    var has_execve = false;
    for (rules) |rule| {
        if (rule.syscall) |sc| {
            if (sc == .execve) has_execve = true;
        }
    }
    try std.testing.expect(has_execve);
}

test "SeccompFilter init" {
    var filter = SeccompFilter.init(std.testing.allocator);
    defer filter.deinit();

    try std.testing.expectEqual(Action.allow, filter.default_action);
}

test "SeccompFilter fromProfile" {
    var filter = try SeccompFilter.fromProfile(std.testing.allocator, .standard);
    defer filter.deinit();

    try std.testing.expect(filter.rules.items.len > 0);
}

test "SeccompFilter addRule" {
    var filter = SeccompFilter.init(std.testing.allocator);
    defer filter.deinit();

    try filter.allow(.read);
    try filter.block(.ptrace);

    try std.testing.expectEqual(@as(usize, 2), filter.rules.items.len);
}

test "BpfInsn load_syscall_nr" {
    const insn = BpfInsn.load_syscall_nr();
    try std.testing.expectEqual(@as(u16, 0x20), insn.code); // BPF_LD | BPF_W | BPF_ABS
    try std.testing.expectEqual(@as(u32, 0), insn.k);
}

test "BpfInsn ret" {
    const insn = BpfInsn.ret(@intFromEnum(Action.allow));
    try std.testing.expectEqual(@as(u16, 0x06), insn.code); // BPF_RET | BPF_K
    try std.testing.expectEqual(@as(u32, 0x7fff0000), insn.k);
}

test "isAvailable does not crash" {
    _ = isAvailable();
}

test "getMode does not crash" {
    _ = getMode();
}

test "Syscall enum values" {
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(Syscall.read));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(Syscall.write));
    try std.testing.expectEqual(@as(u32, 59), @intFromEnum(Syscall.execve));
    try std.testing.expectEqual(@as(u32, 317), @intFromEnum(Syscall.seccomp));
}
