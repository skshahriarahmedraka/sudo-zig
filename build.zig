const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options (compile-time features)
    const pam_login = b.option(bool, "pam-login", "Use 'sudo-i' PAM service for login shells (Debian/Fedora)") orelse false;
    const apparmor = b.option(bool, "apparmor", "Enable AppArmor profile enforcement") orelse false;
    const gettext = b.option(bool, "gettext", "Enable internationalization support") orelse false;
    const dev_mode = b.option(bool, "dev", "Enable development logging (INSECURE)") orelse false;
    const enable_pam = b.option(bool, "pam", "Enable PAM authentication (requires libpam)") orelse false;

    // Build options struct for compile-time configuration
    const build_options = b.addOptions();
    build_options.addOption(bool, "pam_login", pam_login);
    build_options.addOption(bool, "apparmor", apparmor);
    build_options.addOption(bool, "gettext", gettext);
    build_options.addOption(bool, "dev_mode", dev_mode);
    build_options.addOption(bool, "enable_pam", enable_pam);

    // ============================================
    // Shared Library Module
    // ============================================
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/lib/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_module.addOptions("build_options", build_options);
    lib_module.link_libc = true;

    // ============================================
    // sudo executable
    // ============================================
    const sudo_module = b.createModule(.{
        .root_source_file = b.path("src/bin/sudo.zig"),
        .target = target,
        .optimize = optimize,
    });
    sudo_module.addImport("sudo-zig-lib", lib_module);
    sudo_module.addOptions("build_options", build_options);
    sudo_module.link_libc = true;

    const sudo_exe = b.addExecutable(.{
        .name = "sudo",
        .root_module = sudo_module,
    });
    if (enable_pam) {
        sudo_exe.linkSystemLibrary("pam");
    }
    if (apparmor) {
        sudo_exe.linkSystemLibrary("apparmor");
    }

    b.installArtifact(sudo_exe);

    // ============================================
    // su executable
    // ============================================
    const su_module = b.createModule(.{
        .root_source_file = b.path("src/bin/su.zig"),
        .target = target,
        .optimize = optimize,
    });
    su_module.addImport("sudo-zig-lib", lib_module);
    su_module.addOptions("build_options", build_options);
    su_module.link_libc = true;

    const su_exe = b.addExecutable(.{
        .name = "su",
        .root_module = su_module,
    });
    if (enable_pam) {
        su_exe.linkSystemLibrary("pam");
    }

    b.installArtifact(su_exe);

    // ============================================
    // visudo executable
    // ============================================
    const visudo_module = b.createModule(.{
        .root_source_file = b.path("src/bin/visudo.zig"),
        .target = target,
        .optimize = optimize,
    });
    visudo_module.addImport("sudo-zig-lib", lib_module);
    visudo_module.addOptions("build_options", build_options);
    visudo_module.link_libc = true;

    const visudo_exe = b.addExecutable(.{
        .name = "visudo",
        .root_module = visudo_module,
    });

    b.installArtifact(visudo_exe);

    // ============================================
    // Unit Tests
    // ============================================
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/lib/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addOptions("build_options", build_options);
    test_module.link_libc = true;

    const lib_unit_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // ============================================
    // External Unit Tests (tests/unit/)
    // ============================================
    
    // Sudoers tokenizer tests
    const tokens_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/sudoers/tokens_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    tokens_test_module.addImport("sudo-zig-lib", lib_module);
    tokens_test_module.link_libc = true;
    const tokens_tests = b.addTest(.{ .root_module = tokens_test_module });
    const run_tokens_tests = b.addRunArtifact(tokens_tests);

    // Sudoers parser tests
    const parser_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/sudoers/parser_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    parser_test_module.addImport("sudo-zig-lib", lib_module);
    parser_test_module.link_libc = true;
    const parser_tests = b.addTest(.{ .root_module = parser_test_module });
    const run_parser_tests = b.addRunArtifact(parser_tests);

    // Common string tests
    const string_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/string_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    string_test_module.addImport("sudo-zig-lib", lib_module);
    string_test_module.link_libc = true;
    const string_tests = b.addTest(.{ .root_module = string_test_module });
    const run_string_tests = b.addRunArtifact(string_tests);

    // Common path tests
    const path_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/path_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    path_test_module.addImport("sudo-zig-lib", lib_module);
    path_test_module.link_libc = true;
    const path_tests = b.addTest(.{ .root_module = path_test_module });
    const run_path_tests = b.addRunArtifact(path_tests);

    // System user tests
    const user_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/system/user_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    user_test_module.addImport("sudo-zig-lib", lib_module);
    user_test_module.link_libc = true;
    const user_tests = b.addTest(.{ .root_module = user_test_module });
    const run_user_tests = b.addRunArtifact(user_tests);

    // Network tests
    const network_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/network_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    network_test_module.addImport("sudo-zig-lib", lib_module);
    network_test_module.link_libc = true;
    const network_tests = b.addTest(.{ .root_module = network_test_module });
    const run_network_tests = b.addRunArtifact(network_tests);

    // Defaults/Settings tests
    const defaults_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/defaults/defaults_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    defaults_test_module.addImport("sudo-zig-lib", lib_module);
    defaults_test_module.link_libc = true;
    const defaults_tests = b.addTest(.{ .root_module = defaults_test_module });
    const run_defaults_tests = b.addRunArtifact(defaults_tests);

    // Log tests (logging, mail, audit)
    const log_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/log/log_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    log_test_module.addImport("sudo-zig-lib", lib_module);
    log_test_module.link_libc = true;
    const log_tests = b.addTest(.{ .root_module = log_test_module });
    const run_log_tests = b.addRunArtifact(log_tests);

    // Signal tests
    const signal_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/system/signal_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    signal_test_module.addImport("sudo-zig-lib", lib_module);
    signal_test_module.link_libc = true;
    const signal_tests = b.addTest(.{ .root_module = signal_test_module });
    const run_signal_tests = b.addRunArtifact(signal_tests);

    // Command tests
    const command_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/command_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    command_test_module.addImport("sudo-zig-lib", lib_module);
    command_test_module.link_libc = true;
    const command_tests = b.addTest(.{ .root_module = command_test_module });
    const run_command_tests = b.addRunArtifact(command_tests);

    // Digest tests
    const digest_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/digest_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    digest_test_module.addImport("sudo-zig-lib", lib_module);
    digest_test_module.link_libc = true;
    const digest_tests = b.addTest(.{ .root_module = digest_test_module });
    const run_digest_tests = b.addRunArtifact(digest_tests);

    // Context tests
    const context_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/context_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    context_test_module.addImport("sudo-zig-lib", lib_module);
    context_test_module.link_libc = true;
    const context_tests = b.addTest(.{ .root_module = context_test_module });
    const run_context_tests = b.addRunArtifact(context_tests);

    // Error tests
    const error_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/error_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    error_test_module.addImport("sudo-zig-lib", lib_module);
    error_test_module.link_libc = true;
    const error_tests = b.addTest(.{ .root_module = error_test_module });
    const run_error_tests = b.addRunArtifact(error_tests);

    // Exec/PTY tests
    const exec_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/exec/exec_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    exec_test_module.addImport("sudo-zig-lib", lib_module);
    exec_test_module.link_libc = true;
    const exec_tests = b.addTest(.{ .root_module = exec_test_module });
    const run_exec_tests = b.addRunArtifact(exec_tests);

    // Policy tests
    const policy_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/sudoers/policy_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    policy_test_module.addImport("sudo-zig-lib", lib_module);
    policy_test_module.link_libc = true;
    const policy_tests = b.addTest(.{ .root_module = policy_test_module });
    const run_policy_tests = b.addRunArtifact(policy_tests);

    // AppArmor tests
    const apparmor_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/system/apparmor_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    apparmor_test_module.addImport("sudo-zig-lib", lib_module);
    apparmor_test_module.addOptions("build_options", build_options);
    apparmor_test_module.link_libc = true;
    const apparmor_tests = b.addTest(.{ .root_module = apparmor_test_module });
    const run_apparmor_tests = b.addRunArtifact(apparmor_tests);

    // Timestamp tests
    const timestamp_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/system/timestamp_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    timestamp_test_module.addImport("sudo-zig-lib", lib_module);
    timestamp_test_module.link_libc = true;
    const timestamp_tests = b.addTest(.{ .root_module = timestamp_test_module });
    const run_timestamp_tests = b.addRunArtifact(timestamp_tests);

    // i18n tests
    const i18n_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/common/i18n_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    i18n_test_module.addImport("sudo-zig-lib", lib_module);
    i18n_test_module.addOptions("build_options", build_options);
    i18n_test_module.link_libc = true;
    const i18n_tests = b.addTest(.{ .root_module = i18n_test_module });
    const run_i18n_tests = b.addRunArtifact(i18n_tests);

    // su tests
    const su_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/su/su_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    su_test_module.addImport("sudo-zig-lib", lib_module);
    su_test_module.link_libc = true;
    const su_tests = b.addTest(.{ .root_module = su_test_module });
    const run_su_tests = b.addRunArtifact(su_tests);

    // visudo tests
    const visudo_test_module = b.createModule(.{
        .root_source_file = b.path("tests/unit/visudo/visudo_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    visudo_test_module.addImport("sudo-zig-lib", lib_module);
    visudo_test_module.link_libc = true;
    const visudo_tests = b.addTest(.{ .root_module = visudo_test_module });
    const run_visudo_tests = b.addRunArtifact(visudo_tests);

    // Test step for unit tests
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_tokens_tests.step);
    test_step.dependOn(&run_parser_tests.step);
    test_step.dependOn(&run_string_tests.step);
    test_step.dependOn(&run_path_tests.step);
    test_step.dependOn(&run_user_tests.step);
    test_step.dependOn(&run_network_tests.step);
    test_step.dependOn(&run_defaults_tests.step);
    test_step.dependOn(&run_log_tests.step);
    test_step.dependOn(&run_signal_tests.step);
    test_step.dependOn(&run_command_tests.step);
    test_step.dependOn(&run_digest_tests.step);
    test_step.dependOn(&run_context_tests.step);
    test_step.dependOn(&run_error_tests.step);
    test_step.dependOn(&run_exec_tests.step);
    test_step.dependOn(&run_policy_tests.step);
    test_step.dependOn(&run_apparmor_tests.step);
    test_step.dependOn(&run_timestamp_tests.step);
    test_step.dependOn(&run_i18n_tests.step);
    test_step.dependOn(&run_su_tests.step);
    test_step.dependOn(&run_visudo_tests.step);

    // ============================================
    // Run targets for development
    // ============================================
    const run_sudo = b.addRunArtifact(sudo_exe);
    run_sudo.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_sudo.addArgs(args);
    }

    const run_step = b.step("run", "Run sudo with arguments");
    run_step.dependOn(&run_sudo.step);

    // ============================================
    // Format step
    // ============================================
    const fmt = b.addFmt(.{
        .paths = &.{
            "src",
            "tests",
            "build.zig",
        },
    });
    const fmt_step = b.step("fmt", "Format source code");
    fmt_step.dependOn(&fmt.step);

    // ============================================
    // Check step
    // ============================================
    const check_step = b.step("check", "Check if code compiles without errors");
    check_step.dependOn(&sudo_exe.step);
}
