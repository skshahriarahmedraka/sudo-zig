# Changelog

All notable changes to sudo-zig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-12

### 🎉 Initial Release - Feature Complete

This is the first feature-complete release of sudo-zig, a memory-safe implementation
of sudo written in Zig. This release achieves feature parity with traditional sudo
and sudo-rs.

### Added

#### Core Binaries
- **sudo** - Execute commands with elevated privileges
- **su** - Switch user identity
- **visudo** - Safely edit sudoers files with syntax validation

#### Sudoers Support
- Full sudoers file parsing with comprehensive grammar support
- User aliases, Host aliases, Cmnd aliases, Runas aliases
- Defaults settings (env_reset, secure_path, mail_badpass, etc.)
- `@include` and `@includedir` directives for modular configuration
- Command digest verification (SHA-224, SHA-256, SHA-384, SHA-512)
- Wildcard and pattern matching for commands and paths
- Negation support for users, hosts, and commands

#### Authentication & Security
- PAM authentication integration
- Credential timestamp caching with configurable timeout
- Rate limiting with exponential backoff for brute-force protection
- Secure memory handling for passwords (automatic zeroing, memory locking)
- Constant-time password comparison to prevent timing attacks
- Environment variable security (LD_PRELOAD, LD_LIBRARY_PATH filtering)
- PATH validation and sanitization

#### Enterprise Features
- **LDAP/SSSD Integration** - Centralized sudoers management via directory services
  - OpenLDAP support
  - SSSD (System Security Services Daemon) integration
  - Active Directory compatibility
  - sudoRole LDAP schema support
- **SELinux Support** - Security context management
  - Role and type transitions
  - Context parsing and validation
  - Enforcing/Permissive mode detection

#### Security Frameworks
- **AppArmor Integration** - Profile enforcement for contained execution
  - changeProfile, setExecProfile, stackProfile support
- **SELinux Integration** - Mandatory access control support

#### Logging & Auditing
- Syslog integration
- File-based audit logging
- JSON structured logging
- Mail notifications for security events

#### Process Execution
- PTY allocation for interactive commands
- Signal forwarding (SIGTERM, SIGINT, SIGQUIT, etc.)
- Session management
- Close-on-exec handling for file descriptors
- Timeout support for command execution

#### Additional Features
- First-use lecture display
- `sudoedit` mode for safe file editing
- Internationalization (i18n) with gettext support
- Network/IP address matching in host rules
- Comprehensive error handling and reporting

### Performance

Benchmark results (ReleaseFast build):

| Operation | Average Time | Notes |
|-----------|-------------|-------|
| Parse simple sudoers | 7.5 µs | Single rule |
| Parse complex sudoers | 44.5 µs | Multi-rule with aliases |
| Tokenize sudoers | 2.5 µs | Lexical analysis |
| Policy check | 19 ns | Authorization lookup |
| Environment validation | 732 ns | Security check |
| Secure password handling | 80 ns | Buffer operations |
| Secure compare | 13 ns | Constant-time |
| User lookup | 2.8 µs | NSS query |
| Group lookup | 2.8 µs | NSS query |
| Hostname lookup | 219 ns | Cached |
| Path validation | 13 ns | Security check |
| String validation | 13 ns | Security check |

### Testing

Comprehensive test suite with 700+ tests:
- Unit tests for all modules
- Integration tests for cross-module functionality
- Compliance tests for sudo/sudo-rs behavior parity
- End-to-end tests for full workflows

### Build Requirements

- Zig 0.15.0 or later
- Linux (primary target)
- Optional: libpam-dev for PAM support
- Optional: libapparmor-dev for AppArmor support

### Build Commands

```bash
# Build all binaries
zig build

# Run tests
zig build test

# Run benchmarks
zig build benchmark

# Build with PAM support
zig build -Dpam=true

# Build with AppArmor support
zig build -Dapparmor=true

# Build with all features
zig build -Dpam=true -Dapparmor=true -Dgettext=true
```

### Additional Features (Latest Update)

#### I/O Session Logging (`src/lib/log/iolog.zig`)
- Session recording with timestamps (sudo-compatible format)
- Configurable logging for stdin, stdout, stderr, TTY I/O
- Timing file for synchronized replay
- Session metadata in JSON format
- Log rotation and retention policies

#### Seccomp Sandboxing (`src/lib/system/seccomp.zig`)
- Linux seccomp-bpf syscall filtering
- Predefined security profiles:
  - `strict` - Minimal syscalls for basic I/O
  - `standard` - Block dangerous operations (modules, debugging, BPF)
  - `permissive` - Only block kernel module loading
  - `noexec` - Prevent exec* syscalls
- Custom syscall rules with argument filters
- BPF program generation

#### Plugin API (`src/lib/sudo/plugin.zig`)
- Extensible architecture for custom modules
- Plugin types: Policy, I/O Log, Audit, Authentication
- Plugin registry for managing multiple plugins
- Example implementations included

### Known Limitations

- Requires root privileges for full functionality
- Some features require specific kernel/system support
- LDAP/SSSD requires appropriate system configuration

### Security Considerations

This implementation prioritizes memory safety through Zig's compile-time checks
and safe memory handling. Key security features:

- No buffer overflows possible in safe Zig code
- Automatic memory zeroing for sensitive data
- Constant-time comparisons for authentication
- Strict input validation throughout
- Defense-in-depth with multiple security layers

### Contributors

- Initial implementation and architecture

### License

See LICENSE file for details.

---

## Future Plans

- [ ] macOS support
- [ ] FreeBSD support
- [ ] sudo_logsrvd compatibility
- [ ] I/O logging
- [ ] Plugin API

[0.1.0]: https://github.com/sudo-zig/sudo-zig/releases/tag/v0.1.0
