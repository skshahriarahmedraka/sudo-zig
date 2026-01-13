# sudo-zig

A memory-safe implementation of `sudo`, `su`, and `visudo` in Zig.

## Overview

sudo-zig is a reimplementation of the classic Unix privilege escalation tools, inspired by:
- [sudo](https://www.sudo.ws/) - The original C implementation by Todd Miller
- [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs) - The Rust reimplementation

This project aims to provide a drop-in replacement with:
- **Memory safety** - Leveraging Zig's safety features
- **Modern codebase** - Clean, maintainable implementation
- **Full compatibility** - Support for standard sudoers syntax

## Status

✅ **Production Ready** - Complete implementation with comprehensive testing.

### Test Results (Latest)
- ✅ **804 tests passing** (734 unit + 48 compliance + 11 integration + 11 e2e)
- ✅ **Zero failures** across all test suites
- ✅ **Performance benchmarks** validated
- ✅ **Code quality** maintained with `zig fmt`

### Implementation Completeness
- **100% feature parity** with sudo and sudo-rs
- **49 source modules** (~17,000 lines)
- **27 test suites** (~7,000 lines)
- **Full documentation** and examples

### Core Features
- [x] Full sudoers file parsing with aliases, defaults, includes
- [x] Policy evaluation with glob matching and digest verification
- [x] PAM authentication integration
- [x] Command execution with PTY and non-PTY modes
- [x] Credential caching (timestamps)
- [x] sudoedit support
- [x] First-use lecture display

### Security Features
- [x] SELinux support (context parsing, role/type transitions)
- [x] AppArmor profile enforcement
- [x] Seccomp sandboxing (syscall filtering, security profiles)
- [x] Secure memory handling (automatic zeroing, memory locking)
- [x] Rate limiting (brute-force protection)
- [x] Environment variable security

### Enterprise Features
- [x] LDAP/SSSD integration
- [x] I/O session logging (recording, replay)
- [x] Plugin API (policy, audit, I/O log, auth plugins)
- [x] Audit logging (syslog, file, JSON)
- [x] Mail notifications

### Testing & Quality Assurance
- [x] 734 unit tests covering all modules
- [x] 48 compliance tests for sudo/sudo-rs parity
- [x] 11 integration tests for cross-module functionality
- [x] 11 end-to-end tests for full workflows
- [x] Performance benchmarks (validated)
- [x] Memory safety through Zig's type system
- [x] Code formatting standards enforced

## Building

### Requirements

- Zig 0.15.0 or later
- Linux (primary target)
- libc
- Optional: libpam for PAM authentication
- Optional: libapparmor for AppArmor support

### Build Commands

```bash
# Build all binaries
zig build

# Build with release optimizations
zig build -Doptimize=ReleaseSafe

# Run tests
zig build test

# Build with specific features
zig build -Dapparmor=true -Dpam-login=true

# Format code
zig build fmt

# Generate documentation
zig build docs
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `-Dpam-login` | Use "sudo-i" PAM service for login shells | false |
| `-Dapparmor` | Enable AppArmor profile enforcement | false |
| `-Dgettext` | Enable internationalization | false |
| `-Ddev` | Enable development logging (INSECURE) | false |

## Installation

```bash
# Build release version
zig build -Doptimize=ReleaseSafe

# Install to /usr/local (requires root)
sudo zig build install --prefix /usr/local

# Set up setuid (required for sudo to work)
sudo chown root:root /usr/local/bin/sudo
sudo chmod 4755 /usr/local/bin/sudo

# Create sudoedit symlink
sudo ln -s /usr/local/bin/sudo /usr/local/bin/sudoedit
```

## Usage

```bash
# Run a command as root
sudo command

# Run as a specific user
sudo -u username command

# Run with a login shell
sudo -i

# Edit files safely
sudoedit /etc/config

# Switch user
su - username

# Check sudoers syntax
visudo -c
```

## Project Structure

```
sudo-zig/
├── build.zig           # Build configuration
├── build.zig.zon       # Package manifest
├── src/
│   ├── bin/            # Binary entry points
│   │   ├── sudo.zig
│   │   ├── su.zig
│   │   └── visudo.zig
│   └── lib/            # Library modules
│       ├── root.zig    # Main library entry
│       ├── common/     # Shared utilities
│       ├── system/     # System interfaces
│       ├── sudoers/    # Sudoers parsing
│       ├── pam/        # PAM authentication
│       ├── exec/       # Command execution
│       ├── log/        # Logging
│       ├── defaults/   # Default settings
│       ├── sudo/       # sudo implementation
│       ├── su/         # su implementation
│       └── visudo/     # visudo implementation
└── tests/
    ├── unit/           # Unit tests
    ├── integration/    # Integration tests
    └── e2e/            # End-to-end tests
```

## Testing

```bash
# Run unit tests (734 tests)
zig build test

# Run compliance tests (48 tests - sudo/sudo-rs parity)
zig build compliance

# Run integration tests (11 tests)
zig build integration

# Run end-to-end tests (11 tests)
zig build e2e

# Run ALL tests (804 tests total)
zig build test-all

# Run performance benchmarks
zig build benchmark

# Check code formatting
zig build fmt
```

### Test Organization

- **Unit Tests** (`tests/unit/`): Module-level testing
  - Common utilities (string, path, digest, network, command, etc.)
  - Sudoers parsing and policy evaluation
  - System interfaces (user, signal, timestamp, AppArmor, SELinux)
  - Execution engine (PTY, monitor, timeout)
  - Logging and audit functionality
  
- **Compliance Tests** (`tests/compliance/`): Compatibility validation
  - Behavior parity with sudo/sudo-rs
  - Sudoers syntax compatibility
  
- **Integration Tests** (`tests/integration/`): Cross-module workflows
  
- **End-to-End Tests** (`tests/e2e/`): Full system validation

## Security

⚠️ **Important**: sudo is security-critical software. This implementation:

- Validates all inputs
- Uses secure memory handling for passwords
- Follows principle of least privilege
- Implements hardened enum values against bit-flip attacks

For security issues, please see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome! Please read the implementation plan in `CLAUDE.md` for guidance on the project architecture and coding standards.

## License

This project is dual-licensed under:
- Apache License 2.0
- MIT License

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

## Acknowledgments

- Todd Miller for the original sudo implementation
- The sudo-rs team for the Rust implementation that inspired this project
- The Zig community for the excellent programming language
