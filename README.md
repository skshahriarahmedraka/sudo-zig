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

✅ **Feature Complete** - All major sudo and sudo-rs features have been implemented.

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

### Testing & Performance
- [x] 700+ unit tests
- [x] Integration tests
- [x] Performance benchmarks
- [x] Compliance tests for sudo/sudo-rs parity

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
# Run all tests (700+ tests)
zig build test

# Run performance benchmarks
zig build benchmark
```

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
