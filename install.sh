#!/bin/bash
#
# sudo-zig Installation Script
# Installs sudo-zig binaries to a Unix-based operating system
#
# This script installs:
#   - sudo-zig     (alternative to sudo)
#   - su-zig       (alternative to su)
#   - visudo-zig   (alternative to visudo)
#   - sudoedit-zig (symlink to sudo-zig)
#
# IMPORTANT: This does NOT modify or replace the system's native sudo command.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default installation prefix
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-$PREFIX/bin}"

# Build optimization level
OPTIMIZE="${OPTIMIZE:-ReleaseSafe}"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                    sudo-zig Installer                     ║"
    echo "║     Memory-safe sudo implementation written in Zig        ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_requirements() {
    info "Checking requirements..."

    # Check for Unix-like OS
    case "$(uname -s)" in
        Linux*|Darwin*|FreeBSD*|OpenBSD*|NetBSD*)
            info "Detected OS: $(uname -s)"
            ;;
        *)
            error "This installer only supports Unix-based operating systems."
            ;;
    esac

    # Check for Zig compiler
    if ! command -v zig &> /dev/null; then
        error "Zig compiler not found. Please install Zig 0.13.0 or later.
       Visit: https://ziglang.org/download/"
    fi

    # Check Zig version
    ZIG_VERSION=$(zig version)
    info "Found Zig version: $ZIG_VERSION"

    # Check for root/sudo access for installation
    if [ "$EUID" -ne 0 ] && [ ! -w "$BINDIR" ]; then
        warn "Installation to $BINDIR requires root privileges."
        warn "You may need to run this script with sudo or as root."
    fi

    success "All requirements met."
}

build_release() {
    info "Building sudo-zig with $OPTIMIZE optimization..."

    cd "$SCRIPT_DIR"

    # Clean previous build
    if [ -d "zig-out" ]; then
        info "Cleaning previous build..."
        rm -rf zig-out
    fi

    # Build with release optimizations
    if ! zig build -Doptimize="$OPTIMIZE"; then
        error "Build failed. Please check the error messages above."
    fi

    # Verify binaries were created
    if [ ! -f "zig-out/bin/sudo" ]; then
        error "Build completed but sudo binary not found."
    fi
    if [ ! -f "zig-out/bin/su" ]; then
        error "Build completed but su binary not found."
    fi
    if [ ! -f "zig-out/bin/visudo" ]; then
        error "Build completed but visudo binary not found."
    fi

    success "Build completed successfully."
}

install_binaries() {
    info "Installing binaries to $BINDIR..."

    # Create bin directory if it doesn't exist
    if [ ! -d "$BINDIR" ]; then
        info "Creating directory: $BINDIR"
        mkdir -p "$BINDIR" || error "Failed to create $BINDIR"
    fi

    # Install sudo as sudo-zig
    info "Installing sudo-zig..."
    cp "$SCRIPT_DIR/zig-out/bin/sudo" "$BINDIR/sudo-zig" || error "Failed to install sudo-zig"
    chmod 755 "$BINDIR/sudo-zig" || error "Failed to set permissions on sudo-zig"

    # Install su as su-zig
    info "Installing su-zig..."
    cp "$SCRIPT_DIR/zig-out/bin/su" "$BINDIR/su-zig" || error "Failed to install su-zig"
    chmod 755 "$BINDIR/su-zig" || error "Failed to set permissions on su-zig"

    # Install visudo as visudo-zig
    info "Installing visudo-zig..."
    cp "$SCRIPT_DIR/zig-out/bin/visudo" "$BINDIR/visudo-zig" || error "Failed to install visudo-zig"
    chmod 755 "$BINDIR/visudo-zig" || error "Failed to set permissions on visudo-zig"

    # Create sudoedit-zig symlink
    info "Creating sudoedit-zig symlink..."
    ln -sf sudo-zig "$BINDIR/sudoedit-zig" || error "Failed to create sudoedit-zig symlink"

    success "Binaries installed successfully."
}

setup_setuid() {
    info "Setting up setuid permissions..."

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        warn "Setuid setup requires root privileges."
        warn "To enable privilege escalation, run the following commands as root:"
        echo ""
        echo "    sudo chown root:root $BINDIR/sudo-zig"
        echo "    sudo chmod 4755 $BINDIR/sudo-zig"
        echo ""
        return
    fi

    # Set ownership to root
    chown root:root "$BINDIR/sudo-zig" || error "Failed to change ownership of sudo-zig"

    # Set setuid bit
    chmod 4755 "$BINDIR/sudo-zig" || error "Failed to set setuid on sudo-zig"

    success "Setuid permissions configured."
}

print_summary() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                  Installation Complete!                     ${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Installed binaries:"
    echo "  • sudo-zig     -> $BINDIR/sudo-zig"
    echo "  • su-zig       -> $BINDIR/su-zig"
    echo "  • visudo-zig   -> $BINDIR/visudo-zig"
    echo "  • sudoedit-zig -> $BINDIR/sudoedit-zig (symlink)"
    echo ""
    echo "Usage examples:"
    echo "  sudo-zig whoami              # Run command as root"
    echo "  sudo-zig -u username command # Run as specific user"
    echo "  sudo-zig -i                  # Start root shell"
    echo "  su-zig - username            # Switch user"
    echo "  visudo-zig -c                # Check sudoers syntax"
    echo "  sudoedit-zig /etc/config     # Edit files safely"
    echo ""
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}NOTE: To enable privilege escalation, run as root:${NC}"
        echo "  sudo chown root:root $BINDIR/sudo-zig"
        echo "  sudo chmod 4755 $BINDIR/sudo-zig"
        echo ""
    fi

    echo -e "${BLUE}The system's native 'sudo' command has NOT been modified.${NC}"
    echo ""
}

show_help() {
    echo "sudo-zig Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -p, --prefix DIR    Installation prefix (default: /usr/local)"
    echo "  -b, --bindir DIR    Binary directory (default: PREFIX/bin)"
    echo "  -o, --optimize OPT  Optimization level (default: ReleaseSafe)"
    echo "                      Options: Debug, ReleaseSafe, ReleaseFast, ReleaseSmall"
    echo "  --build-only        Only build, do not install"
    echo "  --skip-build        Skip build, only install (requires previous build)"
    echo ""
    echo "Environment variables:"
    echo "  PREFIX    Installation prefix"
    echo "  BINDIR    Binary directory"
    echo "  OPTIMIZE  Optimization level"
    echo ""
    echo "Examples:"
    echo "  $0                           # Build and install to /usr/local/bin"
    echo "  $0 --prefix /opt/sudo-zig    # Install to /opt/sudo-zig/bin"
    echo "  sudo $0                      # Install with setuid permissions"
    echo ""
}

# Parse command line arguments
BUILD_ONLY=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -p|--prefix)
            PREFIX="$2"
            BINDIR="$PREFIX/bin"
            shift 2
            ;;
        -b|--bindir)
            BINDIR="$2"
            shift 2
            ;;
        -o|--optimize)
            OPTIMIZE="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        *)
            error "Unknown option: $1. Use --help for usage information."
            ;;
    esac
done

# Main execution
main() {
    print_banner
    check_requirements

    if [ "$SKIP_BUILD" = false ]; then
        build_release
    else
        info "Skipping build (--skip-build specified)"
        if [ ! -f "$SCRIPT_DIR/zig-out/bin/sudo" ]; then
            error "No previous build found. Run without --skip-build first."
        fi
    fi

    if [ "$BUILD_ONLY" = false ]; then
        install_binaries
        setup_setuid
        print_summary
    else
        info "Build complete (--build-only specified)"
        echo ""
        echo "Built binaries are in: $SCRIPT_DIR/zig-out/bin/"
        echo "  • sudo"
        echo "  • su"
        echo "  • visudo"
        echo ""
    fi
}

main
