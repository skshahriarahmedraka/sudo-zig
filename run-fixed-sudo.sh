#!/bin/bash
# Helper script to run the newly fixed sudo binary

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO_BIN=$(find "$SCRIPT_DIR/.zig-cache" -name "sudo" -type f -executable 2>/dev/null | head -1)

if [ -z "$SUDO_BIN" ]; then
    echo "Error: Could not find sudo binary. Run 'zig build' first."
    exit 1
fi

echo "Using fixed sudo binary: $SUDO_BIN" >&2
exec "$SUDO_BIN" "$@"
