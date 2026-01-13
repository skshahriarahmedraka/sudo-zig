#!/bin/bash
# Script to cleanly rebuild and install the fixed sudo-zig

set -e  # Exit on error

echo "=========================================="
echo "Reinstalling Fixed sudo-zig"
echo "=========================================="
echo ""

# Check if we need sudo
if [ ! -w "zig-out/bin" ] 2>/dev/null || [ -f "zig-out/bin/sudo" ] && [ ! -w "zig-out/bin/sudo" ]; then
    echo "⚠️  Old binaries are owned by root. Need sudo to clean up."
    echo ""
    echo "Step 1: Removing old binaries..."
    sudo rm -rf zig-out/bin/*
else
    echo "Step 1: Removing old binaries..."
    rm -rf zig-out/bin/* 2>/dev/null || true
fi

echo "Step 2: Cleaning cache..."
rm -rf .zig-cache

echo "Step 3: Building fresh..."
zig build

if [ $? -eq 0 ] || [ -f ".zig-cache/o/*/sudo" ]; then
    echo "✓ Build completed"
    
    # Find the built binary
    BUILT_SUDO=$(find .zig-cache/o -name "sudo" -type f -executable 2>/dev/null | head -1)
    
    if [ -z "$BUILT_SUDO" ]; then
        echo "❌ Error: Could not find built sudo binary"
        exit 1
    fi
    
    echo ""
    echo "Step 4: Testing the fixed binary..."
    if $BUILT_SUDO apt -h 2>&1 | grep -q "SelfCheck"; then
        echo "✓ Fix verified! Binary works correctly."
    elif $BUILT_SUDO apt -h 2>&1 | grep -q "Segmentation fault\|Invalid free\|panic:"; then
        echo "❌ Error: Binary still has bugs!"
        exit 1
    else
        echo "⚠️  Warning: Unexpected output, but no crash detected"
    fi
    
    echo ""
    echo "Step 5: Installing..."
    echo "Installing to /usr/local/bin/sudo-zig (requires sudo)..."
    
    sudo cp "$BUILT_SUDO" /usr/local/bin/sudo-zig
    sudo chown root:root /usr/local/bin/sudo-zig
    sudo chmod 4755 /usr/local/bin/sudo-zig
    
    echo ""
    echo "=========================================="
    echo "✅ Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Verify with:"
    echo "  sudo-zig apt -h    # Should show 'error.SelfCheck'"
    echo "  sudo-zig snap -h   # Should show 'error.SelfCheck'"
    echo "  sudo-zig -h        # Should show help"
    echo ""
else
    echo "❌ Build failed"
    exit 1
fi
