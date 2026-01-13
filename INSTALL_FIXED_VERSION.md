# Installing the Fixed Version

## The Problem
The `zig-out/bin/` directory contains old binaries owned by root that can't be overwritten.

## Solution: Clean Install

Run these commands:

```bash
# Step 1: Remove old binaries (requires sudo)
sudo rm -rf zig-out/bin/*

# Step 2: Remove old cache to force rebuild
rm -rf .zig-cache

# Step 3: Build fresh
zig build

# Step 4: Install with the install script
sudo ./install.sh
```

Or manually:

```bash
# Remove old files
sudo rm -rf zig-out/bin/*

# Build
zig build

# Manually copy the fixed binary
sudo cp .zig-cache/o/*/sudo /usr/local/bin/sudo-zig
sudo chown root:root /usr/local/bin/sudo-zig
sudo chmod 4755 /usr/local/bin/sudo-zig
```

## Verify the Fix

After installation:

```bash
# Test commands that previously crashed:
sudo-zig apt -h    # Should show: error.SelfCheck (not segfault!)
sudo-zig snap -h   # Should show: error.SelfCheck (not "Invalid free"!)
sudo-zig -h        # Should show help
```

## Alternative: Test Without Installing

To test the fixed version without installing:

```bash
# Use the helper script
./run-fixed-sudo.sh apt -h

# Or run directly from cache
.zig-cache/o/*/sudo apt -h
```

This should show `error.SelfCheck` (expected) instead of crashing.
