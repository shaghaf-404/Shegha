#!/usr/bin/env bash
# install.sh — Register the `shegha` terminal command
# Usage:  bash install.sh
set -e

echo ""
echo "  Installing Shegha..."
echo ""

# Try normal install first; fall back to --break-system-packages for
# Ubuntu 23.04+ / Debian Bookworm systems with externally-managed Python
if pip install . --quiet 2>/dev/null; then
    echo "  ✔  Installed. Run:  shegha"
elif pip install . --break-system-packages --quiet 2>/dev/null; then
    echo "  ✔  Installed (system Python). Run:  shegha"
else
    echo "  Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install . --quiet
    echo ""
    echo "  ✔  Installed inside .venv. Activate it first:"
    echo "     source .venv/bin/activate"
    echo "     shegha"
fi
echo ""
