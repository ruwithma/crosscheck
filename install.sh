#!/bin/bash
# CrossCheck IDOR Scanner - Linux/macOS Installation Script

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       CrossCheck IDOR Scanner - Installation             ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "[*] Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION < 3.9" | bc -l) -eq 1 ]]; then
    echo "[!] Error: Python 3.9+ is required"
    exit 1
fi

# Create virtual environment (optional but recommended)
if [ "$1" == "--venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[+] Virtual environment activated"
fi

# Install the package
echo "[*] Installing CrossCheck..."
pip3 install -e .

# Install optional dependencies
echo "[*] Installing optional dependencies..."
pip3 install playwright 2>/dev/null || echo "[!] Playwright install failed (optional)"

# Install Playwright browsers (for headless mode)
if command -v playwright &> /dev/null; then
    echo "[*] Installing Playwright browsers..."
    playwright install chromium
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                 Installation Complete!                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Usage:"
echo "  idor-scanner --help              # Show help"
echo "  idor-scanner bounty-list         # List bug bounty presets"
echo "  idor-scanner scan <target> ...   # Run a scan"
echo ""
echo "Quick Start:"
echo "  idor-scanner scan https://api.example.com \\"
echo "    --user1 'alice:password' \\"
echo "    --user2 'bob:password'"
echo ""
