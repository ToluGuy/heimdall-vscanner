#!/bin/bash
# One-time whatweb install helper. Never called by run.py — see NOTES.md.

set -e

echo "Installing whatweb..."
if command -v whatweb &>/dev/null; then
    echo "whatweb is already installed ($(whatweb --version 2>&1 | head -1))."
elif command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y whatweb
elif command -v brew &>/dev/null; then
    brew install whatweb
elif command -v gem &>/dev/null; then
    echo "No apt/brew found — falling back to gem (whatweb is a Ruby tool)."
    sudo gem install whatweb
else
    echo "Could not detect a supported installer on this system."
    echo "Install whatweb manually: https://github.com/urbanadventurer/WhatWeb#installation"
    exit 1
fi

echo ""
echo "Done. whatweb_scan has no wordlist dependency — nothing else to set up."
