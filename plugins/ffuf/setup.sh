#!/bin/bash
# One-time ffuf + wordlist install helper. Never called by run.py — see NOTES.md.

set -e

echo "Installing ffuf..."
if command -v ffuf &>/dev/null; then
    echo "ffuf is already installed ($(ffuf -V 2>&1 | head -1))."
elif command -v go &>/dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    echo "Installed via go. Make sure \$(go env GOPATH)/bin is on your PATH."
elif command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y ffuf
elif command -v brew &>/dev/null; then
    brew install ffuf
else
    echo "Could not detect a supported installer on this system."
    echo "Install ffuf manually: https://github.com/ffuf/ffuf#installation"
    exit 1
fi

echo ""
echo "Checking for a default wordlist..."
if [ -f /usr/share/wordlists/dirb/common.txt ]; then
    echo "Found: /usr/share/wordlists/dirb/common.txt — use this as wordlist_path."
elif command -v apt-get &>/dev/null; then
    read -rp "No wordlist found. Install the 'dirb' package for a default one? [Y/n]: " _choice
    if [[ ! "$_choice" =~ ^[Nn]$ ]]; then
        sudo apt-get install -y dirb
        echo "Installed. Use /usr/share/wordlists/dirb/common.txt as wordlist_path."
    fi
else
    echo "No default wordlist found — point wordlist_path at your own (e.g. SecLists)."
fi
