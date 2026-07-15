#!/bin/bash
# One-time hydra + wordlist install helper. Never called by run.py — see NOTES.md.

set -e

echo "Installing hydra..."
if command -v hydra &>/dev/null; then
    echo "hydra is already installed ($(hydra 2>&1 | head -1))."
elif command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y hydra
elif command -v brew &>/dev/null; then
    brew install hydra
else
    echo "Could not detect a supported installer on this system."
    echo "Install hydra manually: https://github.com/vanhauser-thc/thc-hydra"
    exit 1
fi

echo ""
echo "Checking for a default password wordlist..."
if [ -f /usr/share/wordlists/rockyou.txt ]; then
    echo "Found: /usr/share/wordlists/rockyou.txt — use this as password_wordlist_path."
elif [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    read -rp "Found rockyou.txt.gz but not extracted. Extract it now? [Y/n]: " _choice
    if [[ ! "$_choice" =~ ^[Nn]$ ]]; then
        sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
        echo "Extracted. Use /usr/share/wordlists/rockyou.txt as password_wordlist_path."
    fi
else
    echo "No default wordlist found — point password_wordlist_path at your own."
    echo "Remember: hydra_scan is 'high' risk tier, so keep the list scope-appropriate"
    echo "rather than reaching for the biggest list available."
fi
