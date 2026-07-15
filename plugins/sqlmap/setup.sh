#!/bin/bash
# One-time sqlmap install helper. Never called by run.py — see NOTES.md.

set -e

echo "Installing sqlmap..."
if command -v sqlmap &>/dev/null; then
    echo "sqlmap is already installed ($(sqlmap --version 2>&1 | head -1))."
elif command -v apt-get &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y sqlmap
else
    echo "No apt package manager detected."
    echo "sqlmap's own recommended install is a git checkout, not a package:"
    echo "  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap-dev"
    echo "  sudo ln -s ~/sqlmap-dev/sqlmap.py /usr/local/bin/sqlmap"
    echo "That symlink step matters — run.py calls the plain 'sqlmap' command."
    exit 1
fi

echo ""
echo "Done. sqlmap_scan has no wordlist or extra dependency — nothing else to set up."
