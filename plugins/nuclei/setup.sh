#!/bin/bash
# One-time nuclei install + template update helper. Never called by run.py — see NOTES.md.

set -e

echo "Installing nuclei..."
if command -v nuclei &>/dev/null; then
    echo "nuclei is already installed ($(nuclei -version 2>&1 | head -1))."
elif command -v go &>/dev/null; then
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    echo "Installed via go. Make sure \$(go env GOPATH)/bin is on your PATH."
else
    echo "Could not detect a Go toolchain to install nuclei with."
    echo "Install manually: https://github.com/projectdiscovery/nuclei#install-nuclei"
    exit 1
fi

echo ""
echo "Fetching/updating the template library..."
nuclei -update-templates
