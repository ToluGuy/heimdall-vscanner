#!/bin/bash
# install_plugin.sh — deploys a plugin's execution code onto a scanner or
# agent running on THIS machine, and updates its advertised capabilities.
#
# This never fetches anything over the network and never talks to the
# Heimdall server. The plugin's manifest (plugin.json) gets registered on
# the server separately, via the dashboard's Plugins panel — that's pure
# metadata. This script is the other half: putting the actual code that
# performs the scan onto a specific machine, deliberately, by hand.
#
# Usage:
#   ./install_plugin.sh <plugin_source_dir> <job_type> <scanner:NAME|agent>
#
# <plugin_source_dir>   A directory containing run.py, with an
#                       execute(target, profile, **kwargs) function.
# <job_type>            Must match the "type" in that plugin's plugin.json.
# scanner:NAME          A scanner registered through the dashboard, e.g.
#                       scanner:scanner-default — installs to
#                       backend/app/plugins/<job_type>/ and restarts
#                       vapt-scanner-NAME via systemd.
# agent                 The endpoint agent on this machine — installs to
#                       agent/plugins/<job_type>/. Not assumed to run under
#                       systemd; restart it yourself afterwards.
#
# Example (run from inside plugins/):
#   ./install_plugin.sh ./ffuf ffuf_scan scanner:scanner-default

set -e

PLUGIN_SRC="$1"
JOB_TYPE="$2"
TARGET="$3"

if [ -z "$PLUGIN_SRC" ] || [ -z "$JOB_TYPE" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <plugin_source_dir> <job_type> <scanner:NAME|agent>"
    exit 1
fi

if [ ! -f "$PLUGIN_SRC/run.py" ]; then
    echo "Error: $PLUGIN_SRC/run.py not found."
    echo "A plugin needs a run.py with an execute(target, profile, **kwargs) function."
    exit 1
fi

INSTALL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME=""

if [[ "$TARGET" == scanner:* ]]; then
    SCANNER_NAME="${TARGET#scanner:}"
    DEST="$INSTALL_DIR/backend/app/plugins/$JOB_TYPE"
    ENV_FILE="$INSTALL_DIR/.env"
    SERVICE_NAME="vapt-scanner-$SCANNER_NAME"
elif [ "$TARGET" == "agent" ]; then
    DEST="$INSTALL_DIR/agent/plugins/$JOB_TYPE"
    ENV_FILE="$INSTALL_DIR/agent/.env"
else
    echo "Error: target must be 'scanner:NAME' or 'agent'"
    exit 1
fi

echo "Copying $PLUGIN_SRC -> $DEST"
mkdir -p "$DEST"
cp -r "$PLUGIN_SRC"/* "$DEST/"

echo "Updating VAPT_CAPABILITIES in $ENV_FILE"
if [ -f "$ENV_FILE" ] && grep -q "^VAPT_CAPABILITIES=" "$ENV_FILE"; then
    CURRENT=$(grep "^VAPT_CAPABILITIES=" "$ENV_FILE" | cut -d'=' -f2-)
    if [[ ",$CURRENT," != *",$JOB_TYPE,"* ]]; then
        NEW="$CURRENT,$JOB_TYPE"
        sed -i "s/^VAPT_CAPABILITIES=.*/VAPT_CAPABILITIES=$NEW/" "$ENV_FILE"
        echo "  $CURRENT -> $NEW"
    else
        echo "  '$JOB_TYPE' already present — no change needed"
    fi
else
    echo "VAPT_CAPABILITIES=nmap_scan,nikto_scan,nse_scan,$JOB_TYPE" >> "$ENV_FILE"
    echo "  Created VAPT_CAPABILITIES with nmap_scan,nikto_scan,nse_scan,$JOB_TYPE"
fi

if [ -n "$SERVICE_NAME" ]; then
    if systemctl list-unit-files "$SERVICE_NAME.service" &>/dev/null && \
       systemctl list-unit-files "$SERVICE_NAME.service" | grep -q "$SERVICE_NAME"; then
        echo "Restarting $SERVICE_NAME..."
        sudo systemctl restart "$SERVICE_NAME"
        echo "Done. Check status with: sudo systemctl status $SERVICE_NAME"
    else
        echo "Done. No systemd unit named '$SERVICE_NAME' found — you're likely running this"
        echo "scanner manually. Restart it yourself (Ctrl+C + re-run, or however you normally"
        echo "start it) for '$JOB_TYPE' to become available."
    fi
else
    echo "Done. Restart the agent process manually for '$JOB_TYPE' to become available."
fi
