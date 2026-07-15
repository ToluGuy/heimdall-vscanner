#!/bin/bash
# uninstall_plugin.sh — removes a plugin's execution code from a scanner or
# agent running on THIS machine, and drops it from the advertised capabilities.
#
# This is the disk-side half only. It does NOT touch the plugin's manifest
# registration on the server (the Plugin/TargetAuthorization DB rows) —
# that's removed separately via the dashboard's Settings → Plugins page
# (or DELETE /plugins/{name}), which also cancels any pending jobs of that
# type. Doing both is the full uninstall; doing just this one leaves the
# manifest registered with no code backing it on this particular machine,
# which is harmless but pointless — the job type just fails on this
# machine specifically if something tries to run it here.
#
# Usage:
#   ./uninstall_plugin.sh <job_type> <scanner:NAME|agent>
#
# Example:
#   ./uninstall_plugin.sh echo_test_scan scanner:scanner-default

set -e

JOB_TYPE="$1"
TARGET="$2"

if [ -z "$JOB_TYPE" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <job_type> <scanner:NAME|agent>"
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

if [ ! -d "$DEST" ]; then
    echo "Nothing to remove — $DEST doesn't exist."
else
    echo "Removing $DEST"
    rm -rf "$DEST"
fi

echo "Updating VAPT_CAPABILITIES in $ENV_FILE"
if [ -f "$ENV_FILE" ] && grep -q "^VAPT_CAPABILITIES=" "$ENV_FILE"; then
    CURRENT=$(grep "^VAPT_CAPABILITIES=" "$ENV_FILE" | cut -d'=' -f2-)
    NEW=$(echo ",$CURRENT," | sed "s/,$JOB_TYPE,/,/" | sed 's/^,//;s/,$//')
    if [ "$NEW" != "$CURRENT" ]; then
        sed -i "s/^VAPT_CAPABILITIES=.*/VAPT_CAPABILITIES=$NEW/" "$ENV_FILE"
        echo "  $CURRENT -> $NEW"
    else
        echo "  '$JOB_TYPE' wasn't listed — no change needed"
    fi
else
    echo "  No VAPT_CAPABILITIES line found in $ENV_FILE — nothing to update"
fi

if [ -n "$SERVICE_NAME" ]; then
    if systemctl list-unit-files "$SERVICE_NAME.service" &>/dev/null && \
       systemctl list-unit-files "$SERVICE_NAME.service" | grep -q "$SERVICE_NAME"; then
        echo "Restarting $SERVICE_NAME..."
        sudo systemctl restart "$SERVICE_NAME"
        echo "Done. Check status with: sudo systemctl status $SERVICE_NAME"
    else
        echo "Done. No systemd unit named '$SERVICE_NAME' found — restart that scanner"
        echo "process yourself for the removal to take effect."
    fi
else
    echo "Done. Restart the agent process manually for the removal to take effect."
fi

echo ""
echo "Reminder: if this plugin is still registered on the server, remove it from"
echo "Settings → Plugins too, or POST DELETE /plugins/$JOB_TYPE — this script only"
echo "handled the code on this machine."
