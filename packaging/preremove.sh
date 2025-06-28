#!/bin/bash
set -e

# Stop and disable the service if it is running
if systemctl is-enabled --quiet vzesync.service; then
    systemctl disable vzesync.service || true
fi

if systemctl is-active --quiet vzesync.service; then
    systemctl stop vzesync.service || true
fi

echo "🛑 vzesync services have been stopped and disabled."
