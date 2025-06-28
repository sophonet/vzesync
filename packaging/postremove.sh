#!/bin/bash
set -e

# Reload systemd to drop uninstalled service, only if systemctl is available
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
