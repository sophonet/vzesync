#!/bin/bash
set -e

if command -v systemctl >/dev/null 2>&1; then
    # Reload systemd to pick up the new service
    systemctl daemon-reload

    # Optional: enable service so it starts on boot
    systemctl enable vzesync.service

    echo "✅ vzesync has been installed."
    echo "👉 Edit /etc/vzesync.toml before starting the service:"
    echo "   sudo nano /etc/vzesync.toml"
    echo "Then start the service with:"
    echo "   sudo systemctl start vzesync"
else
    echo "systemctl not found. Please configure and start vzesync manually."
fi
