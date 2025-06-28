#!/bin/bash
set -e

# Reload systemd to pick up the new service
systemctl daemon-reload
