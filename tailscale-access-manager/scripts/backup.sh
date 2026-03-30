#!/usr/bin/env bash
set -euo pipefail

# Backup the Access Manager SQLite database
# Run inside CT 110 or via: pct exec 110 -- bash /opt/tailscale-access-manager/scripts/backup.sh

DATA_DIR="/opt/tailscale-access-manager/data"
BACKUP_DIR="$DATA_DIR/backups"
DB_FILE="$DATA_DIR/access-manager.db"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB_FILE" ]; then
  echo "ERROR: Database file not found at $DB_FILE"
  exit 1
fi

cp "$DB_FILE" "$BACKUP_DIR/access-manager-$DATE.db"
echo "Backup created: $BACKUP_DIR/access-manager-$DATE.db"

# Keep last 30 days
find "$BACKUP_DIR" -name "access-manager-*.db" -mtime +30 -delete
echo "Old backups cleaned up (30-day retention)."
