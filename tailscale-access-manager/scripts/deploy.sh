#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════
# Tailscale Access Manager — Deployment Script
# Run this on proxmox2 (10.0.0.72) as root
# Creates CT 110 with static IP 10.0.0.110
# ═══════════════════════════════════════════════════════

CTID=110
HOSTNAME="access-manager"
STATIC_IP="10.0.0.110/24"
GATEWAY="10.0.0.1"
MEMORY=512
CORES=1
DISK_SIZE=8
TEMPLATE="local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst"
APP_PORT=3100

echo "╔══════════════════════════════════════╗"
echo "║  Tailscale Access Manager Deployer   ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ─── Pre-flight checks ───
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: Must run as root on proxmox2"
  exit 1
fi

if pct status $CTID 2>/dev/null | grep -q "running\|stopped"; then
  echo "WARNING: CT $CTID already exists."
  read -p "Destroy and recreate? (yes/no): " confirm
  if [ "$confirm" = "yes" ]; then
    pct stop $CTID 2>/dev/null || true
    pct destroy $CTID --force
    echo "CT $CTID destroyed."
  else
    echo "Aborting."
    exit 1
  fi
fi

# ─── Step 1: Create LXC ───
echo ""
echo "[1/7] Creating LXC container CT $CTID..."
pct create $CTID $TEMPLATE \
  --hostname $HOSTNAME \
  --memory $MEMORY \
  --cores $CORES \
  --net0 name=eth0,bridge=vmbr0,ip=$STATIC_IP,gw=$GATEWAY \
  --rootfs local-lvm:$DISK_SIZE \
  --features nesting=1 \
  --unprivileged 1 \
  --start 0

echo "CT $CTID created."

# ─── Step 2: Start container ───
echo ""
echo "[2/7] Starting CT $CTID..."
pct start $CTID
sleep 5

# ─── Step 3: Install Docker ───
echo ""
echo "[3/7] Installing Docker in CT $CTID..."
pct exec $CTID -- bash -c '
  apt-get update -qq
  apt-get install -y -qq curl git ca-certificates gnupg lsb-release > /dev/null 2>&1

  # Docker official install
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin > /dev/null 2>&1

  systemctl enable docker
  systemctl start docker

  echo "Docker $(docker --version) installed."
'

# ─── Step 4: Clone project ───
echo ""
echo "[4/7] Setting up project directory..."
pct exec $CTID -- bash -c '
  mkdir -p /opt/tailscale-access-manager/data
  cd /opt/tailscale-access-manager
'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  MANUAL STEP: Copy project files to the container       ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║                                                         ║"
echo "║  From your local machine, run:                          ║"
echo "║                                                         ║"
echo "║  scp -r /path/to/tailscale-access-manager/*  \\          ║"
echo "║    root@10.0.0.72:/tmp/access-manager/               ║"
echo "║                                                         ║"
echo "║  Then on proxmox2:                                      ║"
echo "║  pct push $CTID /tmp/access-manager /opt/tailscale-access-manager ║"
echo "║                                                         ║"
echo "║  OR use git clone if you've pushed to a repo.           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
read -p "Press Enter once files are in /opt/tailscale-access-manager inside CT $CTID..."

# ─── Step 5: Configure .env ───
echo ""
echo "[5/7] Configuring environment..."

read -p "Enter NEXTAUTH_SECRET (or press Enter to auto-generate): " auth_secret
if [ -z "$auth_secret" ]; then
  auth_secret=$(pct exec $CTID -- openssl rand -base64 32)
  echo "Generated: $auth_secret"
fi

read -p "Enter KEYCLOAK_CLIENT_SECRET: " kc_secret
read -p "Enter TAILSCALE_API_KEY (tskey-api-...): " ts_key

pct exec $CTID -- bash -c "cat > /opt/tailscale-access-manager/.env << 'ENVEOF'
# Database
DATABASE_URL=\"file:./data/access-manager.db\"

# NextAuth
NEXTAUTH_URL=\"http://10.0.0.110:$APP_PORT\"
NEXTAUTH_SECRET=\"$auth_secret\"

# Keycloak OIDC
KEYCLOAK_CLIENT_ID=\"tailscale-access-manager\"
KEYCLOAK_CLIENT_SECRET=\"$kc_secret\"
KEYCLOAK_ISSUER=\"https://keycloak.example.com/realms/master\"

# Tailscale
TAILSCALE_API_KEY=\"$ts_key\"
TAILSCALE_TAILNET=\"admin@example.com\"

# Security
ADMIN_EMAILS=\"admin@example.com\"

# Session
SESSION_TIMEOUT_MINUTES=15
ENVEOF
"

echo ".env configured."

# ─── Step 6: Build and start ───
echo ""
echo "[6/7] Building and starting Docker container..."
pct exec $CTID -- bash -c '
  cd /opt/tailscale-access-manager
  docker compose up -d --build
'

echo "Waiting for health check..."
sleep 15

pct exec $CTID -- bash -c '
  curl -sf http://localhost:3100/api/health && echo " ✓ App is healthy!" || echo " ✗ Health check failed"
'

# ─── Step 7: Seed database ───
echo ""
echo "[7/7] Seeding database..."
pct exec $CTID -- bash -c '
  cd /opt/tailscale-access-manager
  docker compose exec app npx prisma db push
  docker compose exec app node prisma/seed.js
'

# ─── Step 8: Setup backup cron ───
echo ""
echo "Setting up daily backup cron..."
pct exec $CTID -- bash -c '
  mkdir -p /opt/tailscale-access-manager/data/backups
  (crontab -l 2>/dev/null; echo "0 2 * * * cp /opt/tailscale-access-manager/data/access-manager.db /opt/tailscale-access-manager/data/backups/access-manager-\$(date +\%Y\%m\%d).db") | crontab -
  (crontab -l 2>/dev/null; echo "0 3 * * * find /opt/tailscale-access-manager/data/backups/ -mtime +30 -delete") | crontab -
'

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                  DEPLOYMENT COMPLETE                     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  Access Manager: http://10.0.0.110:$APP_PORT            ║"
echo "║  Container:      CT $CTID on proxmox2                      ║"
echo "║  IP:             10.0.0.110                            ║"
echo "║  Data:           /opt/tailscale-access-manager/data       ║"
echo "║  Logs:           docker compose logs -f                   ║"
echo "║                                                          ║"
echo "║  REMAINING STEPS:                                        ║"
echo "║  1. Create Keycloak client (see SETUP.md)                ║"
echo "║  2. Generate Tailscale API key                           ║"
echo "║  3. Add Tailscale ACL entry for port $APP_PORT             ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
