# Tailscale Access Manager — Setup Guide

## Prerequisites

- Proxmox 8.x with proxmox2 node (10.0.0.72)
- Keycloak running on CT 3001 (10.0.0.30)
- Tailscale subnet router on CT 105 (10.0.0.155)

---

## Step 1: Generate Tailscale API Access Token

You need an **API access token** (NOT an auth key).

1. Go to https://login.tailscale.com/admin/settings/keys
2. Under **API access tokens**, click **"Generate access token..."**
3. Copy the token (starts with `tskey-api-...`)
4. Save it — you'll need it for the `.env` file

> **90-day expiry**: Tailscale API tokens expire after 90 days max.
> Set a calendar reminder to rotate the key. The app will log an error
> when API calls start failing, which is your signal to regenerate.
>
> Future enhancement: the app could auto-check token validity on startup
> and warn in the UI when expiry is approaching.

---

## Step 2: Create Keycloak Client

1. Log into Keycloak admin: https://keycloak.example.com/admin/
2. Select the **master** realm (or create a new one)
3. Go to **Clients** → **Create client**
4. Configure:
   - **Client ID**: `tailscale-access-manager`
   - **Client Protocol**: `openid-connect`
   - **Client authentication**: ON (confidential)
   - **Valid Redirect URIs**: `http://10.0.0.110:3100/*`
   - **Valid post logout redirect URIs**: `http://10.0.0.110:3100/*`
   - **Web Origins**: `http://10.0.0.110:3100`
5. Click **Save**
6. Go to the **Credentials** tab → copy the **Client secret**

---

## Step 3: Deploy

```bash
# SSH into proxmox2
ssh root@10.0.0.72

# Copy the project to proxmox2 first (from your machine):
# scp -r ./tailscale-access-manager root@10.0.0.72:/tmp/access-manager/

# Run the deployment script
chmod +x /tmp/access-manager/scripts/deploy.sh
bash /tmp/access-manager/scripts/deploy.sh
```

The script will:
1. Create CT 110 (10.0.0.110) with Docker
2. Prompt you for secrets (Keycloak client secret, Tailscale API token)
3. Build and start the app on port 3100
4. Seed the database with your infrastructure data
5. Set up daily backup cron

---

## Step 4: Lock Down Access via Tailscale ACL

Add this to your Tailscale ACL (at login.tailscale.com → Access Controls):

```jsonc
{
  "action": "accept",
  "src": ["admin@example.com"],
  "dst": ["10.0.0.110:3100"],
  "comment": "Access Manager UI — admin only via Tailscale"
}
```

This ensures the Access Manager is ONLY reachable through Tailscale,
and ONLY by your admin account.

---

## Step 5: Verify

1. Connect to Tailscale on your device
2. Open http://10.0.0.110:3100
3. You'll be redirected to Keycloak for login
4. After authenticating, you should see the Access Manager dashboard

---

## Maintenance

### Rotate Tailscale API Key (every 90 days)

1. Generate new token at https://login.tailscale.com/admin/settings/keys
2. SSH into the container:
   ```bash
   pct exec 110 -- bash
   cd /opt/tailscale-access-manager
   # Edit .env — update TAILSCALE_API_KEY
   nano .env
   docker compose restart
   ```

### View Logs

```bash
pct exec 110 -- bash -c 'cd /opt/tailscale-access-manager && docker compose logs -f --tail 50'
```

### Manual Backup

```bash
pct exec 110 -- bash /opt/tailscale-access-manager/scripts/backup.sh
```

### Rebuild After Code Changes

```bash
pct exec 110 -- bash -c 'cd /opt/tailscale-access-manager && docker compose up -d --build'
```
