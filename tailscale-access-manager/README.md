# Tailscale Access Manager

A self-hosted web application for managing user access to Proxmox infrastructure through Tailscale ACLs. Provides a centralized dashboard to grant, revoke, and audit fine-grained port-level access to Proxmox nodes and LXC containers, enforced via Tailscale's ACL policy engine.

![Next.js 14](https://img.shields.io/badge/next.js-14-black)
![Prisma](https://img.shields.io/badge/prisma-5-blue)
![Docker](https://img.shields.io/badge/docker-ready-blue)

---

## Features

- **User management** --- create users with roles (Viewer, Developer, Maintainer, Admin), set expiry dates, suspend/reactivate
- **Access rules** --- grant users access to specific containers, entire nodes, or all infrastructure with per-port control
- **ACL generation** --- automatically generates Tailscale ACL JSON from your rules and pushes it to Tailscale's API
- **Infrastructure view** --- see all Proxmox nodes and containers with IPs, status, and criticality flags
- **Audit logging** --- every action is logged with timestamp, severity, and user attribution
- **Emergency lockdown** --- instantly suspend all non-admin users and block mutations
- **Session security** --- 15-minute idle timeout with re-authentication prompt
- **Conflict detection** --- ETag-based optimistic locking prevents overwriting externally modified ACLs
- **Rate limiting** --- max 3 ACL pushes per 5 minutes

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React 18 |
| Backend | Next.js App Router API routes |
| Auth | NextAuth.js + Keycloak (OIDC) |
| Database | SQLite via Prisma ORM |
| Deployment | Docker (multi-stage, non-root, read-only FS) |
| Integration | Tailscale API v2, Proxmox |

---

## Prerequisites

- **Keycloak** instance with admin access (for OIDC authentication)
- **Tailscale** account with an API access token (`tskey-api-...`)
- **Node.js 20+** (for local development) or **Docker** (for production)

---

## Quick Start (Development)

```bash
# Install dependencies
npm install

# Copy and configure environment
cp .env.example .env
# Edit .env --- fill in Keycloak and Tailscale credentials (see below)

# Set up database
npx prisma generate
npx prisma db push

# Seed with example infrastructure data
npm run seed

# Start dev server
npm run dev
```

The app starts on **http://localhost:3000**.

---

## Production (Docker)

```bash
# Build and start
docker compose up -d --build

# Seed the database (first run only)
docker compose exec app npx prisma db push
docker compose exec app node prisma/seed.js
```

The app runs on **http://localhost:3100**.

The Docker setup includes:
- Multi-stage build (Node 20 Alpine)
- Non-root user (`nextjs:nodejs`)
- Read-only root filesystem with tmpfs for `/tmp`
- Memory limit (512 MB) and CPU limit (1 core)
- Health check every 30 seconds (`/api/health`)
- SQLite data persisted via volume mount (`./data:/app/data`)

---

## Environment Variables

Create a `.env` file from `.env.example`:

```bash
# Database
DATABASE_URL="file:./data/access-manager.db"

# NextAuth
NEXTAUTH_URL="http://localhost:3100"         # Your app's public URL
NEXTAUTH_SECRET=""                           # Generate: openssl rand -base64 32

# Keycloak OIDC
KEYCLOAK_CLIENT_ID="tailscale-access-manager"
KEYCLOAK_CLIENT_SECRET=""                    # From Keycloak > Clients > Credentials tab
KEYCLOAK_ISSUER="https://keycloak.example.com/realms/master"

# Tailscale
TAILSCALE_API_KEY=""                         # Generate at login.tailscale.com > Settings > Keys
TAILSCALE_TAILNET="admin@example.com"        # Your Tailscale tailnet identifier

# Security
ADMIN_EMAILS="admin@example.com"             # Comma-separated whitelist of allowed admin emails

# Session
SESSION_TIMEOUT_MINUTES=15
```

---

## Keycloak Client Setup

1. Log into your Keycloak admin console
2. Select the **master** realm (or your preferred realm)
3. Go to **Clients** > **Create client**
4. Configure:
   - **Client ID**: `tailscale-access-manager`
   - **Client Protocol**: `openid-connect`
   - **Client authentication**: ON (confidential)
   - **Valid Redirect URIs**: `http://<your-app-url>/*`
   - **Valid post logout redirect URIs**: `http://<your-app-url>/*`
   - **Web Origins**: `http://<your-app-url>`
5. Go to the **Credentials** tab and copy the **Client secret** into your `.env`

---

## Tailscale API Token

1. Go to https://login.tailscale.com/admin/settings/keys
2. Under **API access tokens**, click **Generate access token**
3. Copy the token (starts with `tskey-api-...`) into your `.env`

> Tailscale API tokens expire after 90 days. Set a calendar reminder to rotate.

---

## How It Works

```
Users & Rules (Prisma/SQLite)
        |
        v
  ACL Generator --- builds Tailscale ACL JSON from active users + rules
        |
        v
  Tailscale API --- pushes ACL policy (with ETag conflict detection)
        |
        v
  Tailscale Network --- enforces access at the network level
```

1. **Admin logs in** via Keycloak (only whitelisted emails allowed)
2. **Creates users** with roles and optional expiry dates
3. **Assigns access rules** --- pick a container/node, select ports
4. **Generates ACL preview** --- see exactly what will be pushed
5. **Pushes to Tailscale** --- ACL is applied network-wide
6. **Audit trail** --- every action is logged for compliance

---

## User Roles

| Role | Description |
|---|---|
| **Viewer** | Read-only access to logs and monitoring |
| **Developer** | SSH + web access to assigned containers |
| **Maintainer** | Deploy and manage capabilities |
| **Admin** | Full access to all infrastructure |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET/POST | `/api/auth/[...nextauth]` | Authentication (Keycloak OIDC) |
| GET | `/api/users` | List all users with rules |
| POST | `/api/users` | Create user |
| PATCH | `/api/users/:id` | Update user (status, role, expiry) |
| DELETE | `/api/users/:id` | Delete user |
| POST | `/api/rules` | Add access rule |
| DELETE | `/api/rules/:id` | Remove access rule |
| POST | `/api/acl/generate` | Generate ACL preview |
| POST | `/api/acl/push` | Push ACL to Tailscale |
| GET | `/api/infra/nodes` | List Proxmox nodes |
| PATCH | `/api/infra/nodes/:id` | Update node IP |
| GET | `/api/infra/containers` | List containers/VMs |
| PATCH | `/api/infra/containers/:id` | Update container IP |
| GET | `/api/tailscale/devices` | List Tailscale devices |
| GET/POST | `/api/emergency` | Check/activate/lift lockdown |
| GET | `/api/audit` | Paginated audit log (`?page=&limit=&severity=`) |
| GET | `/api/health` | Health check |

---

## Security

- **Auth whitelist** --- only emails listed in `ADMIN_EMAILS` can sign in
- **Session timeout** --- JWT sessions expire after 15 minutes of inactivity
- **Emergency lockdown** --- suspends all non-admin users instantly, blocks all mutations
- **Last admin protection** --- cannot suspend or delete the last active admin
- **Rate limiting** --- max 3 ACL pushes per 5 minutes (429 on exceed)
- **ETag conflict detection** --- prevents overwriting externally modified ACLs
- **Input validation** --- emails, IPs (must be in expected subnet), names, and ports are all validated
- **Forbidden ports** --- port 3100 (the app itself) cannot be assigned
- **Protected containers** --- assigning access to critical containers triggers elevated audit severity
- **HTTP headers** --- X-Frame-Options DENY, strict CSP, HSTS, no-sniff, XSS protection
- **Docker hardening** --- non-root user, read-only FS, no-new-privileges, memory/CPU limits

---

## Project Structure

```
tailscale-access-manager/
  package.json
  next.config.js              # Security headers (CSP, HSTS, etc.)
  Dockerfile                  # Multi-stage production build
  docker-compose.yaml         # Production deployment config
  .env.example                # Environment variable template
  SETUP.md                    # Detailed deployment guide
  prisma/
    schema.prisma             # Database schema (7 models)
    seed.js                   # Seed data (nodes, containers, admin user)
  scripts/
    deploy.sh                 # Automated Proxmox LXC deployment
    backup.sh                 # Daily SQLite backup script
  src/
    app/
      page.js                 # Home page (loads data, renders UI)
      layout.js               # Root layout and metadata
      globals.css             # Fonts and base styles
      components/
        AccessManager.jsx     # Main UI component (users, rules, ACL, audit)
      api/                    # All API route handlers
        auth/                 # NextAuth Keycloak OIDC
        users/                # User CRUD
        rules/                # Rule CRUD
        acl/                  # ACL generate + push
        infra/                # Nodes + containers
        emergency/            # Lockdown
        audit/                # Audit log
        health/               # Health check
        tailscale/            # Tailscale device proxy
    lib/
      auth.js                 # NextAuth config + requireAuth()
      prisma.js               # Prisma client singleton
      acl-generator.js        # Builds Tailscale ACL JSON from rules
      tailscale.js            # Tailscale API client (get/push ACL, devices)
      validators.js           # Input validation (email, IP, name, ports)
      rate-limit.js           # In-memory rate limiter
  data/                       # SQLite database + backups (gitignored)
```

---

## Maintenance

### Rotate Tailscale API Key (every 90 days)

```bash
# Generate new token at login.tailscale.com > Settings > Keys
# Then update .env and restart:
docker compose restart
```

### View Logs

```bash
docker compose logs -f --tail 50
```

### Manual Backup

```bash
docker compose exec app node scripts/backup.sh
```

### Rebuild After Code Changes

```bash
docker compose up -d --build
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
