# Infrastructure Toolkit Web

A Flask-based web UI for managing infrastructure services from a single dashboard. Wraps common admin operations for **Keycloak**, **Jenkins**, **Garage S3**, **PostgreSQL**, and **SSH remotes** into a point-and-click interface with real-time terminal output.

![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue)
![Flask](https://img.shields.io/badge/flask-3.1-green)

---

## Features

### Keycloak Management
- **Realm lifecycle** --- create realms with SMTP, security policies, OTP, and brute-force protection
- **User CRUD** --- create, find, list, and delete users (single or batch)
- **Role management** --- create standard roles and assign them individually or in batch
- **Client setup** --- create public (SPA/PKCE) and confidential (API) OIDC clients, update redirect URIs
- **Google IdP** --- configure Google as a social login provider
- **Cross-realm search** --- find a user across multiple realms at once
- **Full-setup wizard** --- one-click: realm + security + roles + clients + users + role assignments

### Jenkins
- Create multibranch pipelines with Git repository integration

### Garage S3
- Configure CORS rules on S3 buckets (origins, methods, headers)

### PostgreSQL
- Run arbitrary SQL queries (via Docker exec or SSH)
- Search and delete users by email/username

### SSH Remote Keycloak
- List and bulk-delete users on remote Keycloak instances via SSH tunnel

### General
- **Async execution** --- all operations run in background threads
- **Live streaming** --- real-time terminal output via Server-Sent Events
- **Preset system** --- save and reuse URLs, credentials, and config values across sessions (persisted to `presets.json`)
- **Dark-themed UI** --- single-page app with sidebar navigation and output terminal

---

## Prerequisites

- Python 3.13+
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`
- External tools depending on which operations you use:
  - `curl` --- Keycloak / Jenkins / S3 API calls
  - `docker` --- PostgreSQL queries via container exec
  - `ssh` --- remote Keycloak and database operations
  - `aws` CLI or `garage` CLI --- S3 bucket management

---

## Quick Start

```bash
# Clone and enter the project
cd infra-toolkit-web

# Install dependencies
uv sync
# or: pip install flask>=3.1.3

# Start the server
python app.py
```

The app starts on **http://localhost:5111** with debug/auto-reload enabled.

---

## Configuration

All connection details (URLs, usernames, hosts, etc.) are managed through the **Presets** system:

1. Click **Manage Presets** in the sidebar
2. Add your Keycloak URLs, Jenkins endpoints, SSH hosts, S3 endpoints, etc.
3. Presets are saved to `presets.json` and populate dropdowns throughout the UI

Default presets ship in `presets.json` with placeholder values --- replace them with your actual infrastructure details.

### Preset Categories

| Category | Examples |
|---|---|
| Keycloak | URLs, realms, admin usernames |
| Jenkins | URLs, usernames, credential IDs |
| SSH | Hosts, Keycloak ports |
| S3 / Garage | Endpoints, bucket names |
| Database | Hosts, container names, DB users, DB names |
| SPA / CORS | Application URLs, allowed origins |
| Git | Repository SSH URLs |
| SMTP | Mail server hosts, sender addresses |
| Google OAuth | Client IDs, client secrets |

---

## Project Structure

```
infra-toolkit-web/
  app.py            # Flask application (all routes and logic)
  main.py           # Alternative entry point
  presets.json      # Saved preset values (auto-updated via UI)
  pyproject.toml    # Python project metadata and dependencies
  uv.lock           # Locked dependency versions
  templates/
    index.html      # Single-page frontend (HTML + CSS + JS)
```

---

## API Endpoints

All endpoints accept and return JSON. Operations run asynchronously --- the response contains a `job_id` that can be polled or streamed.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/presets` | Get all saved presets |
| POST | `/api/presets` | Add/remove/set preset values |
| GET | `/api/jobs/<id>` | Poll job status and output |
| GET | `/api/jobs/<id>/stream` | Stream job output (SSE) |
| | | |
| POST | `/api/kc/create-realm` | Create Keycloak realm |
| POST | `/api/kc/configure-security` | Apply security policies to realm |
| POST | `/api/kc/full-setup` | Full realm setup wizard |
| POST | `/api/kc/list-users` | List realm users |
| POST | `/api/kc/find-user` | Find user by email/username |
| POST | `/api/kc/create-user` | Create single user |
| POST | `/api/kc/create-users-batch` | Create batch of test users |
| POST | `/api/kc/delete-user` | Delete user by email |
| POST | `/api/kc/search-all-realms` | Search user across realms |
| POST | `/api/kc/create-roles` | Create standard realm roles |
| POST | `/api/kc/assign-roles` | Assign roles to a user |
| POST | `/api/kc/assign-roles-batch` | Batch role assignment |
| POST | `/api/kc/create-clients` | Create SPA + API clients |
| POST | `/api/kc/update-client-urls` | Update client redirect URIs |
| POST | `/api/kc/setup-google` | Configure Google IdP |
| POST | `/api/ssh/list-users` | List users via SSH |
| POST | `/api/ssh/delete-all-users` | Delete all users via SSH |
| POST | `/api/s3/set-cors` | Set S3 bucket CORS rules |
| POST | `/api/jenkins/create-multibranch` | Create Jenkins pipeline |
| POST | `/api/db/query` | Run SQL query |
| POST | `/api/db/search-user` | Search user in database |
| POST | `/api/db/delete-user` | Delete user from database |

---

## Security Notes

- **Development only** --- debug mode is enabled and there is no authentication on the UI
- **No input sanitization** --- commands are built dynamically from user input; do not expose to untrusted networks
- **Passwords in presets** --- stored in plain-text JSON on disk
- Run behind a VPN or on `localhost` only

---

## License

MIT License. See [LICENSE](LICENSE) for details.
