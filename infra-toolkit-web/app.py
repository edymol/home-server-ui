#!/usr/bin/env python3
"""Infrastructure Toolkit — Web UI wrapping infra-toolkit.sh operations."""

import json
import subprocess
import threading
import time
import uuid
import os
import urllib.parse
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)
BASE_DIR = Path(__file__).parent
PRESETS_FILE = BASE_DIR / "presets.json"
JOBS: dict = {}  # job_id -> {status, output, command}

# ── Presets persistence ──────────────────────────────────────

DEFAULT_PRESETS = {
    "keycloak_urls": ["https://keycloak.example.com"],
    "keycloak_realms": ["master", "my-realm-1", "my-realm"],
    "keycloak_usernames": ["admin"],
    "keycloak_passwords": [],
    "jenkins_urls": ["https://jenkins.example.com"],
    "jenkins_usernames": ["admin"],
    "jenkins_passwords": [],
    "ssh_hosts": ["10.0.0.30"],
    "ssh_kc_ports": ["8090", "8080"],
    "s3_access_keys": [],
    "s3_secret_keys": [],
    "s3_endpoints": ["https://s3.example.com"],
    "s3_buckets": ["my-bucket"],
    "db_hosts": ["local"],
    "db_containers": ["my-db-container"],
    "db_users": ["my-db-user"],
    "db_names": ["my_database"],
    "spa_urls": ["http://localhost:4200", "https://invest.example.com"],
    "git_repos": ["git@github.com:your-org/your-repo.git"],
    "jenkins_cred_ids": ["jenkins-github-ssh"],
    "cors_origins": [
        "https://example.com",
        "https://www.example.com",
        "https://staging.example.com",
    ],
    "google_client_ids": [],
    "google_client_secrets": [],
    "smtp_hosts": ["smtp.example.com"],
    "smtp_froms": ["info@example.com"],
}


def load_presets() -> dict:
    if PRESETS_FILE.exists():
        with open(PRESETS_FILE) as f:
            saved = json.load(f)
        # merge with defaults so new keys appear
        merged = {**DEFAULT_PRESETS, **saved}
        return merged
    return dict(DEFAULT_PRESETS)


def save_presets(presets: dict):
    with open(PRESETS_FILE, "w") as f:
        json.dump(presets, f, indent=2)


# ── Command runner ───────────────────────────────────────────


def run_command(job_id: str, cmd: str, env_extra: dict | None = None):
    """Run a shell command, stream output into JOBS[job_id]."""
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["output"] = ""
    env = {**os.environ, **(env_extra or {})}
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            JOBS[job_id]["output"] += line
        proc.wait()
        JOBS[job_id]["exit_code"] = proc.returncode
        JOBS[job_id]["status"] = "done"
    except Exception as e:
        JOBS[job_id]["output"] += f"\n[ERROR] {e}\n"
        JOBS[job_id]["status"] = "error"


def start_job(cmd: str, env_extra: dict | None = None) -> str:
    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {"status": "queued", "output": "", "command": cmd}
    t = threading.Thread(target=run_command, args=(job_id, cmd, env_extra), daemon=True)
    t.start()
    return job_id


# ── Keycloak token helper (builds a bash snippet) ───────────


def kc_token_snippet(url: str, user: str, password: str) -> str:
    return (
        f'KC_RESPONSE=$(curl -s -X POST "{url}/realms/master/protocol/openid-connect/token" '
        f'-H "Content-Type: application/x-www-form-urlencoded" '
        f'-d "username={user}" '
        f'-d "password={password}" '
        f'-d "grant_type=password" '
        f'-d "client_id=admin-cli" '
        f'-w "\\n%{{http_code}}")\n'
        f'KC_HTTP_CODE=$(echo "$KC_RESPONSE" | tail -1)\n'
        f'KC_BODY=$(echo "$KC_RESPONSE" | sed \\$d)\n'
        f'if [ "$KC_HTTP_CODE" != "200" ] || [ -z "$KC_BODY" ]; then\n'
        f'  echo "ERROR: Keycloak auth failed (HTTP $KC_HTTP_CODE). Check URL and credentials." >&2\n'
        f'  echo "Response: $KC_BODY" >&2\n'
        f'  exit 1\n'
        f'fi\n'
        f"KC_TOKEN=$(echo \"$KC_BODY\" | python3 -c \"import sys,json; print(json.load(sys.stdin)['access_token'])\")"
    )


# ── Routes ───────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html", presets=load_presets())


# ── Presets API ──────────────────────────────────────────────


@app.route("/api/presets", methods=["GET"])
def get_presets():
    return jsonify(load_presets())


@app.route("/api/presets", methods=["POST"])
def update_presets():
    data = request.json
    presets = load_presets()
    key = data.get("key")
    value = data.get("value")
    action = data.get("action", "add")
    if key not in presets:
        return jsonify({"error": f"Unknown preset key: {key}"}), 400
    if action == "add" and value and value not in presets[key]:
        presets[key].append(value)
    elif action == "remove" and value in presets[key]:
        presets[key].remove(value)
    elif action == "set":
        presets[key] = data.get("values", [])
    save_presets(presets)
    return jsonify(presets)


# ── Job status API ───────────────────────────────────────────


@app.route("/api/jobs/<job_id>")
def job_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify(job)


@app.route("/api/jobs/<job_id>/stream")
def job_stream(job_id):
    def generate():
        last_len = 0
        while True:
            job = JOBS.get(job_id)
            if not job:
                break
            current = job["output"]
            if len(current) > last_len:
                yield f"data: {json.dumps({'text': current[last_len:], 'status': job['status']})}\n\n"
                last_len = len(current)
            if job["status"] in ("done", "error"):
                yield f"data: {json.dumps({'text': '', 'status': job['status'], 'exit_code': job.get('exit_code', -1)})}\n\n"
                break
            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream")


# ── Keycloak: Users ──────────────────────────────────────────


@app.route("/api/kc/list-users", methods=["POST"])
def kc_list_users():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    cmd = f"""
{token_cmd}
curl -s "{d['url']}/admin/realms/{d['realm']}/users?max={d.get('max', 100)}" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "
import sys,json
users=json.load(sys.stdin)
if not users: print('No users found.')
else:
    for u in users:
        print(f\\"{{u['id']}}  {{u.get('email','-')}}  {{u.get('username','-')}}\\")
    print(f'\\nTotal: {{len(users)}}')
"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/find-user", methods=["POST"])
def kc_find_user():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    search_param = f"email={d['search_value']}" if d.get("search_by") == "email" else f"username={d['search_value']}&exact=true"
    cmd = f"""
{token_cmd}
curl -s "{d['url']}/admin/realms/{d['realm']}/users?{search_param}" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -m json.tool
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/create-user", methods=["POST"])
def kc_create_user():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    actions = json.dumps(d.get("required_actions", []))
    user_json = json.dumps({
        "username": d["new_username"],
        "email": d["new_email"],
        "firstName": d["first_name"],
        "lastName": d["last_name"],
        "enabled": True,
        "emailVerified": d.get("email_verified", True),
        "credentials": [{"type": "password", "value": d["new_password"], "temporary": d.get("temp_password", False)}],
        "requiredActions": d.get("required_actions", []),
    })
    target_realm = d.get("target_realm", d.get("realm", "master"))
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{target_realm}/users" \\
  -H "Authorization: Bearer $KC_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{user_json}')
echo "User '{d['new_username']}': HTTP $CODE (realm: {target_realm})"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/delete-user", methods=["POST"])
def kc_delete_user():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    emails = d.get("emails", [])
    delete_cmds = ""
    for email in emails:
        delete_cmds += f"""
USER_ID=$(curl -s "{d['url']}/admin/realms/{d['realm']}/users?email={email}" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
if [ -z "$USER_ID" ]; then
  echo "{email}: NOT FOUND"
else
  CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X DELETE "{d['url']}/admin/realms/{d['realm']}/users/$USER_ID" \\
    -H "Authorization: Bearer $KC_TOKEN")
  echo "{email} ($USER_ID): HTTP $CODE"
fi
"""
    cmd = f"""
{token_cmd}
{delete_cmds}
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/create-users-batch", methods=["POST"])
def kc_create_users_batch():
    d = request.json
    target_realm = d.get("target_realm", d.get("realm", "master"))
    users = d.get("users", [])
    if not users:
        return jsonify({"error": "No users provided"}), 400
    cmds = ""
    for u in users:
        user_json = json.dumps({
            "username": u["username"],
            "email": u.get("email", ""),
            "firstName": u.get("firstName", ""),
            "lastName": u.get("lastName", ""),
            "enabled": True,
            "emailVerified": u.get("emailVerified", True),
            "credentials": [{"type": "password", "value": u.get("password", ""), "temporary": u.get("temporary", False)}],
            "requiredActions": [],
        })
        cmds += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{target_realm}/users" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{user_json}')
echo "{u['username']}: HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmds)})


@app.route("/api/kc/search-all-realms", methods=["POST"])
def kc_search_all_realms():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    cmd = f"""
{token_cmd}
REALMS=$(curl -s "{d['url']}/admin/realms" -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; [print(r['realm']) for r in json.load(sys.stdin)]")
for REALM in $REALMS; do
  echo "=== $REALM ==="
  curl -s "{d['url']}/admin/realms/$REALM/users?email={d['email']}" \\
    -H "Authorization: Bearer $KC_TOKEN" | python3 -c "
import sys,json
try:
    users=json.load(sys.stdin)
    if not users: print('  (none)')
    else: [print(f\\"  {{u['id']}} — {{u.get('email','-')}} — {{u.get('username','-')}}\\") for u in users]
except: print('  (access denied or error)')
"
done
"""
    return jsonify({"job_id": start_job(cmd)})


# ── Keycloak: Roles ──────────────────────────────────────────


@app.route("/api/kc/create-roles", methods=["POST"])
def kc_create_roles():
    d = request.json
    target_realm = d.get("target_realm", d.get("realm", "master"))
    roles = d.get("roles", [])
    if not roles:
        return jsonify({"error": "No roles provided"}), 400
    cmds = f"{kc_token_snippet(d['url'], d['username'], d['password'])}\n"
    for role in roles:
        name = role["name"]
        rj = json.dumps({"name": name, "description": role.get("description", "")})
        cmds += f"""
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{target_realm}/roles" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{rj}')
echo "{name}: HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmds)})


@app.route("/api/kc/assign-roles", methods=["POST"])
def kc_assign_roles():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    target_user = d["target_username"]
    roles = d["roles"]  # list of role names
    role_fetch = ""
    role_vars = []
    for i, r in enumerate(roles):
        var = f"ROLE{i}"
        role_fetch += f'{var}=$(curl -s "{d["url"]}/admin/realms/{d["realm"]}/roles/{r}" -H "Authorization: Bearer $KC_TOKEN")\n'
        role_vars.append(f"${var}")
    role_array = "[" + ",".join(role_vars) + "]"
    cmd = f"""
{token_cmd}
USER_ID=$(curl -s "{d['url']}/admin/realms/{d['realm']}/users?username={target_user}&exact=true" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
if [ -z "$USER_ID" ]; then
  echo "User '{target_user}' not found"
  exit 1
fi
echo "User ID: $USER_ID"
{role_fetch}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST \\
  "{d['url']}/admin/realms/{d['realm']}/users/$USER_ID/role-mappings/realm" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d "{role_array}")
echo "{target_user} roles ({', '.join(roles)}): HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/assign-roles-batch", methods=["POST"])
def kc_assign_roles_batch():
    d = request.json
    target_realm = d.get("target_realm", d.get("realm", "master"))
    assignments = d.get("assignments", [])
    if not assignments:
        return jsonify({"error": "No assignments provided"}), 400
    cmds = ""
    for entry in assignments:
        user = entry["username"]
        roles = entry["roles"]
        token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
        role_fetch = ""
        role_vars = []
        for i, r in enumerate(roles):
            var = f"R{i}"
            role_fetch += f'{var}=$(curl -s "{d["url"]}/admin/realms/{target_realm}/roles/{r}" -H "Authorization: Bearer $KC_TOKEN")\n'
            role_vars.append(f"${var}")
        role_array = "[" + ",".join(role_vars) + "]"
        cmds += f"""
{token_cmd}
UID=$(curl -s "{d['url']}/admin/realms/{target_realm}/users?username={user}&exact=true" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
if [ -z "$UID" ]; then echo "{user}: NOT FOUND"; else
{role_fetch}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST \\
  "{d['url']}/admin/realms/{target_realm}/users/$UID/role-mappings/realm" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d "{role_array}")
echo "{user} ({', '.join(roles)}): HTTP $CODE"
fi
"""
    return jsonify({"job_id": start_job(cmds)})


# ── Keycloak: Realm ──────────────────────────────────────────


@app.route("/api/kc/create-realm", methods=["POST"])
def kc_create_realm():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    realm_json = json.dumps({
        "realm": d["realm_name"],
        "enabled": True,
        "displayName": d.get("display_name", d["realm_name"]),
        "registrationAllowed": True,
        "resetPasswordAllowed": True,
        "rememberMe": True,
        "verifyEmail": d.get("verify_email", "false") == "true",
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "bruteForceProtected": True,
        "permanentLockout": False,
        "failureFactor": 5,
        "waitIncrementSeconds": 60,
        "maxFailureWaitSeconds": 900,
        "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 28800,
        "loginTheme": d.get("login_theme", d["realm_name"]),
        "accountTheme": "keycloak.v2",
        "sslRequired": "external",
        "otpPolicyType": "totp",
        "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyDigits": 6,
        "otpPolicyPeriod": 30,
        "smtpServer": {
            "host": d.get("smtp_host", "smtp.example.com"),
            "port": d.get("smtp_port", "465"),
            "from": d.get("smtp_from", "info@example.com"),
            "fromDisplayName": d.get("display_name", d["realm_name"]),
            "ssl": "true",
            "starttls": "false",
            "auth": "true",
            "user": d.get("smtp_user", d.get("smtp_from", "info@example.com")),
        },
    })
    client_cmd = ""
    if d.get("client_id"):
        client_type = d.get("client_type", "confidential")
        is_public = client_type == "public"
        root_url = d.get("root_url", "http://localhost:3000")
        web_origins = d.get("web_origins", root_url)
        client_json = json.dumps({
            "clientId": d["client_id"],
            "name": d.get("client_name", d["client_id"]),
            "enabled": True,
            "publicClient": is_public,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": not is_public,
            "rootUrl": root_url,
            "baseUrl": root_url,
            "redirectUris": [f"{root_url}/*"],
            "webOrigins": [o.strip() for o in web_origins.split(",")],
            "protocol": "openid-connect",
            **({"attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{root_url}/*"}} if is_public else {}),
            **({"secret": d["client_secret"]} if not is_public and d.get("client_secret") else {}),
        })
        client_cmd = f"""
echo ""
echo "--- Creating client '{d['client_id']}' ---"
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{d['realm_name']}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{client_json}')
echo "Client '{d['client_id']}': HTTP $CODE"

if [ "$CODE" = "201" ] || [ "$CODE" = "409" ]; then
  {kc_token_snippet(d['url'], d['username'], d['password'])}
  CLIENT_DATA=$(curl -s "{d['url']}/admin/realms/{d['realm_name']}/clients?clientId={d['client_id']}" \\
    -H "Authorization: Bearer $KC_TOKEN")
  echo "Client UUID: $(echo "$CLIENT_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)"
  SECRET=$(echo "$CLIENT_DATA" | python3 -c "import sys,json; c=json.load(sys.stdin)[0]; print(c.get('secret','(fetch from Keycloak Credentials tab)'))" 2>/dev/null)
  echo "Client Secret: $SECRET"
fi
"""
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{realm_json}')
echo "Realm '{d['realm_name']}': HTTP $CODE"
{client_cmd}
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/configure-security", methods=["POST"])
def kc_configure_security():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT "{d['url']}/admin/realms/{d['realm']}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{{"verifyEmail": true}}')
echo "Email verification: HTTP $CODE"

{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT "{d['url']}/admin/realms/{d['realm']}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{{"passwordPolicy": "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername"}}')
echo "Password policy: HTTP $CODE"

{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT "{d['url']}/admin/realms/{d['realm']}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{{"bruteForceProtected": true, "failureFactor": 5, "waitIncrementSeconds": 900}}')
echo "Brute force protection: HTTP $CODE"

{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT "{d['url']}/admin/realms/{d['realm']}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{{"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30}}')
echo "OTP policy: HTTP $CODE"
echo ""
echo "Users can enable 2FA at: {d['url']}/realms/{d['realm']}/account/#/security/signingin"
"""
    return jsonify({"job_id": start_job(cmd)})


# ── Keycloak: Clients ────────────────────────────────────────


@app.route("/api/kc/create-client-custom", methods=["POST"])
def kc_create_client_custom():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    client_type = d.get("client_type", "confidential")
    is_public = client_type == "public"
    root_url = d.get("root_url", "http://localhost:3000")
    web_origins = d.get("web_origins", root_url)
    client_json = json.dumps({
        "clientId": d["client_id"],
        "name": d.get("client_name", d["client_id"]),
        "enabled": True,
        "publicClient": is_public,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": not is_public,
        "rootUrl": root_url,
        "baseUrl": root_url,
        "redirectUris": [f"{root_url}/*"],
        "webOrigins": [o.strip() for o in web_origins.split(",")],
        "protocol": "openid-connect",
        **({"attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{root_url}/*"}} if is_public else {}),
    })
    target_realm = d.get("target_realm", d.get("realm", "master"))
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{target_realm}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{client_json}')
echo "{d['client_id']}: HTTP $CODE (realm: {target_realm})"

if [ "$CODE" = "201" ] || [ "$CODE" = "409" ]; then
  {kc_token_snippet(d['url'], d['username'], d['password'])}
  CLIENT_UUID=$(curl -s "{d['url']}/admin/realms/{target_realm}/clients?clientId={d['client_id']}" \\
    -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
  echo ""
  echo "Client UUID: $CLIENT_UUID"
  SECRET=$(curl -s "{d['url']}/admin/realms/{target_realm}/clients/$CLIENT_UUID/client-secret" \\
    -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('value','(none)'))" 2>/dev/null)
  echo "Client Secret: $SECRET"
fi
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/client-roles", methods=["POST"])
def kc_client_roles():
    d = request.json
    action = d.get("action", "list")
    target_realm = d.get("target_realm", d.get("realm", "master"))
    import subprocess

    # Get token
    token_result = subprocess.run(
        ["curl", "-sf", "-X", "POST",
         f"{d['url']}/realms/master/protocol/openid-connect/token",
         "-H", "Content-Type: application/x-www-form-urlencoded",
         "-d", f"username={d['username']}",
         "-d", f"password={d['password']}",
         "-d", "grant_type=password",
         "-d", "client_id=admin-cli"],
        capture_output=True, text=True, timeout=10
    )
    try:
        token = json.loads(token_result.stdout)["access_token"]
    except Exception:
        return jsonify({"error": "Auth failed"})

    auth_header = f"Authorization: Bearer {token}"

    # Get target client UUID
    r = subprocess.run(["curl", "-s", f"{d['url']}/admin/realms/{target_realm}/clients?clientId={d['client_id']}", "-H", auth_header], capture_output=True, text=True, timeout=10)
    try:
        client_uuid = json.loads(r.stdout)[0]["id"]
    except Exception:
        return jsonify({"error": f"Client '{d.get('client_id', '')}' not found in realm '{target_realm}'"})

    # Get realm-management client UUID
    r = subprocess.run(["curl", "-s", f"{d['url']}/admin/realms/{target_realm}/clients?clientId=realm-management", "-H", auth_header], capture_output=True, text=True, timeout=10)
    try:
        rm_uuid = json.loads(r.stdout)[0]["id"]
    except Exception:
        return jsonify({"error": "realm-management client not found"})

    # Get service account user
    r = subprocess.run(["curl", "-s", f"{d['url']}/admin/realms/{target_realm}/clients/{client_uuid}/service-account-user", "-H", auth_header], capture_output=True, text=True, timeout=10)
    try:
        sa_user_id = json.loads(r.stdout)["id"]
    except Exception:
        return jsonify({"error": "No service account found — is 'Service accounts roles' enabled on this client?"})

    if action == "list":
        # Get current client role mappings for realm-management
        r = subprocess.run(["curl", "-s", f"{d['url']}/admin/realms/{target_realm}/users/{sa_user_id}/role-mappings/clients/{rm_uuid}", "-H", auth_header], capture_output=True, text=True, timeout=10)
        current = json.loads(r.stdout) if r.stdout else []

        # Get all available realm-management roles
        r = subprocess.run(["curl", "-s", f"{d['url']}/admin/realms/{target_realm}/clients/{rm_uuid}/roles", "-H", auth_header], capture_output=True, text=True, timeout=10)
        available = json.loads(r.stdout) if r.stdout else []

        return jsonify({
            "current": [{"name": r["name"]} for r in current],
            "available": [{"name": r["name"]} for r in available],
            "sa_user_id": sa_user_id,
            "rm_uuid": rm_uuid,
        })

    elif action == "assign":
        roles = d.get("roles", [])
        token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
        role_fetch = ""
        role_vars = []
        for i, r in enumerate(roles):
            var = f"R{i}"
            role_fetch += f'{var}=$(curl -s "{d["url"]}/admin/realms/{target_realm}/clients/{rm_uuid}/roles/{r}" -H "Authorization: Bearer $KC_TOKEN")\n'
            role_vars.append(f"${var}")
        role_array = "[" + ",".join(role_vars) + "]"
        cmd = f"""
{token_cmd}
echo "Assigning realm-management roles to service account..."
{role_fetch}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST \\
  "{d['url']}/admin/realms/{target_realm}/users/{sa_user_id}/role-mappings/clients/{rm_uuid}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d "{role_array}")
echo "Assign roles ({', '.join(roles)}): HTTP $CODE"
"""
        return jsonify({"job_id": start_job(cmd)})

    return jsonify({"error": "Unknown action"})


@app.route("/api/kc/list-clients", methods=["POST"])
def kc_list_clients():
    d = request.json
    import subprocess
    # Get token
    token_result = subprocess.run(
        ["curl", "-sf", "-X", "POST",
         f"{d['url']}/realms/master/protocol/openid-connect/token",
         "-H", "Content-Type: application/x-www-form-urlencoded",
         "-d", f"username={d['username']}",
         "-d", f"password={d['password']}",
         "-d", "grant_type=password",
         "-d", "client_id=admin-cli"],
        capture_output=True, text=True, timeout=10
    )
    try:
        token = json.loads(token_result.stdout)["access_token"]
    except Exception:
        return jsonify({"clients": [], "error": "Auth failed"})
    # List clients
    target_realm = d.get("target_realm", d.get("realm", "master"))
    clients_result = subprocess.run(
        ["curl", "-s",
         f"{d['url']}/admin/realms/{target_realm}/clients",
         "-H", f"Authorization: Bearer {token}"],
        capture_output=True, text=True, timeout=10
    )
    try:
        clients = json.loads(clients_result.stdout)
        # Filter out Keycloak internal clients
        filtered = [{"clientId": c["clientId"], "name": c.get("name", ""), "protocol": c.get("protocol", "")}
                     for c in clients if not c.get("clientId", "").startswith(("account", "admin-cli", "broker", "realm-management", "security-admin"))]
        return jsonify({"clients": filtered})
    except Exception:
        return jsonify({"clients": [], "error": "Failed to parse clients"})


@app.route("/api/kc/delete-client", methods=["POST"])
def kc_delete_client():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    client_id = d["client_id"]
    target_realm = d.get("target_realm", d.get("realm", "master"))
    cmd = f"""
{token_cmd}
CLIENT_UUID=$(curl -s "{d['url']}/admin/realms/{target_realm}/clients?clientId={client_id}" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['id'] if data else '')" 2>/dev/null)
if [ -z "$CLIENT_UUID" ]; then
  echo "Client '{client_id}' not found in realm '{target_realm}'"
  exit 1
fi
echo "Found client UUID: $CLIENT_UUID"
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X DELETE "{d['url']}/admin/realms/{target_realm}/clients/$CLIENT_UUID" \\
  -H "Authorization: Bearer $KC_TOKEN")
echo "Delete '{client_id}': HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/create-clients", methods=["POST"])
def kc_create_clients():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    spa_url = d.get("spa_url", "http://localhost:4200")
    api_secret = d.get("api_secret", "property-api-secret")
    spa_json = json.dumps({
        "clientId": "property-spa",
        "name": "My Platform SPA",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "rootUrl": spa_url,
        "baseUrl": spa_url,
        "redirectUris": [f"{spa_url}/*"],
        "webOrigins": [spa_url],
        "protocol": "openid-connect",
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{spa_url}/*"},
        "fullScopeAllowed": True,
    })
    api_json = json.dumps({
        "clientId": "property-api",
        "name": "My Platform API",
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "secret": api_secret,
        "protocol": "openid-connect",
    })
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{d['realm']}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{spa_json}')
echo "property-spa: HTTP $CODE"

{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{d['realm']}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{api_json}')
echo "property-api: HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/update-client-urls", methods=["POST"])
def kc_update_client_urls():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    client_id = d.get("client_id", "property-spa")
    prod_url = d["prod_url"]
    update_json = json.dumps({
        "clientId": client_id,
        "rootUrl": prod_url,
        "baseUrl": prod_url,
        "redirectUris": [f"{prod_url}/*", "http://localhost:4200/*"],
        "webOrigins": [prod_url, "http://localhost:4200"],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": f"{prod_url}/*##http://localhost:4200/*",
        },
    })
    cmd = f"""
{token_cmd}
CLIENT_UUID=$(curl -s "{d['url']}/admin/realms/{d['realm']}/clients?clientId={client_id}" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)
echo "Client UUID: $CLIENT_UUID"
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT \\
  "{d['url']}/admin/realms/{d['realm']}/clients/$CLIENT_UUID" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{update_json}')
echo "Update: HTTP $CODE"
"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/kc/setup-google", methods=["POST"])
def kc_setup_google():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    idp_json = json.dumps({
        "alias": "google",
        "providerId": "google",
        "enabled": True,
        "trustEmail": True,
        "config": {
            "clientId": d["google_client_id"],
            "clientSecret": d["google_client_secret"],
            "defaultScope": "openid email profile",
            "syncMode": "IMPORT",
            "guiOrder": "1",
        },
    })
    cmd = f"""
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST \\
  "{d['url']}/admin/realms/{d['realm']}/identity-provider/instances" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{idp_json}')
if [ "$CODE" = "409" ]; then
  echo "Google IDP exists, updating..."
  {kc_token_snippet(d['url'], d['username'], d['password'])}
  CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT \\
    "{d['url']}/admin/realms/{d['realm']}/identity-provider/instances/google" \\
    -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
    -d '{idp_json}')
  echo "Update: HTTP $CODE"
else
  echo "Create: HTTP $CODE"
fi
"""
    return jsonify({"job_id": start_job(cmd)})


# ── SSH Remote Keycloak ──────────────────────────────────────


@app.route("/api/ssh/list-users", methods=["POST"])
def ssh_list_users():
    d = request.json
    encoded_pass = urllib.parse.quote(d["password"])
    cmd = f"""ssh {d['ssh_host']} "
TOKEN=\\$(curl -s -X POST 'http://localhost:{d['ssh_port']}/realms/master/protocol/openid-connect/token' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'client_id=admin-cli&username={d['username']}&password={encoded_pass}&grant_type=password' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\\"access_token\\"])')
curl -s 'http://localhost:{d['ssh_port']}/admin/realms/{d['realm']}/users?max=100' \\
  -H \\"Authorization: Bearer \\$TOKEN\\" | python3 -c 'import sys,json; users=json.load(sys.stdin); [print(u[\\"id\\"], u.get(\\"email\\",\\"-\\"), u.get(\\"username\\",\\"-\\")) for u in users]; print(\\"Total:\\", len(users))'
" 2>&1"""
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/ssh/delete-all-users", methods=["POST"])
def ssh_delete_all_users():
    d = request.json
    encoded_pass = urllib.parse.quote(d["password"])
    cmd = f"""ssh {d['ssh_host']} "
TOKEN=\\$(curl -s -X POST 'http://localhost:{d['ssh_port']}/realms/master/protocol/openid-connect/token' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -d 'client_id=admin-cli&username={d['username']}&password={encoded_pass}&grant_type=password' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\\"access_token\\"])')
USERS=\\$(curl -s 'http://localhost:{d['ssh_port']}/admin/realms/{d['realm']}/users?max=100' \\
  -H \\"Authorization: Bearer \\$TOKEN\\" | python3 -c 'import sys,json; [print(u[\\"id\\"]) for u in json.load(sys.stdin)]')
for ID in \\$USERS; do
  STATUS=\\$(curl -s -o /dev/null -w '%{{http_code}}' -X DELETE \\"http://localhost:{d['ssh_port']}/admin/realms/{d['realm']}/users/\\$ID\\" \\
    -H \\"Authorization: Bearer \\$TOKEN\\")
  echo \\"Deleted \\$ID: \\$STATUS\\"
done
" 2>&1"""
    return jsonify({"job_id": start_job(cmd)})


# ── Garage S3 CORS ───────────────────────────────────────────


@app.route("/api/s3/set-cors", methods=["POST"])
def s3_set_cors():
    d = request.json
    origins = d.get("origins", [])
    cors_config = json.dumps({
        "CORSRules": [{
            "AllowedOrigins": origins,
            "AllowedMethods": ["GET", "HEAD", "PUT"],
            "AllowedHeaders": ["Content-Type"],
            "ExposeHeaders": ["ETag"],
            "MaxAgeSeconds": 3600,
        }]
    })
    cors_file = f"/tmp/cors-{uuid.uuid4().hex[:8]}.json"
    cmd = f"""
cat > {cors_file} <<'EOFCORS'
{cors_config}
EOFCORS
echo "CORS config written to {cors_file}"
cat {cors_file}
echo ""
AWS_ACCESS_KEY_ID="{d['access_key']}" \\
AWS_SECRET_ACCESS_KEY="{d['secret_key']}" \\
AWS_DEFAULT_REGION=garage \\
aws s3api put-bucket-cors \\
  --bucket "{d['bucket']}" \\
  --cors-configuration "file://{cors_file}" \\
  --endpoint-url "{d['endpoint']}" && echo "CORS applied successfully" || echo "CORS failed"
rm -f {cors_file}
"""
    return jsonify({"job_id": start_job(cmd)})


# ── Jenkins ──────────────────────────────────────────────────


@app.route("/api/jenkins/create-multibranch", methods=["POST"])
def jenkins_create_multibranch():
    d = request.json
    cmd = f"""
COOKIE_JAR="/tmp/jenkins-cookies-$$.txt"
CRUMB=$(curl -s -u "{d['jenkins_user']}:{d['jenkins_pass']}" \\
  -c "$COOKIE_JAR" \\
  "{d['jenkins_url']}/crumbIssuer/api/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['crumb'])" 2>/dev/null)
if [ -z "$CRUMB" ]; then echo "Failed to get crumb"; exit 1; fi
echo "Crumb obtained"
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" \\
  -u "{d['jenkins_user']}:{d['jenkins_pass']}" \\
  -b "$COOKIE_JAR" \\
  -H "Jenkins-Crumb: $CRUMB" \\
  -H "Content-Type: application/xml" \\
  -X POST "{d['jenkins_url']}/createItem?name={d['job_name']}" \\
  -d '<?xml version="1.0" encoding="UTF-8"?>
<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject plugin="workflow-multibranch">
  <description>{d['job_name']}</description>
  <factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory">
    <scriptPath>{d.get('jenkinsfile', 'jenkins/Jenkinsfile.frontend')}</scriptPath>
  </factory>
  <sources class="jenkins.branch.MultiBranchProject$$BranchSourceList">
    <data>
      <jenkins.branch.BranchSource>
        <source class="jenkins.plugins.git.GitSCMSource">
          <id>{d['job_name']}-src</id>
          <remote>{d['git_repo']}</remote>
          <credentialsId>{d.get('cred_id', 'jenkins-github-ssh')}</credentialsId>
          <traits>
            <jenkins.plugins.git.traits.BranchDiscoveryTrait/>
          </traits>
        </source>
      </jenkins.branch.BranchSource>
    </data>
  </sources>
  <orphanedItemStrategy class="com.cloudbees.hudson.plugins.folder.computed.DefaultOrphanedItemStrategy">
    <pruneDeadBranches>true</pruneDeadBranches>
    <daysToKeep>7</daysToKeep>
    <numToKeep>5</numToKeep>
  </orphanedItemStrategy>
</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>')
echo "{d['job_name']}: HTTP $CODE"
rm -f "$COOKIE_JAR"
"""
    return jsonify({"job_id": start_job(cmd)})


# ── Docker Database ──────────────────────────────────────────


@app.route("/api/db/query", methods=["POST"])
def db_query():
    d = request.json
    psql_cmd = f'docker exec {d["container"]} psql -U {d["db_user"]} -d {d["db_name"]} -c "{d["query"]}"'
    if d.get("db_host", "local") == "local":
        cmd = psql_cmd
    else:
        cmd = f'ssh {d["db_host"]} \'{psql_cmd}\''
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/db/search-user", methods=["POST"])
def db_search_user():
    d = request.json
    pattern = d["pattern"]
    sql = f"SELECT id, email, first_name, last_name, username FROM users WHERE email ILIKE '%{pattern}%' OR username ILIKE '%{pattern}%';"
    psql_cmd = f'docker exec {d["container"]} psql -U {d["db_user"]} -d {d["db_name"]} -c "{sql}"'
    if d.get("db_host", "local") == "local":
        cmd = psql_cmd
    else:
        cmd = f'ssh {d["db_host"]} \'{psql_cmd}\''
    return jsonify({"job_id": start_job(cmd)})


@app.route("/api/db/delete-user", methods=["POST"])
def db_delete_user():
    d = request.json
    email = d["email"]
    sql_select = f"SELECT id, email, first_name, last_name FROM users WHERE email = '{email}';"
    sql_delete = f"DELETE FROM users WHERE email = '{email}';"
    psql_base = f'docker exec {d["container"]} psql -U {d["db_user"]} -d {d["db_name"]}'
    if d.get("db_host", "local") == "local":
        cmd = f'{psql_base} -c "{sql_select}" && echo "---" && {psql_base} -c "{sql_delete}"'
    else:
        cmd = f'ssh {d["db_host"]} \'{psql_base} -c "{sql_select}" && echo "---" && {psql_base} -c "{sql_delete}"\''
    return jsonify({"job_id": start_job(cmd)})


# ── Full Setup Wizard ────────────────────────────────────────


@app.route("/api/kc/full-setup", methods=["POST"])
def kc_full_setup():
    d = request.json
    token_cmd = kc_token_snippet(d["url"], d["username"], d["password"])
    realm_name = d.get("realm_name", d["realm"])
    display_name = d.get("display_name", "My Platform")
    spa_url = d.get("spa_url", "http://localhost:4200")
    api_secret = d.get("api_secret", "property-api-secret")

    realm_json = json.dumps({
        "realm": realm_name, "enabled": True, "displayName": display_name,
        "registrationAllowed": True, "resetPasswordAllowed": True, "rememberMe": True,
        "verifyEmail": True, "loginWithEmailAllowed": True, "duplicateEmailsAllowed": False,
        "bruteForceProtected": True, "permanentLockout": False, "failureFactor": 5,
        "waitIncrementSeconds": 60, "maxFailureWaitSeconds": 900, "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
        "loginTheme": d.get("login_theme", realm_name), "accountTheme": "keycloak.v2",
        "sslRequired": "external", "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyDigits": 6, "otpPolicyPeriod": 30,
        "smtpServer": {
            "host": d.get("smtp_host", "smtp.example.com"), "port": d.get("smtp_port", "465"),
            "from": d.get("smtp_from", "info@example.com"), "fromDisplayName": display_name,
            "ssl": "true", "starttls": "false", "auth": "true",
            "user": d.get("smtp_user", d.get("smtp_from", "info@example.com")),
        },
    })

    roles = [
        ("ROLE_USER", "Free/trial tier user"), ("ROLE_PREMIUM_USER", "Paying investor with full access"),
        ("ROLE_ANALYST", "Internal operations analyst"), ("ROLE_ADMIN", "Platform administrator"),
        ("ROLE_SUPER_ADMIN", "Platform owner - highest privilege"),
    ]

    spa_json = json.dumps({
        "clientId": "property-spa", "name": "My Platform SPA", "enabled": True,
        "publicClient": True, "standardFlowEnabled": True, "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": True, "rootUrl": spa_url, "baseUrl": spa_url,
        "redirectUris": [f"{spa_url}/*"], "webOrigins": [spa_url], "protocol": "openid-connect",
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"{spa_url}/*"},
        "fullScopeAllowed": True,
    })

    api_json = json.dumps({
        "clientId": "property-api", "name": "My Platform API", "enabled": True,
        "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False, "secret": api_secret, "protocol": "openid-connect",
    })

    users = [
        {"username": "edy", "email": "edy@example.com", "firstName": "Edy", "lastName": "Molina",
         "enabled": True, "emailVerified": True, "credentials": [{"type": "password", "value": "Test1234!", "temporary": False}],
         "requiredActions": ["CONFIGURE_TOTP"]},
        {"username": "admin-user", "email": "admin@example.com", "firstName": "Admin", "lastName": "User",
         "enabled": True, "emailVerified": True, "credentials": [{"type": "password", "value": "Admin1234!", "temporary": False}],
         "requiredActions": []},
        {"username": "free-user", "email": "free@example.com", "firstName": "Jan", "lastName": "Kowalski",
         "enabled": True, "emailVerified": True, "credentials": [{"type": "password", "value": "Test1234!", "temporary": False}],
         "requiredActions": []},
        {"username": "newuser", "email": "newuser@example.com", "firstName": "New", "lastName": "User",
         "enabled": True, "emailVerified": False, "credentials": [{"type": "password", "value": "Test1234!", "temporary": False}],
         "requiredActions": ["VERIFY_EMAIL", "CONFIGURE_TOTP"]},
    ]

    assignments = [
        ("edy", ["ROLE_USER", "ROLE_PREMIUM_USER"]),
        ("admin-user", ["ROLE_USER", "ROLE_PREMIUM_USER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN"]),
        ("free-user", ["ROLE_USER"]),
        ("newuser", ["ROLE_USER"]),
    ]

    cmd = f"""
echo "══════ STEP 1: Create Realm ══════"
{token_cmd}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{realm_json}')
echo "Realm '{realm_name}': HTTP $CODE"

echo ""
echo "══════ STEP 2: Security Config ══════"
"""
    for label, payload in [
        ("Email verification", '{"verifyEmail": true}'),
        ("Password policy", '{"passwordPolicy": "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername"}'),
        ("Brute force", '{"bruteForceProtected": true, "failureFactor": 5, "waitIncrementSeconds": 900}'),
        ("OTP policy", '{"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30}'),
    ]:
        cmd += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X PUT "{d['url']}/admin/realms/{realm_name}" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{payload}')
echo "{label}: HTTP $CODE"
"""

    cmd += '\necho ""\necho "══════ STEP 3: Create Roles ══════"\n'
    for name, desc in roles:
        rj = json.dumps({"name": name, "description": desc})
        cmd += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{realm_name}/roles" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{rj}')
echo "{name}: HTTP $CODE"
"""

    cmd += '\necho ""\necho "══════ STEP 4: Create Clients ══════"\n'
    cmd += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{realm_name}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{spa_json}')
echo "property-spa: HTTP $CODE"
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{realm_name}/clients" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{api_json}')
echo "property-api: HTTP $CODE"
"""

    cmd += '\necho ""\necho "══════ STEP 5: Create Users ══════"\n'
    for u in users:
        uj = json.dumps(u)
        cmd += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST "{d['url']}/admin/realms/{realm_name}/users" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d '{uj}')
echo "{u['username']}: HTTP $CODE"
"""

    cmd += '\necho ""\necho "══════ STEP 6: Assign Roles ══════"\n'
    for user, user_roles in assignments:
        role_fetch = ""
        role_vars = []
        for i, r in enumerate(user_roles):
            var = f"R{i}"
            role_fetch += f'{var}=$(curl -s "{d["url"]}/admin/realms/{realm_name}/roles/{r}" -H "Authorization: Bearer $KC_TOKEN")\n'
            role_vars.append(f"${var}")
        role_array = "[" + ",".join(role_vars) + "]"
        cmd += f"""
{kc_token_snippet(d['url'], d['username'], d['password'])}
UID=$(curl -s "{d['url']}/admin/realms/{realm_name}/users?username={user}&exact=true" \\
  -H "Authorization: Bearer $KC_TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
{role_fetch}
CODE=$(curl -s -o /dev/null -w "%{{http_code}}" -X POST \\
  "{d['url']}/admin/realms/{realm_name}/users/$UID/role-mappings/realm" \\
  -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" \\
  -d "{role_array}")
echo "{user} ({', '.join(user_roles)}): HTTP $CODE"
"""
    cmd += '\necho ""\necho "══════ FULL SETUP COMPLETE ══════"'
    return jsonify({"job_id": start_job(cmd)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5111, debug=True)
