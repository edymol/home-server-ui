#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  Infrastructure Toolkit — Interactive Admin Script
#  Keycloak · Jenkins · Garage S3 · Docker DB
# ============================================================

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# --------------- Global state ---------------
KC_URL=""
KC_ADMIN_USER=""
KC_ADMIN_PASS=""
KC_REALM=""
KC_TOKEN=""
JENKINS_URL=""
JENKINS_USER=""
JENKINS_PASS=""
SSH_HOST=""
SSH_KC_PORT="8090"
S3_ACCESS_KEY=""
S3_SECRET_KEY=""
S3_ENDPOINT=""
S3_BUCKET=""
DB_CONTAINER=""
DB_USER=""
DB_NAME=""
DB_HOST=""

# --------------- Helpers ---------------
banner() {
  echo -e "\n${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC}  ${BOLD}$1${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}\n"
}

info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*"; }
prompt()  { echo -en "${BOLD}$1${NC}"; }

read_input() {
  local var_name="$1" prompt_text="$2" default="${3:-}"
  if [[ -n "$default" ]]; then
    prompt "$prompt_text [$default]: "
    read -r value
    eval "$var_name=\"${value:-$default}\""
  else
    prompt "$prompt_text: "
    read -r value
    eval "$var_name=\"$value\""
  fi
}

read_secret() {
  local var_name="$1" prompt_text="$2" default="${3:-}"
  if [[ -n "$default" ]]; then
    prompt "$prompt_text [****]: "
    read -rs value; echo
    eval "$var_name=\"${value:-$default}\""
  else
    prompt "$prompt_text: "
    read -rs value; echo
    eval "$var_name=\"$value\""
  fi
}

confirm() {
  prompt "$1 [y/N]: "
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

pause() {
  echo
  prompt "Press Enter to continue..."
  read -r
}

# --------------- Keycloak token ---------------
kc_get_token() {
  if [[ -z "$KC_URL" || -z "$KC_ADMIN_USER" || -z "$KC_ADMIN_PASS" ]]; then
    warn "Keycloak credentials not set. Configure them first."
    return 1
  fi
  KC_TOKEN=$(curl -sf -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KC_ADMIN_USER}" \
    -d "password=${KC_ADMIN_PASS}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) || {
    err "Failed to obtain Keycloak token. Check URL/credentials."
    KC_TOKEN=""
    return 1
  }
  info "Token acquired (valid ~60s)"
}

kc_ensure_token() {
  kc_get_token || return 1
}

# --------------- SSH Keycloak token ---------------
ssh_kc_get_token() {
  if [[ -z "$SSH_HOST" ]]; then
    warn "SSH host not set."
    return 1
  fi
  local token
  token=$(ssh "$SSH_HOST" "curl -s -X POST 'http://localhost:${SSH_KC_PORT}/realms/master/protocol/openid-connect/token' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'client_id=admin-cli&username=${KC_ADMIN_USER}&password=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${KC_ADMIN_PASS}'))")&grant_type=password' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"access_token\"])'") || {
    err "Failed to get token via SSH"
    return 1
  }
  echo "$token"
}

# ============================================================
#  CONFIGURATION MENUS
# ============================================================
configure_keycloak() {
  banner "Configure Keycloak Connection"
  read_input KC_URL        "Keycloak base URL (no trailing /)" "${KC_URL:-https://keycloak.neuracodeinc.com}"
  read_input KC_ADMIN_USER "Admin username"                     "${KC_ADMIN_USER:-edymolina}"
  read_secret KC_ADMIN_PASS "Admin password"                    "$KC_ADMIN_PASS"
  read_input KC_REALM      "Target realm"                       "${KC_REALM:-property-platform}"
  info "Keycloak configured: ${KC_URL} | realm=${KC_REALM}"
}

configure_jenkins() {
  banner "Configure Jenkins Connection"
  read_input JENKINS_URL   "Jenkins base URL"   "${JENKINS_URL:-https://jenkins.codershub.top}"
  read_input JENKINS_USER  "Jenkins username"    "${JENKINS_USER:-edymolina}"
  read_secret JENKINS_PASS "Jenkins password"    "$JENKINS_PASS"
  info "Jenkins configured: ${JENKINS_URL}"
}

configure_ssh() {
  banner "Configure SSH Keycloak (remote server)"
  read_input SSH_HOST     "SSH host (e.g. 192.168.0.30)" "${SSH_HOST}"
  read_input SSH_KC_PORT  "Keycloak port on remote"      "${SSH_KC_PORT:-8090}"
  info "SSH configured: ${SSH_HOST}:${SSH_KC_PORT}"
}

configure_s3() {
  banner "Configure Garage S3"
  read_input S3_ACCESS_KEY "AWS_ACCESS_KEY_ID"       "$S3_ACCESS_KEY"
  read_secret S3_SECRET_KEY "AWS_SECRET_ACCESS_KEY"  "$S3_SECRET_KEY"
  read_input S3_ENDPOINT   "S3 endpoint URL"         "${S3_ENDPOINT:-https://s3.revivedeal.com}"
  read_input S3_BUCKET     "Bucket name"             "${S3_BUCKET:-revive-deal}"
  info "S3 configured: ${S3_ENDPOINT} / ${S3_BUCKET}"
}

configure_docker_db() {
  banner "Configure Docker Database"
  read_input DB_HOST      "Docker host (SSH target or 'local')" "${DB_HOST:-local}"
  read_input DB_CONTAINER "Container name"                       "${DB_CONTAINER:-revive-db-prod}"
  read_input DB_USER      "Postgres user"                        "${DB_USER:-revive-prod}"
  read_input DB_NAME      "Database name"                        "${DB_NAME:-realestate_db_prod}"
  info "DB configured: ${DB_CONTAINER} (${DB_USER}@${DB_NAME})"
}

# ============================================================
#  KEYCLOAK — USER MANAGEMENT
# ============================================================
kc_list_users() {
  banner "List Users in Realm: ${KC_REALM}"
  kc_ensure_token || return
  local max
  read_input max "Max users to fetch" "100"
  echo
  curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?max=${max}" \
    -H "Authorization: Bearer ${KC_TOKEN}" | \
    python3 -c "
import sys,json
users=json.load(sys.stdin)
if not users:
    print('No users found.')
else:
    print(f'{'ID':<40} {'Email':<35} {'Username':<20}')
    print('-'*95)
    for u in users:
        print(f\"{u['id']:<40} {u.get('email','-'):<35} {u.get('username','-'):<20}\")
    print(f'\nTotal: {len(users)}')
"
}

kc_find_user() {
  banner "Find User"
  kc_ensure_token || return
  local search_type search_val
  echo "  1) By email"
  echo "  2) By username"
  read_input search_type "Choice" "1"
  if [[ "$search_type" == "1" ]]; then
    read_input search_val "Email address" ""
    curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?email=${search_val}" \
      -H "Authorization: Bearer ${KC_TOKEN}" | python3 -m json.tool
  else
    read_input search_val "Username" ""
    curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?username=${search_val}&exact=true" \
      -H "Authorization: Bearer ${KC_TOKEN}" | python3 -m json.tool
  fi
}

kc_delete_user() {
  banner "Delete User from Realm: ${KC_REALM}"
  kc_ensure_token || return
  local email user_id
  read_input email "Email of user to delete" ""
  user_id=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?email=${email}" \
    -H "Authorization: Bearer ${KC_TOKEN}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)

  if [[ -z "$user_id" ]]; then
    err "User not found: ${email}"
    return
  fi
  info "Found user: ${user_id}"
  if confirm "Delete user ${email} (${user_id})?"; then
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
      "${KC_URL}/admin/realms/${KC_REALM}/users/${user_id}" \
      -H "Authorization: Bearer ${KC_TOKEN}")
    [[ "$code" == "204" ]] && info "Deleted (HTTP ${code})" || err "Failed (HTTP ${code})"
  else
    warn "Aborted."
  fi
}

kc_delete_user_bulk() {
  banner "Bulk Delete Users from Realm: ${KC_REALM}"
  kc_ensure_token || return
  echo "Enter emails to delete (one per line, blank line to finish):"
  local emails=()
  while true; do
    read -r line
    [[ -z "$line" ]] && break
    emails+=("$line")
  done
  if [[ ${#emails[@]} -eq 0 ]]; then warn "No emails entered."; return; fi
  echo
  for email in "${emails[@]}"; do
    kc_get_token 2>/dev/null || { err "Token refresh failed"; return; }
    local user_id
    user_id=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?email=${email}" \
      -H "Authorization: Bearer ${KC_TOKEN}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)
    if [[ -z "$user_id" ]]; then
      warn "${email}: not found, skipping"
      continue
    fi
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
      "${KC_URL}/admin/realms/${KC_REALM}/users/${user_id}" \
      -H "Authorization: Bearer ${KC_TOKEN}")
    [[ "$code" == "204" ]] && info "${email}: deleted" || err "${email}: failed (HTTP ${code})"
  done
}

kc_create_user() {
  banner "Create User in Realm: ${KC_REALM}"
  kc_ensure_token || return
  local username email first last password email_verified temp_pass req_actions
  read_input username       "Username"          ""
  read_input email          "Email"             ""
  read_input first          "First name"        ""
  read_input last           "Last name"         ""
  read_secret password      "Password"          ""
  read_input email_verified "Email verified? (true/false)" "true"
  read_input temp_pass      "Temporary password? (true/false)" "false"
  read_input req_actions    "Required actions (comma-sep, e.g. VERIFY_EMAIL,CONFIGURE_TOTP or blank)" ""

  local actions_json="[]"
  if [[ -n "$req_actions" ]]; then
    actions_json=$(python3 -c "print('[' + ','.join(['\"'+a.strip()+'\"' for a in '${req_actions}'.split(',')]) + ']')")
  fi

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms/${KC_REALM}/users" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"username\": \"${username}\",
      \"email\": \"${email}\",
      \"firstName\": \"${first}\",
      \"lastName\": \"${last}\",
      \"enabled\": true,
      \"emailVerified\": ${email_verified},
      \"credentials\": [{\"type\": \"password\", \"value\": \"${password}\", \"temporary\": ${temp_pass}}],
      \"requiredActions\": ${actions_json}
    }")
  [[ "$code" == "201" ]] && info "User created (HTTP ${code})" || err "Failed (HTTP ${code})"
}

kc_create_users_batch() {
  banner "Create Batch Users in Realm: ${KC_REALM}"
  echo "This creates the predefined set of test users."
  echo
  local users=(
    'edy|edy@molinainvestments.com|Edy|Molina|Test1234!|true|false|CONFIGURE_TOTP'
    'admin-user|admin@propertyplatform.pl|Admin|User|Admin1234!|true|false|'
    'free-user|free@test.pl|Jan|Kowalski|Test1234!|true|false|'
    'newuser|newuser@test.pl|New|User|Test1234!|false|false|VERIFY_EMAIL,CONFIGURE_TOTP'
  )

  for entry in "${users[@]}"; do
    IFS='|' read -r username email first last password verified temp actions <<< "$entry"
    kc_get_token 2>/dev/null || { err "Token refresh failed"; return; }
    local actions_json="[]"
    if [[ -n "$actions" ]]; then
      actions_json=$(python3 -c "print('[' + ','.join(['\"'+a.strip()+'\"' for a in '${actions}'.split(',')]) + ']')")
    fi
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      "${KC_URL}/admin/realms/${KC_REALM}/users" \
      -H "Authorization: Bearer ${KC_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{
        \"username\": \"${username}\",
        \"email\": \"${email}\",
        \"firstName\": \"${first}\",
        \"lastName\": \"${last}\",
        \"enabled\": true,
        \"emailVerified\": ${verified},
        \"credentials\": [{\"type\": \"password\", \"value\": \"${password}\", \"temporary\": ${temp}}],
        \"requiredActions\": ${actions_json}
      }")
    [[ "$code" == "201" ]] && info "${username}: created" || warn "${username}: HTTP ${code}"
  done
}

# ============================================================
#  KEYCLOAK — ROLE MANAGEMENT
# ============================================================
kc_create_roles() {
  banner "Create Roles in Realm: ${KC_REALM}"
  kc_ensure_token || return
  local roles=(
    'ROLE_USER|Free/trial tier user'
    'ROLE_PREMIUM_USER|Paying investor with full access'
    'ROLE_ANALYST|Internal operations analyst'
    'ROLE_ADMIN|Platform administrator'
    'ROLE_SUPER_ADMIN|Platform owner - highest privilege'
  )
  for entry in "${roles[@]}"; do
    IFS='|' read -r name desc <<< "$entry"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      "${KC_URL}/admin/realms/${KC_REALM}/roles" \
      -H "Authorization: Bearer ${KC_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"name\": \"${name}\", \"description\": \"${desc}\"}")
    [[ "$code" == "201" ]] && info "${name}: created" || warn "${name}: HTTP ${code} (may already exist)"
  done
}

kc_assign_roles() {
  banner "Assign Roles to User"
  kc_ensure_token || return
  local username
  read_input username "Username" ""

  # Get user ID
  local user_id
  user_id=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?username=${username}&exact=true" \
    -H "Authorization: Bearer ${KC_TOKEN}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)

  if [[ -z "$user_id" ]]; then
    err "User '${username}' not found"
    return
  fi
  info "User ID: ${user_id}"

  # List available realm roles
  echo -e "\nAvailable realm roles:"
  curl -s "${KC_URL}/admin/realms/${KC_REALM}/roles" \
    -H "Authorization: Bearer ${KC_TOKEN}" | \
    python3 -c "import sys,json; [print(f'  - {r[\"name\"]}') for r in json.load(sys.stdin)]"

  local role_names
  read_input role_names "Roles to assign (comma-separated)" ""

  # Build role representations
  local role_reps="["
  local first=true
  IFS=',' read -ra role_arr <<< "$role_names"
  for role_name in "${role_arr[@]}"; do
    role_name=$(echo "$role_name" | xargs)  # trim
    local rep
    rep=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/roles/${role_name}" \
      -H "Authorization: Bearer ${KC_TOKEN}")
    if echo "$rep" | python3 -c "import sys,json; json.load(sys.stdin)['name']" &>/dev/null; then
      [[ "$first" == "true" ]] && first=false || role_reps+=","
      role_reps+="$rep"
    else
      warn "Role '${role_name}' not found, skipping"
    fi
  done
  role_reps+="]"

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms/${KC_REALM}/users/${user_id}/role-mappings/realm" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$role_reps")
  [[ "$code" == "204" ]] && info "Roles assigned to ${username}" || err "Failed (HTTP ${code})"
}

kc_assign_roles_batch() {
  banner "Batch Assign Roles (Predefined Users)"
  kc_ensure_token || return
  echo "This assigns roles to the predefined test users."
  echo

  local assignments=(
    'edy|ROLE_USER,ROLE_PREMIUM_USER'
    'admin-user|ROLE_USER,ROLE_PREMIUM_USER,ROLE_ADMIN,ROLE_SUPER_ADMIN'
    'free-user|ROLE_USER'
    'newuser|ROLE_USER'
  )

  for entry in "${assignments[@]}"; do
    IFS='|' read -r username roles_csv <<< "$entry"
    kc_get_token 2>/dev/null || { err "Token refresh failed"; return; }

    local user_id
    user_id=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?username=${username}&exact=true" \
      -H "Authorization: Bearer ${KC_TOKEN}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null)

    if [[ -z "$user_id" ]]; then
      warn "${username}: not found, skipping"
      continue
    fi

    local role_reps="["
    local first=true
    IFS=',' read -ra role_arr <<< "$roles_csv"
    for rn in "${role_arr[@]}"; do
      local rep
      rep=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/roles/${rn}" -H "Authorization: Bearer ${KC_TOKEN}")
      [[ "$first" == "true" ]] && first=false || role_reps+=","
      role_reps+="$rep"
    done
    role_reps+="]"

    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      "${KC_URL}/admin/realms/${KC_REALM}/users/${user_id}/role-mappings/realm" \
      -H "Authorization: Bearer ${KC_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$role_reps")
    [[ "$code" == "204" ]] && info "${username}: roles assigned (${roles_csv})" || err "${username}: HTTP ${code}"
  done
}

# ============================================================
#  KEYCLOAK — REALM MANAGEMENT
# ============================================================
kc_create_realm() {
  banner "Create / Import Realm"
  kc_ensure_token || return
  local realm_name display_name login_theme smtp_host smtp_port smtp_from smtp_user
  read_input realm_name    "Realm name"     "${KC_REALM}"
  read_input display_name  "Display name"   "Property Platform"
  read_input login_theme   "Login theme"    "property-platform"

  echo -e "\n${BOLD}SMTP Configuration:${NC}"
  read_input smtp_host  "SMTP host"        "smtp.hostinger.com"
  read_input smtp_port  "SMTP port"        "465"
  read_input smtp_from  "From email"       "info@neuracodeinc.com"
  read_input smtp_user  "SMTP user"        "info@neuracodeinc.com"

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
    \"realm\": \"${realm_name}\",
    \"enabled\": true,
    \"displayName\": \"${display_name}\",
    \"registrationAllowed\": true,
    \"resetPasswordAllowed\": true,
    \"rememberMe\": true,
    \"verifyEmail\": true,
    \"loginWithEmailAllowed\": true,
    \"duplicateEmailsAllowed\": false,
    \"bruteForceProtected\": true,
    \"permanentLockout\": false,
    \"failureFactor\": 5,
    \"waitIncrementSeconds\": 60,
    \"maxFailureWaitSeconds\": 900,
    \"accessTokenLifespan\": 300,
    \"ssoSessionIdleTimeout\": 1800,
    \"ssoSessionMaxLifespan\": 28800,
    \"loginTheme\": \"${login_theme}\",
    \"accountTheme\": \"keycloak.v2\",
    \"sslRequired\": \"external\",
    \"otpPolicyType\": \"totp\",
    \"otpPolicyAlgorithm\": \"HmacSHA1\",
    \"otpPolicyDigits\": 6,
    \"otpPolicyPeriod\": 30,
    \"smtpServer\": {
      \"host\": \"${smtp_host}\",
      \"port\": \"${smtp_port}\",
      \"from\": \"${smtp_from}\",
      \"fromDisplayName\": \"${display_name}\",
      \"ssl\": \"true\",
      \"starttls\": \"false\",
      \"auth\": \"true\",
      \"user\": \"${smtp_user}\"
    }
  }")
  [[ "$code" == "201" ]] && info "Realm '${realm_name}' created" || err "Failed (HTTP ${code})"
}

kc_configure_realm_security() {
  banner "Configure Realm Security: ${KC_REALM}"
  kc_ensure_token || return

  echo "Applying: email verification, password policy, brute force, OTP..."
  echo

  # Email verification
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KC_URL}/admin/realms/${KC_REALM}" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"verifyEmail": true}')
  [[ "$code" == "204" ]] && info "Email verification: enabled" || err "Email verification: HTTP ${code}"

  # Password policy
  kc_get_token 2>/dev/null
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KC_URL}/admin/realms/${KC_REALM}" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"passwordPolicy": "length(8) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername"}')
  [[ "$code" == "204" ]] && info "Password policy: set" || err "Password policy: HTTP ${code}"

  # Brute force
  kc_get_token 2>/dev/null
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KC_URL}/admin/realms/${KC_REALM}" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"bruteForceProtected": true, "failureFactor": 5, "waitIncrementSeconds": 900}')
  [[ "$code" == "204" ]] && info "Brute force protection: enabled" || err "Brute force: HTTP ${code}"

  # OTP policy
  kc_get_token 2>/dev/null
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KC_URL}/admin/realms/${KC_REALM}" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30}')
  [[ "$code" == "204" ]] && info "OTP policy: configured" || err "OTP policy: HTTP ${code}"

  echo -e "\nUsers can activate 2FA at:"
  echo "  ${KC_URL}/realms/${KC_REALM}/account/#/security/signingin"
}

# ============================================================
#  KEYCLOAK — CLIENT MANAGEMENT
# ============================================================
kc_create_clients() {
  banner "Create OIDC Clients in Realm: ${KC_REALM}"
  kc_ensure_token || return

  local spa_root spa_redirect
  read_input spa_root "SPA root URL" "http://localhost:4200"

  # Public SPA client
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms/${KC_REALM}/clients" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
    \"clientId\": \"property-spa\",
    \"name\": \"Property Platform Angular SPA\",
    \"enabled\": true,
    \"publicClient\": true,
    \"standardFlowEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"directAccessGrantsEnabled\": true,
    \"rootUrl\": \"${spa_root}\",
    \"baseUrl\": \"${spa_root}\",
    \"redirectUris\": [\"${spa_root}/*\"],
    \"webOrigins\": [\"${spa_root}\"],
    \"protocol\": \"openid-connect\",
    \"attributes\": {
      \"pkce.code.challenge.method\": \"S256\",
      \"post.logout.redirect.uris\": \"${spa_root}/*\"
    },
    \"fullScopeAllowed\": true
  }")
  [[ "$code" == "201" ]] && info "property-spa: created" || warn "property-spa: HTTP ${code}"

  # Confidential API client
  kc_get_token 2>/dev/null
  local api_secret
  read_input api_secret "API client secret" "property-api-secret"
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms/${KC_REALM}/clients" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
    \"clientId\": \"property-api\",
    \"name\": \"Property Platform Spring Boot API\",
    \"enabled\": true,
    \"publicClient\": false,
    \"serviceAccountsEnabled\": true,
    \"standardFlowEnabled\": false,
    \"directAccessGrantsEnabled\": false,
    \"secret\": \"${api_secret}\",
    \"protocol\": \"openid-connect\"
  }")
  [[ "$code" == "201" ]] && info "property-api: created" || warn "property-api: HTTP ${code}"
}

kc_update_client_urls() {
  banner "Update SPA Client URLs"
  kc_ensure_token || return
  local client_id prod_url
  read_input client_id "Client ID" "property-spa"
  read_input prod_url  "Production URL" "https://invest.revivedeal.com"

  # Get internal UUID
  local uuid
  uuid=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/clients?clientId=${client_id}" \
    -H "Authorization: Bearer ${KC_TOKEN}" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])" 2>/dev/null)

  if [[ -z "$uuid" ]]; then
    err "Client '${client_id}' not found"
    return
  fi
  info "Client UUID: ${uuid}"

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    "${KC_URL}/admin/realms/${KC_REALM}/clients/${uuid}" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
    \"clientId\": \"${client_id}\",
    \"rootUrl\": \"${prod_url}\",
    \"baseUrl\": \"${prod_url}\",
    \"redirectUris\": [\"${prod_url}/*\", \"http://localhost:4200/*\"],
    \"webOrigins\": [\"${prod_url}\", \"http://localhost:4200\"],
    \"attributes\": {
      \"pkce.code.challenge.method\": \"S256\",
      \"post.logout.redirect.uris\": \"${prod_url}/*##http://localhost:4200/*\"
    }
  }")
  [[ "$code" == "204" ]] && info "Client URLs updated" || err "Failed (HTTP ${code})"
}

# ============================================================
#  KEYCLOAK — IDENTITY PROVIDER (Google)
# ============================================================
kc_setup_google_idp() {
  banner "Setup Google Identity Provider"
  kc_ensure_token || return
  local google_client_id google_client_secret
  read_input google_client_id     "Google Client ID"     ""
  read_secret google_client_secret "Google Client Secret" ""

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${KC_URL}/admin/realms/${KC_REALM}/identity-provider/instances" \
    -H "Authorization: Bearer ${KC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
    \"alias\": \"google\",
    \"providerId\": \"google\",
    \"enabled\": true,
    \"trustEmail\": true,
    \"config\": {
      \"clientId\": \"${google_client_id}\",
      \"clientSecret\": \"${google_client_secret}\",
      \"defaultScope\": \"openid email profile\",
      \"syncMode\": \"IMPORT\",
      \"guiOrder\": \"1\"
    }
  }")
  if [[ "$code" == "201" ]]; then
    info "Google IDP created"
  elif [[ "$code" == "409" ]]; then
    warn "Already exists. Updating..."
    kc_get_token 2>/dev/null
    code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
      "${KC_URL}/admin/realms/${KC_REALM}/identity-provider/instances/google" \
      -H "Authorization: Bearer ${KC_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{
      \"alias\": \"google\",
      \"providerId\": \"google\",
      \"enabled\": true,
      \"trustEmail\": true,
      \"config\": {
        \"clientId\": \"${google_client_id}\",
        \"clientSecret\": \"${google_client_secret}\",
        \"defaultScope\": \"openid email profile\",
        \"syncMode\": \"IMPORT\",
        \"guiOrder\": \"1\"
      }
    }")
    [[ "$code" == "204" ]] && info "Google IDP updated" || err "Update failed (HTTP ${code})"
  else
    err "Failed (HTTP ${code})"
  fi
}

# ============================================================
#  KEYCLOAK — SEARCH ACROSS REALMS
# ============================================================
kc_search_all_realms() {
  banner "Search User Across All Realms"
  kc_ensure_token || return
  local email
  read_input email "Email to search" ""
  echo

  for realm in master real-estate property-platform; do
    echo -e "${BOLD}=== ${realm} ===${NC}"
    local result
    result=$(curl -s "${KC_URL}/admin/realms/${realm}/users?email=${email}" \
      -H "Authorization: Bearer ${KC_TOKEN}")
    local count
    count=$(echo "$result" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "error")
    if [[ "$count" == "0" ]]; then
      echo "  (none)"
    elif [[ "$count" == "error" ]]; then
      echo "  (access denied or error)"
    else
      echo "$result" | python3 -c "import sys,json; [print(f'  {u[\"id\"]} — {u.get(\"email\",\"-\")} — {u.get(\"username\",\"-\")}') for u in json.load(sys.stdin)]"
    fi
  done
}

# ============================================================
#  SSH — REMOTE KEYCLOAK MANAGEMENT
# ============================================================
ssh_kc_list_users() {
  banner "List Users via SSH (${SSH_HOST}:${SSH_KC_PORT})"
  if [[ -z "$SSH_HOST" ]]; then configure_ssh; fi
  if [[ -z "$KC_ADMIN_USER" ]]; then configure_keycloak; fi

  local encoded_pass
  encoded_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${KC_ADMIN_PASS}'))")

  ssh "$SSH_HOST" "
TOKEN=\$(curl -s -X POST 'http://localhost:${SSH_KC_PORT}/realms/master/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=admin-cli&username=${KC_ADMIN_USER}&password=${encoded_pass}&grant_type=password' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"access_token\"])')
curl -s 'http://localhost:${SSH_KC_PORT}/admin/realms/${KC_REALM}/users?max=100' \
  -H \"Authorization: Bearer \$TOKEN\" | python3 -c 'import sys,json; users=json.load(sys.stdin); [print(u[\"id\"], u.get(\"email\",\"-\"), u.get(\"username\",\"-\")) for u in users]; print(\"Total:\", len(users))'
" 2>&1
}

ssh_kc_delete_all_users() {
  banner "Delete ALL Users via SSH (${SSH_HOST}:${SSH_KC_PORT})"
  if [[ -z "$SSH_HOST" ]]; then configure_ssh; fi
  if ! confirm "This will DELETE ALL users in realm '${KC_REALM}' on ${SSH_HOST}. Are you sure?"; then
    warn "Aborted."
    return
  fi

  local encoded_pass
  encoded_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${KC_ADMIN_PASS}'))")

  ssh "$SSH_HOST" "
TOKEN=\$(curl -s -X POST 'http://localhost:${SSH_KC_PORT}/realms/master/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=admin-cli&username=${KC_ADMIN_USER}&password=${encoded_pass}&grant_type=password' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"access_token\"])')
USERS=\$(curl -s 'http://localhost:${SSH_KC_PORT}/admin/realms/${KC_REALM}/users?max=100' \
  -H \"Authorization: Bearer \$TOKEN\" | python3 -c 'import sys,json; [print(u[\"id\"]) for u in json.load(sys.stdin)]')
for ID in \$USERS; do
  STATUS=\$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \"http://localhost:${SSH_KC_PORT}/admin/realms/${KC_REALM}/users/\$ID\" \
    -H \"Authorization: Bearer \$TOKEN\")
  echo \"Deleted \$ID: \$STATUS\"
done
" 2>&1
}

# ============================================================
#  GARAGE S3 — CORS
# ============================================================
s3_set_cors() {
  banner "Set Bucket CORS"
  if [[ -z "$S3_ACCESS_KEY" ]]; then configure_s3; fi

  echo "Enter allowed origins (comma-separated):"
  local origins_input
  read_input origins_input "Origins" "https://revivedeal.com,https://www.revivedeal.com,https://staging.revivedeal.com"

  local origins_json
  origins_json=$(python3 -c "
origins = [o.strip() for o in '${origins_input}'.split(',')]
print('[' + ','.join(['\"'+o+'\"' for o in origins]) + ']')
")

  local cors_file="/tmp/cors-$$.json"
  cat > "$cors_file" <<EOFCORS
{
  "CORSRules": [
    {
      "AllowedOrigins": ${origins_json},
      "AllowedMethods": ["GET", "HEAD", "PUT"],
      "AllowedHeaders": ["Content-Type"],
      "ExposeHeaders": ["ETag"],
      "MaxAgeSeconds": 3600
    }
  ]
}
EOFCORS

  echo -e "\nCORS config:"
  cat "$cors_file"
  echo

  if confirm "Apply this CORS configuration?"; then
    AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
    AWS_DEFAULT_REGION=garage \
    aws s3api put-bucket-cors \
      --bucket "$S3_BUCKET" \
      --cors-configuration "file://${cors_file}" \
      --endpoint-url "$S3_ENDPOINT" && info "CORS applied" || err "CORS failed"
  fi
  rm -f "$cors_file"
}

# ============================================================
#  JENKINS — JOB MANAGEMENT
# ============================================================
jenkins_create_multibranch() {
  banner "Create Jenkins Multibranch Pipeline"
  if [[ -z "$JENKINS_URL" ]]; then configure_jenkins; fi

  local job_name repo_url cred_id jenkinsfile_path
  read_input job_name         "Job name"           "pp-frontend"
  read_input repo_url         "Git repo URL"       "git@github.com:NeuraCodeSys/properties.git"
  read_input cred_id          "Credentials ID"     "jenkins-github-ssh"
  read_input jenkinsfile_path "Jenkinsfile path"   "jenkins/Jenkinsfile.frontend"

  # Get crumb with cookie jar
  local cookie_jar="/tmp/jenkins-cookies-$$.txt"
  local crumb
  crumb=$(curl -s -u "${JENKINS_USER}:${JENKINS_PASS}" \
    -c "$cookie_jar" \
    "${JENKINS_URL}/crumbIssuer/api/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['crumb'])" 2>/dev/null) || {
    err "Failed to get Jenkins crumb"
    rm -f "$cookie_jar"
    return
  }

  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "${JENKINS_USER}:${JENKINS_PASS}" \
    -b "$cookie_jar" \
    -H "Jenkins-Crumb: ${crumb}" \
    -H "Content-Type: application/xml" \
    -X POST "${JENKINS_URL}/createItem?name=${job_name}" \
    -d "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject plugin=\"workflow-multibranch\">
  <description>${job_name}</description>
  <factory class=\"org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory\">
    <scriptPath>${jenkinsfile_path}</scriptPath>
  </factory>
  <sources class=\"jenkins.branch.MultiBranchProject\$BranchSourceList\">
    <data>
      <jenkins.branch.BranchSource>
        <source class=\"jenkins.plugins.git.GitSCMSource\">
          <id>${job_name}-src</id>
          <remote>${repo_url}</remote>
          <credentialsId>${cred_id}</credentialsId>
          <traits>
            <jenkins.plugins.git.traits.BranchDiscoveryTrait/>
          </traits>
        </source>
      </jenkins.branch.BranchSource>
    </data>
  </sources>
  <orphanedItemStrategy class=\"com.cloudbees.hudson.plugins.folder.computed.DefaultOrphanedItemStrategy\">
    <pruneDeadBranches>true</pruneDeadBranches>
    <daysToKeep>7</daysToKeep>
    <numToKeep>5</numToKeep>
  </orphanedItemStrategy>
</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>")
  rm -f "$cookie_jar"
  [[ "$code" == "200" ]] && info "${job_name}: created" || err "${job_name}: HTTP ${code}"
}

# ============================================================
#  DOCKER DATABASE
# ============================================================
db_run_query() {
  banner "Run Database Query"
  if [[ -z "$DB_CONTAINER" ]]; then configure_docker_db; fi

  local query
  echo "Enter SQL query (single line):"
  read_input query "SQL" "SELECT id, email, first_name, last_name, username FROM users LIMIT 20;"

  local cmd="docker exec -it ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -c \"${query}\""

  if [[ "$DB_HOST" == "local" ]]; then
    eval "$cmd"
  else
    ssh "$DB_HOST" "$cmd"
  fi
}

db_delete_user() {
  banner "Delete Database User"
  if [[ -z "$DB_CONTAINER" ]]; then configure_docker_db; fi

  local email
  read_input email "Email of user to delete" ""

  # First show matching users
  local select_cmd="docker exec ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -c \"SELECT id, email, first_name, last_name FROM users WHERE email = '${email}';\""
  echo -e "\nMatching users:"
  if [[ "$DB_HOST" == "local" ]]; then
    eval "$select_cmd"
  else
    ssh "$DB_HOST" "$select_cmd"
  fi

  if confirm "Delete this user?"; then
    local delete_cmd="docker exec ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -c \"DELETE FROM users WHERE email = '${email}';\""
    if [[ "$DB_HOST" == "local" ]]; then
      eval "$delete_cmd"
    else
      ssh "$DB_HOST" "$delete_cmd"
    fi
    info "Done."
  fi
}

db_search_user() {
  banner "Search Database Users"
  if [[ -z "$DB_CONTAINER" ]]; then configure_docker_db; fi

  local pattern
  read_input pattern "Search pattern (email/username)" ""

  local cmd="docker exec ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -c \"SELECT id, email, first_name, last_name, username FROM users WHERE email ILIKE '%${pattern}%' OR username ILIKE '%${pattern}%';\""
  if [[ "$DB_HOST" == "local" ]]; then
    eval "$cmd"
  else
    ssh "$DB_HOST" "$cmd"
  fi
}

# ============================================================
#  FULL SETUP WIZARD
# ============================================================
full_setup() {
  banner "Full Keycloak Setup Wizard"
  echo "This will run the complete setup sequence:"
  echo "  1. Create realm"
  echo "  2. Configure security (password policy, brute force, OTP)"
  echo "  3. Create roles"
  echo "  4. Create OIDC clients"
  echo "  5. Create batch users"
  echo "  6. Assign roles to batch users"
  echo "  7. Setup Google IDP (optional)"
  echo

  if ! confirm "Proceed with full setup?"; then return; fi

  kc_create_realm
  pause
  kc_configure_realm_security
  pause
  kc_create_roles
  pause
  kc_create_clients
  pause
  kc_create_users_batch
  pause
  kc_assign_roles_batch
  pause

  if confirm "Setup Google Identity Provider?"; then
    kc_setup_google_idp
  fi

  echo -e "\n${GREEN}${BOLD}Full setup complete!${NC}"
}

# ============================================================
#  MAIN MENU
# ============================================================
show_config_status() {
  echo -e "${BOLD}Current Configuration:${NC}"
  [[ -n "$KC_URL" ]]        && echo -e "  Keycloak: ${GREEN}${KC_URL}${NC} (realm: ${KC_REALM})" || echo -e "  Keycloak: ${RED}not configured${NC}"
  [[ -n "$JENKINS_URL" ]]   && echo -e "  Jenkins:  ${GREEN}${JENKINS_URL}${NC}" || echo -e "  Jenkins:  ${RED}not configured${NC}"
  [[ -n "$SSH_HOST" ]]      && echo -e "  SSH:      ${GREEN}${SSH_HOST}:${SSH_KC_PORT}${NC}" || echo -e "  SSH:      ${RED}not configured${NC}"
  [[ -n "$S3_ACCESS_KEY" ]] && echo -e "  S3:       ${GREEN}${S3_ENDPOINT}/${S3_BUCKET}${NC}" || echo -e "  S3:       ${RED}not configured${NC}"
  [[ -n "$DB_CONTAINER" ]]  && echo -e "  Database: ${GREEN}${DB_CONTAINER}${NC}" || echo -e "  Database: ${RED}not configured${NC}"
  echo
}

main_menu() {
  while true; do
    banner "Infrastructure Toolkit"
    show_config_status

    echo -e "${BOLD}── Configuration ──${NC}"
    echo "  1)  Configure Keycloak connection"
    echo "  2)  Configure Jenkins connection"
    echo "  3)  Configure SSH remote"
    echo "  4)  Configure Garage S3"
    echo "  5)  Configure Docker database"
    echo
    echo -e "${BOLD}── Keycloak: Realm ──${NC}"
    echo "  10) Create / import realm"
    echo "  11) Configure realm security (password policy, brute force, OTP)"
    echo "  12) Full setup wizard (realm + roles + clients + users)"
    echo
    echo -e "${BOLD}── Keycloak: Users ──${NC}"
    echo "  20) List users"
    echo "  21) Find user (by email/username)"
    echo "  22) Create user"
    echo "  23) Create batch users (predefined set)"
    echo "  24) Delete user"
    echo "  25) Bulk delete users"
    echo "  26) Search user across all realms"
    echo
    echo -e "${BOLD}── Keycloak: Roles ──${NC}"
    echo "  30) Create roles"
    echo "  31) Assign roles to user"
    echo "  32) Batch assign roles (predefined)"
    echo
    echo -e "${BOLD}── Keycloak: Clients ──${NC}"
    echo "  40) Create OIDC clients (SPA + API)"
    echo "  41) Update SPA client URLs"
    echo "  42) Setup Google Identity Provider"
    echo
    echo -e "${BOLD}── SSH Remote Keycloak ──${NC}"
    echo "  50) List users (via SSH)"
    echo "  51) Delete ALL users (via SSH)"
    echo
    echo -e "${BOLD}── Garage S3 ──${NC}"
    echo "  60) Set bucket CORS"
    echo
    echo -e "${BOLD}── Jenkins ──${NC}"
    echo "  70) Create multibranch pipeline"
    echo
    echo -e "${BOLD}── Docker Database ──${NC}"
    echo "  80) Run SQL query"
    echo "  81) Search user in DB"
    echo "  82) Delete user from DB"
    echo
    echo "   0) Exit"
    echo

    local choice
    read_input choice "Select option" ""

    case "$choice" in
      1)  configure_keycloak ;;
      2)  configure_jenkins ;;
      3)  configure_ssh ;;
      4)  configure_s3 ;;
      5)  configure_docker_db ;;
      10) kc_create_realm ;;
      11) kc_configure_realm_security ;;
      12) full_setup ;;
      20) kc_list_users ;;
      21) kc_find_user ;;
      22) kc_create_user ;;
      23) kc_create_users_batch ;;
      24) kc_delete_user ;;
      25) kc_delete_user_bulk ;;
      26) kc_search_all_realms ;;
      30) kc_create_roles ;;
      31) kc_assign_roles ;;
      32) kc_assign_roles_batch ;;
      40) kc_create_clients ;;
      41) kc_update_client_urls ;;
      42) kc_setup_google_idp ;;
      50) ssh_kc_list_users ;;
      51) ssh_kc_delete_all_users ;;
      60) s3_set_cors ;;
      70) jenkins_create_multibranch ;;
      80) db_run_query ;;
      81) db_search_user ;;
      82) db_delete_user ;;
      0)  echo -e "\n${GREEN}Goodbye!${NC}"; exit 0 ;;
      *)  err "Invalid option: ${choice}" ;;
    esac
    pause
  done
}

# ============================================================
#  Entry point
# ============================================================
main_menu
