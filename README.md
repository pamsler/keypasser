# 🔒 KeyPasser

One-time secrets & files — secure, simple, self-hosted.
Send a link (or email) that auto-expires and is destroyed on first access. Local login or Microsoft Entra ID (Azure AD) SSO.

---

## 🚀 Quick start (docker-compose)

```yaml
services:
  db:
    image: postgres:16-alpine
    container_name: keypasser-db
    environment:
      POSTGRES_DB: change_me
      POSTGRES_USER: change_me
      POSTGRES_PASSWORD: change_me
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]
      interval: 3s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  keypasser:
    image: pamsler/keypasser:${KP_VERSION}
    container_name: keypasser-server
    env_file:
      - .env
    environment:
      APP_VERSION: ${KP_VERSION}
      DOCKERHUB_REPO: ${DOCKERHUB_REPO:-pamsler/keypasser}
    ports:
      - "1313:1313"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - uploads:/app/data
    restart: unless-stopped

volumes:
  pgdata:
  uploads:
```
➡️ Open https://your.domain.tld, pick your language (🇬🇧/🇩🇪) from the top bar, and configure SMTP + optional Azure/SSO in **Settings**.

---

## ✨ Features

- Encrypted at rest (libsodium crypto_secretbox + HKDF); tokens Argon2id-hashed

- Optional recipient password (Argon2id-derived key combined with base key)

- TTL + one-time links (auto delete on first view/download)

- Built-in SMTP (587/465), custom subject/message, optional branded logo

- Auth: Local accounts or Entra ID SSO; optional group gates (access/admin)

- MFA (TOTP + backup codes) for local users

- Auditing & stats, 14-day chart; Reports export (CSV / PDF / XLSX)

- Clean Tailwind UI, dark/light, EN & DE (auto-detect + switcher)

- One-time files (encrypted on disk, wiped after first download/expiry)

---


## ⚙️ Environment (.env)

**Note:** Keep `MASTER_KEY` & `SESSION_SECRET` stable and secret. In Docker, double every `$` in bcrypt hashes.

| Key | Required | Example | Notes |
|---|---|---|---|
| `PORT` | no | `1313` | Container listens here |
| `DATABASE_URL` | yes | `postgres://user:pass@db:5432/keypasser` | Postgres 13+ |
| `BASE_URL` | yes | `https://your.domain.tld` | Used in links/emails & CSRF origin check |
| `COOKIE_SECURE` | recommended | `true` | Set `false` only without HTTPS/proxy |
| `TRUST_PROXY` | optional | `1` | If behind reverse proxy |
| `ADMIN_EMAIL` | optional | `admin@example.com` | Seed/ensure admin |
| `ADMIN_PASSWORD_HASH` | optional | `$argon2id$...` | **Argon2id** (recommended); `$` must always be doubled in `.env`/Compose |
| `ADMIN_USERNAME` | optional | `admin` | Only set if seeding admin |
| `ADMIN_FIRST_NAME` | optional | `Admin` | 〃 |
| `ADMIN_LAST_NAME` | optional | `User` | 〃 |
| `KP_VERSION` | optional | `x.y.z` | Image tag (semver) |
| `DOCKERHUB_REPO` | optional | `pamsler/keypasser` | Used by update checker |

```env
PORT=1313
DATABASE_URL=postgres://keypasser:change_me@db:5432/keypasser
ROTATE_SESSION_SECRET_DAYS=90
ROTATE_MASTER_KEY_DAYS=180
BASE_URL=https://your.domain.tld
COOKIE_SECURE=true
TRUST_PROXY=1


# Admin seed (optional; bcrypt, $ doubled)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD_HASH=$$2a$$12$$...
ADMIN_USERNAME=admin
ADMIN_FIRST_NAME=Admin
ADMIN_LAST_NAME=User

# Image tag / version
KP_VERSION=x.x.x
DOCKERHUB_REPO=pamsler/keypasser
```
---


## 🔑 Generate an admin hash (Argon2id)

```bash
npm i argon2
```

hash.js
```js
#!/usr/bin/env node
import argon2 from "argon2";

const password = process.argv[2];
if (!password) {
  console.error("Please enter your password as an argument.");
  process.exit(1);
}

const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 3,
  parallelism: 1
});

console.log(hash);
```

Run:
```bash
node hash.js "super-secret"   # -> $argon2id$...
```

---

## ✅ Verify a hash
verify.js
```js
#!/usr/bin/env node
import argon2 from "argon2";
import bcrypt from "bcryptjs";
 
const [ , , plain, hash ] = process.argv;
 if (!plain || !hash) {
   console.error("Usage: node verify.js <plain> <hash>");
   process.exit(1);
 }
 
try {
  let ok = false;
  if (hash.startsWith("$argon2id$")) {
    ok = await argon2.verify(hash, plain);
  } else if (hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$")) {
    ok = await bcrypt.compare(plain, hash);
  } else {
    try { ok = await argon2.verify(hash, plain); } catch {}
    if (!ok) { try { ok = await bcrypt.compare(plain, hash); } catch {} }
  }
  console.log(ok ? "OK" : "FAIL");
} catch (e) {
  console.error("Error:", e.message);
  process.exit(1);
}
```

Run:
```bash
node verify.js 'super-secret-password' '$argon2id$...'
# -> OK
```
---

## 🔄 Update script
```bash
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

has() { command -v "$1" >/dev/null 2>&1; }

env_get() {
  local key="$1"
  sed -nE "s/^${key}=(.*)/\1/p" "$ENV_FILE" | tail -n1 || true
}

semvers_only() { grep -E '^[vV]?[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$' | sed -E 's/^[vV]//' ; }

pick_max() { sort -V | tail -n1; }

DC="docker compose"
$DC version >/dev/null 2>&1 || DC="docker-compose"

REPO="${DOCKERHUB_REPO:-$(env_get DOCKERHUB_REPO)}"
REPO="${REPO:-pamsler/keypasser}"
CUR="$(env_get KP_VERSION)"; CUR="${CUR:-0.0.0}"
TO_TAG=""
CHECK_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --to) TO_TAG="${2:-}"; shift 2 ;;
    --check) CHECK_ONLY=1; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

fetch_ns_all() {
  local ns name url page res
  ns="${REPO%%/*}"
  name="${REPO#*/}"
  url="https://hub.docker.com/v2/namespaces/${ns}/repositories/${name}/tags?page_size=100"
  page=1
  while :; do
    res="$(curl -fsSL "${url}&page=${page}" -H 'Accept: application/json' -H 'User-Agent: keypasser-updater/2' || true)"
    [ -n "$res" ] || break
    printf '%s\n' "$res" | grep -o '"name":"[^"]*"' | cut -d'"' -f4
    printf '%s' "$res" | grep -q '"next":null' && break
    page=$((page+1))
  done | sed '/^$/d' | sort -u
}

fetch_registry_all() {
  local tok
  tok="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" \
         -H 'User-Agent: keypasser-updater/2' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "${tok:-}" ] || return 0
  curl -fsSL "https://registry-1.docker.io/v2/${REPO}/tags/list" \
    -H "Authorization: Bearer ${tok}" -H 'Accept: application/json' -H 'User-Agent: keypasser-updater/2' \
  | tr '[],"' '\n' | sed -n 's/^[[:space:]]*\([^[:space:]]\+\)[[:space:]]*$/\1/p' \
  | sed -n '1,/^tags$/d;p' | sed '/^$/d' | sort -u
}

get_latest() { { fetch_ns_all || true; fetch_registry_all || true; } | semvers_only | pick_max; }

LATEST="${TO_TAG:-$(get_latest)}"
[ -n "$LATEST" ] || { echo "Konnte keine Tags abrufen (Repo: $REPO)"; exit 2; }

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo "Repo: $REPO"
  echo "Local: $CUR"
  echo "Remote: $LATEST"
  exit 0
fi

if [ -z "$TO_TAG" ]; then
  if [ "$CUR" = "$LATEST" ] || [ "$(printf '%s\n%s\n' "$CUR" "$LATEST" | sort -V | tail -n1)" = "$CUR" ]; then
    echo "Already latest ($CUR)."
    exit 0
  fi
fi

echo "Update: $CUR -> $LATEST"

if grep -qE '^KP_VERSION=' "$ENV_FILE" 2>/dev/null; then
  sed -i.bak -E "s/^KP_VERSION=.*/KP_VERSION=$LATEST/" "$ENV_FILE"
else
  echo "KP_VERSION=$LATEST" >> "$ENV_FILE"
fi

grep -qE '^DOCKERHUB_REPO=' "$ENV_FILE" 2>/dev/null || echo "DOCKERHUB_REPO=$REPO" >> "$ENV_FILE"

TEMP_ENV=$(mktemp)
cp "$ENV_FILE" "$TEMP_ENV"
sed -i.bak -E 's/^(ADMIN_PASSWORD_HASH=)([^"].*[^"])$/\1"\2"/' "$TEMP_ENV"
sed -i.bak -E 's/^(ADMIN_PASSWORD_HASH=.*)\$/\1\\$/' "$TEMP_ENV"

$DC -f "$COMPOSE_FILE" --env-file "$TEMP_ENV" pull app
$DC -f "$COMPOSE_FILE" --env-file "$TEMP_ENV" up -d app

rm -f "$TEMP_ENV" "$TEMP_ENV.bak"

echo "Done."
```

---

## ✉️ SMTP

- Configure via Settings → SMTP

- Supports STARTTLS/587 and SMTPS/465.

- Custom sender, enforce TLS, optional inline logo

---

## 🌍 Languages

EN (en-GB) & DE (de-CH). Auto-detect + switcher on login/top-bar. Emails localized.

---

## 📊 Reports (CSV / PDF / XLSX)

Export activity by date range (portrait/landscape PDF, nicely formatted XLSX).

---

## Bugs & Support
- Report a bug: https://github.com/pamsler/keypasser/issues/new?labels=bug&template=bug_report.yml&title=%5Bbug%5D%3A+  
- Feature request: https://github.com/pamsler/keypasser/issues/new?labels=enhancement&template=feature_request.yml&title=%5Bfeat%5D%3A+  
- Discussions (Q&A): https://github.com/pamsler/keypasser/discussions  
- Security: see https://github.com/pamsler/keypasser/security/policy
