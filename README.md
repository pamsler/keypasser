# 🔒 KeyPasser

One-time secrets & files — secure, simple, self-hosted.  
Now with **integrated ClamAV malware scanning**, **admin alerts**, an **installable PWA with custom logo**, and **user profile pictures**.  

---

## 🚀 Quick start (docker-compose)

```yaml
services:
  app:
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
      - clamdb:/var/lib/clamav
      - keypasser_data:/data
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    container_name: keypasser-db
    environment:
      POSTGRES_DB: keypasserdb
      POSTGRES_USER: pascaldbuser
      POSTGRES_PASSWORD: MqII45IhSGXBTZshUz8OxgQsEyk6sckS
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"]
      interval: 3s
      timeout: 3s
      retries: 10
    restart: unless-stopped

volumes:
  pgdata:
  uploads:
  clamdb:
  keypasser_data:

```
➡️ Open https://your.domain.tld, choose your language (EN/DE), and follow the First-Run Setup wizard.
After setup you can **install KeyPasser as a PWA** (Add to Home Screen / Install app) on iOS/Android/Desktop.

### Notes
- `clamdb` caches antivirus signatures between restarts (faster startup). Allow outbound to `database.clamav.net`
- `keypasser_data` persists `/data/config.json` which stores DB connection and setup state.
- `uploads` stores branded logos and **user profile pictures**.  
---

## 🧭 First-Run Setup (wizard)
On a fresh, empty instance KeyPasser starts in setup mode:

Select language.

- Database: enter Postgres connection → migrations run → saved to /data/config.json.

- Create/ensure admin (local account).

- Finish: the app leaves setup mode immediately (no container restart required).

- Configure SMTP and optional Azure/SSO in Settings; upload your logo.

> The wizard requires an empty DB and a clean `/data` directory.

---

## ⛔ Breaking change — upgrading **from v1.3.3 to v2.0.0**
v2 introduces a new bootstrap/setup path. **When coming from any v1.x (incl. 1.3.3) you MUST deploy a clean instance**:

This removes all existing data. Proceed only if you accept data loss.

```bash
# stop stack and remove ALL volumes for a clean first-run
docker compose down -v
docker volume rm <your_project>_pgdata <your_project>_uploads <your_project>_clamdb <your_project>_keypasser_data  # or `docker volume ls` then rm
docker compose pull
docker compose up -d
```
> After the clean deploy, visit your domain and complete the setup wizard once.

## ➡️ Upgrading from v2.0.0 to any v2.x.x
No database/volume reset is required. All volumes (`pgdata`, `uploads`, `clamdb`, `keypasser_data`) are kept and the wizard will **not** run again.

**Option A — use the provided update script**

**Option B — update the tag manually**
1) Edit `.env` and change:
```env
KP_VERSION=2.x.x
```
2) Pull & restart just the app:
```bash
docker compose pull app
docker compose up -d app
```

---

## ✨ Features

- **Secure Encryption**: Data encrypted at rest using `libsodium` (`crypto_secretbox`) with `HKDF`-derived keys. User passwords and tokens hashed with `Argon2id` (memoryCost: 19MiB, timeCost: 3, parallelism: 1).
- **Password-Protected Secrets**: Optional recipient password with `Argon2id`-derived key combined with base key.
- **One-Time Links**: Links with configurable TTL (1 min to 24h) auto-delete after first view/download or expiry.
- **SMTP Integration**: Supports SMTP (587/465) with custom subject/message and optional branded logo in emails.
- **Authentication**: Local accounts or Entra ID SSO. Optional group-based access control for users and admins.
- **Multi-Factor Authentication**: TOTP with backup codes for local accounts.
- **Auditing & Reporting**: Audit logs, 14-day activity charts, and exportable reports in CSV, PDF, or XLSX formats.
- **User Interface**: Clean, responsive Tailwind CSS UI with dark/light modes and EN/DE language support (auto-detect + switcher).
- **Installable PWA**: Works as a Progressive Web App. Upload your logo in **Settings → Logo** and it’s applied to the app header/sidebar, favicon, emails, and PWA icons (Home-Screen).
- **Profile pictures (avatars)**: Users can upload and manage their avatar in **Profile → Avatar** (PNG/JPG/WEBP/GIF, up to 5 MB). Avatars are shown in the UI (topbar/sidebar) and stored in the `uploads` volume.
- **One-Time File Sharing**: Encrypted file uploads (up to 20MB) with one-time download and auto-deletion.
- Malware Scanning & File-Type Blocking: Uploads are streamed to ClamAV (clamd); EICAR and known malware are blocked.
- Admin Notifications: When a malicious file is detected, an alert email is sent to the default admin (ADMIN_EMAIL) with user, file name/type/size, IP, and timestamp. Localized EN/DE.

---

## 📱 Progressive Web App (PWA)

- **Install**: Visit your site and choose *Install app* / *Add to Home Screen*.  
- **Branding**: Upload a square PNG/SVG in **Settings → Logo**. The app updates:
  - Topbar & sidebar logo
  - Favicon & Apple touch icon
  - PWA icons/manifest (`/manifest.webmanifest`, `/pwa/icon-192.png`, `/pwa/icon-512.png`)
  - Branded emails (inline logo)
- **Updates**: The service worker refreshes on reload. After changing the logo, do a hard efresh; iOS may cache icons longer.

No extra config is required in Docker; all PWA assets are served by the app.

---

## ⚙️ Environment (.env)

**Note:** Keep `MASTER_KEY` & `SESSION_SECRET` stable and secret. In Docker, double every `$` in bcrypt hashes.

| Key | Required | Example | Notes |
|---|---|---|---|
| `PORT` | no | `1313` | Container listens here |
| `BASE_URL` | yes | `https://your.domain.tld` | Used in links/emails & CSRF origin check |
| `COOKIE_SECURE` | recommended | `true` | Set `false` only without HTTPS/proxy |
| `TRUST_PROXY` | optional | `1` | If behind reverse proxy |
| `KP_VERSION` | optional | `x.y.z` | Image tag (semver) |
| `DOCKERHUB_REPO` | optional | `pamsler/keypasser` | Used by update checker |
```env
PORT=1313
ROTATE_SESSION_SECRET_DAYS=90
ROTATE_MASTER_KEY_DAYS=180
BASE_URL=https://your.domain.tld
COOKIE_SECURE=true
TRUST_PROXY=1

# Image tag / version
KP_VERSION=x.x.x
DOCKERHUB_REPO=pamsler/keypasser
```
---


## 🔑 Generate an admin hash (Argon2id)

```bash
npm i argon2
```

hash.mjs
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
env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }
semvers_only() { grep -E '^[vV]?[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$' | sed -E 's/^[vV]//' ; }
pick_max() { sort -V | tail -n1; }

DC="docker compose"; $DC version >/dev/null 2>&1 || DC="docker-compose"

REPO="${DOCKERHUB_REPO:-$(env_get DOCKERHUB_REPO)}"
REPO="${REPO:-pamsler/keypasser}"
CUR="$(env_get KP_VERSION)"; CUR="${CUR:-0.0.0}"

TO_TAG=""; CHECK_ONLY=0
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
  echo "Repo:   $REPO"
  echo "Local:  $CUR"
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

# Standard-Aufruf, .env wird automatisch geladen; weitere Secrets kommen über env_file im Compose
$DC -f "$COMPOSE_FILE" pull app
$DC -f "$COMPOSE_FILE" up -d app
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

## 🛡️ Malware scanning & admin alerts

- How it works: On upload, files are streamed to the embedded clamd via INSTREAM. If a signature is found, the upload is rejected (malware_detected) and nothing is stored.
- Dangerous extensions: With BLOCK_DANGEROUS_FILES=true, risky file types (e.g. .exe, .bat, .ps1, .js, .vbs, …) are rejected even before scanning.
- Admin alert: An email is sent to ADMIN_EMAIL (or ALERT_MALWARE_TO if set) including:

user (local or SSO), file name/type/size, request IP, and timestamp

localized content (English/German)
- Signatures: The clamdb volume persists databases; freshclam runs in the background to keep them current.

> Tip: You can test the setup with the EICAR test file: https://www.eicar.org/download-anti-malware-testfile/

---

## Bugs & Support
- Report a bug: https://github.com/pamsler/keypasser/issues/new?labels=bug&template=bug_report.yml&title=%5Bbug%5D%3A+  
- Feature request: https://github.com/pamsler/keypasser/issues/new?labels=enhancement&template=feature_request.yml&title=%5Bfeat%5D%3A+  
- Discussions (Q&A): https://github.com/pamsler/keypasser/discussions  
- Security: see https://github.com/pamsler/keypasser/security/policy
