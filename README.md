# 🔒 KeyPasser

Send sensitive information once — securely.  
Generate a one-time, time-limited secret and share it via link or email.  
After the first view, the secret is destroyed.

---

## ✨ Features

- **Secrets**: Encrypted at rest (libsodium `crypto_secretbox` + HKDF). Access tokens are Argon2-hashed.
- **TTL + one-time**: Links expire automatically and are deleted on first view.
- **Delivery**: Built-in SMTP (STARTTLS/587 or SMTPS/465) with custom subject/message and optional branded logo.
- **Auth modes**: Local accounts or Microsoft Entra ID (Azure AD) SSO. Optional group gates for access/admin.
- **User management**: Local users (passwords) + SSO users (read-only).
- **MFA**: TOTP for local accounts with backup codes.
- **Auditing & stats**: Track who sent what to whom, status (active/used/expired), plus a 14-day activity chart.
- **UI**: Light/Dark theme, mobile-friendly, minimal Tailwind design.
- **Localization (i18n)**: UI and emails available in **English** and **German**. Auto-detects browser language (de* → German) and includes a top-bar language switcher; choice is saved per device.

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
      - app.env
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

## ⚙️ Environment (.env)

```env
PORT=1313
DATABASE_URL=postgres://user:pass@db:5432/keypasserdb
SESSION_SECRET=long-random-string
MASTER_KEY=32-byte-or-longer-secret
BASE_URL=https://your.domain.tld

# For LAN access, e.g.:
# BASE_URL=http://192.168.1.50:1313

# Cookie security (set false if running without HTTPS/proxy)
COOKIE_SECURE=true
TRUST_PROXY=1

# Admin seed (optional, bcrypt hash with doubled $$)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD_HASH=$$2a$$12$$...

# Image tag / version
KP_VERSION=x.x.x
DOCKERHUB_REPO=pamsler/keypasser
```
---


## 🔑 Generate an admin hash

```bash
npm install bcryptjs
```

hash.js
```js
#!/usr/bin/env node
import bcrypt from "bcryptjs";

const password = process.argv[2];
if (!password) {
  console.error("Usage: node hash.js <password>");
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);
// Docker-safe: double all '$'
console.log(hash.replace(/\$/g, "$$$$"));
```

Run:
```bash
node hash.js "super-secret-password"
# -> $$2a$$12$$...   (paste into ADMIN_PASSWORD_HASH)
```

---

## ✅ Verify a hash
verify.js
```js
#!/usr/bin/env node
import bcrypt from "bcryptjs";

const [ , , plain, hash ] = process.argv;
if (!plain || !hash) {
  console.error("Usage: node verify.js <plain> <hash>");
  process.exit(1);
}

(async () => {
  const ok = await bcrypt.compare(plain, hash);
  console.log(ok ? "OK" : "FAIL");
})();
```
Run:
```bash
node verify.js 'super-secret-password' '$$2a$$12$$...'
# -> OK
```

---

## 🔄 Update script
```bash
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

semvers_only() { grep -E '^[vV]?[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$' | sed -E 's/^[vV]//'; }
pick_max() { sort -V | tail -n1; }

DC="docker compose"; $DC version >/dev/null 2>&1 || DC="docker-compose"

REPO=$(grep -E '^DOCKERHUB_REPO=' "$ENV_FILE" | cut -d= -f2- || echo "pamsler/keypasser")
CUR=$(grep -E '^KP_VERSION=' "$ENV_FILE" | cut -d= -f2- || echo "0.0.0")

fetch_ns_all() {
  local ns name url page res
  ns="${REPO%%/*}"
  name="${REPO#*/}"
  url="https://hub.docker.com/v2/namespaces/${ns}/repositories/${name}/tags?page_size=100"
  page=1
  while :; do
    res="$(curl -fsSL "${url}&page=${page}" -H 'Accept: application/json' || true)"
    [ -n "$res" ] || break
    printf '%s\n' "$res" | grep -o '"name":"[^"]*"' | cut -d'"' -f4
    printf '%s' "$res" | grep -q '"next":null' && break
    page=$((page+1))
  done | sed '/^$/d' | sort -u
}

get_latest() { fetch_ns_all | semvers_only | pick_max; }

LATEST="$(get_latest)"
[ -n "$LATEST" ] || { echo "Could not fetch tags (repo $REPO)"; exit 2; }

if [ "$CUR" = "$LATEST" ]; then
  echo "Already up to date ($CUR)"
  exit 0
fi

echo "Update: $CUR -> $LATEST"
sed -i.bak -E "s/^KP_VERSION=.*/KP_VERSION=$LATEST/" "$ENV_FILE" || echo "KP_VERSION=$LATEST" >> "$ENV_FILE"

$DC -f "$COMPOSE_FILE" pull app
$DC -f "$COMPOSE_FILE" up -d app
echo "Done."
```

---

## ✉️ SMTP

- Configure via UI (/settings).

- Supports STARTTLS/587 and SMTPS/465.

- Custom sender, TLS enforcement, and optional logo attachment.

---

## 🔐 Security notes
- Always run behind HTTPS and set COOKIE_SECURE=true.

- Keep MASTER_KEY and SESSION_SECRET secret and persistent.

- Secrets are encrypted in Postgres and deleted on first view or expiry.

- Use app-specific SMTP credentials where possible.

---

## 🌍 Languages

- **Supported:** English (en-GB) and German (de-CH).
- **Auto-detect:** If no preference is saved, the app detects the browser language (de* → German; otherwise English).
- **Switcher:** Available on the **top bar** and the **login** screen; persisted per device (localStorage).
- **Emails:** Subjects and bodies are localized as well.
