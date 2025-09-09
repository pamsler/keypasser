# KeyPasser

Send sensitive information once — securely.

Generate a one-time, time-limited secret and share it via link or email. After the first view, the secret is destroyed.

--------------------------------------------------------------------------------------

### 🔑 How it works (at a glance)

- Client data at rest: libsodium crypto_secretbox with an HKDF-derived key; access tokens Argon2-hashed.

- TTL + one-time: Expiring links; first successful view deletes the secret.

- Delivery: Built-in SMTP (STARTTLS/587 or SMTPS/465) with custom subject/message and optional branded logo.

--------------------------------------------------------------------------------------

### ✨ Features

- Auth modes: Local accounts or Microsoft Entra ID (Azure AD) SSO; optional group gate for access/admin.

- User management: Local users + passwords; SSO users are read-only.

- MFA for local users: TOTP with backup codes.

- Auditing & stats: Who sent what to whom, status (active/used/expired), and a 14-day chart.

- UI: Dark/Light theme, mobile-friendly, minimal Tailwind.

--------------------------------------------------------------------------------------
### Quick start (docker-compose)

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
     image: pamsler/keypasser:1.x.x
     container_name: keypasser-server
     env_file: .env
     ports: ["1313:1313"]
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

Open https://your.domain.tld → Settings to configure SMTP and (optionally) Azure/SSO.

### 📦 Install
```bash

npm install bcryptjs
```

### 📁 Create the file
```js
// hash.js
import bcrypt from "bcryptjs";

const password = process.argv[2];
if (!password) {
  console.error("Please pass a password as the first argument");
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12); // cost factor 12
console.log(hash);
```

### ▶️ Run
```bash
node hash.js "super-secret-password"
# -> $2a$12$Qy...  (paste this into ADMIN_PASSWORD_HASH)
```

### ✅ Optional: verify a hash

```js
// verify.js
import bcrypt from "bcryptjs";

const [ , , plain, hash ] = process.argv;
if (!plain || !hash) {
  console.error("Usage: node verify.js <plain> <hash>");
  process.exit(1);
}
console.log(await bcrypt.compare(plain, hash) ? "OK" : "FAIL");
```
--------------------------------------------------------------------------------------

### ⚙️ Configuration (env)

- DATABASE_URL (req.) – Postgres connection string

- PORT (default 1313)

- BASE_URL (req.) – public URL used in generated links

- SESSION_SECRET (req.) – long random string

- MASTER_KEY (req.) – ≥32-byte secret for encryption key derivation

- ADMIN_EMAIL, ADMIN_PASSWORD_HASH (opt.) – seed an admin user

- TRUST_PROXY (default 1) – set when behind a reverse proxy

- COOKIE_SECURE (true when site is served via HTTPS)

- HTTPS, TLS_KEY, TLS_CERT – enable built-in HTTPS (optional)

--------------------------------------------------------------------------------------

### ✉️ SMTP

Configure in the UI. Works with STARTTLS/587 or SMTPS/465.
Supports custom sender name/address, require TLS, and optional logo.

--------------------------------------------------------------------------------------

### 🔐 Security notes

- Always deploy behind HTTPS and set COOKIE_SECURE=true.

- Keep MASTER_KEY and SESSION_SECRET secret and stable across restarts.

- Secrets exist only in Postgres (encrypted) and are deleted on first view or expiry.

- Prefer app-specific SMTP passwords where available.
