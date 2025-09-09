export async function migrate(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations(
      version integer PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  const { rows } = await pool.query(`SELECT COALESCE(MAX(version),0) AS v FROM schema_migrations`);
  let current = Number(rows[0].v) || 0;

  if (current < 1) {
    await withTx(pool, async (tx) => {
      await tx.query(`
        -- Benutzer
        CREATE TABLE IF NOT EXISTS users (
          id serial PRIMARY KEY,
          email text UNIQUE NOT NULL,
          password_hash text NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

        -- SMTP-Einstellungen (verschlüsselte Creds)
        CREATE TABLE IF NOT EXISTS smtp_settings (
          id serial PRIMARY KEY,
          host text NOT NULL,
          port int NOT NULL,
          secure boolean NOT NULL,
          user_enc bytea NOT NULL,
          pass_enc bytea NOT NULL,
          from_name text,
          from_email text,
          require_tls boolean DEFAULT true,
          updated_at timestamptz DEFAULT now()
        );

        -- App-Settings (Logo)
        CREATE TABLE IF NOT EXISTS app_settings (
          id serial PRIMARY KEY,
          logo_path text,
          updated_at timestamptz DEFAULT now()
        );

        -- Einmal-Secrets
        CREATE TABLE IF NOT EXISTS secrets (
          id uuid PRIMARY KEY,
          cipher bytea NOT NULL,
          nonce bytea NOT NULL,
          token_hash text NOT NULL,
          expires_at timestamptz NOT NULL,
          created_by integer REFERENCES users(id) ON DELETE SET NULL,
          retrieved_at timestamptz,
          retrieved_ip inet
        );
        CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);
      `);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (1)`);
    });
    current = 1;
    console.log("DB migration -> v1 angewendet");
  }

  if (current < 2) {
    await withTx(pool, async (tx) => {
      await tx.query(`
        CREATE TABLE IF NOT EXISTS audit_events(
          id bigserial PRIMARY KEY,
          created_at timestamptz NOT NULL DEFAULT now(),
          user_id integer REFERENCES users(id) ON DELETE SET NULL,
          secret_id uuid,
          to_email text
        );
        CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
          ON audit_events(created_at);
      `);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (2)`);
    });
    current = 2;
    console.log("DB migration -> v2 angewendet");
  }
  
  if (current < 3) {
    await withTx(pool, async (tx) => {
      await tx.query(`
        CREATE TABLE IF NOT EXISTS azure_settings(
          id serial PRIMARY KEY,
          tenant_id text,
          client_id text,
          client_secret_enc bytea,
          redirect_uri text,
          allowed_group text,
          admin_group text,
          updated_at timestamptz DEFAULT now()
        );
        CREATE TABLE IF NOT EXISTS auth_settings(
          id serial PRIMARY KEY,
          login_mode text NOT NULL DEFAULT 'local', -- local | sso | both
          updated_at timestamptz DEFAULT now()
        );
        INSERT INTO auth_settings(login_mode)
        SELECT 'local' WHERE NOT EXISTS (SELECT 1 FROM auth_settings);
      `);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (3)`);
    });
    current = 3;
    console.log("DB migration -> v3 angewendet");
  }
  
  if (current < 4) {
    await withTx(pool, async (tx) => {
      await tx.query(`
        ALTER TABLE users
          ADD COLUMN IF NOT EXISTS totp_secret text,
          ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false,
          ADD COLUMN IF NOT EXISTS mfa_backup_codes text[]; -- gehashte Codes
      `);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (4)`);
    });
    current = 4;
    console.log("DB migration -> v4 angewendet");
  }
  
  if (current < 5) {
    await withTx(pool, async (tx) => {
      await tx.query(`
        ALTER TABLE users
          ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now(),
          ADD COLUMN IF NOT EXISTS password_changed_at timestamptz,
          ADD COLUMN IF NOT EXISTS last_login_at timestamptz;
      `);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (5)`);
    });
    current = 5;
    console.log("DB migration -> v5 angewendet");
  }
  
  if (current < 6) {
    await withTx(pool, async (tx) => {
      await tx.query(`ALTER TABLE secrets ADD COLUMN IF NOT EXISTS fail_count integer NOT NULL DEFAULT 0`);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (6)`);
    });
    current = 6;
    console.log("DB migration -> v6 angewendet");
  }
  
  if (current < 7) {
    await withTx(pool, async (tx) => {
      await tx.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false`);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (7)`);
    });
    current = 7;
    console.log("DB migration -> v7 angewendet");
  }

  if (current < 8) {
    await withTx(pool, async (tx) => {
      await tx.query(`ALTER TABLE azure_settings ADD COLUMN IF NOT EXISTS client_secret_enc bytea`);
      await tx.query(`INSERT INTO schema_migrations(version) VALUES (8)`);
    });
    current = 8;
    console.log("DB migration -> v8 angewendet");
  }

}

async function withTx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await fn(client);
    await client.query("COMMIT");
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    throw e;
  } finally {
    client.release();
  }
}
