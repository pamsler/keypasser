import express from "express";
import helmet from "helmet";
import session from "express-session";
import rateLimit from "express-rate-limit";
import connectPgSimple from "connect-pg-simple";
import pg from "pg";
import crypto from "crypto";
import argon2 from "argon2";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import sodium from "libsodium-wrappers";
import multer from "multer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";
import https from "https";
import { migrate } from "./lib/db.js";
import { Issuer, generators } from "openid-client";
import fetch from "node-fetch";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import querystring from "querystring";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rlTight = rateLimit({ windowMs: 15*60*1000, limit: 100, standardHeaders:true, legacyHeaders:false });
const rlLogin = rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders:true, legacyHeaders:false });
const rlSecretGet = rateLimit({ windowMs: 10*60*1000, limit: 30, standardHeaders:true, legacyHeaders:false });

const {
  DATABASE_URL,
  PORT = 1313,
  SESSION_SECRET,
  MASTER_KEY,
  BASE_URL,
  ADMIN_EMAIL,
  ADMIN_PASSWORD_HASH
} = process.env;

if (!DATABASE_URL || !SESSION_SECRET || !MASTER_KEY || !BASE_URL) {
  console.error("Fehlende ENV Variablen. Siehe .env.example");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: DATABASE_URL });

async function waitForDb(attempts=40) {
  for (let i=0;i<attempts;i++) {
    try { const c = await pool.connect(); c.release(); return; }
    catch { await new Promise(r=>setTimeout(r, 1500)); }
  }
  throw new Error("DB nicht erreichbar");
}

const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'","https://cdn.tailwindcss.com"],
      "style-src": ["'self'","'unsafe-inline'"],
      "img-src": ["'self'","data:"],
      "connect-src": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  referrerPolicy: { policy: "no-referrer" },
  crossOriginOpenerPolicy: { policy:"same-origin" }
}));
if (String(process.env.TRUST_PROXY||"1") !== "0") app.set('trust proxy', 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "128kb" }));
 const PgStore = connectPgSimple(session);
 app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: (String(process.env.COOKIE_SECURE||"false")==="true") ? "__Host-psid" : "psid",
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: String(process.env.COOKIE_SECURE||"false") === "true",
    maxAge: 8*60*60*1000 
  },
  store: new PgStore({ pool, createTableIfMissing: true })
}));

app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));
app.use("/uploads", express.static(path.join(__dirname, "data", "uploads"), {
  setHeaders: (res)=> { res.setHeader("Content-Security-Policy","default-src 'none'; img-src 'self' data:;"); }
}));

const uploadDir = path.join(__dirname, "data", "uploads");
try {
  fs.mkdirSync(uploadDir, { recursive: true });
} catch (e) {
  console.error("Upload-Verzeichnis nicht beschreibbar:", uploadDir, e.message);
  process.exit(1);
}
const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb)=> {
    const ok = /^image\/(png|jpe?g|gif|webp)$/.test(file.mimetype) &&
               /\.(png|jpe?g|jpg|gif|webp)$/i.test(file.originalname||"");
    return cb(ok ? null : new Error("Nur Bilddateien (PNG/JPG/GIF/WebP)"));
  }
});

const requireAuth = (req,res,next)=> req.session.uid ? next() : res.status(401).end();
const toU8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(Buffer.isBuffer(x) ? x : Buffer.from(x)));
const toU8Str = (s) => sodium.from_string(String(s ?? ""));
const hkdf = (salt) => {
  const s = Buffer.isBuffer(salt) || salt instanceof Uint8Array ? Buffer.from(salt) : Buffer.from(String(salt));
  const keyBuf = crypto.hkdfSync("sha256", Buffer.from(MASTER_KEY), s, "secretbox", 32);
  return toU8(keyBuf);
};
await sodium.ready;

async function latestLogoRow() {
  const r = await pool.query("select logo_path from app_settings order by id desc limit 1");
  return r.rows[0] || null;
}
function toPublicLogo(p) {
  const fname = path.basename(p);
  return `/uploads/${fname}`;
}

const requireAdmin = async (req,res,next) => {
  if (req.session?.is_admin === true) return next();
  if (!req.session?.uid) return res.status(403).json({ error: "admin required" });
  try {
    const r = await pool.query("select is_admin from users where id=$1", [req.session.uid]);
    if (r.rowCount && r.rows[0].is_admin) {
      req.session.is_admin = true;
      return req.session.save(() => next());
    }
  } catch {}
  return res.status(403).json({ error: "admin required" });
};

app.get("/api/branding", async (_req,res)=>{
  try{
    const row = await latestLogoRow();
    res.json(row?.logo_path ? { logo_url: toPublicLogo(row.logo_path) } : {});
  }catch{ res.json({}); }
});

app.get("/api/me", async (_req,res)=>{
  if (!_req.session?.uid) return res.json({ authed:false });
  const u = await pool.query("select id,email,is_admin from users where id=$1",[ _req.session.uid ]);
  const row = u.rows[0] || {};
  const is_admin = !!row.is_admin || !!_req.session.is_admin;
  res.json({ authed:true, user: { id: row.id, email: row.email }, is_admin });
});

async function readAzureSettings() {
  const s = await pool.query("select tenant_id,client_id,client_secret_enc,redirect_uri,allowed_group,admin_group from azure_settings order by id desc limit 1");
  const a = s.rows[0];
  if (!a) return null;
  let client_secret = null;
  if (a.client_secret_enc) {
    try {
      const salt = a.client_secret_enc.subarray(0,16);
      const key  = hkdf(salt);
      const n = toU8(a.client_secret_enc.subarray(16, 16 + sodium.crypto_secretbox_NONCEBYTES));
      const c = toU8(a.client_secret_enc.subarray(16 + sodium.crypto_secretbox_NONCEBYTES));
      client_secret = sodium.to_string(sodium.crypto_secretbox_open_easy(c, n, key));
    } catch (e) {
      console.warn("Azure client_secret entschlüsseln fehlgeschlagen (MASTER_KEY?):", e.message);
      client_secret = null;
    }
  }
  return { ...a, client_secret };
}

async function getOidcClient(){
  const a = await readAzureSettings();
  if(!a) throw new Error("Azure nicht konfiguriert");
  const issuer = await Issuer.discover(`https://login.microsoftonline.com/${a.tenant_id}/v2.0`);
  return { a, client: new issuer.Client({
    client_id: a.client_id, client_secret: a.client_secret, redirect_uris: [a.redirect_uri], response_types:["code"]
  })};
}
app.get("/auth/login", async (req,res)=>{
  const { client } = await getOidcClient();
  const cv = generators.codeVerifier(); const cc = generators.codeChallenge(cv);
  req.session.cv = cv;
  const url = client.authorizationUrl({
    scope:"openid profile email offline_access",
    code_challenge:cc, code_challenge_method:"S256",
    max_age: 8*60*60
  });
  req.session.save(()=> res.redirect(url));
});
app.get("/auth/callback", async (req,res,next)=>{
  try{
    const { a, client } = await getOidcClient();
    const params = client.callbackParams(req);
    if (!req.session.cv) {
      return res.status(400).send("Session/PKCE verloren (Cookie?). Bitte erneut versuchen.");
    }
    const ts = await client.callback(a.redirect_uri, params, { code_verifier: req.session.cv });
    const c = ts.claims();
    const email = c.email || c.preferred_username;
    if(!email) return res.status(403).send("Kein E-Mail im Token");
    let groupIds = Array.isArray(c.groups) ? c.groups.slice() : [];
    let groupNames;

    if (!groupIds.length && ts.access_token) {
      try {
        const r = await fetch(
          "https://graph.microsoft.com/v1.0/me/memberOf?$select=id,displayName",
          { headers:{ Authorization:`Bearer ${ts.access_token}` } }
        );
        if (!r.ok) {
          console.warn("Graph memberOf failed:", r.status, await r.text());
        } else {
          const j = await r.json();
          const items = Array.isArray(j.value) ? j.value : [];
          groupIds = items.map(x=>x.id).filter(Boolean);
          groupNames = new Set(items.map(x=>String(x.displayName||"").toLowerCase()));
        }
      } catch (e) {
        console.warn("Graph memberOf error:", e.message);
      }
    }

    const needRaw  = (a.allowed_group||"").trim();
    const adminRaw = (a.admin_group||"").trim();
    const idsLower = new Set(groupIds.map(x=>String(x).toLowerCase()));

    const inNeed = !needRaw ? true : (
      idsLower.has(needRaw.toLowerCase()) ||
      (groupNames && groupNames.has(needRaw.toLowerCase()))
    );
    const isAdmin = !!adminRaw && (
      idsLower.has(adminRaw.toLowerCase()) ||
      (groupNames && groupNames.has(adminRaw.toLowerCase()))
    );

    if (!inNeed) {
      return res.status(403).send("Kein Gruppen-Zugang");
    }

    const u = await pool.query("insert into users(email,password_hash) values($1,'sso') on conflict(email) do update set email=excluded.email returning id",[email]);
    req.session.uid = u.rows[0].id;
    const loc = await pool.query("select is_admin from users where id=$1",[u.rows[0].id]);
    req.session.is_admin = isAdmin || !!loc.rows[0]?.is_admin;
    res.redirect("/#/dashboard");
  }catch(e){ next(e); }
});

(async ()=>{
  await waitForDb();
  await migrate(pool);
  if (ADMIN_EMAIL && ADMIN_PASSWORD_HASH) {
    const r = await pool.query("select id from users where email=$1",[ADMIN_EMAIL]);
    if (r.rowCount===0) {
      await pool.query("insert into users(email,password_hash,is_admin) values($1,$2,true)",[ADMIN_EMAIL, ADMIN_PASSWORD_HASH]);
      console.log("Admin angelegt:", ADMIN_EMAIL);
    } else {
      await pool.query("update users set is_admin=true where email=$1",[ADMIN_EMAIL]);
    }
  }
})().catch(err=>{ console.error(err); process.exit(1); });

app.post("/api/login", rlLogin, async (req,res)=>{
  const { email, password, otp } = req.body||{};
  const r = await pool.query("select id,password_hash,mfa_enabled,totp_secret,is_admin from users where email=$1",[email]);
  if (!r.rowCount) return res.status(401).end();
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) return res.status(401).end();
  if (r.rows[0].mfa_enabled && r.rows[0].totp_secret) {
    if (!otp || !authenticator.check(String(otp), r.rows[0].totp_secret)) {
      return res.status(401).json({ error: "MFA_REQUIRED" });
    }
  }
  req.session.regenerate(err=>{
    if (err) return res.status(500).end();
    req.session.uid = r.rows[0].id;
	req.session.is_admin = !!r.rows[0].is_admin;
    pool.query("update users set last_login_at=now() where id=$1",[r.rows[0].id]).catch(()=>{});
    return res.json({ ok:true });
  });
});
app.post("/api/logout", (req,res)=> { req.session.destroy(()=>res.json({ok:true})); });

 app.get("/api/smtp", requireAuth, requireAdmin, async (_req,res)=>{
   const r = await pool.query(
     "select host,port,secure,from_name,from_email,require_tls,user_enc,pass_enc from smtp_settings order by id desc limit 1"
   );
   if (!r.rowCount) return res.json(null);
   const row = r.rows[0];
   res.json({
     host: row.host,
     port: row.port,
     secure: row.secure,
     from_name: row.from_name,
     from_email: row.from_email,
     require_tls: row.require_tls,
     has_creds: !!row.user_enc && !!row.pass_enc
   });
 });
app.post("/api/smtp", requireAuth, requireAdmin, async (req,res)=>{
  try {
    const { host, port, secure, user, pass, from_name, from_email, require_tls=true } = req.body||{};
    if (!host || !port || typeof secure!=="boolean") return res.status(400).json({error:"Ungültig"});
    const cur = await pool.query("select user_enc,pass_enc from smtp_settings order by id desc limit 1");
    let user_enc = cur.rows[0]?.user_enc || null;
    let pass_enc = cur.rows[0]?.pass_enc || null;
    if (user || pass) {
      if (!user || !pass) return res.status(400).json({error:"Benutzer & Passwort gemeinsam angeben"});
      const salt = crypto.randomBytes(16);               
      const key  = hkdf(salt);                          
      const n1   = toU8(sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES));
      const n2   = toU8(sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES));
      const cUser = sodium.crypto_secretbox_easy(toU8Str(user), n1, key);
      const cPass = sodium.crypto_secretbox_easy(toU8Str(pass), n2, key);
      user_enc = Buffer.concat([salt, Buffer.from(n1), Buffer.from(cUser)]);
      pass_enc = Buffer.concat([salt, Buffer.from(n2), Buffer.from(cPass)]);
    }
    if (!user_enc || !pass_enc) return res.status(400).json({error:"SMTP-Zugangsdaten fehlen"});
    await pool.query(
      "insert into smtp_settings(host,port,secure,user_enc,pass_enc,from_name,from_email,require_tls,updated_at) values($1,$2,$3,$4,$5,$6,$7,$8,now())",
      [host, Number(port), !!secure, user_enc, pass_enc, from_name||null, from_email||null, !!require_tls]
    );
    res.json({ ok:true });
  } catch (e) {
    console.error("POST /api/smtp failed:", e);
    res.status(500).json({ error: e.message||"internal error" });
  }
 });

async function getTransport() {
  const r = await pool.query("select * from smtp_settings order by id desc limit 1");
  if (!r.rowCount) throw new Error("SMTP nicht konfiguriert");
  const row = r.rows[0];
  const salt = row.user_enc.subarray(0,16);
  const key  = hkdf(salt);
  const n1 = toU8(row.user_enc.subarray(16, 16 + sodium.crypto_secretbox_NONCEBYTES));
  const c1 = toU8(row.user_enc.subarray(16 + sodium.crypto_secretbox_NONCEBYTES));
  const n2 = toU8(row.pass_enc.subarray(16, 16 + sodium.crypto_secretbox_NONCEBYTES));
  const c2 = toU8(row.pass_enc.subarray(16 + sodium.crypto_secretbox_NONCEBYTES));
  const user = sodium.to_string(sodium.crypto_secretbox_open_easy(c1, n1, key));
  const pass = sodium.to_string(sodium.crypto_secretbox_open_easy(c2, n2, key));
  return nodemailer.createTransport({
    host: row.host,
    port: row.port,
    secure: row.secure,         
    requireTLS: !!row.require_tls,
    auth: { user, pass }
  });
}

app.get("/api/settings", requireAuth, async (_req,res)=>{
  const r = await pool.query("select logo_path from app_settings order by id desc limit 1");
  const row = r.rows[0];
  res.json(row?.logo_path ? { logo_url: toPublicLogo(row.logo_path) } : {});
});
app.post("/api/settings/logo", requireAuth, requireAdmin, upload.single("logo"), async (req,res)=>{
  if (!req.file) return res.status(400).json({error:"Datei fehlt"});
  const ext = (req.file.mimetype.split("/")[1]||"png").toLowerCase();
  const safeName = "logo_" + crypto.randomBytes(6).toString("hex") + "." + ext;
  const finalPath = path.join(uploadDir, safeName);
  fs.renameSync(req.file.path, finalPath);
  await pool.query("insert into app_settings(logo_path,updated_at) values($1, now())",[finalPath]);
  res.json({ ok:true, logo_url: toPublicLogo(finalPath) });
});

app.get("/api/auth", async (_req,res)=>{
  const r = await pool.query("select login_mode from auth_settings order by id desc limit 1");
  const mode = r.rows[0]?.login_mode || "local";
  res.json({ login_mode: ["local","sso","both"].includes(mode) ? mode : "local" });
});
app.post("/api/auth", requireAuth, requireAdmin, async (req,res)=>{
  const { login_mode="local" } = req.body||{};
  if(!["local","sso","both"].includes(login_mode)) return res.status(400).json({error:"invalid mode"});
  await pool.query("insert into auth_settings(login_mode,updated_at) values($1,now())",[login_mode]);
  res.json({ok:true});
});

app.get("/api/azure", requireAuth, requireAdmin, async (_req,res)=>{
  const r = await pool.query("select tenant_id,client_id,redirect_uri,allowed_group,admin_group from azure_settings order by id desc limit 1");
  res.json(r.rows[0]||null);
});
app.post("/api/azure", requireAuth, requireAdmin, async (req,res)=>{
  const { tenant_id, client_id, client_secret, redirect_uri, allowed_group, admin_group } = req.body||{};
  if(!tenant_id || !client_id || !redirect_uri) return res.status(400).json({error:"ungueltig"});
  const cur = await pool.query("select client_secret_enc from azure_settings order by id desc limit 1");
  let effectiveSecretEnc = cur.rows[0]?.client_secret_enc || null;
  if (typeof client_secret === "string" && client_secret !== "") {
    const salt = crypto.randomBytes(16);
    const key = hkdf(salt);
    const n = toU8(sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES));
    const c = sodium.crypto_secretbox_easy(toU8Str(client_secret), n, key);
    effectiveSecretEnc = Buffer.concat([salt,n,c]);
  }
  await pool.query(`
    insert into azure_settings(tenant_id,client_id,client_secret_enc,redirect_uri,allowed_group,admin_group,updated_at)
    values($1,$2,$3,$4,$5,$6,now())`,
    [tenant_id, client_id, effectiveSecretEnc, redirect_uri, allowed_group||null, admin_group||null]);
  res.json({ok:true});
});

app.get("/api/azure/secret", requireAuth, requireAdmin, async (_req, res) => {
  const r = await pool.query("select client_secret_enc from azure_settings order by id desc limit 1");
  const has = !!r.rows[0]?.client_secret_enc;
  res.json({ client_secret: has ? "********" : "" });
});

async function getGraphAppToken(){
  const a = await readAzureSettings();
  if(!a?.tenant_id || !a?.client_id || !a?.client_secret) return null;
  const body = querystring.stringify({
    client_id: a.client_id,
    client_secret: a.client_secret,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials"
  });
  const tok = await fetch(`https://login.microsoftonline.com/${a.tenant_id}/oauth2/v2.0/token`,{
    method:"POST",
    headers:{ "content-type":"application/x-www-form-urlencoded" },
    body
  });
  if(!tok.ok) {
    const txt = await tok.text().catch(()=>"(no body)");
    console.warn("Graph token fetch failed:", tok.status, txt);
    return null;
  }
  const j = await tok.json();
  return j?.access_token || null;
}

app.get("/api/recipients", requireAuth, async (req,res)=>{
  try{
    const q = String(req.query.q||"").trim();
    if (q.length < 2) return res.json([]);  
    const token = await getGraphAppToken();
    if(!token) return res.json([]);
    const enc = encodeURIComponent(q.replace(/'/g,""));
    const url = `https://graph.microsoft.com/v1.0/users?$top=8&$select=displayName,mail,userPrincipalName&$filter=`+
      `startswith(displayName,'${enc}') or startswith(mail,'${enc}') or startswith(userPrincipalName,'${enc}')`;
    const r = await fetch(url,{ headers:{ Authorization:`Bearer ${token}` }});
    if(!r.ok) return res.json([]);
    const j = await r.json();
    const items = Array.isArray(j.value) ? j.value : [];
    const out = items.map(u=>({
      name: u.displayName || u.userPrincipalName || u.mail || "",
      email: u.mail || u.userPrincipalName || ""
    })).filter(x=>x.email);
    res.json(out);
  }catch(e){
    res.json([]);
  }
});


app.get("/api/users", requireAuth, requireAdmin, async (_req,res)=>{
  const r = await pool.query(
    "select id,email,(password_hash='sso') as is_sso from users order by email asc"
  );
  res.json(r.rows);
});
app.post("/api/users", requireAuth, requireAdmin, async (req,res)=>{
  const { email,password } = req.body||{};
  if(!email || !password) return res.status(400).json({error:"ungueltig"});
  const hash = await bcrypt.hash(password, 10);
  await pool.query("insert into users(email,password_hash) values($1,$2) on conflict(email) do update set password_hash=excluded.password_hash",[email,hash]);
  res.json({ok:true});
});
app.delete("/api/users/:id", requireAuth, requireAdmin, async (req,res)=>{
  const u = await pool.query("select password_hash from users where id=$1",[req.params.id]);
  if(!u.rowCount) return res.status(404).end();
  if(u.rows[0].password_hash === "sso")
    return res.status(400).json({error:"SSO-Benutzer können hier nicht gelöscht werden"});
  await pool.query("delete from users where id=$1",[req.params.id]);
  res.json({ok:true});
});
app.post("/api/users/:id/password", requireAuth, requireAdmin, async (req,res)=>{
  const { password } = req.body||{};
  if(!password) return res.status(400).json({error:"Passwort fehlt"});
  const u = await pool.query("select password_hash from users where id=$1",[req.params.id]);
  if(!u.rowCount) return res.status(404).end();
  if(u.rows[0].password_hash === "sso")
    return res.status(400).json({error:"SSO-Benutzer: Passwort wird bei Microsoft verwaltet"});
  const hash = await bcrypt.hash(password, 10);
  await pool.query("update users set password_hash=$1 where id=$2",[hash, req.params.id]);
  res.json({ok:true});
});


app.post("/api/secrets", requireAuth, rlTight, async (req,res)=>{
  try {
    const { plaintext, ttl_minutes=60 } = req.body||{};
    if (!plaintext || typeof plaintext!=="string") return res.status(400).json({error:"plaintext erforderlich"});
    const id = crypto.randomUUID();
    const token = crypto.randomBytes(32).toString("base64url");
    const token_hash = await argon2.hash(token, { type: argon2.argon2id });
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const key = hkdf(id);
    const cipher = sodium.crypto_secretbox_easy(toU8Str(plaintext), toU8(nonce), key);
    const expires = new Date(Date.now() + Number(ttl_minutes)*60*1000);
    await pool.query(
      "insert into secrets(id,cipher,nonce,token_hash,expires_at,created_by) values($1,$2,$3,$4,$5,$6)",
      [id, Buffer.from(cipher), Buffer.from(nonce), token_hash, expires, req.session.uid]
    );
    const url = `${BASE_URL}/s/${id}?t=${token}`;
    res.json({ url, expires_at: expires.toISOString() });
  } catch (e) {
    res.status(500).json({ error: e.message||"internal error" });
  }
});

app.post("/api/secrets/send", requireAuth, rlTight, async (req,res)=>{
  try {
    const { plaintext, ttl_minutes=60, to, subject="Sicherer Zugriff", message="Klicke auf den Link:" } = req.body||{};
	const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;
    if (!to || !emailRe.test(String(to))) return res.status(400).json({error:"ungültige Empfängeradresse"});
    const id = crypto.randomUUID();
    const token = crypto.randomBytes(32).toString("base64url");
    const token_hash = await argon2.hash(token, { type: argon2.argon2id });
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const key = hkdf(id);
    const cipher = sodium.crypto_secretbox_easy(toU8Str(plaintext), toU8(nonce), key);
    const expires_at = new Date(Date.now() + Number(ttl_minutes)*60*1000).toISOString();
    await pool.query(
      "insert into secrets(id,cipher,nonce,token_hash,expires_at,created_by) values($1,$2,$3,$4,$5,$6)",
      [id, Buffer.from(cipher), Buffer.from(nonce), token_hash, expires_at, req.session.uid]
    );
    const url = `${BASE_URL}/s/${id}?t=${token}`;
    const expiresAtCH = new Intl.DateTimeFormat('de-CH', {
      timeZone: 'Europe/Zurich',
      dateStyle: 'short',
      timeStyle: 'short'
    }).format(new Date(expires_at));

  let logoAttachment = null;
  let logoCid = null;
  const s = await pool.query("select logo_path from app_settings order by id desc limit 1");
  if (s.rowCount && s.rows[0].logo_path && fs.existsSync(s.rows[0].logo_path)) {
    logoCid = "logo@" + crypto.randomBytes(5).toString("hex");
    logoAttachment = {
      filename: path.basename(s.rows[0].logo_path),
      path: s.rows[0].logo_path,
      cid: logoCid
    };
  }


  const tpl = fs.readFileSync(path.join(__dirname, "templates", "email.html"), "utf8");
  const html = tpl
    .replace("{{url}}", url)
    .replace("{{expires_at}}", expiresAtCH)
    .replace("{{message}}", escapeHtml(message))
    .replace("{{#if logoCid}}","")
    .replace("{{/if}}","")
    .replaceAll("{{logoCid}}", logoCid || "");

    const transport = await getTransport();
    const fromRow = await getFrom();
    const fromAddr = rowAddress(fromRow);
    await transport.sendMail({
      to,
      subject,
      from: fromAddr,
      envelope: { from: fromRow.from_email, to },
      text: `${message}\n${url}\nGültig bis: ${expiresAtCH} (Europe/Zurich)`,
      html: logoCid ? html : html.replace(/<img[^>]*>/, ""),
      attachments: logoAttachment ? [logoAttachment] : []
    });
    await pool.query(
      "insert into audit_events(user_id, secret_id, to_email, created_at) values ($1,$2,$3, now())",
      [req.session.uid, new URL(url).pathname.split('/').pop().split('?')[0], to]
    );
    res.json({ ok:true, url, expires_at });
  } catch (e) {
    res.status(500).json({ error: e.message||"mail send failed" });
  }
});

app.get("/api/audit", requireAuth, async (req,res)=>{
  const page = Math.max(1, Number(req.query.page||1));
  const size = Math.min(50, Math.max(5, Number(req.query.size||10)));
  const off  = (page-1)*size;
  const totalQ = await pool.query(`select count(*)::int as n from audit_events`);
  const rowsQ  = await pool.query(`
    select ae.id, ae.created_at, ae.to_email,
           u.email as from_email,
           s.expires_at, s.retrieved_at
    from audit_events ae
    left join users u on u.id = ae.user_id
    left join secrets s on s.id = ae.secret_id
    order by ae.created_at desc
    limit $1 offset $2
  `,[size, off]);
  const items = rowsQ.rows.map(r=>{
    let status = "active";
    if (r.retrieved_at) status = "used";
    else if (new Date(r.expires_at) < new Date()) status = "expired";
    return { ...r, status };
  });
  res.json({ total: totalQ.rows[0].n, page, size, items });
});

app.get("/api/stats/day", requireAuth, async (_req,res)=>{
  const r = await pool.query(`
    with d as (
      select generate_series::date as day
      from generate_series((now()::date - interval '13 day')::date, now()::date, '1 day')
    )
    select d.day,
           coalesce(x.sent,0)::int as sent
    from d
    left join (
      select date_trunc('day', created_at)::date as day, count(*)::int as sent
      from audit_events
      where created_at >= now()::date - interval '13 day'
      group by 1
    ) x on x.day = d.day
    order by d.day
  `);
  res.json(r.rows);
});

async function getFrom() {
  const r = await pool.query("select from_name,from_email from smtp_settings order by id desc limit 1");
  const { from_name, from_email } = r.rows[0] || {};
  return { from_name: from_name||"", from_email };
}
function rowAddress({from_name, from_email}) {
  if (!from_email) return undefined;
  return from_name ? `${from_name} <${from_email}>` : from_email;
}


app.post("/api/profile/password", requireAuth, async (req,res)=>{
  const { current_password, new_password } = req.body||{};
  if (!new_password) return res.status(400).json({error:"Neues Passwort fehlt"});
  const r = await pool.query("select password_hash from users where id=$1",[req.session.uid]);
  if (!r.rowCount || r.rows[0].password_hash==="sso") return res.status(400).json({error:"SSO-Benutzer"});
  if (!await bcrypt.compare(current_password||"", r.rows[0].password_hash)) return res.status(403).json({error:"Falsches Passwort"});
  const hash = await bcrypt.hash(new_password,10);
  await pool.query("update users set password_hash=$1, password_changed_at=now() where id=$2",[hash, req.session.uid]);
  res.json({ok:true});
});
app.post("/api/profile/email", requireAuth, async (req,res)=>{
  const { email } = req.body||{};
  if(!email) return res.status(400).json({error:"E-Mail fehlt"});
  await pool.query("update users set email=$1 where id=$2",[email, req.session.uid]);
  res.json({ok:true});
});

function hashBackup(code){ return crypto.createHash("sha256").update(code).digest("hex"); }
function makeBackupCodes(n=8){
  const codes=[]; for(let i=0;i<n;i++){ const raw=crypto.randomBytes(4).toString("hex");
    codes.push({ raw, hash: hashBackup(raw) }); }
  return codes;
}

app.post("/api/mfa/start", requireAuth, async (_req,res)=>{
  const u = await pool.query("select email,password_hash from users where id=$1",[ _req.session.uid ]);
  if (!u.rowCount || u.rows[0].password_hash==="sso") return res.status(400).json({error:"SSO-Benutzer"});
  const secret = authenticator.generateSecret();
  const label  = encodeURIComponent(u.rows[0].email||"KeyPasser");
  const issuer = encodeURIComponent("KeyPasser");
  const otpauth = `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}`;
  const qr = await QRCode.toDataURL(otpauth);

  _req.session.mfa_setup = { secret };
  res.json({ otpauth, qr, secret });
});

app.post("/api/mfa/verify", requireAuth, async (req,res)=>{
  const setup = req.session.mfa_setup;
  const code = String(req.body?.otp||"");
  if(!setup?.secret) return res.status(400).json({error:"Setup abgelaufen"});
  if(!authenticator.check(code, setup.secret)) return res.status(400).json({error:"Code ungültig"});
  const codes = makeBackupCodes();
  await pool.query("update users set totp_secret=$1,mfa_enabled=true,mfa_backup_codes=$2 where id=$3",
    [ setup.secret, codes.map(c=>c.hash), req.session.uid ]);
  req.session.mfa_setup = null;
  res.json({ ok:true, backup_codes: codes.map(c=>c.raw) });
});

 app.post("/api/mfa/disable", requireAuth, async (_req,res)=>{
   await pool.query(
     "update users set mfa_enabled=false, totp_secret=NULL, mfa_backup_codes=NULL where id=$1",
     [_req.session.uid]
   );
  res.json({ok:true});
});

app.get("/api/profile", requireAuth, async (req,res)=>{
  const u = await pool.query(
    "select email, created_at, password_changed_at, last_login_at, mfa_enabled from users where id=$1",
    [req.session.uid]
  );
  const row = u.rows[0];
  const sentQ = await pool.query("select count(*)::int as n from audit_events where user_id=$1",[req.session.uid]);
  res.json({
    email: row.email,
    created_at: row.created_at,
    password_changed_at: row.password_changed_at,
    last_login_at: row.last_login_at,
    mfa_enabled: row.mfa_enabled,
    sent_count: sentQ.rows[0].n
  });
});


app.post("/api/login/backup", rlLogin, async (req,res)=>{
  const { email, password, backup_code } = req.body||{};
  const r = await pool.query("select id,password_hash,mfa_enabled,mfa_backup_codes from users where email=$1",[email]);
  if (!r.rowCount) return res.status(401).end();
  if (!await bcrypt.compare(password||"", r.rows[0].password_hash)) return res.status(401).end();
  if (!r.rows[0].mfa_enabled) return res.status(400).json({error:"MFA nicht aktiv"});
  const hash = hashBackup(String(backup_code||""));
  const list = r.rows[0].mfa_backup_codes||[];
  if (!list.includes(hash)) return res.status(401).json({error:"Backup-Code ungültig"});
  const rest = list.filter(h=>h!==hash);
  await pool.query("update users set mfa_backup_codes=$1 where id=$2",[rest, r.rows[0].id]);
  req.session.regenerate(err=>{
    if (err) return res.status(500).end();
    req.session.uid = r.rows[0].id;
	req.session.is_admin = !!r.rows[0].is_admin;
    res.json({ok:true});
  });
});


app.get("/s/:id", rlSecretGet, async (req,res)=>{
  const render = (title, inner) => `<!doctype html>
  <html lang="de" class="h-full">
  <head>
    <meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>${escapeHtml(title)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
      (function(){const t=localStorage.getItem("theme");
        if(t==="dark"||(!t&&window.matchMedia("(prefers-color-scheme: dark)").matches)){
          document.documentElement.classList.add("dark");
        }})();
      tailwind.config={darkMode:'class'};
    </script>
  </head>
  <body class="h-full bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
    <main class="min-h-screen flex items-start md:items-center justify-center p-6">
      <div class="backdrop-blur bg-white/70 dark:bg-gray-800/70 border border-gray-200/60 dark:border-gray-700/60 rounded-2xl shadow p-6 max-w-2xl w-full">
        ${inner}
      </div>
    </main>
  </body></html>`;
  try {
    const { id } = req.params;
    const token = String(req.query.t||"");
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).send(render("Ungültige Anfrage", `<h2 class="text-lg font-semibold mb-2">Ungültige ID</h2><p class="text-sm text-gray-600 dark:text-gray-400">Die Anfrage konnte nicht verarbeitet werden.</p>`));
    }
    if (!token) {
      return res.status(400).send(render("Token fehlt", `<h2 class="text-lg font-semibold mb-2">Token fehlt</h2><p class="text-sm text-gray-600 dark:text-gray-400">Der Link ist unvollständig.</p>`));
    }
    const r = await pool.query("select *, coalesce(fail_count,0)::int as fail_count from secrets where id=$1", [id]);
    if (!r.rowCount) {
      return res.status(404).send(render("Nicht gefunden", `<h2 class="text-lg font-semibold mb-2">Secret nicht gefunden</h2><p class="text-sm text-gray-600 dark:text-gray-400">Entweder bereits abgerufen oder nie vorhanden.</p>`));
    }
    const row = r.rows[0];
    if (new Date(row.expires_at) < new Date()) {
      await pool.query("delete from secrets where id=$1",[id]);
      return res.status(410).send(render("Abgelaufen", `<h2 class="text-lg font-semibold mb-2">Secret abgelaufen</h2><p class="text-sm text-gray-600 dark:text-gray-400">Die Gültigkeit ist abgelaufen.</p>`));
    }
    const hash = typeof row.token_hash === "string" ? row.token_hash : row.token_hash?.toString?.() || "";
    const ok = hash && await argon2.verify(hash, token);
    if (!ok) {
      const fc = (row.fail_count||0)+1;
      await pool.query("update secrets set fail_count=$2 where id=$1",[id, fc]);
      if (fc >= 5) await pool.query("delete from secrets where id=$1",[id]);
      return res.status(403).send(render("Ungültiger Token", `<h2 class="text-lg font-semibold mb-2">Zugriff verweigert</h2><p class="text-sm text-gray-600 dark:text-gray-400">Der Token ist ungültig.</p>`));
    }
    const key = hkdf(id);
    const plaintext = sodium.to_string(
      sodium.crypto_secretbox_open_easy(toU8(row.cipher), toU8(row.nonce), key)
    );
    await pool.query("update secrets set retrieved_at=now(), retrieved_ip=$2 where id=$1",[id, req.headers["x-forwarded-for"]||req.ip]);
    await pool.query("delete from secrets where id=$1",[id]);

    return res
      .status(200)
      .send(render("Secret anzeigen", `
        <h2 class="text-xl font-semibold mb-4">Einmaliges Secret</h2>
        <p class="text-sm text-gray-600 dark:text-gray-400 mb-3">Der Inhalt wurde entschlüsselt. Kopiere ihn jetzt. Beim Schließen dieser Seite ist der Link verbraucht.</p>
        <pre id="secret" class="whitespace-pre-wrap break-words bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-4 mb-4">${escapeHtml(plaintext)}</pre>
        <div class="flex gap-3">
          <button id="copyBtn" class="px-4 py-2 rounded-xl bg-indigo-600 text-white hover:bg-indigo-500">In Zwischenablage</button>
        </div>
        <script>
          const s=document.getElementById('secret');
          const btn=document.getElementById('copyBtn');
          function toast(msg){
            const t=document.createElement('div');
            t.className='fixed bottom-5 left-1/2 -translate-x-1/2 px-3 py-1.5 rounded-lg bg-gray-900 text-white text-xs';
            t.textContent=msg; document.body.appendChild(t);
            setTimeout(()=>t.remove(),1800);
          }
          btn.addEventListener('click', async ()=>{
            const text=s.textContent||'';
            try{
              if(navigator.clipboard && window.isSecureContext){
                await navigator.clipboard.writeText(text);
              }else{
                const ta=document.createElement('textarea');
                ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
                document.body.appendChild(ta); ta.focus(); ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
              }
              toast('Kopiert');
            }catch(e){ toast('Kopieren fehlgeschlagen'); }
          });
          try{ const u=new URL(window.location.href); u.search=''; history.replaceState(null,'',u.toString()); }catch{}
        </script>
      `));
  } catch (e) {
    console.error(e);
    return res
      .status(500)
      .send(render("Fehler", `<h2 class="text-lg font-semibold mb-2">Serverfehler</h2><p class="text-sm text-gray-600 dark:text-gray-400">Bitte versuche es erneut.</p>`));
  }
});

setInterval(()=> pool.query("delete from secrets where expires_at < now()").catch(()=>{}), 60_000).unref();

if (String(process.env.HTTPS||"false") === "true") {
  const key = fs.readFileSync(process.env.TLS_KEY);
  const cert = fs.readFileSync(process.env.TLS_CERT);
  https.createServer({ key, cert }, app).listen(PORT, ()=> console.log("listening https", PORT));
} else {
  http.createServer(app).listen(PORT, ()=> console.log("listening http", PORT));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (m)=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m]));
}

