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
