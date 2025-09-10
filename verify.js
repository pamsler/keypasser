#!/usr/bin/env node
import bcrypt from "bcryptjs";

const [ , , plain, hash ] = process.argv;
if (!plain || !hash) {
  console.error("Usage: node verify.js <plain> <hash>");
  process.exit(1);
}

(async () => {
  try {
    const ok = await bcrypt.compare(plain, hash);
    console.log(ok ? "OK" : "FAIL");
  } catch (e) {
    console.error("Error:", e.message);
    process.exit(1);
  }
})();

