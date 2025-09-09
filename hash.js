// hash.js
import bcrypt from "bcryptjs";

const password = process.argv[2];
if (!password) {
  console.error("Bitte Passwort als Argument angeben");
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);
console.log(hash);

