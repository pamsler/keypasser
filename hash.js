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
