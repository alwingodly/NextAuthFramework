// Seed script — creates test users for development
// Run with: npx prisma db seed
// Or manually: npx ts-node prisma/seed.ts

import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const db = new PrismaClient({ adapter });

async function main() {
  const adminPlainPassword =
    process.env.SEED_ADMIN_PASSWORD ?? crypto.randomBytes(18).toString("base64url");
  const userPlainPassword =
    process.env.SEED_USER_PASSWORD ?? crypto.randomBytes(18).toString("base64url");
  const adminPassword = await bcrypt.hash(adminPlainPassword, 12);
  const userPassword = await bcrypt.hash(userPlainPassword, 12);

  await db.user.upsert({
    where: { email: "admin@example.com" },
    update: {},
    create: {
      email: "admin@example.com",
      name: "Admin User",
      password: adminPassword,
      role: "ADMIN",
    },
  });

  await db.user.upsert({
    where: { email: "user@example.com" },
    update: {},
    create: {
      email: "user@example.com",
      name: "Regular User",
      password: userPassword,
      role: "USER",
    },
  });

  const usedGeneratedPasswords =
    !process.env.SEED_ADMIN_PASSWORD || !process.env.SEED_USER_PASSWORD;

  console.log("✓ Seeded users: admin@example.com and user@example.com");
  if (usedGeneratedPasswords) {
    const credFile = path.resolve(".seed-credentials.txt");
    const content = [
      "# Auto-generated seed credentials — DO NOT COMMIT",
      `admin@example.com  ${adminPlainPassword}`,
      `user@example.com   ${userPlainPassword}`,
    ].join("\n") + "\n";
    fs.writeFileSync(credFile, content, { mode: 0o600 });
    console.log(`✓ Generated credentials written to .seed-credentials.txt (chmod 600)`);
    console.log("  Set SEED_ADMIN_PASSWORD and SEED_USER_PASSWORD env vars to use fixed passwords.");
  }
}

main()
  .catch(console.error)
  .finally(() => db.$disconnect());
