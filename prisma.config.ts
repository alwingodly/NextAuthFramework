import { config } from "dotenv";
// Load .env.local first (secrets), then .env (non-secret defaults).
// dotenv does not override already-set variables, so .env.local wins.
config({ path: ".env.local" });
config({ path: ".env" });
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: process.env["DATABASE_URL"], // Transaction pooler
    shadowDatabaseUrl: process.env["DIRECT_URL"] // Direct connection
  },
});
