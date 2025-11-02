-- SQL script to add Role column to Users table (PostgreSQL)
-- Adds a non-nullable text column with default 'User' and updates existing rows.

BEGIN;

ALTER TABLE "Users"
ADD COLUMN IF NOT EXISTS "Role" text NOT NULL DEFAULT 'User';

-- If you prefer to set default only for existing rows and then remove the default:
-- UPDATE "Users" SET "Role" = 'User' WHERE "Role" IS NULL;
-- ALTER TABLE "Users" ALTER COLUMN "Role" DROP DEFAULT;

COMMIT;
