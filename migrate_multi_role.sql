-- =========================================================
-- Multi-Role Migration Script for PostgreSQL
-- =========================================================
-- This script migrates from single role (User.role) to multi-role system
-- with primary_role and UserRole join table.
--
-- Run this script on your PostgreSQL database BEFORE deploying the updated code.
-- =========================================================

BEGIN;

-- Step 1: Add primary_role column to user table
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS primary_role roleenum;

-- Step 2: Copy existing role values to primary_role
UPDATE "user" SET primary_role = role WHERE primary_role IS NULL;

-- Step 3: Set default for primary_role (for any NULL values)
UPDATE "user" SET primary_role = 'artist'::roleenum WHERE primary_role IS NULL;

-- Step 4: Make primary_role NOT NULL (after all values are set)
ALTER TABLE "user" ALTER COLUMN primary_role SET NOT NULL;
ALTER TABLE "user" ALTER COLUMN primary_role SET DEFAULT 'artist'::roleenum;

-- Step 5: Create user_role join table
CREATE TABLE IF NOT EXISTS user_role (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    role roleenum NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE,
    CONSTRAINT uq_user_role_user_role UNIQUE (user_id, role)
);

-- Step 6: Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_role_user_id ON user_role(user_id);
CREATE INDEX IF NOT EXISTS idx_user_role_role ON user_role(role);

-- Step 7: Migrate existing roles: Insert (user_id, primary_role) into user_role
-- This ensures every user has at least one role entry
INSERT INTO user_role (user_id, role, created_at)
SELECT id, primary_role, NOW()
FROM "user"
WHERE NOT EXISTS (
    SELECT 1 FROM user_role ur WHERE ur.user_id = "user".id AND ur.role = "user".primary_role
);

-- Step 8: (OPTIONAL) After verifying the migration works, you can drop the old role column
-- Uncomment the line below ONLY after you've verified everything works correctly:
-- ALTER TABLE "user" DROP COLUMN IF EXISTS role;

COMMIT;

-- =========================================================
-- Verification Queries (run these after migration to verify)
-- =========================================================
-- SELECT COUNT(*) as total_users FROM "user";
-- SELECT COUNT(*) as users_with_primary_role FROM "user" WHERE primary_role IS NOT NULL;
-- SELECT COUNT(*) as user_role_entries FROM user_role;
-- SELECT u.id, u.username, u.primary_role, array_agg(ur.role) as all_roles
-- FROM "user" u
-- LEFT JOIN user_role ur ON u.id = ur.user_id
-- GROUP BY u.id, u.username, u.primary_role
-- LIMIT 10;

