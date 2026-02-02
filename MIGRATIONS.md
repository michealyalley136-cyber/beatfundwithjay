# Database Migrations Guide

## CHANGELOG - Production Hardening Updates

### Critical Bug Fixes
1. **Fixed `market_upload()` indentation bug** - Preview audio and deliverable files now save correctly
2. **Removed duplicate seller notifications** in `market_buy()` - seller notified only once
3. **Transaction safety** - `create_notification()` and `notify_user()` no longer commit by default
4. **Fixed `ProjectVault.is_locked_now()`** - Now side-effect free, returns `(is_locked, should_auto_unlock)` tuple

### Database Changes
1. **New Model: `TransactionIdempotency`** - Prevents duplicate wallet transfers and beat purchases
   - Columns: `id`, `user_id`, `key` (unique), `scope`, `result_json`, `created_at`
   - Unique constraint on `key` for idempotency

2. **Wallet balance computation** - Replaced Python loop with SQL aggregation for performance

### Infrastructure Changes
1. **Redis rate limiting** - Replaces in-memory rate limiting (fallback to memory in dev)
2. **Storage abstraction** - S3 support via `STORAGE_BACKEND=s3` env var
3. **Structured logging** - JSON logs in production, console in dev
4. **Sentry integration** - Error tracking when `SENTRY_DSN` is set
5. **Request ID middleware** - Unique request IDs for tracing
6. **ProxyFix support** - Enable with `TRUST_PROXY=1` for reverse proxy deployments

### Concurrency Safety
1. **Row-level locking** - `SELECT ... FOR UPDATE` on Postgres for wallet/beat operations
2. **Idempotency keys** - Required for wallet transfers and beat purchases

### Production Settings
1. **SQLite auto-migrations disabled in prod** - Use Alembic only in production
2. **Postgres safe auto-migrations (optional)** - Set `PG_AUTO_MIGRATE=1` to apply add-only schema fixes (creates missing tables + login-critical user columns) at app startup.
3. **CSP improvements** - Stricter Content Security Policy in production

---

## Alembic Setup Instructions

### 1. Install Alembic

```bash
pip install alembic
```

### 2. Initialize Alembic (one-time setup)

```bash
cd beatfund
alembic init alembic
```

This creates an `alembic/` directory with migration scripts.

### 3. Configure Alembic

Edit `alembic/env.py`:

```python
from app import app, db
from models import *  # Import all models

# Use the same database URL as Flask app
config.set_main_option('sqlalchemy.url', app.config['SQLALCHEMY_DATABASE_URI'])

target_metadata = db.metadata
```

### 4. Create Initial Migration (if starting fresh)

```bash
alembic revision --autogenerate -m "Initial schema"
```

### 5. Create Migration for TransactionIdempotency

```bash
alembic revision --autogenerate -m "Add transaction_idempotency table"
```

Review the generated migration in `alembic/versions/` and adjust if needed.

### 6. Apply Migrations

**Development:**
```bash
alembic upgrade head
```

**Production:**
```bash
# Always backup first!
alembic upgrade head
```

### 7. Rollback (if needed)

```bash
alembic downgrade -1  # Rollback one migration
alembic downgrade base  # Rollback all migrations
```

---

## Migration Workflow

### Development

1. Make model changes in `app.py`
2. Generate migration: `alembic revision --autogenerate -m "Description"`
3. Review generated migration file
4. Apply: `alembic upgrade head`
5. Test thoroughly

### Staging

1. Pull latest code
2. Backup database
3. Run: `alembic upgrade head`
4. Verify application works
5. Monitor logs for errors

### Production

1. **CRITICAL: Backup database first**
2. Pull latest code
3. Run migrations during maintenance window: `alembic upgrade head`
4. Verify application health
5. Monitor error tracking (Sentry)
6. Have rollback plan ready: `alembic downgrade -1`

---

## Environment Variables for Production

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Redis (for rate limiting)
REDIS_URL=redis://localhost:6379/0

# Storage (S3)
STORAGE_BACKEND=s3
S3_BUCKET=your-bucket-name
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_REGION=us-east-1

# Sentry
SENTRY_DSN=https://your-sentry-dsn

# Proxy
TRUST_PROXY=1  # If behind reverse proxy

# App
APP_ENV=prod
SECRET_KEY=your-secret-key-here
```

---

## Notes

- **Never run migrations directly on production database** without testing in staging first
- **Always backup** before running migrations in production
- **Test rollback procedures** in staging before production deployment
- SQLite auto-migrations are **disabled in production** - use Alembic only
- In development, SQLite auto-migrations still work for convenience
