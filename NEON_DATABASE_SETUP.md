# Neon Postgres Database Setup

This guide explains how to connect your Flask app to a Neon Postgres database.

## Configuration Summary

The app is now configured to:
- ✅ Automatically detect Neon databases and enable SSL
- ✅ Normalize database URLs to use `postgresql+psycopg2://`
- ✅ Provide helpful error messages for common connection issues
- ✅ Test connections on startup (dev mode)
- ✅ Fall back to SQLite if DATABASE_URL is not set

## Environment Variable

Add to your `.env` file:

```bash
# Neon Postgres (Direct Connection - NOT pooler URL)
DATABASE_URL=postgresql://username:password@ep-xxxx-xxxx.us-east-2.aws.neon.tech/dbname?sslmode=require
```

### Format Breakdown

```
postgresql://[username]:[password]@[host]/[database]?sslmode=require
```

**Important Notes:**
- Use **direct connection URLs** (not pooler URLs)
- The `?sslmode=require` parameter is optional - the app adds it automatically for Neon
- Username and password come from your Neon dashboard
- Host format: `ep-xxxx-xxxx.region.aws.neon.tech`
- Database name is set when you create the database in Neon

## SQLAlchemy Configuration

The configuration in `app.py` handles:

1. **URL Normalization**: Converts `postgres://` → `postgresql+psycopg2://`
2. **SSL Detection**: Automatically detects Neon databases and enables SSL
3. **Connection Pooling**: Configured for production use
4. **Error Handling**: Provides specific error messages for common issues

### Key Configuration Block

```python
# Automatically normalizes URL format
db_url = normalize_database_url(os.getenv("DATABASE_URL"))

# Detects Neon and enables SSL
if "neon.tech" in db_url.lower():
    engine_options["connect_args"]["sslmode"] = "require"

# Connection pool settings
engine_options = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 5,
    "max_overflow": 10,
    "connect_args": {
        "connect_timeout": 10,
        "sslmode": "require"  # For Neon
    }
}
```

## Testing the Connection

### Quick Test

```bash
python test_neon_connection.py
```

This script will:
- ✅ Test basic connectivity
- ✅ Show database information
- ✅ Query database version
- ✅ List existing tables
- ✅ Test transactions

### Manual Test

```python
from app import app, db, test_database_connection

with app.app_context():
    success, message = test_database_connection()
    print(f"{'✅' if success else '❌'} {message}")
```

## Common Errors and Solutions

### `sqlalchemy.exc.ProgrammingError: database "xxx" does not exist`

**Solution**: Create the database in Neon dashboard or use the correct database name.

```sql
-- In Neon SQL editor or psql
CREATE DATABASE your_database_name;
```

### `sqlalchemy.exc.ProgrammingError: permission denied for schema public`

**Solution**: Grant proper permissions to your database user.

```sql
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_username;
GRANT ALL ON SCHEMA public TO your_username;
```

### `sqlalchemy.exc.OperationalError: could not connect to server`

**Solutions**:
1. Verify DATABASE_URL is correct
2. Check network connectivity
3. Ensure you're using direct connection (not pooler)
4. Verify SSL is enabled (automatic for Neon)

### `sqlalchemy.exc.OperationalError: SSL connection required`

**Solution**: The app automatically adds SSL for Neon. If you see this:
1. Verify your URL contains `neon.tech`
2. Check that `sslmode=require` is in the URL or connect_args

### Missing Tables Error

**Solution**: Initialize the database schema.

```bash
# Option 1: Using Flask-Migrate (recommended)
flask db upgrade

# Option 2: Using init script
python init_db.py

# Option 3: Manual bootstrap
BOOTSTRAP_DB=1 python app.py
```

## Flask-Migrate Compatibility

The configuration is fully compatible with Flask-Migrate:

```bash
# Initialize migrations (first time)
flask db init

# Create migration
flask db migrate -m "Description"

# Apply migration
flask db upgrade

# Rollback
flask db downgrade
```

## Production Checklist

- [ ] DATABASE_URL is set in production environment
- [ ] Using direct Neon connection (not pooler)
- [ ] SSL is enabled (automatic for Neon)
- [ ] Database user has proper permissions
- [ ] All tables are created (via migrations)
- [ ] Connection pooling is configured (already done)
- [ ] Error logging is enabled (already done)

## Security Notes

1. **Never commit `.env` files** - They contain sensitive credentials
2. **Use environment variables** - Never hardcode database URLs
3. **SSL is required** - Neon requires encrypted connections
4. **Connection pooling** - Configured to prevent connection exhaustion
5. **Password masking** - Logs mask passwords automatically

## Troubleshooting

### Check Current Configuration

```python
from app import app, db

with app.app_context():
    print(f"Database: {db.engine.url}")
    print(f"Backend: {db.engine.url.get_backend_name()}")
    print(f"SSL Mode: {app.config['SQLALCHEMY_ENGINE_OPTIONS']['connect_args'].get('sslmode')}")
```

### Verify Connection

```python
from app import app, db, test_database_connection

with app.app_context():
    success, message = test_database_connection()
    print(message)
```

### View Connection Pool Status

```python
from app import app, db

with app.app_context():
    pool = db.engine.pool
    print(f"Pool size: {pool.size()}")
    print(f"Checked out: {pool.checkedout()}")
    print(f"Overflow: {pool.overflow()}")
```

## Example .env File

```bash
# Flask
FLASK_ENV=development
APP_BASE_URL=http://localhost:5000

# Database - Neon Postgres
DATABASE_URL=postgresql://myuser:mypassword@ep-cool-name-123456.us-east-2.aws.neon.tech/beatfund?sslmode=require

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Other variables...
```

## Support

If you encounter issues:
1. Run `python test_neon_connection.py` to diagnose
2. Check application logs for detailed error messages
3. Verify DATABASE_URL format matches the examples above
4. Ensure database exists and user has permissions

