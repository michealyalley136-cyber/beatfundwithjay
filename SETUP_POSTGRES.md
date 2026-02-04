# PostgreSQL Setup Guide

## Quick Setup

### 1. Install PostgreSQL

**Windows:**
- Download from https://www.postgresql.org/download/windows/
- Or use Chocolatey: `choco install postgresql`

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
```

### 2. Create Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE beatfund;

# Create user (optional, or use existing postgres user)
CREATE USER beatfund_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE beatfund TO beatfund_user;

# Exit
\q
```

### 3. Set Environment Variable

**Windows (PowerShell):**
```powershell
$env:DATABASE_URL="postgresql://beatfund_user:your_password@localhost:5432/beatfund"
```

**Windows (CMD):**
```cmd
set DATABASE_URL=postgresql://beatfund_user:your_password@localhost:5432/beatfund
```

**macOS/Linux:**
```bash
export DATABASE_URL="postgresql://beatfund_user:your_password@localhost:5432/beatfund"
```

**Or create a `.env` file:**
```
DATABASE_URL=postgresql://beatfund_user:your_password@localhost:5432/beatfund
```

### 4. Install Dependencies

The `psycopg2-binary` package is already in `requirements.txt`. Install it:

```bash
pip install -r requirements.txt
```

### 5. Initialize Database

Run the migration script to create the `studio_availability` table:

```bash
python migrate_studio_availability.py
```

Or initialize all tables:

```bash
python init_db.py
```

### 6. Verify Connection

Test the connection:

```python
from app import app, db
with app.app_context():
    print(f"Connected to: {db.engine.url}")
    print(f"Tables: {db.engine.table_names()}")
```

## Troubleshooting

### Connection Error
- Make sure PostgreSQL is running: `sudo systemctl status postgresql` (Linux) or check Services (Windows)
- Verify credentials in DATABASE_URL
- Check firewall settings if connecting remotely

### Table Already Exists
- The migration script will skip creation if the table exists
- To recreate, drop the table first: `DROP TABLE studio_availability;`

### Permission Denied
- Make sure the database user has proper permissions
- Grant privileges: `GRANT ALL PRIVILEGES ON DATABASE beatfund TO beatfund_user;`

## Production (Render/Heroku)

For production deployments, the `DATABASE_URL` environment variable is usually set automatically by the platform. The app will automatically detect and use it.

