"""
Test Neon Postgres database connection.
This script verifies the database connection is working correctly.
"""
from dotenv import load_dotenv
load_dotenv()

import os
from app import app, db, test_database_connection
from sqlalchemy import text, inspect
from sqlalchemy.exc import SQLAlchemyError

def main():
    print("=" * 60)
    print("Neon Postgres Connection Test")
    print("=" * 60)
    
    # Check if DATABASE_URL is set
    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        print("\n⚠️  DATABASE_URL not set. Using SQLite fallback.")
        print("   To use Neon Postgres, set DATABASE_URL in your .env file.")
    else:
        # Mask password for display
        from urllib.parse import urlparse, urlunparse
        try:
            parsed = urlparse(db_url)
            safe_url = urlunparse(parsed._replace(password="***"))
            print(f"\n📋 Database URL: {safe_url}")
            if "neon.tech" in db_url.lower():
                print("   ✅ Neon Postgres detected")
            else:
                print("   ℹ️  Non-Neon database (SSL may not be required)")
        except Exception:
            print(f"\n📋 Database URL: (configured)")
    
    with app.app_context():
        # Test 1: Basic connection
        print("\n" + "-" * 60)
        print("Test 1: Basic Connection")
        print("-" * 60)
        success, message = test_database_connection()
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
            print("\n💡 Troubleshooting tips:")
            print("   - Verify DATABASE_URL is correct")
            print("   - Check database name exists")
            print("   - Verify user has proper permissions")
            print("   - Ensure SSL is enabled (required for Neon)")
            return
        
        # Test 2: Database info
        print("\n" + "-" * 60)
        print("Test 2: Database Information")
        print("-" * 60)
        try:
            db_name = db.engine.url.database
            db_user = db.engine.url.username
            db_host = db.engine.url.host
            db_port = db.engine.url.port
            db_backend = db.engine.url.get_backend_name()
            
            print(f"Backend: {db_backend}")
            print(f"Host: {db_host}")
            print(f"Port: {db_port}")
            print(f"Database: {db_name}")
            print(f"User: {db_user}")
            
            # Check SSL mode
            connect_args = app.config.get("SQLALCHEMY_ENGINE_OPTIONS", {}).get("connect_args", {})
            ssl_mode = connect_args.get("sslmode", "not set")
            if ssl_mode != "not set":
                print(f"SSL Mode: {ssl_mode}")
        except Exception as e:
            print(f"⚠️  Could not get database info: {e}")
        
        # Test 3: Query database version
        print("\n" + "-" * 60)
        print("Test 3: Database Version Query")
        print("-" * 60)
        try:
            with db.engine.connect() as conn:
                if db_backend == "postgresql":
                    result = conn.execute(text("SELECT version()"))
                    version = result.fetchone()[0]
                    print(f"✅ PostgreSQL version: {version[:50]}...")
                else:
                    result = conn.execute(text("SELECT sqlite_version()"))
                    version = result.fetchone()[0]
                    print(f"✅ SQLite version: {version}")
        except Exception as e:
            print(f"❌ Query failed: {e}")
        
        # Test 4: List tables
        print("\n" + "-" * 60)
        print("Test 4: Existing Tables")
        print("-" * 60)
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            if tables:
                print(f"✅ Found {len(tables)} table(s):")
                for table in sorted(tables)[:10]:  # Show first 10
                    print(f"   - {table}")
                if len(tables) > 10:
                    print(f"   ... and {len(tables) - 10} more")
            else:
                print("⚠️  No tables found. Run migrations or db.create_all()")
        except Exception as e:
            print(f"⚠️  Could not list tables: {e}")
        
        # Test 5: Test transaction
        print("\n" + "-" * 60)
        print("Test 5: Transaction Test")
        print("-" * 60)
        try:
            with db.engine.connect() as conn:
                trans = conn.begin()
                try:
                    result = conn.execute(text("SELECT 1 as test"))
                    test_value = result.fetchone()[0]
                    trans.commit()
                    if test_value == 1:
                        print("✅ Transaction test passed")
                    else:
                        print(f"⚠️  Unexpected result: {test_value}")
                except Exception as e:
                    trans.rollback()
                    raise
        except Exception as e:
            print(f"❌ Transaction test failed: {e}")
    
    print("\n" + "=" * 60)
    print("Connection Test Complete")
    print("=" * 60)
    print("\n💡 Next steps:")
    print("   - If all tests passed, your database is ready!")
    print("   - Run migrations: flask db upgrade (if using Flask-Migrate)")
    print("   - Or initialize tables: python init_db.py")
    print("=" * 60)

if __name__ == "__main__":
    main()

