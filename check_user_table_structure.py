"""
Check the structure of the user table in PostgreSQL
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db
from sqlalchemy import text

with app.app_context():
    print("=" * 60)
    print("User Table Structure Check")
    print("=" * 60)
    
    try:
        with db.engine.connect() as conn:
            # Get table columns
            print("\n1. Table Columns:")
            result = conn.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_name = 'user' AND table_schema = 'public'
                ORDER BY ordinal_position
            """))
            columns = result.fetchall()
            if columns:
                print(f"   Found {len(columns)} column(s):")
                for col in columns:
                    nullable = "NULL" if col[2] == "YES" else "NOT NULL"
                    default = f" DEFAULT {col[3]}" if col[3] else ""
                    print(f"     - {col[0]}: {col[1]} {nullable}{default}")
            else:
                print("   ❌ No columns found!")
            
            # Check if table exists in public schema
            print("\n2. Table Existence Check:")
            result = conn.execute(text("""
                SELECT table_name, table_schema
                FROM information_schema.tables
                WHERE table_name = 'user'
            """))
            tables = result.fetchall()
            if tables:
                for table in tables:
                    print(f"   ✅ Found: {table[1]}.{table[0]}")
            else:
                print("   ❌ Table not found in information_schema")
            
            # Try to get row count
            print("\n3. Row Count:")
            result = conn.execute(text('SELECT COUNT(*) FROM "user"'))
            count = result.fetchone()[0]
            print(f"   ✅ {count} row(s) in user table")
            
            # Check for username column specifically
            print("\n4. Username Column Check:")
            result = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'user' 
                AND table_schema = 'public'
                AND column_name = 'username'
            """))
            username_col = result.fetchone()
            if username_col:
                print(f"   ✅ username column exists")
            else:
                print("   ❌ username column not found!")
            
            # Test the exact query that's failing
            print("\n5. Testing the Failing Query:")
            try:
                result = conn.execute(text("""
                    SELECT id, username, email
                    FROM "user"
                    WHERE lower(username) = lower(:username)
                    LIMIT 1
                """), {"username": "artist1"})
                row = result.fetchone()
                if row:
                    print(f"   ✅ Query succeeded! Found user: {row[1]}")
                else:
                    print("   ✅ Query succeeded but no user found with username 'artist1'")
            except Exception as e:
                print(f"   ❌ Query failed: {e}")
                
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)

