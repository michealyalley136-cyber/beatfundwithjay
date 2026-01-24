"""
Check what tables exist in the PostgreSQL database
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db
from sqlalchemy import inspect, text

with app.app_context():
    print("=" * 60)
    print("PostgreSQL Database Tables Check")
    print("=" * 60)
    
    # Check database backend
    backend = db.engine.url.get_backend_name()
    print(f"\nDatabase Backend: {backend}")
    
    if backend != "postgresql":
        print("⚠️  This script is for PostgreSQL. Current database is not PostgreSQL.")
        exit(1)
    
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        print(f"\nFound {len(tables)} table(s):")
        for table in sorted(tables):
            print(f"  - {table}")
        
        # Check specifically for user table variations
        print("\n" + "-" * 60)
        print("Checking for 'user' table variations:")
        print("-" * 60)
        
        user_variants = [t for t in tables if 'user' in t.lower()]
        if user_variants:
            print("Found user-related tables:")
            for variant in user_variants:
                print(f"  ✅ {variant}")
        else:
            print("  ❌ No 'user' table found!")
        
        # Check if "user" table exists (case-sensitive)
        if "user" in tables:
            print("\n✅ Table 'user' exists (lowercase)")
        elif "User" in tables:
            print("\n⚠️  Table 'User' exists (capitalized) - this might cause issues")
        else:
            print("\n❌ Table 'user' does not exist")
            print("\n💡 You may need to:")
            print("   1. Run migrations: flask db upgrade")
            print("   2. Or initialize: python init_db.py")
            print("   3. Or bootstrap: BOOTSTRAP_DB=1 python app.py")
        
        # Try to query the user table directly
        print("\n" + "-" * 60)
        print("Testing direct query on 'user' table:")
        print("-" * 60)
        try:
            with db.engine.connect() as conn:
                # Try different table name variations
                for table_name in ["user", '"user"', "users", '"users"']:
                    try:
                        result = conn.execute(text(f'SELECT COUNT(*) FROM {table_name}'))
                        count = result.fetchone()[0]
                        print(f"  ✅ {table_name}: {count} row(s)")
                        break
                    except Exception as e:
                        print(f"  ❌ {table_name}: {str(e)[:80]}")
                        continue
        except Exception as e:
            print(f"  ❌ Query failed: {e}")
        
        # Check schema
        print("\n" + "-" * 60)
        print("Checking schema:")
        print("-" * 60)
        try:
            with db.engine.connect() as conn:
                result = conn.execute(text("SELECT current_schema()"))
                schema = result.fetchone()[0]
                print(f"  Current schema: {schema}")
                
                # List all schemas
                result = conn.execute(text("""
                    SELECT schema_name 
                    FROM information_schema.schemata 
                    WHERE schema_name NOT IN ('pg_catalog', 'information_schema')
                """))
                schemas = [row[0] for row in result]
                print(f"  Available schemas: {', '.join(schemas)}")
        except Exception as e:
            print(f"  ⚠️  Could not check schema: {e}")
            
    except Exception as e:
        print(f"\n❌ Error inspecting database: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)

