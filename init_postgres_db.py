"""
Initialize PostgreSQL database with all tables.
This script creates all tables defined in SQLAlchemy models.
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db
from sqlalchemy import inspect

def init_postgres_database():
    """Create all database tables in PostgreSQL"""
    with app.app_context():
        backend = db.engine.url.get_backend_name()
        print("=" * 60)
        print("PostgreSQL Database Initialization")
        print("=" * 60)
        print(f"\nDatabase Backend: {backend}")
        
        if backend != "postgresql":
            print("⚠️  Warning: This script is for PostgreSQL.")
            print(f"   Current database is: {backend}")
            response = input("   Continue anyway? (y/N): ")
            if response.lower() != 'y':
                print("Aborted.")
                return
        
        # Check existing tables
        try:
            inspector = inspect(db.engine)
            existing_tables = set(inspector.get_table_names())
            print(f"\nExisting tables: {len(existing_tables)}")
            if existing_tables:
                print("  " + ", ".join(sorted(existing_tables)[:10]))
                if len(existing_tables) > 10:
                    print(f"  ... and {len(existing_tables) - 10} more")
        except Exception as e:
            print(f"\n⚠️  Could not list existing tables: {e}")
            existing_tables = set()
        
        # Create all tables
        print("\n" + "-" * 60)
        print("Creating tables...")
        print("-" * 60)
        
        try:
            db.create_all()
            print("✅ db.create_all() completed")
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Verify tables were created
        print("\n" + "-" * 60)
        print("Verifying tables...")
        print("-" * 60)
        try:
            inspector = inspect(db.engine)
            new_tables = set(inspector.get_table_names())
            created_tables = new_tables - existing_tables
            
            if created_tables:
                print(f"✅ Created {len(created_tables)} new table(s):")
                for table in sorted(created_tables):
                    print(f"   - {table}")
            else:
                print("ℹ️  No new tables created (they may already exist)")
            
            # Check specifically for user table
            if "user" in new_tables:
                print("\n✅ 'user' table exists")
                
                # Check row count
                try:
                    with db.engine.connect() as conn:
                        from sqlalchemy import text
                        result = conn.execute(text('SELECT COUNT(*) FROM "user"'))
                        count = result.fetchone()[0]
                        print(f"   Row count: {count}")
                except Exception as e:
                    print(f"   ⚠️  Could not count rows: {e}")
            else:
                print("\n⚠️  'user' table not found after creation")
                print("   This might indicate a schema or permissions issue")
            
            print(f"\nTotal tables in database: {len(new_tables)}")
            
        except Exception as e:
            print(f"❌ Error verifying tables: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n" + "=" * 60)
        print("Database initialization complete!")
        print("=" * 60)
        print("\n💡 Next steps:")
        print("   - If using Flask-Migrate, run: flask db upgrade")
        print("   - Create admin user: python create_admin.py")
        print("   - Test connection: python test_neon_connection.py")

if __name__ == "__main__":
    init_postgres_database()

