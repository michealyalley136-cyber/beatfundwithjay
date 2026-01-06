"""
Initialize database - creates all tables defined in models
Works with both SQLite and PostgreSQL
"""
from app import app, db
from sqlalchemy import inspect

def get_existing_tables():
    """Get list of existing tables"""
    try:
        inspector = inspect(db.engine)
        return set(inspector.get_table_names())
    except Exception:
        return set()

def init_database():
    """Create all database tables"""
    with app.app_context():
        db_type = db.engine.url.get_backend_name()
        print(f"Database type: {db_type}")
        print(f"Database URL: {db.engine.url}")
        
        existing_tables = get_existing_tables()
        print(f"Existing tables: {len(existing_tables)}")
        
        # Create all tables
        db.create_all()
        
        new_tables = get_existing_tables()
        created_tables = new_tables - existing_tables
        
        if created_tables:
            print(f"✅ Created {len(created_tables)} new table(s): {', '.join(created_tables)}")
        else:
            print("✅ All tables already exist. Database is up to date.")
        
        print("Database initialization completed successfully!")

if __name__ == "__main__":
    print("=" * 60)
    print("Initializing database...")
    print("=" * 60)
    init_database()
    print("=" * 60)