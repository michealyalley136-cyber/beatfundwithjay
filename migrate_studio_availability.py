"""
Migration script to create studio_availability table
Run this script to add the new table to your database.

Usage:
    # For PostgreSQL (set DATABASE_URL environment variable):
    export DATABASE_URL="postgresql://user:password@localhost:5432/beatfund"
    python migrate_studio_availability.py
    
    # Or for SQLite (default):
    python migrate_studio_availability.py
"""
from app import app, db
from sqlalchemy import inspect, text

def table_exists(table_name: str) -> bool:
    """Check if a table exists in the database"""
    try:
        inspector = inspect(db.engine)
        return table_name in inspector.get_table_names()
    except Exception as e:
        print(f"Error checking table existence: {e}")
        return False

def create_studio_availability_table():
    """Create the studio_availability table if it doesn't exist"""
    with app.app_context():
        db_type = db.engine.url.get_backend_name()
        print(f"Database type: {db_type}")
        
        if table_exists("studio_availability"):
            print("✅ Table 'studio_availability' already exists. Skipping creation.")
            return
        
        try:
            # Create the table using SQLAlchemy
            from app import StudioAvailability
            StudioAvailability.__table__.create(db.engine, checkfirst=True)
            db.session.commit()
            print("✅ Table 'studio_availability' created successfully!")
        except Exception as e:
            print(f"❌ Error creating table: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    print("=" * 60)
    print("Migration: Creating studio_availability table")
    print("=" * 60)
    create_studio_availability_table()
    print("=" * 60)
    print("Migration completed!")
    print("=" * 60)

