"""
Migration script to add lock columns to project_vault table
Works with both SQLite and PostgreSQL
"""
from app import app, db
from sqlalchemy import text, inspect

def migrate_vault_lock():
    """Add lock columns to project_vault table"""
    with app.app_context():
        try:
            # Detect database type
            db_type = db.engine.url.get_backend_name()
            print(f"Database type: {db_type}")
            
            # Check if columns already exist
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('project_vault')]
            
            print("Existing columns:", columns)
            
            # PostgreSQL uses different syntax for boolean defaults
            if db_type == 'postgresql':
                bool_default = "FALSE"
                bool_type = "BOOLEAN"
            else:  # SQLite
                bool_default = "0"
                bool_type = "BOOLEAN"
            
            # Add is_locked column if it doesn't exist
            if 'is_locked' not in columns:
                print("Adding is_locked column...")
                if db_type == 'postgresql':
                    db.session.execute(text(f"ALTER TABLE project_vault ADD COLUMN is_locked {bool_type} NOT NULL DEFAULT {bool_default}"))
                else:
                    db.session.execute(text(f"ALTER TABLE project_vault ADD COLUMN is_locked {bool_type} NOT NULL DEFAULT {bool_default}"))
                db.session.commit()
                print("✅ Added is_locked column")
            else:
                print("✓ is_locked column already exists")
            
            # Add lock_until_date column if it doesn't exist
            if 'lock_until_date' not in columns:
                print("Adding lock_until_date column...")
                if db_type == 'postgresql':
                    db.session.execute(text("ALTER TABLE project_vault ADD COLUMN lock_until_date TIMESTAMP"))
                else:
                    db.session.execute(text("ALTER TABLE project_vault ADD COLUMN lock_until_date DATETIME"))
                db.session.commit()
                print("✅ Added lock_until_date column")
            else:
                print("✓ lock_until_date column already exists")
            
            # Add lock_until_goal column if it doesn't exist
            if 'lock_until_goal' not in columns:
                print("Adding lock_until_goal column...")
                if db_type == 'postgresql':
                    db.session.execute(text(f"ALTER TABLE project_vault ADD COLUMN lock_until_goal {bool_type} NOT NULL DEFAULT {bool_default}"))
                else:
                    db.session.execute(text(f"ALTER TABLE project_vault ADD COLUMN lock_until_goal {bool_type} NOT NULL DEFAULT {bool_default}"))
                db.session.commit()
                print("✅ Added lock_until_goal column")
            else:
                print("✓ lock_until_goal column already exists")
            
            print("\n✅ Migration completed successfully!")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error during migration: {e}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == "__main__":
    print("=" * 60)
    print("Migrating project_vault table - adding lock columns")
    print("=" * 60)
    migrate_vault_lock()
    print("=" * 60)

