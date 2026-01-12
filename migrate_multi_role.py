"""
Migration script to add multi-role support
Works with both SQLite and PostgreSQL
"""
from app import app, db, User, UserRole, RoleEnum
from sqlalchemy import text, inspect
from datetime import datetime

def migrate_multi_role():
    """Migrate from single role to multi-role system"""
    with app.app_context():
        try:
            # Detect database type
            db_type = db.engine.url.get_backend_name()
            print(f"Database type: {db_type}")
            
            inspector = inspect(db.engine)
            
            # Check if primary_role column exists
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            print(f"Existing user columns: {user_columns}")
            
            # Step 1: Add primary_role column if it doesn't exist
            if 'primary_role' not in user_columns:
                print("Adding primary_role column...")
                if db_type == 'postgresql':
                    db.session.execute(text("ALTER TABLE \"user\" ADD COLUMN primary_role roleenum"))
                else:  # SQLite
                    db.session.execute(text("ALTER TABLE user ADD COLUMN primary_role VARCHAR(50)"))
                db.session.commit()
                print("✅ Added primary_role column")
            else:
                print("✓ primary_role column already exists")
            
            # Step 2: Copy existing role values to primary_role
            print("Copying existing role values to primary_role...")
            if db_type == 'postgresql':
                db.session.execute(text("UPDATE \"user\" SET primary_role = role::text::roleenum WHERE primary_role IS NULL"))
            else:  # SQLite - need to handle enum as string
                # Get all users and update in Python
                users = User.query.all()
                for user in users:
                    if not user.primary_role:
                        # Try to get role value
                        if hasattr(user, 'role') and user.role:
                            try:
                                user.primary_role = user.role if isinstance(user.role, RoleEnum) else RoleEnum(str(user.role))
                            except (ValueError, TypeError):
                                user.primary_role = RoleEnum.artist
                        else:
                            user.primary_role = RoleEnum.artist
                db.session.commit()
            print("✅ Copied role values to primary_role")
            
            # Step 3: Check if user_role table exists
            tables = inspector.get_table_names()
            if 'user_role' not in tables:
                print("Creating user_role table...")
                # Create table using SQLAlchemy
                UserRole.__table__.create(db.engine)
                print("✅ Created user_role table")
            else:
                print("✓ user_role table already exists")
            
            # Step 4: Migrate existing roles to user_role table
            print("Migrating existing roles to user_role table...")
            users = User.query.all()
            migrated_count = 0
            for user in users:
                if user.primary_role:
                    # Check if this role already exists in user_role
                    existing = UserRole.query.filter_by(user_id=user.id, role=user.primary_role).first()
                    if not existing:
                        user_role = UserRole(user_id=user.id, role=user.primary_role)
                        db.session.add(user_role)
                        migrated_count += 1
            db.session.commit()
            print(f"✅ Migrated {migrated_count} user roles to user_role table")
            
            # Step 5: Set NOT NULL constraint on primary_role (PostgreSQL only)
            if db_type == 'postgresql':
                print("Setting NOT NULL constraint on primary_role...")
                try:
                    db.session.execute(text("ALTER TABLE \"user\" ALTER COLUMN primary_role SET NOT NULL"))
                    db.session.commit()
                    print("✅ Set NOT NULL constraint on primary_role")
                except Exception as e:
                    print(f"⚠️  Could not set NOT NULL constraint (may already be set): {e}")
            
            print("\n✅ Migration completed successfully!")
            print("\nNote: The old 'role' column is kept for backwards compatibility.")
            print("You can drop it later after verifying everything works correctly.")
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error during migration: {e}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == "__main__":
    print("=" * 60)
    print("Migrating to multi-role system")
    print("=" * 60)
    migrate_multi_role()
    print("=" * 60)

