"""
Migrate user data from SQLite to PostgreSQL
"""
import sqlite3
import os
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User

# Connect to SQLite database
sqlite_db_path = os.path.join('instance', 'app.db')
sqlite_conn = sqlite3.connect(sqlite_db_path)
sqlite_cursor = sqlite_conn.cursor()

# Get all users from SQLite
sqlite_cursor.execute('SELECT * FROM user')
users = sqlite_cursor.fetchall()

print(f"Found {len(users)} users in SQLite database")

with app.app_context():
    print("Migrating users to PostgreSQL...")

    for user_data in users:
        # Unpack user data (adjust indices based on your User model columns)
        user_id, username, email, full_name, artist_name, password_hash, role, kyc_status, is_active, is_superadmin, password_changed_at, password_reset_token, password_reset_sent_at, avatar_path, email_notifications_enabled, stripe_account_id = user_data

        # Check if user already exists in PostgreSQL
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"User {email} already exists, skipping...")
            continue

        # Create new user in PostgreSQL
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            artist_name=artist_name,
            password_hash=password_hash,
            role=role,
            kyc_status=kyc_status,
            is_active=is_active,
            is_superadmin=is_superadmin,
            password_changed_at=password_changed_at,
            password_reset_token=password_reset_token,
            password_reset_sent_at=password_reset_sent_at,
            avatar_path=avatar_path,
            email_notifications_enabled=email_notifications_enabled,
            stripe_account_id=stripe_account_id
        )

        db.session.add(new_user)
        print(f"Migrated user: {username} ({email})")

    db.session.commit()
    print("✅ User migration completed successfully!")

sqlite_conn.close()