"""
Diagnostic script to check users in database and test password verification
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from werkzeug.security import check_password_hash

with app.app_context():
    print("=" * 60)
    print("Database User Check")
    print("=" * 60)
    
    # Get all users
    users = User.query.all()
    print(f"\nTotal users in database: {len(users)}")
    
    if len(users) == 0:
        print("\n⚠️  No users found in database!")
        print("You may need to run create_admin.py or register a user.")
    else:
        print("\n" + "=" * 60)
        print("User Details:")
        print("=" * 60)
        
        for user in users:
            print(f"\nUser ID: {user.id}")
            print(f"  Username: {user.username}")
            print(f"  Email: {user.email}")
            print(f"  Role: {user.role if user.role else 'None'}")
            print(f"  Is Active: {user.is_active_col}")
            print(f"  Password Hash: {user.password_hash[:50] if user.password_hash else 'None'}...")
            print(f"  Password Hash Length: {len(user.password_hash) if user.password_hash else 0}")
            
            # Check if password_hash is None or empty
            if not user.password_hash:
                print("  ⚠️  WARNING: Password hash is None or empty!")
            elif len(user.password_hash) < 10:
                print("  ⚠️  WARNING: Password hash seems too short!")
            
            # Test password check with common passwords
            test_passwords = ['admin123', 'password', 'admin', 'test123']
            print("  Testing common passwords:")
            for test_pw in test_passwords:
                try:
                    if user.password_hash:
                        result = check_password_hash(user.password_hash, test_pw)
                        if result:
                            print(f"    ✅ '{test_pw}' matches!")
                        else:
                            print(f"    ❌ '{test_pw}' does not match")
                    else:
                        print(f"    ⚠️  Cannot test - no password hash")
                except Exception as e:
                    print(f"    ⚠️  Error testing '{test_pw}': {e}")
    
    print("\n" + "=" * 60)
    print("Database Check Complete")
    print("=" * 60)

