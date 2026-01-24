"""
Check for users with NULL or invalid password hashes
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from sqlalchemy import or_

with app.app_context():
    print("=" * 60)
    print("Checking Password Hashes")
    print("=" * 60)
    
    # Check for users with NULL or empty password_hash
    users_without_hash = User.query.filter(
        or_(
            User.password_hash == None,
            User.password_hash == "",
            User.password_hash.is_(None)
        )
    ).all()
    
    if users_without_hash:
        print(f"\n⚠️  Found {len(users_without_hash)} user(s) with NULL or empty password_hash:")
        for user in users_without_hash:
            print(f"  - ID: {user.id}, Username: {user.username}, Email: {user.email}")
    else:
        print("\n✅ All users have password hashes")
    
    # Check all users
    all_users = User.query.all()
    print(f"\nTotal users: {len(all_users)}")
    
    for user in all_users:
        print(f"\nUser: {user.username} (ID: {user.id})")
        print(f"  Email: {user.email}")
        print(f"  Password Hash: {'✅ Present' if user.password_hash else '❌ MISSING'}")
        if user.password_hash:
            print(f"  Hash Length: {len(user.password_hash)}")
            print(f"  Hash Format: {user.password_hash.split(':')[0] if ':' in user.password_hash else 'Unknown'}")
            
            # Try to check if it's a valid hash format
            if not user.password_hash.startswith(('pbkdf2:', 'scrypt:', 'argon2:', 'bcrypt:')):
                print(f"  ⚠️  WARNING: Password hash format looks unusual!")
    
    print("\n" + "=" * 60)

