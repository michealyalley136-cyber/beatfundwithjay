"""
Check password expiration status for users
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User, is_password_expired
from datetime import datetime, timedelta

with app.app_context():
    print("=" * 60)
    print("Password Expiration Check")
    print("=" * 60)
    
    users = User.query.all()
    
    for user in users:
        print(f"\nUser: {user.username} (ID: {user.id})")
        print(f"  Role: {user.role.value if user.role else 'None'}")
        print(f"  Password Changed At: {user.password_changed_at}")
        
        if user.password_changed_at:
            age = datetime.utcnow() - user.password_changed_at
            print(f"  Password Age: {age.days} days")
        else:
            print(f"  Password Age: Never set (None)")
        
        is_expired = is_password_expired(user)
        print(f"  Is Expired: {'⚠️ YES' if is_expired else '✅ NO'}")
        
        if is_expired and user.role.value == 'admin':
            print(f"  ⚠️  Admin password is expired - user will be redirected to password reset after login")
    
    print("\n" + "=" * 60)

