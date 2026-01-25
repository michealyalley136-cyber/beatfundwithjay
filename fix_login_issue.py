"""
Diagnostic and fix script for login issues
This script will:
1. Check all users in the database
2. Verify password hashes are valid
3. Test login logic
4. Optionally reset passwords for users
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func

def test_user_login(username_or_email: str, password: str) -> tuple[bool, str]:
    """Test if a user can login with given credentials"""
    identifier = username_or_email.lower().strip()
    
    if "@" in identifier and "." in identifier:
        user = User.query.filter(func.lower(User.email) == identifier).first()
        lookup_type = "email"
    else:
        handle = identifier.lstrip("@")
        user = User.query.filter(func.lower(User.username) == handle).first()
        lookup_type = "username"
    
    if not user:
        return False, f"User not found (lookup by {lookup_type})"
    
    if not user.password_hash:
        return False, "User has no password hash"
    
    if not user.check_password(password):
        return False, "Password does not match"
    
    if not user.is_active_col:
        return False, "User account is disabled"
    
    return True, "Login would succeed"

def reset_user_password(username_or_email: str, new_password: str) -> tuple[bool, str]:
    """Reset a user's password"""
    identifier = username_or_email.lower().strip()
    
    if "@" in identifier and "." in identifier:
        user = User.query.filter(func.lower(User.email) == identifier).first()
    else:
        handle = identifier.lstrip("@")
        user = User.query.filter(func.lower(User.username) == handle).first()
    
    if not user:
        return False, "User not found"
    
    user.set_password(new_password)
    db.session.commit()
    return True, f"Password reset successfully for {user.username}"

with app.app_context():
    print("=" * 60)
    print("Login Issue Diagnostic & Fix Tool")
    print("=" * 60)
    
    # List all users
    users = User.query.all()
    print(f"\nFound {len(users)} user(s) in database:\n")
    
    for user in users:
        print(f"ID: {user.id}")
        print(f"  Username: {user.username}")
        print(f"  Email: {user.email}")
        print(f"  Role: {user.role.value if user.role else 'None'}")
        print(f"  Is Active: {user.is_active_col}")
        print(f"  Has Password Hash: {bool(user.password_hash)}")
        if user.password_hash:
            print(f"  Password Hash Length: {len(user.password_hash)}")
            print(f"  Password Hash Prefix: {user.password_hash[:20]}...")
        
        # Test with common passwords
        print("  Testing common passwords:")
        for test_pw in ['admin123', 'password', 'admin', 'test123']:
            if user.password_hash:
                if check_password_hash(user.password_hash, test_pw):
                    print(f"    ✅ '{test_pw}' matches!")
                else:
                    print(f"    ❌ '{test_pw}' does not match")
        print()
    
    # Interactive mode
    print("=" * 60)
    print("Interactive Testing")
    print("=" * 60)
    print("\nYou can test login credentials or reset passwords.")
    print("Example commands:")
    print("  test admin admin123")
    print("  reset admin newpassword123")
    print("  quit")
    print()
    
    while True:
        try:
            command = input("Enter command (or 'quit' to exit): ").strip()
            if not command or command.lower() == 'quit':
                break
            
            parts = command.split(None, 2)
            if len(parts) < 2:
                print("Invalid command. Use: test <username> <password> or reset <username> <newpassword>")
                continue
            
            action = parts[0].lower()
            username = parts[1]
            password = parts[2] if len(parts) > 2 else ""
            
            if action == "test":
                if not password:
                    print("Please provide a password to test")
                    continue
                success, message = test_user_login(username, password)
                if success:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")
            
            elif action == "reset":
                if not password:
                    print("Please provide a new password")
                    continue
                success, message = reset_user_password(username, password)
                if success:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")
            
            else:
                print("Unknown command. Use 'test' or 'reset'")
        
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    print("\n" + "=" * 60)
    print("Done")
    print("=" * 60)

