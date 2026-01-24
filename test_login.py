"""
Test the login logic to see what's happening
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from sqlalchemy import func

# Test credentials
test_username = "admin"
test_email = "admin@beatfund.com"
test_password = "admin123"

with app.app_context():
    print("=" * 60)
    print("Testing Login Logic")
    print("=" * 60)
    
    # Test username lookup (as in login function)
    print(f"\n1. Testing username lookup: '{test_username}'")
    identifier = test_username.lower().strip()
    handle = identifier.lstrip("@")
    print(f"   Processed identifier: '{identifier}'")
    print(f"   Handle (after lstrip @): '{handle}'")
    
    user_by_username = User.query.filter(func.lower(User.username) == handle).first()
    if user_by_username:
        print(f"   ✅ Found user by username: {user_by_username.username} (ID: {user_by_username.id})")
        print(f"   Testing password check...")
        if user_by_username.check_password(test_password):
            print(f"   ✅ Password check PASSED")
        else:
            print(f"   ❌ Password check FAILED")
    else:
        print(f"   ❌ No user found by username")
    
    # Test email lookup (as in login function)
    print(f"\n2. Testing email lookup: '{test_email}'")
    identifier = test_email.lower().strip()
    print(f"   Processed identifier: '{identifier}'")
    
    if "@" in identifier and "." in identifier:
        user_by_email = User.query.filter(func.lower(User.email) == identifier).first()
        if user_by_email:
            print(f"   ✅ Found user by email: {user_by_email.email} (ID: {user_by_email.id})")
            print(f"   Testing password check...")
            if user_by_email.check_password(test_password):
                print(f"   ✅ Password check PASSED")
            else:
                print(f"   ❌ Password check FAILED")
        else:
            print(f"   ❌ No user found by email")
    else:
        print(f"   ⚠️  Identifier doesn't look like an email")
    
    # Test direct query
    print(f"\n3. Testing direct query (no func.lower):")
    user_direct = User.query.filter(User.username == test_username).first()
    if user_direct:
        print(f"   ✅ Found user directly: {user_direct.username}")
    else:
        print(f"   ❌ No user found directly")
    
    # Check password_hash field directly
    print(f"\n4. Checking password_hash field:")
    if user_by_username:
        print(f"   password_hash type: {type(user_by_username.password_hash)}")
        print(f"   password_hash is None: {user_by_username.password_hash is None}")
        print(f"   password_hash length: {len(user_by_username.password_hash) if user_by_username.password_hash else 0}")
        
        # Try check_password_hash directly
        from werkzeug.security import check_password_hash
        try:
            result = check_password_hash(user_by_username.password_hash, test_password)
            print(f"   Direct check_password_hash result: {result}")
        except Exception as e:
            print(f"   ⚠️  Error in check_password_hash: {e}")
    
    print("\n" + "=" * 60)

