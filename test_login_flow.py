"""
Test the exact login flow with sanitization
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from sqlalchemy import func

def sanitize_input(value: str, max_length: int = 5000) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not isinstance(value, str):
        return ""
    # Remove null bytes and control characters
    cleaned = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
    # Limit length
    return cleaned[:max_length].strip()

# Simulate form data
test_cases = [
    {"username": "admin", "password": "admin123"},
    {"username": "admin@beatfund.com", "password": "admin123"},
    {"username": " admin ", "password": "admin123"},
    {"username": "admin", "password": " admin123 "},
    {"username": "admin", "password": "admin123\n"},
]

with app.app_context():
    print("=" * 60)
    print("Testing Login Flow (with sanitization)")
    print("=" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i} ---")
        print(f"Input - username: '{test_case['username']}', password: '{test_case['password']}'")
        
        # Simulate the login function logic
        raw_identifier = test_case['username'].strip()
        password = test_case['password'].strip()
        
        print(f"After initial strip - identifier: '{raw_identifier}', password: '{password}'")
        
        # Sanitize (as in login function)
        raw_identifier = sanitize_input(raw_identifier, max_length=255)
        password = sanitize_input(password, max_length=500)
        
        print(f"After sanitize - identifier: '{raw_identifier}', password: '{password}'")
        
        if not raw_identifier or not password:
            print("❌ Empty after sanitization!")
            continue
        
        identifier = raw_identifier.lower().strip()
        
        # Find user
        if "@" in identifier and "." in identifier:
            user = User.query.filter(func.lower(User.email) == identifier).first()
            lookup_type = "email"
        else:
            handle = identifier.lstrip("@")
            user = User.query.filter(func.lower(User.username) == handle).first()
            lookup_type = "username"
        
        if not user:
            print(f"❌ User not found (lookup by {lookup_type})")
            continue
        
        print(f"✅ User found: {user.username} (ID: {user.id})")
        
        # Check password
        print(f"Testing password check with: '{password}'")
        print(f"Password length: {len(password)}")
        print(f"Password bytes: {password.encode('utf-8')}")
        
        if user.check_password(password):
            print("✅ Password check PASSED")
        else:
            print("❌ Password check FAILED")
            # Try with original password
            if user.check_password(test_case['password']):
                print("   ⚠️  But original password works! Sanitization may have modified it.")
            else:
                print("   ⚠️  Original password also doesn't work.")
    
    print("\n" + "=" * 60)

