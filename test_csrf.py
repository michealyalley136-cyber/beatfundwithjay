"""
Test CSRF token generation and session initialization
"""
from dotenv import load_dotenv
load_dotenv()

from app import app
from flask import session
from flask_wtf.csrf import generate_csrf

with app.app_context():
    print("=" * 60)
    print("CSRF Token Test")
    print("=" * 60)
    
    # Test 1: Check SECRET_KEY
    print("\n1. SECRET_KEY Check:")
    secret_key = app.config.get("SECRET_KEY")
    if secret_key:
        if secret_key == "dev-secret-change-me":
            print("   ⚠️  Using default dev SECRET_KEY (not secure for production)")
        else:
            print("   ✅ SECRET_KEY is set")
        print(f"   Length: {len(secret_key)} characters")
    else:
        print("   ❌ SECRET_KEY is not set!")
    
    # Test 2: Check CSRF configuration
    print("\n2. CSRF Configuration:")
    print(f"   WTF_CSRF_ENABLED: {app.config.get('WTF_CSRF_ENABLED', 'Not set')}")
    print(f"   WTF_CSRF_TIME_LIMIT: {app.config.get('WTF_CSRF_TIME_LIMIT', 'Not set')}")
    print(f"   WTF_CSRF_CHECK_DEFAULT: {app.config.get('WTF_CSRF_CHECK_DEFAULT', 'Not set')}")
    
    # Test 3: Test session initialization
    print("\n3. Session Test:")
    with app.test_request_context():
        # Simulate a request
        session.permanent = True
        session['_test'] = 'test_value'
        
        print(f"   Session permanent: {session.permanent}")
        print(f"   Session keys: {list(session.keys())}")
        print(f"   Session ID: {session.get('_id', 'Not set')}")
        
        # Test 4: Try to generate CSRF token
        print("\n4. CSRF Token Generation:")
        try:
            csrf_token = generate_csrf()
            print(f"   ✅ CSRF token generated successfully")
            print(f"   Token length: {len(csrf_token)} characters")
            print(f"   Token preview: {csrf_token[:20]}...")
        except Exception as e:
            print(f"   ❌ Failed to generate CSRF token: {e}")
            import traceback
            traceback.print_exc()
    
    # Test 5: Check session cookie settings
    print("\n5. Session Cookie Configuration:")
    print(f"   SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY')}")
    print(f"   SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    print(f"   SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE')}")
    print(f"   SESSION_COOKIE_NAME: {app.config.get('SESSION_COOKIE_NAME')}")
    print(f"   PERMANENT_SESSION_LIFETIME: {app.config.get('PERMANENT_SESSION_LIFETIME')}")
    
    print("\n" + "=" * 60)
    print("CSRF Test Complete")
    print("=" * 60)
    
    print("\n💡 If CSRF token generation failed:")
    print("   - Ensure SECRET_KEY is set in .env file")
    print("   - Check that session cookies can be set")
    print("   - Verify WTF_CSRF_ENABLED is True")
    print("   - Clear browser cookies and try again")

