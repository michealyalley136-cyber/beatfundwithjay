"""
Test the login endpoint directly to see what happens
"""
import requests
from dotenv import load_dotenv
load_dotenv()

# Test the login endpoint
base_url = "http://127.0.0.1:5000"

print("=" * 60)
print("Testing Login Endpoint")
print("=" * 60)

# First, get the login page to get CSRF token
print("\n1. Getting login page to retrieve CSRF token...")
try:
    session = requests.Session()
    response = session.get(f"{base_url}/login")
    print(f"   Status: {response.status_code}")
    
    # Extract CSRF token from the page
    if 'csrf_token' in response.text:
        # Try to find the CSRF token in the form
        import re
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        if csrf_match:
            csrf_token = csrf_match.group(1)
            print(f"   ✅ CSRF token found: {csrf_token[:20]}...")
        else:
            print("   ⚠️  Could not extract CSRF token from form")
            csrf_token = None
    else:
        print("   ⚠️  No CSRF token found in response")
        csrf_token = None
    
    # Test login
    print("\n2. Attempting login...")
    login_data = {
        'username': 'admin',
        'password': 'admin123',
    }
    if csrf_token:
        login_data['csrf_token'] = csrf_token
    
    login_response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
    print(f"   Status: {login_response.status_code}")
    print(f"   Location header: {login_response.headers.get('Location', 'None')}")
    
    # Check for flash messages in the response
    if 'Invalid credentials' in login_response.text:
        print("   ❌ Invalid credentials error found")
    elif 'Too many' in login_response.text:
        print("   ⚠️  Rate limiting message found")
    elif login_response.status_code == 302:
        location = login_response.headers.get('Location', '')
        if 'dashboard' in location or 'login' not in location:
            print("   ✅ Login appears successful (redirected away from login)")
        else:
            print(f"   ⚠️  Redirected to: {location}")
    
    # Check cookies
    if session.cookies:
        print(f"   Cookies set: {list(session.cookies.keys())}")
    
except requests.exceptions.ConnectionError:
    print("   ❌ Could not connect to server. Is the app running?")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "=" * 60)

