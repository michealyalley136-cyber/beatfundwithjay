# Backend API Requirements for Mobile App

The React Native mobile app requires JSON API endpoints. Your Flask app currently returns HTML templates. You'll need to add JSON API endpoints.

## Required API Endpoints

### Authentication

#### POST `/api/auth/login`
**Request:**
```json
{
  "identifier": "user@example.com",
  "password": "password123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "username",
    "email": "user@example.com",
    "primary_role": "producer",
    "roles": ["producer", "studio"],
    "full_name": "John Doe",
    "avatar_url": "https://..."
  },
  "token": "session_token_or_jwt"
}
```

**Response (Error):**
```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

#### POST `/api/auth/register`
**Request:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "confirm": "password123",
  "role": "producer",
  "full_name": "John Doe",
  "artist_name": "Artist Name"
}
```

**Response:** Same format as login

#### GET `/api/auth/logout`
**Response:**
```json
{
  "success": true
}
```

#### GET `/api/user/me`
**Response:**
```json
{
  "id": 1,
  "username": "username",
  "email": "user@example.com",
  "primary_role": "producer",
  "roles": ["producer", "studio"],
  "full_name": "John Doe",
  "avatar_url": "https://...",
  "wallet_balance": 100.50
}
```

### Dashboard Data

#### GET `/api/dashboard`
**Response:**
```json
{
  "role": "producer",
  "stats": {
    "total_beats": 10,
    "sales_count": 5,
    "revenue": 500.00,
    "wallet_balance": 100.50,
    "followers_count": 25,
    "following_count": 10
  },
  "recent_activity": [...]
}
```

### Market

#### GET `/api/market/beats`
**Query params:** `?page=1&limit=20&genre=hip-hop`
**Response:**
```json
{
  "beats": [
    {
      "id": 1,
      "title": "Beat Title",
      "price_cents": 2000,
      "genre": "hip-hop",
      "bpm": 140,
      "owner": {
        "id": 1,
        "username": "producer",
        "avatar_url": "..."
      },
      "cover_url": "...",
      "preview_url": "..."
    }
  ],
  "total": 100,
  "page": 1,
  "limit": 20
}
```

### Wallet

#### GET `/api/wallet`
**Response:**
```json
{
  "balance_cents": 10050,
  "balance_dollars": 100.50,
  "recent_transactions": [...]
}
```

## Implementation Example

Add this to your `app.py`:

```python
from flask import jsonify, request
from flask_login import login_required, current_user

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
    identifier = data.get("identifier", "").strip()
    password = data.get("password", "").strip()
    
    # Your existing login logic here
    # ...
    
    if user:
        login_user(user)
        return jsonify({
            "success": True,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "primary_role": user.primary_role.value,
                "roles": [r.value for r in user.get_roles()],
            },
            "token": "session"  # Or generate JWT
        })
    else:
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

@app.route("/api/user/me", methods=["GET"])
@login_required
def api_user_me():
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "primary_role": current_user.primary_role.value,
        "roles": [r.value for r in current_user.get_roles()],
        "full_name": current_user.full_name,
        "avatar_url": current_user.avatar_url,
    })
```

## CORS Configuration

Add CORS support for mobile app:

```python
from flask_cors import CORS

# Allow requests from mobile app
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # In production, specify your app's origins
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"]
    }
})
```

Add to `requirements.txt`:
```
flask-cors==4.0.0
```

## Session vs JWT

Currently, Flask uses session-based auth. For mobile apps, you have two options:

1. **Keep sessions** - Use cookies (works but less ideal for mobile)
2. **Switch to JWT** - Better for mobile, requires more setup

For now, the mobile app can work with sessions if you configure cookies properly.

