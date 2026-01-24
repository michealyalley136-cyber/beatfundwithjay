"""
Fix the password_changed_at field for admin user
"""
from dotenv import load_dotenv
load_dotenv()

from app import app, db, User
from datetime import datetime

with app.app_context():
    print("=" * 60)
    print("Fixing Admin Password Date")
    print("=" * 60)
    
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        print("❌ Admin user not found!")
    else:
        print(f"Found admin user: {admin.username}")
        print(f"Current password_changed_at: {admin.password_changed_at}")
        
        # Set password_changed_at to now so it's not expired
        admin.password_changed_at = datetime.utcnow()
        db.session.commit()
        
        print(f"✅ Updated password_changed_at to: {admin.password_changed_at}")
        print("Admin can now log in without being forced to reset password")
    
    print("=" * 60)

