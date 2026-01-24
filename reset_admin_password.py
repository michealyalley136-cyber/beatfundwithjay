"""
Reset admin password or create admin account
Run this script to create/reset admin access
"""
from app import app, db, User, RoleEnum
from werkzeug.security import generate_password_hash

# Default admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_EMAIL = 'admin@beatfund.com'
ADMIN_PASSWORD = 'admin123'  # Change this after first login!

with app.app_context():
    print("=" * 60)
    print("Admin Account Setup/Reset")
    print("=" * 60)
    
    # Check if admin exists
    admin = User.query.filter(
        (User.username == ADMIN_USERNAME) | (User.email == ADMIN_EMAIL)
    ).first()
    
    if admin:
        # Reset existing admin password
        print(f"Found existing admin account: {admin.username}")
        print(f"Current role: {admin.role.value}")
        
        # Update password
        admin.password_hash = generate_password_hash(ADMIN_PASSWORD)
        
        # Ensure admin role
        if admin.role != RoleEnum.admin:
            admin.role = RoleEnum.admin
            print(f"Updated role to: {admin.role.value}")
        
        # Make superadmin if not already
        if not admin.is_superadmin:
            admin.is_superadmin = True
            print("Granted superadmin privileges")
        
        db.session.commit()
        print("=" * 60)
        print("✅ ADMIN PASSWORD RESET SUCCESSFULLY!")
        print("=" * 60)
    else:
        # Create new admin account
        print("No admin account found. Creating new admin account...")
        admin = User(
            username=ADMIN_USERNAME,
            email=ADMIN_EMAIL,
            role=RoleEnum.admin,
            full_name='BeatFund Admin',
            is_superadmin=True
        )
        admin.password_hash = generate_password_hash(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print("=" * 60)
        print("✅ ADMIN ACCOUNT CREATED SUCCESSFULLY!")
        print("=" * 60)
    
    print(f"Username: {ADMIN_USERNAME}")
    print(f"Email: {ADMIN_EMAIL}")
    print(f"Password: {ADMIN_PASSWORD}")
    print("=" * 60)
    print("You can now log in and access the admin dashboard at:")
    print("  /dashboard/admin")
    print("=" * 60)
    print("⚠️  IMPORTANT: Change the password after first login!")
    print("=" * 60)

