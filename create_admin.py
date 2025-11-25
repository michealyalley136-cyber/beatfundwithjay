from app import app
from models import db, User

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(email='admin@beatfund.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@beatfund.com',
            role='admin',
            full_name='BeatFund Admin',
            address='123 Admin St',
            ssn_last4='0000',
            is_verified=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("ADMIN CREATED: admin@beatfund.com / admin123")
    else:
        print("Admin already exists")