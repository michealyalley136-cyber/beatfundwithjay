from app import app, db, User, RoleEnum, get_role_display
from sqlalchemy import func

with app.app_context():
    username = 'stud1'
    user = User.query.filter(func.lower(User.username) == username.lower()).first()
    
    if user:
        print(f"User: @{user.username}")
        print(f"Role: {user.role}")
        print(f"Display Name: {get_role_display(user.role)}")
        print(f"Is Studio: {user.role == RoleEnum.studio}")
    else:
        print(f"User '@{username}' not found in database.")

