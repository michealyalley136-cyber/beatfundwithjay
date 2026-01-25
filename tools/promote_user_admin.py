"""
Promote a user to admin and optionally reset their password.

Usage:
  python tools/promote_user_admin.py <username> [password]
"""
from __future__ import annotations

import sys

from werkzeug.security import generate_password_hash

from app import app, db, User, RoleEnum


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python tools/promote_user_admin.py <username> [password]")
        return 1

    username = sys.argv[1].strip()
    password = sys.argv[2] if len(sys.argv) > 2 else None

    if not username:
        print("Username is required.")
        return 1

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(
                username=username,
                email=None,
                role=RoleEnum.admin.value,
                full_name="BeatFund Admin",
                is_superadmin=True,
            )
            db.session.add(user)
            action = "created"
        else:
            user.role = RoleEnum.admin.value
            user.is_superadmin = True
            action = "updated"

        if password:
            user.password_hash = generate_password_hash(password)

        db.session.commit()
        print(f"Admin user {action}: {username}")
        if password:
            print("Password was reset.")
        print("Admin dashboard: /dashboard/admin")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
