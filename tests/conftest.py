import os
import importlib
import pytest
from datetime import datetime, timedelta


@pytest.fixture(scope="session")
def app_module(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("data") / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["APP_ENV"] = "dev"
    os.environ["SECRET_KEY"] = "test-secret"

    import app as app_module  # noqa: WPS433
    importlib.reload(app_module)
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app_module


@pytest.fixture(autouse=True)
def db_setup(app_module):
    db = app_module.db
    with app_module.app.app_context():
        db.drop_all()
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


def create_user(app_module, username, role, password="pass123"):
    db = app_module.db
    user = app_module.User(username=username, email=f"{username}@test.local", role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def login(client, username, password="pass123"):
    return client.post(
        "/login",
        data={"identifier": username, "password": password},
        follow_redirects=True,
    )


def create_booking(app_module, provider, client_user, status):
    db = app_module.db
    booking = app_module.Booking(
        provider_id=provider.id,
        client_id=client_user.id,
        provider_role=provider.role,
        event_title="Test Booking",
        event_datetime=datetime.utcnow() + timedelta(days=1),
        duration_minutes=60,
        status=status,
    )
    db.session.add(booking)
    db.session.commit()
    return booking
