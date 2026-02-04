from datetime import datetime, timedelta

from tests.conftest import create_user, login


def _future_datetime():
    dt = datetime.utcnow() + timedelta(days=2)
    return dt.replace(hour=10, minute=0, second=0, microsecond=0)


def test_availability_overlap_allows_booking(app_module, client):
    provider = create_user(app_module, "avail_provider1", app_module.RoleEnum.designer.value)
    client_user = create_user(app_module, "avail_client1", app_module.RoleEnum.client.value)

    with app_module.app.app_context():
        prof = app_module.BookMeProfile(user_id=provider.id, display_name="Provider One")
        app_module.db.session.add(prof)
        app_module.db.session.add(
            app_module.ProviderAvailability(
                provider_user_id=provider.id,
                day_of_week=_future_datetime().weekday(),
                start_time=datetime.strptime("09:00", "%H:%M").time(),
                end_time=datetime.strptime("12:00", "%H:%M").time(),
                tz="UTC",
                is_active=True,
            )
        )
        app_module.db.session.commit()

    login(client, "avail_client1")
    dt = _future_datetime()
    resp = client.post(
        f"/bookme/{provider.username}/book",
        data={
            "event_date": dt.strftime("%Y-%m-%d"),
            "event_time": dt.strftime("%H:%M"),
            "duration_hours": "1",
            "duration_minutes": "0",
            "message": "Test booking",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        count = app_module.BookingRequest.query.filter_by(provider_id=provider.id, client_id=client_user.id).count()
        assert count == 1


def test_exception_blocks_booking(app_module, client):
    provider = create_user(app_module, "avail_provider2", app_module.RoleEnum.designer.value)
    client_user = create_user(app_module, "avail_client2", app_module.RoleEnum.client.value)

    dt = _future_datetime()
    with app_module.app.app_context():
        prof = app_module.BookMeProfile(user_id=provider.id, display_name="Provider Two")
        app_module.db.session.add(prof)
        app_module.db.session.add(
            app_module.ProviderAvailability(
                provider_user_id=provider.id,
                day_of_week=dt.weekday(),
                start_time=datetime.strptime("09:00", "%H:%M").time(),
                end_time=datetime.strptime("12:00", "%H:%M").time(),
                tz="UTC",
                is_active=True,
            )
        )
        app_module.db.session.add(
            app_module.ProviderAvailabilityException(
                provider_user_id=provider.id,
                date=dt.date(),
                start_time=datetime.strptime("09:30", "%H:%M").time(),
                end_time=datetime.strptime("11:00", "%H:%M").time(),
                is_unavailable=True,
            )
        )
        app_module.db.session.commit()

    login(client, "avail_client2")
    resp = client.post(
        f"/bookme/{provider.username}/book",
        data={
            "event_date": dt.strftime("%Y-%m-%d"),
            "event_time": "10:00",
            "duration_hours": "1",
            "duration_minutes": "0",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        count = app_module.BookingRequest.query.filter_by(provider_id=provider.id, client_id=client_user.id).count()
        assert count == 0


def test_accepting_new_requests_off_blocks_booking(app_module, client):
    provider = create_user(app_module, "avail_provider3", app_module.RoleEnum.designer.value)
    client_user = create_user(app_module, "avail_client3", app_module.RoleEnum.client.value)

    dt = _future_datetime()
    with app_module.app.app_context():
        prof = app_module.BookMeProfile(user_id=provider.id, display_name="Provider Three")
        app_module.db.session.add(prof)
        app_module.db.session.add(
            app_module.ProviderSettings(
                provider_user_id=provider.id,
                accepting_new_requests=False,
            )
        )
        app_module.db.session.commit()

    login(client, "avail_client3")
    resp = client.post(
        f"/bookme/{provider.username}/book",
        data={
            "event_date": dt.strftime("%Y-%m-%d"),
            "event_time": dt.strftime("%H:%M"),
            "duration_hours": "1",
            "duration_minutes": "0",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        count = app_module.BookingRequest.query.filter_by(provider_id=provider.id, client_id=client_user.id).count()
        assert count == 0
