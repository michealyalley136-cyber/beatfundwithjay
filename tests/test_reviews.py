from datetime import datetime

from tests.conftest import create_user, login, create_booking


def test_review_created_for_completed_booking(app_module, client):
    provider = create_user(app_module, "provider1", app_module.RoleEnum.designer.value)
    reviewer = create_user(app_module, "client1", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, reviewer, app_module.BOOKING_STATUS_COMPLETED)

    login(client, "client1")
    resp = client.post(
        f"/bookings/{booking.id}/review",
        data={"rating": "5", "title": "Great", "body": "Excellent service"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app_module.app.app_context():
        review = app_module.ProviderReview.query.filter_by(booking_id=booking.id).first()
        assert review is not None
        assert review.rating == 5


def test_review_denied_if_not_completed(app_module, client):
    provider = create_user(app_module, "provider2", app_module.RoleEnum.designer.value)
    reviewer = create_user(app_module, "client2", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, reviewer, app_module.BOOKING_STATUS_CONFIRMED)

    login(client, "client2")
    resp = client.post(
        f"/bookings/{booking.id}/review",
        data={"rating": "4"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        review = app_module.ProviderReview.query.filter_by(booking_id=booking.id).first()
        assert review is None


def test_review_denied_for_non_participant(app_module, client):
    provider = create_user(app_module, "provider3", app_module.RoleEnum.designer.value)
    reviewer = create_user(app_module, "client3", app_module.RoleEnum.client.value)
    other = create_user(app_module, "other3", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, reviewer, app_module.BOOKING_STATUS_COMPLETED)

    login(client, "other3")
    resp = client.get(f"/bookings/{booking.id}/review")
    assert resp.status_code == 403


def test_duplicate_review_denied(app_module, client):
    provider = create_user(app_module, "provider4", app_module.RoleEnum.designer.value)
    reviewer = create_user(app_module, "client4", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, reviewer, app_module.BOOKING_STATUS_COMPLETED)

    login(client, "client4")
    client.post(
        f"/bookings/{booking.id}/review",
        data={"rating": "5", "title": "Nice"},
        follow_redirects=True,
    )
    resp = client.post(
        f"/bookings/{booking.id}/review",
        data={"rating": "4", "title": "Again"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app_module.app.app_context():
        count = app_module.ProviderReview.query.filter_by(booking_id=booking.id).count()
        assert count == 1


def test_admin_hide_show_review(app_module, client):
    admin = create_user(app_module, "admin1", app_module.RoleEnum.admin.value)
    provider = create_user(app_module, "provider5", app_module.RoleEnum.designer.value)
    reviewer = create_user(app_module, "client5", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, reviewer, app_module.BOOKING_STATUS_COMPLETED)

    with app_module.app.app_context():
        review = app_module.ProviderReview(
            booking_id=booking.id,
            reviewer_user_id=reviewer.id,
            provider_user_id=provider.id,
            rating=4,
            title="Test",
            body="Body",
            status=app_module.ReviewVisibility.visible,
        )
        app_module.db.session.add(review)
        app_module.db.session.commit()
        review_id = review.id

    login(client, "admin1")
    resp = client.post(f"/admin/reviews/{review_id}/hide", follow_redirects=True)
    assert resp.status_code == 200
    with app_module.app.app_context():
        review = app_module.ProviderReview.query.get(review_id)
        assert review.status == app_module.ReviewVisibility.hidden

    resp = client.post(f"/admin/reviews/{review_id}/show", follow_redirects=True)
    assert resp.status_code == 200
    with app_module.app.app_context():
        review = app_module.ProviderReview.query.get(review_id)
        assert review.status == app_module.ReviewVisibility.visible
