from datetime import datetime, timedelta

from tests.conftest import create_user, login, create_booking


def test_support_ticket_create_and_reply(app_module, client):
    admin = create_user(app_module, "support_admin", app_module.RoleEnum.admin.value)
    user = create_user(app_module, "support_user", app_module.RoleEnum.client.value)

    login(client, "support_user")
    resp = client.post(
        "/support/new",
        data={"subject": "Help", "type": app_module.TicketType.other.value, "description": "Need help"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app_module.app.app_context():
        ticket = app_module.SupportTicket.query.filter_by(user_id=user.id).first()
        assert ticket is not None

    resp = client.post(
        f"/support/{ticket.id}/reply",
        data={"body": "Any update?"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        msg_count = app_module.SupportTicketMessage.query.filter_by(ticket_id=ticket.id).count()
        assert msg_count >= 2


def test_support_ticket_idor_blocked(app_module, client):
    admin = create_user(app_module, "support_admin2", app_module.RoleEnum.admin.value)
    owner = create_user(app_module, "support_owner", app_module.RoleEnum.client.value)
    other = create_user(app_module, "support_other", app_module.RoleEnum.client.value)

    with app_module.app.app_context():
        ticket = app_module.SupportTicket(
            user_id=owner.id,
            created_by_admin_id=admin.id,
            type=app_module.TicketType.other,
            status=app_module.TicketStatus.open,
            subject="Secret",
            description="Private",
        )
        app_module.db.session.add(ticket)
        app_module.db.session.commit()

    login(client, "support_other")
    resp = client.get(f"/support/{ticket.id}")
    assert resp.status_code == 403


def test_dispute_create_and_reply(app_module, client):
    provider = create_user(app_module, "dispute_provider", app_module.RoleEnum.designer.value)
    customer = create_user(app_module, "dispute_client", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, customer, app_module.BOOKING_STATUS_COMPLETED)

    login(client, "dispute_client")
    resp = client.post(
        f"/bookings/{booking.id}/dispute",
        data={"reason": "Issue", "details": "Not satisfied"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app_module.app.app_context():
        dispute = app_module.BookingDispute.query.filter_by(booking_id=booking.id).first()
        assert dispute is not None

    login(client, "dispute_provider")
    resp = client.post(
        f"/disputes/{dispute.id}/reply",
        data={"body": "We can resolve this."},
        follow_redirects=True,
    )
    assert resp.status_code == 200


def test_dispute_idor_blocked(app_module, client):
    provider = create_user(app_module, "dispute_provider2", app_module.RoleEnum.designer.value)
    customer = create_user(app_module, "dispute_client2", app_module.RoleEnum.client.value)
    other = create_user(app_module, "dispute_other2", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, customer, app_module.BOOKING_STATUS_COMPLETED)

    with app_module.app.app_context():
        dispute = app_module.BookingDispute(
            booking_id=booking.id,
            opened_by_id=customer.id,
            reason="Issue",
            details="Details",
            status="open",
        )
        app_module.db.session.add(dispute)
        app_module.db.session.commit()

    login(client, "dispute_other2")
    resp = client.get(f"/bookings/{booking.id}/dispute")
    assert resp.status_code == 403


def test_one_dispute_per_booking(app_module, client):
    provider = create_user(app_module, "dispute_provider3", app_module.RoleEnum.designer.value)
    customer = create_user(app_module, "dispute_client3", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, customer, app_module.BOOKING_STATUS_COMPLETED)

    login(client, "dispute_client3")
    client.post(
        f"/bookings/{booking.id}/dispute",
        data={"reason": "Issue", "details": "Details"},
        follow_redirects=True,
    )
    resp = client.post(
        f"/bookings/{booking.id}/dispute",
        data={"reason": "Another issue", "details": "More"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app_module.app.app_context():
        count = app_module.BookingDispute.query.filter_by(booking_id=booking.id).count()
        assert count == 1
