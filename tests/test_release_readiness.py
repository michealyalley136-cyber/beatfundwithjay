import os
from io import BytesIO
from types import SimpleNamespace

from werkzeug.datastructures import FileStorage

from tests.conftest import create_user, login, create_booking


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True


def test_basic_templates_render(client):
    for path in ["/", "/login", "/register"]:
        resp = client.get(path)
        assert resp.status_code == 200


def test_debug_stripe_env_admin_only(app_module, client):
    create_user(app_module, "debug_user", app_module.RoleEnum.client.value)
    login(client, "debug_user")
    resp = client.get("/debug/stripe-env")
    assert resp.status_code == 403

    admin_client = app_module.app.test_client()
    create_user(app_module, "debug_admin", app_module.RoleEnum.admin.value)
    login(admin_client, "debug_admin")
    resp = admin_client.get("/debug/stripe-env")
    assert resp.status_code == 200


def test_holding_fee_checkout_uses_fixed_amount(app_module, monkeypatch):
    app_module.STRIPE_SECRET_KEY = "sk_test"
    app_module.STRIPE_PUBLISHABLE_KEY = "pk_test"
    app_module.APP_BASE_URL = "http://localhost"
    app_module.stripe.api_key = "sk_test"

    captured = {}

    def fake_create(**kwargs):
        captured["line_items"] = kwargs.get("line_items")
        return SimpleNamespace(id="cs_test_123", url="https://example.com/checkout")

    monkeypatch.setattr(app_module.stripe.checkout.Session, "create", fake_create)

    provider = create_user(app_module, "hold_provider", app_module.RoleEnum.producer.value)
    client_user = create_user(app_module, "hold_client", app_module.RoleEnum.client.value)
    booking = create_booking(app_module, provider, client_user, app_module.BOOKING_STATUS_PENDING)

    with app_module.app.app_context():
        booking.total_cents = 5000
        app_module.db.session.commit()

        order, err = app_module.get_or_create_payment_order_for_booking(booking)
        assert err is None
        with app_module.app.test_request_context():
            payload, status = app_module._create_checkout_session_for_order(order, app_module.PaymentLedgerPhase.holding)
            assert status == 200
            assert payload.get("session_id") == "cs_test_123"

    assert captured["line_items"][0]["price_data"]["unit_amount"] == app_module.HOLD_FEE_CENTS


def test_preview_range_support(app_module, client):
    owner = create_user(app_module, "preview_owner", app_module.RoleEnum.producer.value)
    filename = "preview_test.mp3"
    local_path = os.path.join(app_module.app.config["UPLOAD_FOLDER"], filename)
    with open(local_path, "wb") as fh:
        fh.write(b"0" * 2048)

    with app_module.app.app_context():
        beat = app_module.Beat(
            owner_id=owner.id,
            title="Preview Beat",
            price_cents=1000,
            currency="usd",
            is_active=True,
            preview_status="ready",
            preview_path=filename,
            audio_preview_key=filename,
        )
        app_module.db.session.add(beat)
        app_module.db.session.commit()
        beat_id = beat.id

    resp = client.get(f"/beats/{beat_id}/preview", headers={"Range": "bytes=0-10"})
    assert resp.status_code == 206
    assert resp.headers.get("Content-Range", "").startswith("bytes 0-10/")


def test_process_beat_upload_ffmpeg_missing(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "_ffmpeg_available", lambda: False)
    owner = create_user(app_module, "ffmpeg_owner", app_module.RoleEnum.producer.value)

    audio = FileStorage(
        stream=BytesIO(b"fake audio bytes"),
        filename="demo.mp3",
        content_type="audio/mpeg",
    )

    with app_module.app.app_context():
        beat, errors, warnings = app_module.process_beat_upload(
            owner_user_id=owner.id,
            title="No Preview Beat",
            price_cents=1200,
            currency="usd",
            license_type="standard",
            bpm=None,
            genre=None,
            cover_file=None,
            deliverable_file=audio,
            preview_file=None,
            stems_file=None,
            preview_seconds=None,
            allow_user_preview_upload=True,
        )

    assert beat is not None
    assert errors == []
    assert beat.preview_status == "failed"
    assert warnings
