from __future__ import annotations

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify, Response, session, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from sqlalchemy import UniqueConstraint, inspect, text
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError

from functools import wraps
from contextlib import contextmanager
from datetime import datetime, timedelta
from time import time
from jinja2 import TemplateNotFound
from decimal import Decimal, InvalidOperation
from collections import Counter
from calendar import monthrange
from typing import Optional
import enum
import os
import uuid
import pathlib
import csv
from io import StringIO
import re
import json


# =========================================================
# Constants
# =========================================================
HOLD_FEE_CENTS = 2000               # $20 hold fee for accepted bookings
MAX_TXN_DOLLARS = 10_000            # safety cap: max $10k per wallet action in dev
MAX_PORTFOLIO_ITEMS = 8             # max portfolio items per provider

PASSWORD_MAX_AGE_DAYS = 90          # admins must change password every 90 days
RESET_TOKEN_MAX_AGE_HOURS = 1       # reset links valid for 1 hour


# =========================================================
# App / DB setup
# =========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

APP_ENV = os.getenv("APP_ENV", "dev").lower()
IS_DEV = APP_ENV != "prod"

# instance/ for sqlite + meta json
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

app = Flask(
    __name__,
    instance_path=INSTANCE_DIR,
    instance_relative_config=True,
)

# --- Required for session/login/flash/CSRF ---
# In dev: allow a fallback.
# In prod: REQUIRE an env var.
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "").strip() or "dev-secret-change-me"

if not IS_DEV and app.config["SECRET_KEY"] == "dev-secret-change-me":
    raise RuntimeError(
        "Set a strong SECRET_KEY environment variable in production."
    )

# ---------------------------------------------------------
# Session / cookie hardening
# ---------------------------------------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not IS_DEV,
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=not IS_DEV,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
)
app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)

csrf = CSRFProtect(app)


@app.context_processor
def inject_csrf_token():
    # templates can do: {{ csrf_token() }}
    return dict(csrf_token=generate_csrf)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    msg = e.description or "Security error: please refresh the page and try again."
    flash(msg, "error")
    return redirect(request.referrer or url_for("home")), 400


@app.template_test("None")
def jinja_is_None(value):
    return value is None


# =========================================================
# Database (Render Postgres in prod, SQLite locally)
# =========================================================
db_url = os.getenv("DATABASE_URL", "").strip()

if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    if db_url.startswith("postgresql://") and not db_url.startswith("postgresql+psycopg://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'app.db')}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# One-time DB bootstrap (only when explicitly enabled)
if os.getenv("BOOTSTRAP_DB") == "1":
    with app.app_context():
        db.create_all()
        print("✅ BOOTSTRAP_DB=1 -> db.create_all() completed")


# =========================================================
# Uploads
# =========================================================
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_ROOT

ALLOWED_IMAGE = {"png", "jpg", "jpeg"}
ALLOWED_AUDIO = {"mp3", "wav", "m4a", "ogg"}
ALLOWED_STEMS = {"zip", "rar", "7z", "mp3", "wav", "m4a", "ogg"}

ALLOWED_VIDEO_EXTS = {"mp4", "webm", "mov"}


def _ext_ok(filename: str, allowed: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def _save_file(fs, allowed_set: set[str]) -> Optional[str]:
    if not fs or fs.filename == "":
        return None
    if not _ext_ok(fs.filename, allowed_set):
        return None
    ext = fs.filename.rsplit(".", 1)[1].lower()
    fname = f"{uuid.uuid4().hex}.{ext}"
    fs.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
    return fname


def _safe_remove(stored_filename: Optional[str]) -> None:
    if not stored_filename:
        return
    try:
        pathlib.Path(os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)).unlink(missing_ok=True)
    except Exception:
        pass


# =========================================================
# Opportunities Promo Video (Admin Upload + Public Serve)
# =========================================================
OPP_VIDEO_DIR = os.path.join(UPLOAD_ROOT, "opportunities")
OPP_VIDEO_META = os.path.join(INSTANCE_DIR, "opportunities_video.json")
os.makedirs(OPP_VIDEO_DIR, exist_ok=True)


def _allowed_video(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_VIDEO_EXTS


def _load_opp_video_meta() -> dict:
    if not os.path.exists(OPP_VIDEO_META):
        return {}
    try:
        with open(OPP_VIDEO_META, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save_opp_video_meta(data: dict) -> None:
    try:
        with open(OPP_VIDEO_META, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def _current_opp_video_filename() -> Optional[str]:
    return _load_opp_video_meta().get("filename")


def _set_current_opp_video_filename(filename: str) -> None:
    meta = _load_opp_video_meta()
    meta["filename"] = filename
    meta["updated_at"] = datetime.utcnow().isoformat()
    _save_opp_video_meta(meta)


# =========================================================
# Owner panel passcode (secure)
# =========================================================
OWNER_UNLOCK_SESSION_KEY = "owner_panel_unlocked_at"
OWNER_UNLOCK_TTL_SECONDS = 30 * 60

OWNER_PASS_META = os.path.join(INSTANCE_DIR, "owner_passcode.json")


def _load_owner_pass_hash_from_instance() -> Optional[str]:
    if not os.path.exists(OWNER_PASS_META):
        return None
    try:
        with open(OWNER_PASS_META, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        h = data.get("pass_hash")
        return h if isinstance(h, str) and h.strip() else None
    except Exception:
        return None


def _save_owner_pass_hash_to_instance(pass_hash: str) -> None:
    try:
        with open(OWNER_PASS_META, "w", encoding="utf-8") as f:
            json.dump({"pass_hash": pass_hash, "updated_at": datetime.utcnow().isoformat()}, f)
    except Exception:
        pass


def _get_effective_owner_pass_hash() -> Optional[str]:
    env_hash = os.getenv("OWNER_PANEL_PASS_HASH")
    if env_hash and env_hash.strip():
        return env_hash.strip()

    inst_hash = _load_owner_pass_hash_from_instance()
    if inst_hash:
        return inst_hash

    env_plain = os.getenv("OWNER_PANEL_PASS")
    if env_plain and env_plain.strip():
        return generate_password_hash(env_plain.strip())

    if IS_DEV:
        dev_default = os.getenv("DEV_OWNER_PANEL_PASS", "Acidrain@0911")
        return generate_password_hash(dev_default)

    return None


OWNER_PANEL_PASS_HASH_EFFECTIVE = _get_effective_owner_pass_hash()
if not OWNER_PANEL_PASS_HASH_EFFECTIVE:
    raise RuntimeError(
        "SECURITY ERROR: Owner passcode is not configured.\n"
        "Production requires one of:\n"
        "- OWNER_PANEL_PASS_HASH (recommended)\n"
        "- OWNER_PANEL_PASS\n"
        "- instance/owner_passcode.json with {'pass_hash': '...'}\n"
    )

OWNER_PASS_MANAGED_BY_ENV = bool(
    (os.getenv("OWNER_PANEL_PASS_HASH") and os.getenv("OWNER_PANEL_PASS_HASH").strip())
    or (os.getenv("OWNER_PANEL_PASS") and os.getenv("OWNER_PANEL_PASS").strip())
)

OWNER_UNLOCK_ATTEMPTS: dict[str, list[float]] = {}
OWNER_UNLOCK_WINDOW_SECONDS = 10 * 60
OWNER_UNLOCK_MAX_ATTEMPTS = 5


def _owner_unlock_attempts_clean(ts_list: list[float]) -> list[float]:
    now = time()
    return [t for t in ts_list if (now - t) < OWNER_UNLOCK_WINDOW_SECONDS]


def _owner_unlock_blocked(ip: str) -> bool:
    ip = ip or "unknown"
    ts = OWNER_UNLOCK_ATTEMPTS.get(ip, [])
    ts = _owner_unlock_attempts_clean(ts)
    OWNER_UNLOCK_ATTEMPTS[ip] = ts
    return len(ts) >= OWNER_UNLOCK_MAX_ATTEMPTS


def _owner_unlock_fail(ip: str) -> None:
    ip = ip or "unknown"
    ts = OWNER_UNLOCK_ATTEMPTS.get(ip, [])
    ts = _owner_unlock_attempts_clean(ts)
    ts.append(time())
    OWNER_UNLOCK_ATTEMPTS[ip] = ts


def _owner_unlock_clear(ip: str) -> None:
    ip = ip or "unknown"
    OWNER_UNLOCK_ATTEMPTS.pop(ip, None)


def owner_panel_unlocked() -> bool:
    ts = session.get(OWNER_UNLOCK_SESSION_KEY)
    if not ts:
        return False
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False
    return (time() - ts) < OWNER_UNLOCK_TTL_SECONDS


# =========================================================
# Models
# =========================================================
class RoleEnum(str, enum.Enum):
    admin = "admin"
    artist = "artist"
    producer = "producer"
    studio = "studio"
    videographer = "videographer"
    designer = "designer"
    engineer = "engineer"
    manager = "manager"
    vendor = "vendor"
    funder = "funder"
    client = "client"

    dancer_choreographer = "dancer_choreographer"
    makeup_artist = "makeup_artist"
    hair_stylist_barber = "hair_stylist_barber"
    wardrobe_stylist = "wardrobe_stylist"
    photographer = "photographer"
    event_planner = "event_planner"
    emcee_host_hypeman = "emcee_host_hypeman"
    dj = "dj"
    live_sound_engineer = "live_sound_engineer"
    mix_master_engineer = "mix_master_engineer"
    lighting_designer = "lighting_designer"
    stage_set_designer = "stage_set_designer"
    decor_vendor = "decor_vendor"
    caterer_food_truck = "caterer_food_truck"
    brand_pr_consultant = "brand_pr_consultant"
    social_media_manager = "social_media_manager"
    security_usher_crowd_control = "security_usher_crowd_control"


class KYCStatus(str, enum.Enum):
    not_started = "not_started"
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


ROLE_DISPLAY_NAMES = {
    RoleEnum.admin: "Admin",
    RoleEnum.artist: "Artist",
    RoleEnum.producer: "Music Producer",
    RoleEnum.studio: "Recording Studio",
    RoleEnum.videographer: "Videographer",
    RoleEnum.designer: "Graphic / Brand Designer",
    RoleEnum.engineer: "Engineer",
    RoleEnum.manager: "Artist / Talent Manager",
    RoleEnum.vendor: "Service Provider",
    RoleEnum.funder: "Funder / Investor",
    RoleEnum.client: "Client",

    RoleEnum.dancer_choreographer: "Dancer / Choreographer",
    RoleEnum.makeup_artist: "Makeup Artist",
    RoleEnum.hair_stylist_barber: "Hair Stylist / Barber",
    RoleEnum.wardrobe_stylist: "Wardrobe Stylist",
    RoleEnum.photographer: "Photographer",
    RoleEnum.event_planner: "Event Planner",
    RoleEnum.emcee_host_hypeman: "MC / Host / Hypeman",
    RoleEnum.dj: "DJ",
    RoleEnum.live_sound_engineer: "Live Sound Engineer",
    RoleEnum.mix_master_engineer: "Mix & Master Engineer",
    RoleEnum.lighting_designer: "Lighting Designer",
    RoleEnum.stage_set_designer: "Stage / Set Designer",
    RoleEnum.decor_vendor: "Décor Vendor",
    RoleEnum.caterer_food_truck: "Caterer / Food Truck",
    RoleEnum.brand_pr_consultant: "Brand / PR Consultant",
    RoleEnum.social_media_manager: "Social Media Manager",
    RoleEnum.security_usher_crowd_control: "Security / Ushers / Crowd Control",
}


def get_role_display(role: RoleEnum | str) -> str:
    if isinstance(role, RoleEnum):
        return ROLE_DISPLAY_NAMES.get(role, role.value.replace("_", " ").title())
    try:
        r = RoleEnum(str(role))
        return ROLE_DISPLAY_NAMES.get(r, r.value.replace("_", " ").title())
    except Exception:
        return str(role).replace("_", " ").title()


app.jinja_env.globals["RoleEnum"] = RoleEnum
app.jinja_env.globals["KYCStatus"] = KYCStatus
app.jinja_env.globals["MAX_PORTFOLIO_ITEMS"] = MAX_PORTFOLIO_ITEMS
app.jinja_env.globals["get_role_display"] = get_role_display

# ✅ Needed if your templates use {{ datetime.utcnow().year }}
app.jinja_env.globals["datetime"] = datetime


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)

    full_name = db.Column(db.String(150), nullable=True)
    artist_name = db.Column(db.String(150), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(RoleEnum), nullable=False, default=RoleEnum.artist)
    kyc_status = db.Column(db.Enum(KYCStatus), nullable=False, default=KYCStatus.not_started)
    is_active_col = db.Column("is_active", db.Boolean, nullable=False, default=True)

    is_superadmin = db.Column(db.Boolean, nullable=False, default=False)

    password_changed_at = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_sent_at = db.Column(db.DateTime, nullable=True)

    avatar_path = db.Column(db.String(255), nullable=True)

    @property
    def is_active(self):
        return self.is_active_col

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)
        self.password_changed_at = datetime.utcnow()
        self.password_reset_token = None
        self.password_reset_sent_at = None

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    @property
    def avatar_url(self):
        # Always serve avatars through a dedicated endpoint:
        # - Works even if you don't have static/img/default-avatar.png
        # - Adds a cache-busting query param so new uploads show immediately
        v = self.avatar_path or "0"
        return url_for("user_avatar", user_id=self.id, v=v)

    @property
    def display_name(self) -> str:
        return self.artist_name or self.full_name or self.username


# ------- Follows -------
class UserFollow(db.Model):
    __tablename__ = "user_follow"
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    __table_args__ = (UniqueConstraint("follower_id", "followed_id", name="uq_user_follow_follower_followed"),)


# ------- Wallet / Ledger -------
class EntryType(str, enum.Enum):
    deposit = "deposit"
    withdrawal = "withdrawal"
    transfer_in = "transfer_in"
    transfer_out = "transfer_out"
    interest = "interest"
    adjustment = "adjustment"
    sale_income = "sale_income"
    purchase_spend = "purchase_spend"


app.jinja_env.globals["EntryType"] = EntryType


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    user = db.relationship("User", backref=db.backref("wallet", uselist=False))


class LedgerEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallet.id"), nullable=False, index=True)
    entry_type = db.Column(db.Enum(EntryType), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    meta = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())
    wallet = db.relationship("Wallet", backref="entries")


# ------- Marketplace -------
class Beat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    license = db.Column(db.String(80), nullable=False, default="standard")
    bpm = db.Column(db.Integer, nullable=True)
    genre = db.Column(db.String(80), nullable=True)
    cover_path = db.Column(db.String(255), nullable=True)
    preview_path = db.Column(db.String(255), nullable=True)
    stems_path = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_featured = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    owner = db.relationship("User")

    @property
    def cover_url(self):
        return url_for("media_file", filename=self.cover_path) if self.cover_path else None

    @property
    def preview_url(self):
        return url_for("media_file", filename=self.preview_path) if self.preview_path else None

    @property
    def stems_url(self):
        return url_for("media_file", filename=self.stems_path) if self.stems_path else None


class OrderStatus(str, enum.Enum):
    paid = "paid"
    refunded = "refunded"


class Order(db.Model):
    __table_args__ = (db.UniqueConstraint("buyer_id", "beat_id", name="uq_order_buyer_beat"),)
    id = db.Column(db.Integer, primary_key=True)
    beat_id = db.Column(db.Integer, db.ForeignKey("beat.id"), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum(OrderStatus), nullable=False, default=OrderStatus.paid)
    created_at = db.Column(db.DateTime, server_default=func.now())

    beat = db.relationship("Beat")
    buyer = db.relationship("User", foreign_keys=[buyer_id])
    seller = db.relationship("User", foreign_keys=[seller_id])


# ------- Bookings (legacy-ish but used) -------
class Booking(db.Model):
    __tablename__ = "booking"
    id = db.Column(db.Integer, primary_key=True)

    provider_id = db.Column("artist_id", db.Integer, db.ForeignKey("user.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    provider_role = db.Column(db.Enum(RoleEnum), nullable=False)

    event_title = db.Column(db.String(160), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=True)
    location_text = db.Column(db.String(255), nullable=True)

    total_cents = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="pending")

    notes_from_client = db.Column(db.Text, nullable=True)
    notes_from_provider = db.Column("notes_from_artist", db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    provider = db.relationship("User", foreign_keys=[provider_id], backref=db.backref("artist_bookings", lazy="dynamic"))
    client = db.relationship("User", foreign_keys=[client_id], backref=db.backref("client_bookings", lazy="dynamic"))

    @property
    def artist(self):
        return self.provider


class BookingDispute(db.Model):
    __tablename__ = "booking_dispute"
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=False)
    opened_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    reason = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="open")

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    booking = db.relationship("Booking", backref=db.backref("disputes", lazy="dynamic"))
    opened_by = db.relationship("User", foreign_keys=[opened_by_id])


class BookingStatus(str, enum.Enum):
    pending = "pending"
    accepted = "accepted"
    declined = "declined"
    cancelled = "cancelled"


class BookingRequest(db.Model):
    __tablename__ = "booking_request"

    id = db.Column(db.Integer, primary_key=True)

    provider_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    message = db.Column(db.Text, nullable=True)
    preferred_time = db.Column(db.String(120), nullable=False)

    status = db.Column(db.Enum(BookingStatus), nullable=False, default=BookingStatus.pending, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), index=True)

    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=True, unique=True, index=True)

    provider = db.relationship("User", foreign_keys=[provider_id])
    client = db.relationship("User", foreign_keys=[client_id])
    booking = db.relationship("Booking", foreign_keys=[booking_id])


# ------- Payments (model kept for future use) -------
class PaymentProcessor(str, enum.Enum):
    wallet = "wallet"
    stripe = "stripe"
    paypal = "paypal"


class PaymentStatus(str, enum.Enum):
    created = "created"
    processing = "processing"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class PaymentPurpose(str, enum.Enum):
    bookme_hold = "bookme_hold"
    beat_purchase = "beat_purchase"


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    purpose = db.Column(db.Enum(PaymentPurpose), nullable=False)
    processor = db.Column(db.Enum(PaymentProcessor), nullable=False, default=PaymentProcessor.wallet)
    status = db.Column(db.Enum(PaymentStatus), nullable=False, default=PaymentStatus.created)

    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(8), nullable=False, default="usd")

    idempotency_key = db.Column(db.String(120), nullable=False, unique=True)
    external_id = db.Column(db.String(120), nullable=True, unique=True)

    booking_request_id = db.Column(db.Integer, db.ForeignKey("booking_request.id"), nullable=True, unique=True)
    booking_request = db.relationship("BookingRequest", foreign_keys=[booking_request_id])

    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())


# ------- BookMe Profiles / Portfolio -------
BOOKME_PROVIDER_ROLES: set[RoleEnum] = {
    RoleEnum.artist,
    RoleEnum.producer,
    RoleEnum.studio,
    RoleEnum.videographer,
    RoleEnum.designer,
    RoleEnum.engineer,
    RoleEnum.manager,
    RoleEnum.vendor,
    RoleEnum.dancer_choreographer,
    RoleEnum.makeup_artist,
    RoleEnum.hair_stylist_barber,
    RoleEnum.wardrobe_stylist,
    RoleEnum.photographer,
    RoleEnum.event_planner,
    RoleEnum.emcee_host_hypeman,
    RoleEnum.dj,
    RoleEnum.live_sound_engineer,
    RoleEnum.mix_master_engineer,
    RoleEnum.lighting_designer,
    RoleEnum.stage_set_designer,
    RoleEnum.decor_vendor,
    RoleEnum.caterer_food_truck,
    RoleEnum.brand_pr_consultant,
    RoleEnum.social_media_manager,
    RoleEnum.security_usher_crowd_control,
}
app.jinja_env.globals["BOOKME_PROVIDER_ROLES"] = {r.value for r in BOOKME_PROVIDER_ROLES}


PORTFOLIO_REQUIRED_ROLES = {
    RoleEnum.artist,
    RoleEnum.producer,
    RoleEnum.studio,
    RoleEnum.videographer,
    RoleEnum.designer,
    RoleEnum.engineer,
    RoleEnum.vendor,
    RoleEnum.dancer_choreographer,
    RoleEnum.makeup_artist,
    RoleEnum.hair_stylist_barber,
    RoleEnum.wardrobe_stylist,
    RoleEnum.photographer,
    RoleEnum.event_planner,
    RoleEnum.emcee_host_hypeman,
    RoleEnum.dj,
    RoleEnum.live_sound_engineer,
    RoleEnum.mix_master_engineer,
    RoleEnum.lighting_designer,
    RoleEnum.stage_set_designer,
    RoleEnum.decor_vendor,
    RoleEnum.caterer_food_truck,
    RoleEnum.brand_pr_consultant,
    RoleEnum.social_media_manager,
}

PORTFOLIO_OPTIONAL_ROLES = {RoleEnum.manager, RoleEnum.security_usher_crowd_control}


def role_requires_portfolio(role) -> bool:
    try:
        r = role if isinstance(role, RoleEnum) else RoleEnum(str(role))
    except Exception:
        return False
    return r in PORTFOLIO_REQUIRED_ROLES


def is_service_provider(user) -> bool:
    if not user:
        return False
    try:
        r = user.role if isinstance(user.role, RoleEnum) else RoleEnum(str(user.role))
    except Exception:
        return False
    return (r in BOOKME_PROVIDER_ROLES) and (r != RoleEnum.admin)


app.jinja_env.globals["is_service_provider"] = is_service_provider
app.jinja_env.globals["role_requires_portfolio"] = role_requires_portfolio


class BookMeProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)

    display_name = db.Column(db.String(150), nullable=False)
    service_types = db.Column(db.String(255))
    bio = db.Column(db.Text)
    rate_notes = db.Column(db.String(255))

    contact_phone = db.Column(db.String(40))

    zip = db.Column(db.String(20))
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    address = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    is_visible = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship("User", backref=db.backref("bookme_profile", uselist=False))


class PortfolioMediaType(str, enum.Enum):
    image = "image"
    video = "video"
    audio = "audio"
    link = "link"


class PortfolioItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("book_me_profile.id"), nullable=False)

    media_type = db.Column(db.Enum(PortfolioMediaType), nullable=False, default=PortfolioMediaType.image)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=True)

    stored_filename = db.Column(db.String(255), nullable=True)
    external_url = db.Column(db.String(500), nullable=True)

    sort_order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    profile = db.relationship("BookMeProfile", backref=db.backref("portfolio_items", lazy="dynamic"))

    @property
    def media_url(self):
        if self.stored_filename:
            return url_for("media_file", filename=self.stored_filename)
        return self.external_url


# ------- Studio Availability Calendar -------
class StudioAvailability(db.Model):
    __tablename__ = "studio_availability"
    id = db.Column(db.Integer, primary_key=True)
    studio_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    
    available_date = db.Column(db.Date, nullable=False, index=True)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    
    is_available = db.Column(db.Boolean, nullable=False, default=True)
    notes = db.Column(db.String(255), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    studio = db.relationship("User", foreign_keys=[studio_id], backref=db.backref("availability_slots", lazy="dynamic"))


# ------- Audit Log -------
class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    admin = db.relationship("User", foreign_keys=[admin_id], backref="audit_actions")
    user = db.relationship("User", foreign_keys=[user_id])


# ------- Support Tickets -------
class TicketType(str, enum.Enum):
    refund_request = "refund_request"
    fraud_investigation = "fraud_investigation"
    charge_dispute = "charge_dispute"
    technical_issue = "technical_issue"
    other = "other"


class TicketStatus(str, enum.Enum):
    open = "open"
    in_review = "in_review"
    approved = "approved"
    rejected = "rejected"
    resolved = "resolved"


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    related_ledger_id = db.Column(db.Integer, db.ForeignKey("ledger_entry.id"), nullable=True)

    type = db.Column(db.Enum(TicketType), nullable=False, default=TicketType.other)
    status = db.Column(db.Enum(TicketStatus), nullable=False, default=TicketStatus.open)
    priority = db.Column(db.String(20), nullable=False, default="normal")

    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    user = db.relationship("User", foreign_keys=[user_id])
    admin = db.relationship("User", foreign_keys=[created_by_admin_id])
    ledger_entry = db.relationship("LedgerEntry")


class SupportTicketComment(db.Model):
    __tablename__ = "support_ticket_comment"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_ticket.id"), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

    ticket = db.relationship("SupportTicket", backref=db.backref("comments", lazy="dynamic"))
    admin = db.relationship("User")


app.jinja_env.globals["TicketStatus"] = TicketStatus
app.jinja_env.globals["TicketType"] = TicketType


# =========================================================
# Login loader & helpers
# =========================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def is_password_expired(user: User) -> bool:
    if user.role != RoleEnum.admin:
        return False
    if not user.password_changed_at:
        return True
    return (datetime.utcnow() - user.password_changed_at) > timedelta(days=PASSWORD_MAX_AGE_DAYS)


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role.value not in roles:
                flash("You don't have access to that page.", "error")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


def superadmin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_superadmin", False):
            flash("You don't have permission to do that.", "error")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return wrapper


def require_kyc_approved():
    if current_user.kyc_status != KYCStatus.approved:
        flash("Financial features require approved KYC.", "error")
        return False
    return True


def get_or_create_wallet(user_id: int, *, commit: bool = True) -> Wallet:
    w = Wallet.query.filter_by(user_id=user_id).first()
    if not w:
        w = Wallet(user_id=user_id)
        db.session.add(w)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
    return w


def wallet_balance_cents(wallet: Wallet) -> int:
    total = 0
    for e in wallet.entries:
        if e.entry_type in (
            EntryType.deposit,
            EntryType.transfer_in,
            EntryType.interest,
            EntryType.adjustment,
            EntryType.sale_income,
        ):
            total += e.amount_cents
        else:
            total -= e.amount_cents
    return total


def post_ledger(wallet: Wallet, entry_type: EntryType, amount_cents: int, meta: str = "") -> LedgerEntry:
    if amount_cents <= 0:
        raise ValueError("amount must be positive cents")
    entry = LedgerEntry(wallet_id=wallet.id, entry_type=entry_type, amount_cents=amount_cents, meta=meta)
    db.session.add(entry)
    return entry


@contextmanager
def db_txn():
    try:
        yield
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def _user_has_paid_for_beat(user_id: int, beat_id: int) -> bool:
    return (
        db.session.query(Order.id)
        .filter_by(buyer_id=user_id, beat_id=beat_id, status=OrderStatus.paid)
        .first()
        is not None
    )


def _is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == RoleEnum.admin


def get_social_counts(user_id: int) -> tuple[int, int]:
    followers_count = UserFollow.query.filter_by(followed_id=user_id).count()
    following_count = UserFollow.query.filter_by(follower_id=user_id).count()
    return followers_count, following_count


@app.before_request
def _load_my_social_counts():
    if current_user.is_authenticated:
        g.my_followers_count, g.my_following_count = get_social_counts(current_user.id)
    else:
        g.my_followers_count, g.my_following_count = 0, 0


@app.context_processor
def inject_social_counts():
    return dict(
        my_followers_count=getattr(g, "my_followers_count", 0),
        my_following_count=getattr(g, "my_following_count", 0),
    )


# =========================================================
# SQLite Dev Auto-Migrations (safe schema fixes)
# =========================================================
_SCHEMA_BOOTSTRAP_DONE = False


def _sqlite_has_table(name: str) -> bool:
    try:
        return inspect(db.engine).has_table(name)
    except Exception:
        return False


def _sqlite_columns(table: str) -> set[str]:
    try:
        cols = inspect(db.engine).get_columns(table)
        return {c["name"] for c in cols}
    except Exception:
        return set()


def _ensure_sqlite_booking_request_booking_id():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("booking_request"):
        return
    cols = _sqlite_columns("booking_request")
    if "booking_id" in cols:
        return

    db.session.execute(text("ALTER TABLE booking_request ADD COLUMN booking_id INTEGER"))
    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_booking_request_booking_id ON booking_request (booking_id)"
    ))
    db.session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_booking_request_booking_id ON booking_request (booking_id)"
    ))
    db.session.commit()


def _ensure_sqlite_follow_table_name_and_indexes():
    if db.engine.url.get_backend_name() != "sqlite":
        return

    if _sqlite_has_table("follow") and (not _sqlite_has_table("user_follow")):
        db.session.execute(text('ALTER TABLE "follow" RENAME TO user_follow'))
        db.session.commit()

    if not _sqlite_has_table("user_follow"):
        return

    cols = _sqlite_columns("user_follow")
    if not {"follower_id", "followed_id"}.issubset(cols):
        return

    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_user_follow_follower_followed ON user_follow (follower_id, followed_id)"
    ))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_user_follow_followed_id ON user_follow (followed_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_user_follow_follower_id ON user_follow (follower_id)"))
    db.session.commit()


@app.before_request
def _bootstrap_schema_once():
    global _SCHEMA_BOOTSTRAP_DONE
    if _SCHEMA_BOOTSTRAP_DONE:
        return
    _SCHEMA_BOOTSTRAP_DONE = True
    try:
        _ensure_sqlite_follow_table_name_and_indexes()
        _ensure_sqlite_booking_request_booking_id()
    except Exception:
        db.session.rollback()


# =========================================================
# Routes: Core / Auth
# =========================================================
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = (request.form.get("name") or "").strip()
        artist_name = (request.form.get("artist_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        raw_username = (request.form.get("username") or "").strip()
        username = raw_username.lstrip("@").lower()

        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        role_key = (request.form.get("role") or "").strip()

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("register"))
        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("register"))
        if "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        pw_errors = []
        if len(password) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", password):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", password):
            pw_errors.append("Password must contain at least one number.")
        if password != confirm:
            pw_errors.append("Password and confirmation do not match.")
        if pw_errors:
            flash(" ".join(pw_errors), "error")
            return redirect(url_for("register"))

        if User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("That username is already taken.", "error")
            return redirect(url_for("register"))

        if User.query.filter(func.lower(User.email) == email.lower()).first():
            flash("That email is already registered.", "error")
            return redirect(url_for("register"))

        if not role_key:
            flash("Please select your main role.", "error")
            return redirect(url_for("register"))

        try:
            chosen_role = RoleEnum(role_key)
        except ValueError:
            flash("Invalid account type. Please pick a role from the list.", "error")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            full_name=full_name or None,
            artist_name=artist_name or None,
            role=chosen_role,
        )

        if IS_DEV:
            user.kyc_status = KYCStatus.approved

        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        get_or_create_wallet(user.id)

        login_user(user)
        flash("Account created!", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("register.html")


# Simple login rate limiting
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 10


def _clean_attempts(attempts):
    now = time()
    return [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]


def _too_many_failed_logins(remote_addr: str) -> bool:
    remote_addr = remote_addr or "unknown"
    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    LOGIN_ATTEMPTS[remote_addr] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _register_failed_login(remote_addr: str) -> None:
    remote_addr = remote_addr or "unknown"
    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    attempts.append(time())
    LOGIN_ATTEMPTS[remote_addr] = attempts


def _clear_failed_logins(remote_addr: str) -> None:
    remote_addr = remote_addr or "unknown"
    LOGIN_ATTEMPTS.pop(remote_addr, None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        remote_addr = request.remote_addr or "unknown"

        if _too_many_failed_logins(remote_addr):
            flash("Too many failed login attempts. Please wait a few minutes and try again.", "error")
            return redirect(url_for("login"))

        raw_identifier = (
            (request.form.get("identifier") or "").strip()
            or (request.form.get("username") or "").strip()
        )
        password = (request.form.get("password") or "").strip()

        if not raw_identifier or not password:
            flash("Please enter your email/username and password.", "error")
            return redirect(url_for("login"))

        identifier = raw_identifier.lower().strip()

        if "@" in identifier and "." in identifier:
            user = User.query.filter(func.lower(User.email) == identifier).first()
        else:
            handle = identifier.lstrip("@")
            user = User.query.filter(func.lower(User.username) == handle).first()

        if not user or not user.check_password(password):
            _register_failed_login(remote_addr)
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        if not user.is_active_col:
            flash("This account is disabled.", "error")
            return redirect(url_for("login"))

        _clear_failed_logins(remote_addr)
        login_user(user)

        if is_password_expired(user):
            flash("For security, your admin password must be updated before continuing.", "error")
            return redirect(url_for("force_password_reset"))

        return redirect(url_for("route_to_dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["GET"])
@login_required
def logout_get():
    return render_template("logout_confirm.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        raw_identifier = (
            (request.form.get("identifier") or "").strip()
            or (request.form.get("username") or "").strip()
        )
        if not raw_identifier:
            flash("Please enter your email or username.", "error")
            return redirect(url_for("forgot_password"))

        identifier = raw_identifier.lower().strip()

        if "@" in identifier and "." in identifier:
            user = User.query.filter(func.lower(User.email) == identifier).first()
        else:
            handle = identifier.lstrip("@")
            user = User.query.filter(func.lower(User.username) == handle).first()

        if user:
            token = uuid.uuid4().hex
            user.password_reset_token = token
            user.password_reset_sent_at = datetime.utcnow()
            db.session.commit()
            reset_link = url_for("reset_password", token=token, _external=True)
            print("\n[BeatFund] Password reset link:", reset_link, "\n")

        flash(
            "If an account with that email or username exists, a password reset link "
            "has been generated. (In dev, check the terminal output.)",
            "info",
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(password_reset_token=token).first()
    if not user:
        flash("This reset link is invalid or has already been used.", "error")
        return redirect(url_for("forgot_password"))

    if not user.password_reset_sent_at or (
        datetime.utcnow() - user.password_reset_sent_at > timedelta(hours=RESET_TOKEN_MAX_AGE_HOURS)
    ):
        flash("This reset link has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        pw_errors = []
        if len(password) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", password):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", password):
            pw_errors.append("Password must contain at least one number.")
        if password != confirm:
            pw_errors.append("Password and confirmation do not match.")
        if pw_errors:
            flash(" ".join(pw_errors), "error")
            return redirect(url_for("reset_password", token=token))

        user.set_password(password)
        user.password_reset_token = None
        user.password_reset_sent_at = None
        db.session.commit()

        flash("Your password has been updated. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/force-password-reset", methods=["GET", "POST"])
@login_required
def force_password_reset():
    if not is_password_expired(current_user):
        return redirect(url_for("route_to_dashboard"))

    if request.method == "POST":
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not current_user.check_password(current_pw):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("force_password_reset"))

        pw_errors = []
        if len(new_pw) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", new_pw):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", new_pw):
            pw_errors.append("Password must contain at least one number.")
        if new_pw != confirm:
            pw_errors.append("Password and confirmation do not match.")
        if pw_errors:
            flash(" ".join(pw_errors), "error")
            return redirect(url_for("force_password_reset"))

        current_user.set_password(new_pw)
        db.session.commit()

        flash("Password updated. Please continue to your dashboard.", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("force_password_reset.html")


# =========================================================
# KYC
# =========================================================
@app.route("/kyc")
@login_required
def kyc():
    return render_template("kyc.html", status=current_user.kyc_status)


@app.route("/kyc/start", methods=["POST"])
@login_required
def start_kyc():
    current_user.kyc_status = KYCStatus.pending
    db.session.commit()
    flash("KYC session started. Waiting for review.")
    return redirect(url_for("kyc"))


# =========================================================
# Media files
# =========================================================
@app.route("/uploads/<path:filename>")
@login_required
def media_file(filename):
    beat = Beat.query.filter_by(stems_path=filename).first()
    if beat:
        if beat.owner_id != current_user.id and not _user_has_paid_for_beat(current_user.id, beat.id):
            abort(403)
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)

@app.route("/avatar/<int:user_id>", endpoint="user_avatar")
def user_avatar(user_id: int):
    user = User.query.get_or_404(user_id)

    # Serve uploaded avatar if present + exists on disk
    if user.avatar_path:
        # Only serve known image extensions (extra safety)
        ext = user.avatar_path.rsplit(".", 1)[-1].lower() if "." in user.avatar_path else ""
        if ext in ALLOWED_IMAGE:
            avatar_path = os.path.join(app.config["UPLOAD_FOLDER"], user.avatar_path)
            if os.path.exists(avatar_path):
                resp = send_from_directory(app.config["UPLOAD_FOLDER"], user.avatar_path, as_attachment=False)
                # In dev, avoid stale caching so new uploads show immediately
                resp.headers["Cache-Control"] = "no-store"
                return resp

    # Fallback: generate a simple SVG placeholder with initials
    name = (user.display_name or user.username or "U").strip()
    initials = "".join([w[0] for w in name.split() if w])[:2].upper() or "U"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="160" height="160" viewBox="0 0 160 160">
  <defs>
    <linearGradient id="g" x1="0" x2="1" y1="0" y2="1">
      <stop offset="0" stop-color="#1f2a44"/>
      <stop offset="1" stop-color="#0b1024"/>
    </linearGradient>
  </defs>
  <rect width="160" height="160" rx="24" fill="url(#g)"/>
  <text x="80" y="92" text-anchor="middle" font-family="system-ui, -apple-system, Segoe UI, sans-serif"
        font-size="44" font-weight="700" fill="rgba(255,255,255,0.88)">{initials}</text>
</svg>"""

    resp = Response(svg, mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = "no-store"
    return resp




# =========================================================
# Opportunities video admin + serve
# =========================================================
@app.route("/admin/opportunities/video", methods=["GET", "POST"])
@login_required
def admin_opportunities_video():
    if not _is_admin():
        abort(403)

    if request.method == "POST":
        file = request.files.get("video")
        if not file or file.filename.strip() == "":
            flash("Please choose a video file.", "error")
            return redirect(request.url)

        if not _allowed_video(file.filename):
            flash("Invalid file type. Upload mp4/webm/mov.", "error")
            return redirect(request.url)

        ext = file.filename.rsplit(".", 1)[1].lower()
        new_name = secure_filename(f"opportunities_{uuid.uuid4().hex}.{ext}")
        save_path = os.path.join(OPP_VIDEO_DIR, new_name)
        file.save(save_path)

        old = _current_opp_video_filename()
        if old:
            old_path = os.path.join(OPP_VIDEO_DIR, old)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except Exception:
                    pass

        _set_current_opp_video_filename(new_name)
        flash("Opportunities promo video updated!", "success")
        return redirect(url_for("opportunities"))

    meta = _load_opp_video_meta()
    return render_template("admin_opportunities_video.html", meta=meta)


@app.route("/media/opportunities/video")
@login_required
def opportunities_video_media():
    filename = _current_opp_video_filename()
    if not filename:
        abort(404)
    return send_from_directory(OPP_VIDEO_DIR, filename)


# =========================================================
# Wallet (Overview + Transactions)
# =========================================================
@app.route("/wallet", endpoint="wallet_home")
@login_required
def wallet_page():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    tab = (request.args.get("tab") or "overview").strip().lower()

    w = get_or_create_wallet(current_user.id)
    balance = wallet_balance_cents(w) / 100.0

    txns = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
        .limit(100)
        .all()
    )

    return render_template("wallet_center.html", balance=balance, txns=txns, tab=tab)


@app.route("/transactions")
@login_required
def transactions_redirect():
    return redirect(url_for("wallet_home", tab="transactions"))


@app.route("/wallet/statement", endpoint="wallet_statement")
@login_required
def wallet_statement():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    year = request.args.get("year", type=int)
    month = request.args.get("month", type=int)

    now = datetime.utcnow()
    year = year or now.year
    month = month if month and 1 <= month <= 12 else now.month

    wallet = get_or_create_wallet(current_user.id)

    start_dt = datetime(year, month, 1)
    last_day = monthrange(year, month)[1]
    end_dt = datetime(year, month, last_day, 23, 59, 59)

    entries = (
        LedgerEntry.query
        .filter_by(wallet_id=wallet.id)
        .filter(LedgerEntry.created_at >= start_dt, LedgerEntry.created_at <= end_dt)
        .order_by(LedgerEntry.created_at.asc())
        .all()
    )

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["created_at", "entry_type", "direction", "amount_dollars", "meta"])

    credit_types = {
        EntryType.deposit,
        EntryType.transfer_in,
        EntryType.interest,
        EntryType.adjustment,
        EntryType.sale_income,
    }

    for row in entries:
        is_credit = row.entry_type in credit_types
        direction = "credit" if is_credit else "debit"
        created_str = row.created_at.isoformat(sep=" ") if row.created_at else ""
        amount_dollars = f"{row.amount_cents / 100.0:.2f}"
        writer.writerow([created_str, row.entry_type.value, direction, amount_dollars, row.meta or ""])

    output = si.getvalue()
    filename = f"beatfund_statement_{current_user.username}_{year}_{month:02d}.csv"

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/wallet/action", methods=["POST"])
@login_required
def wallet_action():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    action = (request.form.get("action") or "").strip().lower()
    amount_raw = (request.form.get("amount") or "").strip()

    if not amount_raw:
        flash("Amount is required.", "error")
        return redirect(url_for("wallet_home"))

    if not re.match(r"^\d+(\.\d{1,2})?$", amount_raw):
        flash("Amount must be a positive number with at most 2 decimal places (e.g. 12.50).", "error")
        return redirect(url_for("wallet_home"))

    try:
        amt = Decimal(amount_raw)
    except InvalidOperation:
        flash("Invalid amount format.", "error")
        return redirect(url_for("wallet_home"))

    if amt <= 0:
        flash("Amount must be greater than zero.", "error")
        return redirect(url_for("wallet_home"))

    if amt > Decimal(MAX_TXN_DOLLARS):
        flash(f"Amount exceeds the maximum allowed (${MAX_TXN_DOLLARS:,.2f}).", "error")
        return redirect(url_for("wallet_home"))

    cents = int((amt * 100).to_integral_value())
    method = (request.form.get("method") or "").strip()[:50]

    w = get_or_create_wallet(current_user.id, commit=False)

    if action == "add":
        with db_txn():
            post_ledger(w, EntryType.deposit, cents, meta=f"deposit via {method or 'unknown'}")
        flash(f"Added ${amt:,.2f} (demo).", "success")
        return redirect(url_for("wallet_home"))

    if action == "send":
        handle = (request.form.get("handle") or "").strip().lstrip("@").lower()
        if not handle:
            flash("Enter a recipient username (example: @artist1).", "error")
            return redirect(url_for("wallet_home"))

        recipient = User.query.filter(func.lower(User.username) == handle.lower()).first()
        if not recipient:
            flash("Recipient not found.", "error")
            return redirect(url_for("wallet_home"))
        if not recipient.is_active_col:
            flash("Recipient account is disabled.", "error")
            return redirect(url_for("wallet_home"))
        if recipient.id == current_user.id:
            flash("You can't send money to yourself.", "error")
            return redirect(url_for("wallet_home"))

        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.", "error")
            return redirect(url_for("wallet_home"))

        w_recipient = get_or_create_wallet(recipient.id, commit=False)
        note = (request.form.get("note") or "").strip()[:180]

        meta_out = f"to @{recipient.username}"
        meta_in = f"from @{current_user.username}"
        if note:
            meta_out += f" | {note}"
            meta_in += f" | {note}"

        with db_txn():
            if wallet_balance_cents(w) < cents:
                raise ValueError("Insufficient wallet balance.")

            post_ledger(w, EntryType.transfer_out, cents, meta=meta_out)
            post_ledger(w_recipient, EntryType.transfer_in, cents, meta=meta_in)

        flash(f"Sent ${amt:,.2f} to @{recipient.username}.", "success")
        return redirect(url_for("wallet_home"))

    if action == "withdraw":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.", "error")
            return redirect(url_for("wallet_home"))

        with db_txn():
            if wallet_balance_cents(w) < cents:
                raise ValueError("Insufficient wallet balance.")
            post_ledger(w, EntryType.withdrawal, cents, meta="withdraw to bank (demo)")

        flash(f"Withdrew ${amt:,.2f} (demo).", "success")
        return redirect(url_for("wallet_home"))

    flash("Unknown wallet action.", "error")
    return redirect(url_for("wallet_home"))


@app.route("/wallet/ledger")
@login_required
def wallet_ledger_redirect():
    return redirect(url_for("wallet_home", tab="transactions"))


# =========================================================
# Universal profile editor
# =========================================================
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile_edit():
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        display_name = (request.form.get("display_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        bio = (request.form.get("bio") or "").strip()
        city = (request.form.get("city") or "").strip()
        state = (request.form.get("state") or "").strip()

        if display_name:
            current_user.full_name = display_name

        if prof:
            if display_name:
                prof.display_name = display_name
            if phone:
                prof.contact_phone = phone
            if bio:
                prof.bio = bio
            if city:
                prof.city = city
            if state:
                prof.state = state

        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            if not _ext_ok(avatar.filename, ALLOWED_IMAGE):
                flash("Avatar must be an image (png/jpg/jpeg).", "error")
                return redirect(url_for("profile_edit"))

            new_fname = _save_file(avatar, ALLOWED_IMAGE)
            if not new_fname:
                flash("Problem saving avatar. Please try again.", "error")
                return redirect(url_for("profile_edit"))

            if getattr(current_user, "avatar_path", None):
                _safe_remove(current_user.avatar_path)

            current_user.avatar_path = new_fname

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile_edit"))

    return render_template("profile_edit.html", prof=prof)


@app.route("/profile/avatar", methods=["POST"])
@login_required
def update_avatar():
    file = request.files.get("avatar")

    if not file or file.filename == "":
        flash("Please choose an image to upload.", "error")
        return redirect(request.referrer or url_for("route_to_dashboard"))

    if not _ext_ok(file.filename, ALLOWED_IMAGE):
        flash("Invalid image type. Use png, jpg, or jpeg.", "error")
        return redirect(request.referrer or url_for("route_to_dashboard"))

    fname = _save_file(file, ALLOWED_IMAGE)
    if not fname:
        flash("Problem saving image. Please try again.", "error")
        return redirect(request.referrer or url_for("route_to_dashboard"))

    if getattr(current_user, "avatar_path", None):
        _safe_remove(current_user.avatar_path)

    current_user.avatar_path = fname
    db.session.commit()

    flash("Profile picture updated.", "success")
    return redirect(request.referrer or url_for("route_to_dashboard"))


# =========================================================
# Follow APIs (JSON + redirect versions)
# =========================================================
@app.route("/users/<int:user_id>/toggle-follow", methods=["POST"])
@login_required
def toggle_follow(user_id: int):
    target = User.query.get_or_404(user_id)

    if target.role == RoleEnum.admin:
        return jsonify({"ok": False, "error": "You can't follow an admin account."}), 403
    if target.id == current_user.id:
        return jsonify({"ok": False, "error": "You can't follow yourself."}), 400

    existing = UserFollow.query.filter_by(
        follower_id=current_user.id,
        followed_id=target.id
    ).first()

    try:
        if existing:
            db.session.delete(existing)
            db.session.commit()
        else:
            db.session.add(UserFollow(follower_id=current_user.id, followed_id=target.id))
            db.session.commit()
    except IntegrityError:
        db.session.rollback()

    following = (
        UserFollow.query.filter_by(follower_id=current_user.id, followed_id=target.id).first()
        is not None
    )

    followers_count = UserFollow.query.filter_by(followed_id=target.id).count()
    my_following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    my_followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()

    return jsonify({
        "ok": True,
        "target_id": target.id,
        "target_username": target.username,
        "following": following,
        "followers_count": followers_count,
        "my_following_count": my_following_count,
        "my_followers_count": my_followers_count
    })


@app.route("/u/<username>", endpoint="user_profile")
@login_required
def user_profile(username):
    profile_user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    if profile_user.role == RoleEnum.producer:
        return redirect(url_for("producer_catalog_detail", username=profile_user.username))

    if is_service_provider(profile_user):
        # Check if user has a BookMe profile (visible or not) - if so, redirect to portfolio
        prof = BookMeProfile.query.filter_by(user_id=profile_user.id).first()
        if prof:
            return redirect(url_for("provider_portfolio_public", username=profile_user.username))

    followers_count = UserFollow.query.filter_by(followed_id=profile_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=profile_user.id).count()
    is_following = (
        UserFollow.query.filter_by(follower_id=current_user.id, followed_id=profile_user.id).first()
        is not None
    )

    return render_template(
        "public_profile.html",
        profile_user=profile_user,
        role_label=get_role_display(profile_user.role),
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
    )


@app.route("/api/followers/<int:user_id>", endpoint="api_followers")
@login_required
def api_followers(user_id):
    """Get list of users following the specified user"""
    if user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    follow_records = (
        UserFollow.query
        .filter_by(followed_id=user_id)
        .order_by(UserFollow.created_at.desc())
        .all()
    )
    
    result = []
    for follow in follow_records:
        user = User.query.get(follow.follower_id)
        if user:
            result.append({
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name or user.username,
                "avatar_url": user.avatar_url,
                "role": user.role.value if user.role else None,
            })
    
    return jsonify({"followers": result})


@app.route("/api/following/<int:user_id>", endpoint="api_following")
@login_required
def api_following(user_id):
    """Get list of users that the specified user is following"""
    if user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403
    
    follow_records = (
        UserFollow.query
        .filter_by(follower_id=user_id)
        .order_by(UserFollow.created_at.desc())
        .all()
    )
    
    result = []
    for follow in follow_records:
        user = User.query.get(follow.followed_id)
        if user:
            result.append({
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name or user.username,
                "avatar_url": user.avatar_url,
                "role": user.role.value if user.role else None,
            })
    
    return jsonify({"following": result})


@app.route("/u/<username>/follow", methods=["POST"], endpoint="user_follow_toggle")
@login_required
def user_follow_toggle(username):
    target = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    if target.id == current_user.id:
        flash("You can’t follow yourself.", "info")
        return redirect(request.referrer or url_for("user_profile", username=target.username))

    if target.role == RoleEnum.admin:
        flash("You can’t follow an admin account.", "error")
        return redirect(request.referrer or url_for("market_index"))

    existing = UserFollow.query.filter_by(follower_id=current_user.id, followed_id=target.id).first()

    if existing:
        db.session.delete(existing)
        db.session.commit()
        flash(f"You unfollowed @{target.username}.", "success")
    else:
        db.session.add(UserFollow(follower_id=current_user.id, followed_id=target.id))
        db.session.commit()
        flash(f"You followed @{target.username}.", "success")

    return redirect(request.referrer or url_for("user_profile", username=target.username))


# =========================================================
# BookMe
# =========================================================
def _ensure_bookme_provider():
    if current_user.role not in BOOKME_PROVIDER_ROLES:
        flash("Only service providers can edit a BookMe profile.", "error")
        return False
    return True


@app.route("/bookme", endpoint="bookme_search")
@login_required
def bookme_search():
    role = (request.args.get("role") or "").strip().lower()
    zip_code = (request.args.get("zip") or "").strip()
    city = (request.args.get("city") or "").strip()
    state = (request.args.get("state") or "").strip()
    q = (request.args.get("q") or "").strip()

    query = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
    )

    if role:
        try:
            query = query.filter(User.role == RoleEnum(role))
        except ValueError:
            pass

    if zip_code:
        query = query.filter(BookMeProfile.zip.ilike(f"{zip_code}%"))
    if city:
        query = query.filter(BookMeProfile.city.ilike(f"%{city}%"))
    if state:
        query = query.filter(BookMeProfile.state.ilike(f"%{state}%"))

    if q:
        like = f"%{q}%"
        query = query.filter(
            (BookMeProfile.display_name.ilike(like)) |
            (BookMeProfile.service_types.ilike(like)) |
            (BookMeProfile.city.ilike(like)) |
            (BookMeProfile.state.ilike(like))
        )

    profiles = query.order_by(BookMeProfile.city.asc(), BookMeProfile.display_name.asc()).all()
    current_filters = dict(role=role, zip=zip_code, city=city, state=state, q=q)

    providers_payload = []
    for p in profiles:
        if p.lat is None or p.lng is None:
            continue
        providers_payload.append({
            "username": p.user.username if p.user else None,
            "display_name": p.display_name,
            "role": p.user.role.value if getattr(p.user, "role", None) else "",
            "city": p.city or "",
            "state": p.state or "",
            "lat": p.lat,
            "lng": p.lng,
        })

    return render_template(
        "bookme_search.html",
        profiles=profiles,
        BookingStatus=BookingStatus,
        RoleEnum=RoleEnum,
        current_filters=current_filters,
        providers_json=json.dumps(providers_payload),
    )


@app.route("/bookme/data")
@login_required
def bookme_data():
    role = (request.args.get("role") or "").strip().lower()
    zip_code = (request.args.get("zip") or "").strip()
    city = (request.args.get("city") or "").strip()
    state = (request.args.get("state") or "").strip()
    q = (request.args.get("q") or "").strip()

    query = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(
            BookMeProfile.lat.isnot(None),
            BookMeProfile.lng.isnot(None),
        )
    )

    if role:
        try:
            query = query.filter(User.role == RoleEnum(role))
        except ValueError:
            pass

    if zip_code:
        query = query.filter(BookMeProfile.zip.ilike(f"{zip_code}%"))
    if city:
        query = query.filter(BookMeProfile.city.ilike(f"%{city}%"))
    if state:
        query = query.filter(BookMeProfile.state.ilike(f"%{state}%"))

    if q:
        like = f"%{q}%"
        query = query.filter(
            (BookMeProfile.display_name.ilike(like)) |
            (BookMeProfile.service_types.ilike(like)) |
            (BookMeProfile.city.ilike(like)) |
            (BookMeProfile.state.ilike(like))
        )

    rows = query.all()
    return jsonify([
        {
            "username": r.user.username if r.user else None,
            "display_name": r.display_name,
            "service_types": r.service_types or "",
            "city": r.city or "",
            "state": r.state or "",
            "rate_notes": r.rate_notes or "",
            "lat": r.lat,
            "lng": r.lng,
        }
        for r in rows
    ])


@app.route("/bookme/profile", methods=["GET", "POST"])
@login_required
def bookme_profile():
    if not _ensure_bookme_provider():
        return redirect(url_for("bookme_search"))

    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == "POST":
        display_name = (request.form.get("display_name") or "").strip()
        service_types = (request.form.get("service_types") or "").strip()
        bio = (request.form.get("bio") or "").strip()
        rate_notes = (request.form.get("rate_notes") or "").strip()
        contact_phone = (request.form.get("contact_phone") or "").strip()
        zip_code = (request.form.get("zip") or "").strip()
        city = (request.form.get("city") or "").strip()
        state = (request.form.get("state") or "").strip()
        address = (request.form.get("address") or "").strip()
        lat_raw = (request.form.get("lat") or "").strip()
        lng_raw = (request.form.get("lng") or "").strip()

        if not display_name:
            flash("Display Name is required.", "error")
            return redirect(url_for("bookme_profile"))

        if contact_phone and not re.match(r"^[0-9+\-\s().]{6,40}$", contact_phone):
            flash("Contact phone looks invalid. Use digits and + - ( ) spaces only.", "error")
            return redirect(url_for("bookme_profile"))

        lat = lng = None
        if lat_raw or lng_raw:
            try:
                if lat_raw != "" and lng_raw != "":
                    lat = float(lat_raw)
                    lng = float(lng_raw)
                else:
                    raise ValueError()
            except Exception:
                flash("Latitude/Longitude must be numbers (or leave both blank).", "error")
                return redirect(url_for("bookme_profile"))

        if not prof:
            prof = BookMeProfile(user_id=current_user.id, display_name=display_name)
            db.session.add(prof)

        prof.display_name = display_name
        prof.service_types = service_types
        prof.bio = bio
        prof.rate_notes = rate_notes
        prof.contact_phone = contact_phone or None
        prof.zip = zip_code
        prof.city = city
        prof.state = state
        prof.address = address
        prof.lat = lat
        prof.lng = lng
        prof.is_visible = True

        db.session.commit()
        flash("BookMe profile saved.", "success")
        return redirect(url_for("bookme_search"))

    return render_template("bookme_profile.html", prof=prof)


@app.route("/bookme/portfolio", methods=["GET", "POST"])
@login_required
def bookme_portfolio():
    if not _ensure_bookme_provider():
        return redirect(url_for("bookme_search"))

    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    if not prof:
        flash("Create your BookMe profile first.", "error")
        return redirect(url_for("bookme_profile"))

    if request.method == "POST":
        existing_count = prof.portfolio_items.count()
        if existing_count >= MAX_PORTFOLIO_ITEMS:
            flash(f"You can only have up to {MAX_PORTFOLIO_ITEMS} portfolio items.", "error")
            return redirect(url_for("bookme_portfolio"))

        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        media_type_raw = (request.form.get("media_type") or "image").strip()
        external_url = (request.form.get("external_url") or "").strip()
        file = request.files.get("file")

        if not title:
            flash("Title is required.", "error")
            return redirect(url_for("bookme_portfolio"))

        if external_url and not re.match(r"^https?://", external_url, re.I):
            flash("External URL must start with http:// or https://", "error")
            return redirect(url_for("bookme_portfolio"))

        try:
            media_type = PortfolioMediaType(media_type_raw)
        except ValueError:
            media_type = PortfolioMediaType.image

        stored_filename = None
        if file and file.filename:
            if media_type == PortfolioMediaType.image:
                allowed = ALLOWED_IMAGE
            elif media_type == PortfolioMediaType.audio:
                allowed = ALLOWED_AUDIO
            elif media_type == PortfolioMediaType.video:
                allowed = ALLOWED_VIDEO_EXTS
            else:
                allowed = ALLOWED_IMAGE | ALLOWED_AUDIO | ALLOWED_VIDEO_EXTS

            fname = _save_file(file, allowed)
            if not fname:
                flash("Problem saving file – check the file type.", "error")
                return redirect(url_for("bookme_portfolio"))
            stored_filename = fname

        if not stored_filename and not external_url:
            flash("Provide either a file upload or an external URL.", "error")
            return redirect(url_for("bookme_portfolio"))

        last_item = prof.portfolio_items.order_by(PortfolioItem.sort_order.desc()).first()
        next_sort = (last_item.sort_order + 1) if last_item else 0

        item = PortfolioItem(
            profile_id=prof.id,
            media_type=media_type,
            title=title,
            description=description or None,
            stored_filename=stored_filename,
            external_url=external_url or None,
            sort_order=next_sort,
        )
        db.session.add(item)
        db.session.commit()

        flash("Portfolio item added.", "success")
        return redirect(url_for("bookme_portfolio"))

    items = prof.portfolio_items.order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc()).all()
    requires_portfolio = role_requires_portfolio(current_user.role)

    return render_template(
        "bookme_portfolio.html",
        prof=prof,
        items=items,
        PortfolioMediaType=PortfolioMediaType,
        requires_portfolio=requires_portfolio,
        MAX_PORTFOLIO_ITEMS=MAX_PORTFOLIO_ITEMS,
    )


@app.route("/bookme/portfolio/<int:item_id>/delete", methods=["POST"])
@login_required
def bookme_portfolio_delete(item_id):
    if not _ensure_bookme_provider():
        return redirect(url_for("bookme_search"))

    item = PortfolioItem.query.get_or_404(item_id)
    prof = item.profile

    if prof.user_id != current_user.id:
        flash("You can't modify another provider's portfolio.", "error")
        return redirect(url_for("bookme_portfolio"))

    if item.stored_filename:
        _safe_remove(item.stored_filename)

    db.session.delete(item)
    db.session.commit()
    flash("Portfolio item removed.", "success")
    return redirect(url_for("bookme_portfolio"))


@app.route("/bookme/provider/<username>", methods=["GET"])
@login_required
def provider_portfolio_public(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    # Allow viewing portfolio even when profile is not visible (for portfolio review)
    prof = BookMeProfile.query.filter_by(user_id=user.id).first_or_404()
    items = prof.portfolio_items.order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc()).all()

    followers_count = UserFollow.query.filter_by(followed_id=user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=user.id).count()

    is_following = (
        UserFollow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first() is not None
    )

    return render_template(
        "provider_portfolio_public.html",
        provider=user,
        prof=prof,
        items=items,
        PortfolioMediaType=PortfolioMediaType,
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
    )


@app.route("/bookme/request/<int:provider_id>", methods=["GET", "POST"])
@login_required
def bookme_request(provider_id):
    provider = User.query.get_or_404(provider_id)

    if not is_service_provider(provider):
        flash("This user is not available for BookMe bookings.", "error")
        return redirect(url_for("bookme_search"))

    # Check if profile is active (visible) - inactive profiles can't receive bookings
    prof = BookMeProfile.query.filter_by(user_id=provider.id).first()
    if prof and not prof.is_visible:
        flash("This studio profile is currently inactive and not accepting new bookings. You can still follow and view their portfolio.", "error")
        return redirect(url_for("bookme_search"))

    if request.method == "POST":
        msg = (request.form.get("message") or "").strip()
        pref = (request.form.get("preferred_time") or "").strip()

        if not pref:
            flash("Please choose a date and time slot.", "error")
            return redirect(url_for("bookme_request", provider_id=provider_id))
        
        # Check if the requested time is blocked (for studios)
        if provider.role == RoleEnum.studio:
            try:
                # Try to parse the preferred time to extract date
                if " " in pref:
                    date_part = pref.split(" ", 1)[0]
                    check_date = datetime.strptime(date_part, "%Y-%m-%d").date()
                else:
                    # If no date in preferred_time, use today as fallback
                    check_date = datetime.utcnow().date()
                
                if is_time_blocked(provider_id, check_date, pref):
                    flash("This time slot is blocked and not available for booking.", "error")
                    return redirect(url_for("bookme_request", provider_id=provider_id))
            except (ValueError, AttributeError):
                # If we can't parse, continue (let the studio handle it manually)
                pass

        req = BookingRequest(
            provider_id=provider.id,
            client_id=current_user.id,
            message=msg,
            preferred_time=pref,
        )
        db.session.add(req)
        db.session.commit()
        flash("Booking request sent.", "success")
        return redirect(url_for("bookme_requests"))

    return render_template("bookme_request.html", provider=provider, BookingStatus=BookingStatus)


@app.route("/bookme/requests")
@login_required
def bookme_requests():
    incoming_requests = (
        BookingRequest.query
        .filter(
            BookingRequest.provider_id == current_user.id,
            BookingRequest.status == BookingStatus.pending,
        )
        .order_by(BookingRequest.created_at.desc())
        .all()
    )

    outgoing_requests = (
        BookingRequest.query
        .filter(BookingRequest.client_id == current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .all()
    )

    incoming_bookings = (
        Booking.query
        .filter(Booking.provider_id == current_user.id)
        .order_by(Booking.event_datetime.desc().nullslast())
        .all()
    )

    outgoing_bookings = (
        Booking.query
        .filter(Booking.client_id == current_user.id)
        .order_by(Booking.event_datetime.desc().nullslast())
        .all()
    )

    return render_template(
        "bookme_requests.html",
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        incoming_bookings=incoming_bookings,
        outgoing_bookings=outgoing_bookings,
        HOLD_FEE_CENTS=HOLD_FEE_CENTS,
        BookingStatus=BookingStatus,
    )


@app.route("/bookme/requests/<int:req_id>/status", methods=["POST"])
@login_required
def bookme_request_status(req_id):
    action = (request.form.get("action") or "").strip().lower()

    # Provider accept/decline
    if action in ("accept", "decline"):
        req = BookingRequest.query.get_or_404(req_id)
        if current_user.id != req.provider_id:
            flash("You are not allowed to do that.", "error")
            return redirect(url_for("bookme_requests"))

        if action == "decline":
            updated = (
                BookingRequest.query
                .filter_by(id=req_id, provider_id=current_user.id, status=BookingStatus.pending)
                .update({BookingRequest.status: BookingStatus.declined})
            )
            db.session.commit()
            flash("Booking request declined." if updated else "This request is no longer pending.",
                  "success" if updated else "error")
            return redirect(url_for("bookme_requests"))

        # Accept (atomic state change)
        updated = (
            BookingRequest.query
            .filter_by(id=req_id, provider_id=current_user.id, status=BookingStatus.pending)
            .update({BookingRequest.status: BookingStatus.accepted})
        )
        db.session.commit()
        if updated == 0:
            flash("This request is no longer pending.", "error")
            return redirect(url_for("bookme_requests"))

        # Conflict check
        req = BookingRequest.query.get_or_404(req_id)
        conflict = (
            BookingRequest.query
            .filter(
                BookingRequest.id != req.id,
                BookingRequest.provider_id == req.provider_id,
                BookingRequest.preferred_time == req.preferred_time,
                BookingRequest.status == BookingStatus.accepted,
            )
            .first()
        )
        if conflict:
            req.status = BookingStatus.declined
            db.session.commit()
            flash("This time slot is already booked.", "error")
            return redirect(url_for("bookme_requests"))

        flash("Accepted. Waiting for client to confirm & pay the hold fee.", "success")
        return redirect(url_for("bookme_requests"))

    # Client cancel
    if action == "cancel":
        req = BookingRequest.query.get_or_404(req_id)
        if current_user.id != req.client_id:
            flash("You are not allowed to do that.", "error")
            return redirect(url_for("bookme_requests"))

        if req.status in (BookingStatus.pending, BookingStatus.accepted) and not req.booking_id:
            req.status = BookingStatus.cancelled
            db.session.commit()
            flash("Booking request cancelled.", "success")
        else:
            flash("You can only cancel pending/accepted requests that aren’t already paid.", "error")

        return redirect(url_for("bookme_requests"))

    flash("Unknown action.", "error")
    return redirect(url_for("bookme_requests"))


@app.route("/bookings/<int:booking_id>", methods=["GET", "POST"])
@login_required
def booking_detail(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        flash("You don't have access to this booking.", "error")
        return redirect(url_for("bookme_requests"))

    if request.method == "POST":
        action = (request.form.get("action") or "").strip().lower()
        
        if action == "edit_booking":
            # Both provider and client can edit booking details (for pending/confirmed bookings)
            if booking.status in ["completed", "cancelled", "disputed"]:
                flash("Cannot edit bookings that are completed, cancelled, or disputed.", "error")
                return redirect(url_for("booking_detail", booking_id=booking.id))
            
            # Update event title
            event_title = (request.form.get("event_title") or "").strip()
            if event_title:
                booking.event_title = event_title
            
            # Update date/time
            event_date = (request.form.get("event_date") or "").strip()
            event_time = (request.form.get("event_time") or "").strip()
            if event_date and event_time:
                try:
                    booking.event_datetime = datetime.strptime(f"{event_date} {event_time}", "%Y-%m-%d %H:%M")
                except ValueError:
                    flash("Invalid date/time format.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))
            elif event_date or event_time:
                flash("Both date and time are required.", "error")
                return redirect(url_for("booking_detail", booking_id=booking.id))
            
            # Update duration
            duration_minutes_raw = (request.form.get("duration_minutes") or "").strip()
            if duration_minutes_raw:
                try:
                    booking.duration_minutes = int(duration_minutes_raw) if duration_minutes_raw else None
                except ValueError:
                    flash("Duration must be a number.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))
            
            # Update location
            location_text = (request.form.get("location_text") or "").strip()
            booking.location_text = location_text or None
            
            # Update total amount
            total_dollars_raw = (request.form.get("total_dollars") or "").strip()
            if total_dollars_raw:
                try:
                    total_dollars = float(total_dollars_raw)
                    booking.total_cents = int(total_dollars * 100) if total_dollars >= 0 else None
                except ValueError:
                    flash("Total amount must be a valid number.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))
            elif total_dollars_raw == "":
                booking.total_cents = None
            
            # Update notes (provider can update provider notes, client can update client notes)
            if is_provider:
                notes_from_provider = (request.form.get("notes_from_provider") or "").strip()
                booking.notes_from_provider = notes_from_provider or None
            elif is_client:
                notes_from_client = (request.form.get("notes_from_client") or "").strip()
                booking.notes_from_client = notes_from_client or None
            
            # Status updates (only provider can change status)
            if is_provider:
                new_status = (request.form.get("status") or "").strip().lower()
                if new_status and new_status in ["pending", "confirmed", "cancelled"]:
                    booking.status = new_status
                    if new_status == "cancelled":
                        flash("Booking has been cancelled.", "success")
                    elif new_status == "confirmed":
                        flash("Booking has been confirmed.", "success")
            
            db.session.commit()
            flash("Booking updated successfully.", "success")
            return redirect(url_for("booking_detail", booking_id=booking.id))
        
        elif action == "update_notes":
            # Simple note update (existing functionality)
            if is_provider:
                notes_from_provider = (request.form.get("notes_from_provider") or "").strip()
                booking.notes_from_provider = notes_from_provider or None
            elif is_client:
                notes_from_client = (request.form.get("notes_from_client") or "").strip()
                booking.notes_from_client = notes_from_client or None
            else:
                flash("You don't have permission to update notes.", "error")
                return redirect(url_for("booking_detail", booking_id=booking.id))
            
            status_action = (request.form.get("status_action") or "").strip().lower()
            
            if status_action == "mark_completed" and is_provider:
                if booking.status == "confirmed":
                    booking.status = "completed"
                    flash("Booking marked as completed.", "success")
                else:
                    flash("Only confirmed bookings can be marked completed.", "error")
            else:
                flash("Notes updated.", "success")
            
            db.session.commit()
            return redirect(url_for("booking_detail", booking_id=booking.id))

    return render_template("booking_detail.html", booking=booking, is_provider=is_provider, is_client=is_client)


@app.route("/bookme/<username>/book", methods=["GET", "POST"])
@login_required
def bookme_book_provider(username):
    provider = User.query.filter_by(username=username).first_or_404()
    
    if not is_service_provider(provider):
        flash("This user is not available for BookMe bookings.", "error")
        return redirect(url_for("bookme_search"))
    
    if provider.id == current_user.id:
        flash("You can't send a booking request to yourself.", "error")
        return redirect(url_for("provider_portfolio_public", username=username))
    
    # Check if profile is active (visible) - inactive profiles can't receive bookings
    prof = BookMeProfile.query.filter_by(user_id=provider.id).first()
    if prof and not prof.is_visible:
        flash("This studio profile is currently inactive and not accepting new bookings. You can still follow and view their portfolio.", "error")
        return redirect(url_for("provider_portfolio_public", username=username))
    
    # Get follower count and follow status for template
    follower_count = UserFollow.query.filter_by(followed_id=provider.id).count()
    is_following = current_user.is_authenticated and UserFollow.query.filter_by(
        follower_id=current_user.id, followed_id=provider.id
    ).first() is not None
    
    if request.method == "POST":
        # Collect all form fields
        event_date = (request.form.get("event_date") or "").strip()
        event_time = (request.form.get("event_time") or "").strip()
        preferred_time_fallback = (request.form.get("preferred_time") or "").strip()
        budget = (request.form.get("budget") or "").strip()
        message = (request.form.get("message") or "").strip()
        
        # Build preferred_time from date/time or use fallback
        preferred_time = preferred_time_fallback
        if event_date and event_time:
            try:
                dt = datetime.strptime(f"{event_date} {event_time}", "%Y-%m-%d %H:%M")
                preferred_time = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                preferred_time = f"{event_date} {event_time}"
        
        if not preferred_time:
            flash("Please choose a date and time for the booking.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following
            )
        
        # Build comprehensive message from role-specific fields
        role_val = (provider.role.value if provider.role and hasattr(provider.role, 'value') else str(provider.role)).lower()
        message_parts = []
        
        if budget:
            message_parts.append(f"Budget: {budget}")
        
        # Studio-specific fields
        if role_val in ["studio"]:
            session_type = request.form.get("session_type", "").strip()
            hours = request.form.get("hours", "").strip()
            people = request.form.get("people", "").strip()
            engineer_needed = request.form.get("engineer_needed", "").strip()
            
            if session_type:
                message_parts.append(f"Session type: {session_type}")
            if hours:
                message_parts.append(f"Estimated hours: {hours}")
            if people:
                message_parts.append(f"People attending: {people}")
            if engineer_needed:
                message_parts.append(f"Engineer needed: {engineer_needed}")
        
        # Producer-specific fields
        elif role_val in ["producer"]:
            style = request.form.get("style", "").strip()
            deliverables = request.form.get("deliverables", "").strip()
            songs = request.form.get("songs", "").strip()
            deadline = request.form.get("deadline", "").strip()
            
            if style:
                message_parts.append(f"Style/vibe: {style}")
            if deliverables:
                message_parts.append(f"Deliverables: {deliverables}")
            if songs:
                message_parts.append(f"Number of songs: {songs}")
            if deadline:
                message_parts.append(f"Deadline: {deadline}")
        
        # Mix/Master Engineer-specific fields
        elif role_val in ["mix_master_engineer"]:
            service = request.form.get("service", "").strip()
            stems = request.form.get("stems", "").strip()
            format_field = request.form.get("format", "").strip()
            revisions = request.form.get("revisions", "").strip()
            
            if service:
                message_parts.append(f"Service: {service}")
            if stems:
                message_parts.append(f"Estimated stems/tracks: {stems}")
            if format_field:
                message_parts.append(f"File format: {format_field}")
            if revisions:
                message_parts.append(f"Revisions requested: {revisions}")
        
        # Videographer-specific fields
        elif role_val in ["videographer"]:
            video_type = request.form.get("video_type", "").strip()
            duration = request.form.get("duration", "").strip()
            locations = request.form.get("locations", "").strip()
            deliverables_video = request.form.get("deliverables_video", "").strip()
            
            if video_type:
                message_parts.append(f"Video type: {video_type}")
            if duration:
                message_parts.append(f"Video duration: {duration}")
            if locations:
                message_parts.append(f"Shoot locations: {locations}")
            if deliverables_video:
                message_parts.append(f"Deliverables: {deliverables_video}")
        
        # Photographer-specific fields
        elif role_val in ["photographer"]:
            photo_type = request.form.get("photo_type", "").strip()
            photos_needed = request.form.get("photos_needed", "").strip()
            locations_photo = request.form.get("locations_photo", "").strip()
            editing = request.form.get("editing", "").strip()
            
            if photo_type:
                message_parts.append(f"Photo shoot type: {photo_type}")
            if photos_needed:
                message_parts.append(f"Number of photos needed: {photos_needed}")
            if locations_photo:
                message_parts.append(f"Shoot location: {locations_photo}")
            if editing:
                message_parts.append(f"Editing included: {editing}")
        
        # DJ-specific fields
        elif role_val in ["dj"]:
            event_type_dj = request.form.get("event_type_dj", "").strip()
            set_duration = request.form.get("set_duration", "").strip()
            equipment_provided = request.form.get("equipment_provided", "").strip()
            genre_preference = request.form.get("genre_preference", "").strip()
            
            if event_type_dj:
                message_parts.append(f"Event type: {event_type_dj}")
            if set_duration:
                message_parts.append(f"Set duration: {set_duration} hours")
            if equipment_provided:
                message_parts.append(f"Equipment: {equipment_provided}")
            if genre_preference:
                message_parts.append(f"Genre preference: {genre_preference}")
        
        # Artist-specific fields
        elif role_val in ["artist"]:
            performance_type = request.form.get("performance_type", "").strip()
            set_duration_artist = request.form.get("set_duration_artist", "").strip()
            venue_type = request.form.get("venue_type", "").strip()
            expected_audience = request.form.get("expected_audience", "").strip()
            
            if performance_type:
                message_parts.append(f"Performance type: {performance_type}")
            if set_duration_artist:
                message_parts.append(f"Set duration: {set_duration_artist} minutes")
            if venue_type:
                message_parts.append(f"Venue type: {venue_type}")
            if expected_audience:
                message_parts.append(f"Expected audience: {expected_audience}")
        
        # Event Planner-specific fields
        elif role_val in ["event_planner"]:
            event_type_planner = request.form.get("event_type_planner", "").strip()
            guest_count = request.form.get("guest_count", "").strip()
            planning_scope = request.form.get("planning_scope", "").strip()
            venue_location = request.form.get("venue_location", "").strip()
            
            if event_type_planner:
                message_parts.append(f"Event type: {event_type_planner}")
            if guest_count:
                message_parts.append(f"Expected guest count: {guest_count}")
            if planning_scope:
                message_parts.append(f"Planning scope: {planning_scope}")
            if venue_location:
                message_parts.append(f"Venue/location: {venue_location}")
        
        # Live Sound Engineer-specific fields
        elif role_val in ["live_sound_engineer"]:
            event_type_sound = request.form.get("event_type_sound", "").strip()
            venue_size = request.form.get("venue_size", "").strip()
            equipment_needed = request.form.get("equipment_needed", "").strip()
            band_count = request.form.get("band_count", "").strip()
            
            if event_type_sound:
                message_parts.append(f"Event type: {event_type_sound}")
            if venue_size:
                message_parts.append(f"Venue size: {venue_size}")
            if equipment_needed:
                message_parts.append(f"Equipment: {equipment_needed}")
            if band_count:
                message_parts.append(f"Number of performers/bands: {band_count}")
        
        # MC/Host/Hypeman-specific fields
        elif role_val in ["emcee_host_hypeman"]:
            event_type_emcee = request.form.get("event_type_emcee", "").strip()
            hosting_duration = request.form.get("hosting_duration", "").strip()
            style_emcee = request.form.get("style_emcee", "").strip()
            announcements = request.form.get("announcements", "").strip()
            
            if event_type_emcee:
                message_parts.append(f"Event type: {event_type_emcee}")
            if hosting_duration:
                message_parts.append(f"Hosting duration: {hosting_duration} hours")
            if style_emcee:
                message_parts.append(f"Style/preference: {style_emcee}")
            if announcements:
                message_parts.append(f"Special announcements needed: {announcements}")
        
        # Combine message parts with user's message
        full_message = ""
        if message_parts:
            full_message = "\n".join(message_parts)
        if message:
            if full_message:
                full_message += f"\n\nAdditional details:\n{message}"
            else:
                full_message = message
        
        # Create booking request
        req = BookingRequest(
            provider_id=provider.id,
            client_id=current_user.id,
            message=full_message or None,
            preferred_time=preferred_time,
        )
        db.session.add(req)
        db.session.commit()
        
        flash("Booking request sent successfully.", "success")
        return redirect(url_for("bookme_requests"))
    
    return render_template(
        "bookme_book_provider.html",
        provider=provider,
        form_data={},
        follower_count=follower_count,
        is_following=is_following
    )


@app.route("/artists/<username>/book", methods=["GET", "POST"])
@login_required
def book_artist(username):
    artist = User.query.filter_by(username=username).first_or_404()
    is_owner = current_user.id == artist.id

    if request.method == "POST":
        if is_owner:
            flash("You can’t send a booking request to yourself.", "error")
            return redirect(url_for("book_artist", username=username))

        event_title = (request.form.get("event_title") or "").strip()
        event_date = (request.form.get("event_date") or "").strip()
        event_time = (request.form.get("event_time") or "").strip()
        duration_minutes_raw = (request.form.get("duration_minutes") or "").strip()
        location_text = (request.form.get("location_text") or "").strip()
        price_dollars_raw = (request.form.get("price_dollars") or "").strip()
        notes_from_client = (request.form.get("notes_from_client") or "").strip()

        errors = []
        if not event_title:
            errors.append("Please enter an event title or description.")
        if not event_date or not event_time:
            errors.append("Please choose a date and time for the booking.")

        event_datetime = None
        if event_date and event_time:
            try:
                event_datetime = datetime.strptime(f"{event_date} {event_time}", "%Y-%m-%d %H:%M")
            except ValueError:
                errors.append("Event date/time is not in a valid format.")

        duration_minutes = None
        if duration_minutes_raw:
            try:
                duration_minutes = int(duration_minutes_raw)
            except ValueError:
                errors.append("Duration must be a number of minutes.")

        total_cents = None
        if price_dollars_raw:
            try:
                price_dollars = float(price_dollars_raw)
                if price_dollars < 0:
                    errors.append("Price cannot be negative.")
                else:
                    total_cents = int(price_dollars * 100)
            except ValueError:
                errors.append("Price must be a valid number.")

        if errors:
            for msg in errors:
                flash(msg, "danger")
            return render_template("artist_booking.html", artist=artist, form_data=request.form, is_owner=is_owner)

        booking = Booking(
            provider_id=artist.id,
            provider_role=artist.role,
            client_id=current_user.id,
            event_title=event_title,
            event_datetime=event_datetime,
            duration_minutes=duration_minutes,
            location_text=location_text or None,
            total_cents=total_cents,
            notes_from_client=notes_from_client or None,
            status="pending",
        )
        db.session.add(booking)
        db.session.commit()

        flash("Booking request submitted. The artist will review and confirm.", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("artist_booking.html", artist=artist, form_data={}, is_owner=is_owner)


# =========================================================
# Marketplace
# =========================================================
@app.route("/market", endpoint="market_index")
@login_required
def market_index():
    items = Beat.query.filter_by(is_active=True).order_by(Beat.is_featured.desc(), Beat.id.desc()).all()

    provider_profiles = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(User.role.in_(list(BOOKME_PROVIDER_ROLES)))
        .order_by(BookMeProfile.city.asc(), BookMeProfile.display_name.asc())
        .all()
    )

    def profile_has_role(profile, roles: set[RoleEnum]):
        u = profile.user
        return (u is not None) and (u.role in roles)

    studios = [p for p in provider_profiles if profile_has_role(p, {RoleEnum.studio})]
    videographers = [p for p in provider_profiles if profile_has_role(p, {RoleEnum.videographer})]
    talent_roles = {RoleEnum.artist, RoleEnum.dancer_choreographer, RoleEnum.emcee_host_hypeman, RoleEnum.dj}
    talent_profiles = [p for p in provider_profiles if profile_has_role(p, talent_roles)]

    used_ids = {p.id for p in studios + videographers + talent_profiles}
    other_providers = [p for p in provider_profiles if p.id not in used_ids]

    return render_template(
        "market_index.html",
        items=items,
        provider_profiles=provider_profiles,
        studios=studios,
        videographers=videographers,
        talent_profiles=talent_profiles,
        other_providers=other_providers,
        RoleEnum=RoleEnum,
    )


@app.route("/market/my-purchases")
@login_required
def market_my_purchases():
    orders = Order.query.filter_by(buyer_id=current_user.id, status=OrderStatus.paid).order_by(Order.created_at.desc()).all()
    purchases = []
    for o in orders:
        if o.beat:
            purchases.append({"order": o, "beat": o.beat, "producer": User.query.get(o.beat.owner_id)})
    return render_template("market_my_purchases.html", purchases=purchases)


@app.route("/market/buy/<int:beat_id>", methods=["POST"])
@login_required
def market_buy(beat_id):
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    beat = Beat.query.get_or_404(beat_id)

    if hasattr(beat, "is_active") and not beat.is_active:
        flash("This beat is not available for purchase.", "error")
        return redirect(url_for("market_index"))

    seller = User.query.get(beat.owner_id)
    if not seller:
        flash("Seller account not found.", "error")
        return redirect(url_for("market_index"))

    if seller.id == current_user.id:
        flash("You can’t buy your own beat.", "error")
        return redirect(url_for("market_index"))

    if _user_has_paid_for_beat(current_user.id, beat.id):
        flash("You already purchased this beat. Check “My purchases”.", "info")
        return redirect(url_for("market_my_purchases"))

    price_cents = int(beat.price_cents or 0)
    if price_cents < 0:
        flash("Invalid beat price.", "error")
        return redirect(url_for("market_index"))

    if price_cents == 0:
        try:
            with db_txn():
                order = Order(beat_id=beat.id, buyer_id=current_user.id, seller_id=seller.id, amount_cents=0, status=OrderStatus.paid)
                db.session.add(order)
        except IntegrityError:
            flash("This purchase was already processed.", "info")
            return redirect(url_for("market_my_purchases"))

        flash("Added to your purchases!", "success")
        return redirect(url_for("market_my_purchases"))

    buyer_w = get_or_create_wallet(current_user.id, commit=False)
    seller_w = get_or_create_wallet(seller.id, commit=False)

    try:
        with db_txn():
            if _user_has_paid_for_beat(current_user.id, beat.id):
                raise ValueError("already_purchased")
            if wallet_balance_cents(buyer_w) < price_cents:
                raise ValueError("insufficient_funds")

            post_ledger(buyer_w, EntryType.purchase_spend, price_cents, meta=f"buy beat #{beat.id} '{(beat.title or '')[:80]}'")
            post_ledger(seller_w, EntryType.sale_income, price_cents, meta=f"sale beat #{beat.id} to @{current_user.username}")

            order = Order(beat_id=beat.id, buyer_id=current_user.id, seller_id=seller.id, amount_cents=price_cents, status=OrderStatus.paid)
            db.session.add(order)

    except ValueError as e:
        if str(e) == "insufficient_funds":
            flash("Insufficient wallet balance.", "error")
            return redirect(url_for("wallet_home"))
        if str(e) == "already_purchased":
            flash("You already purchased this beat. Check “My purchases”.", "info")
            return redirect(url_for("market_my_purchases"))
        flash("Unable to complete purchase.", "error")
        return redirect(url_for("market_index"))

    except IntegrityError:
        flash("This purchase was already processed.", "info")
        return redirect(url_for("market_my_purchases"))

    flash("Purchase complete! You now have download access.", "success")
    return redirect(url_for("market_my_purchases"))


@app.route("/market/download/<int:beat_id>")
@login_required
def market_download(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    if (beat.owner_id != current_user.id and not _user_has_paid_for_beat(current_user.id, beat_id)):
        flash("You don’t have access to download this file.", "error")
        return redirect(url_for("market_index"))

    if not beat.stems_path:
        flash("No deliverable file available for this beat.", "error")
        return redirect(url_for("market_index"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], beat.stems_path, as_attachment=True)


@app.route("/market/providers.json", endpoint="market_providers_json")
@login_required
def market_providers_json():
    rows = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(
            BookMeProfile.lat.isnot(None),
            BookMeProfile.lng.isnot(None),
            User.role.in_(list(BOOKME_PROVIDER_ROLES)),
        )
        .all()
    )

    payload = []
    for p in rows:
        if not p.user:
            continue
        payload.append({
            "username": p.user.username,
            "display_name": p.display_name,
            "role": p.user.role.value if p.user.role else "",
            "city": p.city or "",
            "state": p.state or "",
            "lat": float(p.lat),
            "lng": float(p.lng),
        })

    return jsonify(payload)


# =========================================================
# Producers Catalog
# =========================================================
@app.route("/producers")
@login_required
def producer_catalog_index():
    all_beats = Beat.query.all()
    producers_map = {}

    for beat in all_beats:
        owner = getattr(beat, "owner", None)
        if not owner:
            continue
        if owner.id not in producers_map:
            producers_map[owner.id] = {"user": owner, "beats": [], "genres": set()}
        producers_map[owner.id]["beats"].append(beat)
        if beat.genre:
            producers_map[owner.id]["genres"].add(beat.genre)

    producers = []
    for data in producers_map.values():
        user = data["user"]
        beats_for_user = data["beats"]
        genres = list(data["genres"])
        prof = BookMeProfile.query.filter_by(user_id=user.id).first()

        producers.append({
            "user": user,
            "display_name": prof.display_name if prof else user.display_name,
            "username": user.username,
            "avatar_url": user.avatar_url,
            "city": prof.city if prof else "",
            "state": prof.state if prof else "",
            "followers_count": UserFollow.query.filter_by(followed_id=user.id).count(),
            "rating": None,
            "rating_count": 0,
            "genres": genres[:3],
            "beats_count": len(beats_for_user),
        })

    producers.sort(key=lambda p: p["beats_count"], reverse=True)
    return render_template("producer_catalog_index.html", producers=producers)


@app.route("/producers/<username>")
@login_required
def producer_catalog_detail(username):
    producer_user = User.query.filter(func.lower(User.username) == username.lower()).first()
    if not producer_user:
        return render_template("producer_catalog_detail.html", producer=None, beats=[], raw_username=username)

    beats_for_producer = Beat.query.filter_by(owner_id=producer_user.id).order_by(Beat.id.desc()).all()
    prof = BookMeProfile.query.filter_by(user_id=producer_user.id).first()

    genres = sorted({b.genre for b in beats_for_producer if b.genre})
    followers_count = UserFollow.query.filter_by(followed_id=producer_user.id).count()
    is_following = UserFollow.query.filter_by(follower_id=current_user.id, followed_id=producer_user.id).first() is not None

    producer_profile = {
        "user": producer_user,
        "display_name": prof.display_name if prof else producer_user.display_name,
        "username": producer_user.username,
        "avatar_url": producer_user.avatar_url,
        "city": prof.city if prof else "",
        "state": prof.state if prof else "",
        "followers_count": followers_count,
        "is_following": is_following,
        "rating": None,
        "rating_count": 0,
        "genres": genres,
        "beats_count": len(beats_for_producer),
    }

    return render_template("producer_catalog_detail.html", producer=producer_profile, beats=beats_for_producer, raw_username=username)


@app.route("/producers/<username>/follow", methods=["POST"])
@login_required
def follow_producer(username):
    return user_follow_toggle(username)


# =========================================================
# Producer Beats
# =========================================================
@app.route("/producer/beats", methods=["GET", "POST"])
@role_required("producer")
def producer_beats():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price_raw = (request.form.get("price_dollars") or "").strip()
        bpm_raw = (request.form.get("bpm") or "").strip()
        genre = (request.form.get("genre") or "").strip()
        cover_file = request.files.get("cover_file")
        preview_file = request.files.get("preview_file")
        stems_file = request.files.get("stems_file")

        errors = []
        if not title:
            errors.append("Title is required.")

        price_cents = 0
        if price_raw:
            try:
                price = Decimal(price_raw)
                if price < 0:
                    errors.append("Price cannot be negative.")
                else:
                    price_cents = int((price * 100).to_integral_value())
            except InvalidOperation:
                errors.append("Price must be a valid number (e.g. 19.99).")

        bpm = None
        if bpm_raw:
            try:
                bpm = int(bpm_raw)
            except ValueError:
                errors.append("BPM must be a whole number (e.g. 130).")

        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("producer_beats"))

        beat = Beat(owner_id=current_user.id, title=title, price_cents=price_cents, bpm=bpm, genre=genre or None, is_active=True)

        if cover_file and cover_file.filename:
            beat.cover_path = _save_file(cover_file, ALLOWED_IMAGE)
        if preview_file and preview_file.filename:
            beat.preview_path = _save_file(preview_file, ALLOWED_AUDIO)
        if stems_file and stems_file.filename:
            beat.stems_path = _save_file(stems_file, ALLOWED_STEMS)

        db.session.add(beat)
        db.session.commit()
        flash("Beat saved to your catalog.", "success")
        return redirect(url_for("producer_beats"))

    beats = Beat.query.filter_by(owner_id=current_user.id).order_by(Beat.id.desc()).all()
    return render_template("producer_beats.html", beats=beats)


@app.route("/producer/beats/<int:beat_id>/delete", methods=["POST"], endpoint="producer_beats_delete")
@role_required("producer")
def producer_beats_delete(beat_id):
    beat = Beat.query.get_or_404(beat_id)

    if beat.owner_id != current_user.id:
        flash("You can't delete another producer's beat.", "error")
        return redirect(url_for("producer_beats"))

    if beat.cover_path:
        _safe_remove(beat.cover_path)
    if beat.preview_path:
        _safe_remove(beat.preview_path)
    if beat.stems_path:
        _safe_remove(beat.stems_path)

    db.session.delete(beat)
    db.session.commit()
    flash("Beat deleted.", "success")
    return redirect(url_for("producer_beats"))


@app.route("/producer/market/mine", endpoint="producer_market_mine")
@role_required("producer")
def producer_market_mine():
    # Get producer's beats
    items = Beat.query.filter_by(owner_id=current_user.id).order_by(Beat.id.desc()).all()
    
    # Calculate sales stats
    orders = Order.query.filter_by(seller_id=current_user.id, status=OrderStatus.paid).all()
    total_sales = len(orders)
    gross_cents = sum(order.amount_cents or 0 for order in orders)
    gross = gross_cents / 100.0
    
    return render_template(
        "producer_market_mine.html",
        items=items,
        total_sales=total_sales,
        gross=gross,
    )


@app.route("/producer/market/delete/<int:beat_id>", methods=["POST"], endpoint="producer_market_delete")
@role_required("producer")
def producer_market_delete(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    
    if beat.owner_id != current_user.id:
        flash("You can only delete your own beats.", "error")
        return redirect(url_for("producer_market_mine"))
    
    db.session.delete(beat)
    db.session.commit()
    flash("Beat deleted from marketplace.", "success")
    return redirect(url_for("producer_market_mine"))


@app.route("/market/upload", methods=["GET", "POST"], endpoint="market_upload")
@app.route("/producer/market/upload", methods=["GET", "POST"], endpoint="producer_market_upload")
@login_required
def market_upload():
    # Only producers can upload beats
    if current_user.role != RoleEnum.producer:
        flash("Only producers can upload beats to the marketplace.", "error")
        return redirect(url_for("market_index"))
    
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price_usd_raw = (request.form.get("price_usd") or "").strip()
        bpm_raw = (request.form.get("bpm") or "").strip()
        genre = (request.form.get("genre") or "").strip()
        license_type = (request.form.get("license") or "standard").strip()
        cover_file = request.files.get("cover_file")
        audio_file = request.files.get("audio_file")
        
        errors = []
        
        if not title:
            errors.append("Title is required.")
        
        price_cents = 0
        if price_usd_raw:
            try:
                price = Decimal(price_usd_raw)
                if price < 0:
                    errors.append("Price cannot be negative.")
                else:
                    price_cents = int((price * 100).to_integral_value())
            except InvalidOperation:
                errors.append("Price must be a valid number (e.g. 29.99).")
        else:
            errors.append("Price is required.")
        
        if not audio_file or not audio_file.filename:
            errors.append("Audio file is required.")
        
        bpm = None
        if bpm_raw:
            try:
                bpm = int(bpm_raw)
                if bpm < 0:
                    errors.append("BPM cannot be negative.")
            except ValueError:
                errors.append("BPM must be a whole number.")
        
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("market_upload.html")
        
        # Create beat record
        beat = Beat(
            owner_id=current_user.id,
            title=title,
            price_cents=price_cents,
            bpm=bpm,
            genre=genre or None,
            license=license_type,
            is_active=True
        )
        
        # Save cover image if provided
        if cover_file and cover_file.filename:
            cover_path = _save_file(cover_file, ALLOWED_IMAGE)
            if cover_path:
                beat.cover_path = cover_path
            else:
                flash("Invalid cover image format. Please use PNG, JPG, or JPEG.", "error")
        
        # Save audio file (used for both preview and stems/deliverable)
        if audio_file and audio_file.filename:
            audio_path = _save_file(audio_file, ALLOWED_AUDIO)
            if audio_path:
                beat.preview_path = audio_path
                beat.stems_path = audio_path  # Use same file for both preview and delivery
            else:
                flash("Invalid audio file format. Please use MP3, WAV, M4A, or OGG.", "error")
                return render_template("market_upload.html")
        
        db.session.add(beat)
        db.session.commit()
        
        flash("Beat uploaded successfully to the marketplace!", "success")
        return redirect(url_for("market_index"))
    
    return render_template("market_upload.html")


# =========================================================
# Tickets (User-facing)
# =========================================================
@app.route("/tickets", endpoint="my_tickets")
@login_required
def my_tickets():
    tickets = SupportTicket.query.filter(SupportTicket.user_id == current_user.id).order_by(SupportTicket.created_at.desc()).all()
    return render_template("my_tickets.html", tickets=tickets, TicketStatus=TicketStatus, TicketType=TicketType)


@app.route("/tickets/<int:ticket_id>", endpoint="my_ticket_detail")
@login_required
def my_ticket_detail(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    if (ticket.user_id != current_user.id) and (current_user.role != RoleEnum.admin):
        abort(403)

    comments = ticket.comments.order_by(SupportTicketComment.created_at.asc()).all()
    return render_template("my_ticket_detail.html", ticket=ticket, comments=comments, TicketStatus=TicketStatus, TicketType=TicketType)


# =========================================================
# Admin Dashboard
# =========================================================
@app.route("/dashboard/admin", endpoint="admin_dashboard")
@role_required("admin")
def admin_dashboard():
    total_users = User.query.filter(User.role != RoleEnum.admin).count()
    total_wallets = Wallet.query.count()
    total_beats = Beat.query.count()
    total_orders = Order.query.count()

    pending_kyc = User.query.filter_by(kyc_status=KYCStatus.pending).count()
    approved_kyc = User.query.filter_by(kyc_status=KYCStatus.approved).count()
    rejected_kyc = User.query.filter_by(kyc_status=KYCStatus.rejected).count()

    total_artists = User.query.filter_by(role=RoleEnum.artist).count()
    total_producers = User.query.filter_by(role=RoleEnum.producer).count()

    total_tickets = SupportTicket.query.count()
    open_tickets = SupportTicket.query.filter_by(status=TicketStatus.open).count()
    in_review_tickets = SupportTicket.query.filter_by(status=TicketStatus.in_review).count()
    resolved_tickets = SupportTicket.query.filter(
        SupportTicket.status.in_([TicketStatus.resolved, TicketStatus.approved, TicketStatus.rejected])
    ).count()

    events = []
    audit_rows = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
    for row in audit_rows:
        events.append({
            "ts": row.created_at,
            "kind": "audit",
            "title": "Wallet access logged",
            "body": f"@{row.admin.username} accessed {'@'+row.user.username if row.user else 'an account'} ({row.action}).",
        })

    ticket_rows = SupportTicket.query.order_by(SupportTicket.created_at.desc()).limit(8).all()
    for t in ticket_rows:
        events.append({
            "ts": t.created_at,
            "kind": "ticket",
            "title": f"Ticket #{t.id} · {t.status.value.replace('_',' ').title()}",
            "body": f"@{t.user.username if t.user else 'Unknown'} · {t.subject}",
        })

    events.sort(key=lambda e: e["ts"], reverse=True)
    recent_events = events[:8]

    return render_template(
        "dash_admin.html",
        total_users=total_users,
        total_wallets=total_wallets,
        total_beats=total_beats,
        total_orders=total_orders,
        pending_kyc=pending_kyc,
        approved_kyc=approved_kyc,
        rejected_kyc=rejected_kyc,
        total_artists=total_artists,
        total_producers=total_producers,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        in_review_tickets=in_review_tickets,
        resolved_tickets=resolved_tickets,
        recent_events=recent_events,
        KYCStatus=KYCStatus,
        RoleEnum=RoleEnum,
        TicketStatus=TicketStatus,
    )


@app.route("/dashboard/admin/superadmin/unlock", methods=["GET", "POST"], endpoint="superadmin_unlock")
@superadmin_required
def superadmin_unlock():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        if _owner_unlock_blocked(ip):
            flash("Too many incorrect passcode attempts. Please wait a few minutes and try again.", "error")
            return redirect(url_for("superadmin_unlock"))

        passphrase = ((request.form.get("owner_pass") or "").strip()
                      or (request.form.get("passphrase") or "").strip())

        if not passphrase:
            flash("Please enter the owner passphrase.", "error")
            return redirect(url_for("superadmin_unlock"))

        if check_password_hash(OWNER_PANEL_PASS_HASH_EFFECTIVE, passphrase):
            _owner_unlock_clear(ip)
            session[OWNER_UNLOCK_SESSION_KEY] = time()
            flash("Owner panel unlocked for this session.", "success")
            return redirect(url_for("superadmin_dashboard"))

        _owner_unlock_fail(ip)
        flash("Incorrect passphrase. Please try again.", "error")

    return render_template("superadmin_unlock.html")


@app.route("/dashboard/admin/superadmin/change-passcode", methods=["GET", "POST"], endpoint="superadmin_change_passcode")
@superadmin_required
def superadmin_change_passcode():
    global OWNER_PANEL_PASS_HASH_EFFECTIVE

    if OWNER_PASS_MANAGED_BY_ENV:
        flash(
            "Owner passcode is managed by server environment secrets in this deployment. "
            "Update OWNER_PANEL_PASS_HASH (recommended) or OWNER_PANEL_PASS in your host settings.",
            "error",
        )
        return redirect(url_for("superadmin_dashboard"))

    if request.method == "POST":
        current_code = (request.form.get("current_passcode") or "").strip()
        new_code = (request.form.get("new_passcode") or "").strip()
        confirm_code = (request.form.get("confirm_passcode") or "").strip()

        if not check_password_hash(OWNER_PANEL_PASS_HASH_EFFECTIVE, current_code):
            flash("Current owner passcode is incorrect.", "error")
            return redirect(url_for("superadmin_change_passcode"))

        errors = []
        if len(new_code) < 8:
            errors.append("Passcode must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", new_code):
            errors.append("Passcode must contain at least one letter.")
        if not re.search(r"\d", new_code):
            errors.append("Passcode must contain at least one number.")
        if new_code != confirm_code:
            errors.append("New passcode and confirmation do not match.")

        if errors:
            flash(" ".join(errors), "error")
            return redirect(url_for("superadmin_change_passcode"))

        new_hash = generate_password_hash(new_code)
        _save_owner_pass_hash_to_instance(new_hash)
        OWNER_PANEL_PASS_HASH_EFFECTIVE = new_hash

        flash("Owner passcode updated and saved securely.", "success")
        return redirect(url_for("superadmin_dashboard"))

    return render_template("superadmin_change_passcode.html")


@app.route("/dashboard/admin/owner", endpoint="superadmin_dashboard")
@superadmin_required
def superadmin_dashboard():
    if not owner_panel_unlocked():
        return redirect(url_for("superadmin_unlock"))

    total_users = User.query.filter(User.role != RoleEnum.admin).count()
    total_wallets = Wallet.query.count()
    total_beats = Beat.query.count()
    total_orders = Order.query.count()

    total_wallet_balance_cents = 0
    for w in Wallet.query.join(User, Wallet.user_id == User.id).all():
        total_wallet_balance_cents += wallet_balance_cents(w)

    total_wallet_balance = total_wallet_balance_cents / 100.0

    total_deposits_cents = (
        db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .filter(LedgerEntry.entry_type == EntryType.deposit)
        .scalar() or 0
    )
    total_withdrawals_cents = (
        db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .filter(LedgerEntry.entry_type == EntryType.withdrawal)
        .scalar() or 0
    )
    total_sales_cents = (
        db.session.query(func.coalesce(func.sum(Order.amount_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )

    total_deposits = total_deposits_cents / 100.0
    total_withdrawals = total_withdrawals_cents / 100.0
    total_sales = total_sales_cents / 100.0
    net_wallet_dollars = (total_deposits_cents - total_withdrawals_cents) / 100.0

    return render_template(
        "dash_superadmin.html",
        APP_ENV=APP_ENV,
        IS_DEV=IS_DEV,
        total_users=total_users,
        total_wallets=total_wallets,
        total_beats=total_beats,
        total_orders=total_orders,
        total_wallet_balance=total_wallet_balance,
        total_deposits=total_deposits,
        total_withdrawals=total_withdrawals,
        total_sales=total_sales,
        net_wallet_dollars=net_wallet_dollars,
        bar_labels=["Users", "Wallets", "Beats", "Orders"],
        bar_values=[total_users, total_wallets, total_beats, total_orders],
        flow_labels=["Deposits ($)", "Withdrawals ($)", "Sales ($)"],
        flow_values=[total_deposits, total_withdrawals, total_sales],
    )


# =========================================================
# Dashboards routing
# =========================================================
@app.route("/dashboard")
@login_required
def route_to_dashboard():
    role = current_user.role.value

    if role == "admin":
        endpoint = "admin_dashboard"
    elif role == "artist":
        endpoint = "artist_dashboard"
    elif role == "producer":
        endpoint = "producer_dashboard"
    elif role == "studio":
        endpoint = "studio_dashboard"
    elif role == "videographer":
        endpoint = "videographer_dashboard"
    elif role == "designer":
        endpoint = "designer_dashboard"
    elif role == "engineer":
        endpoint = "engineer_dashboard"
    elif role == "manager":
        endpoint = "manager_dashboard"
    elif role == "vendor":
        endpoint = "vendor_dashboard"
    elif role == "funder":
        endpoint = "funder_dashboard"
    elif role == "client":
        endpoint = "client_dashboard"
    elif is_service_provider(current_user):
        endpoint = "provider_dashboard"
    else:
        endpoint = "home"

    return redirect(url_for(endpoint))

@app.route("/dashboard/artist", endpoint="artist_dashboard")
@role_required("artist")
def artist_dashboard():
    # Social
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()

    # Wallet
    w = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(w) / 100.0
    recent_txns = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
        .limit(6)
        .all()
    )

    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    portfolio_count = prof.portfolio_items.count() if prof else 0

    # Requests (artist as provider + artist as client)
    incoming_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .order_by(BookingRequest.created_at.desc())
        .limit(6)
        .all()
    )
    outgoing_requests = (
        BookingRequest.query
        .filter_by(client_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(6)
        .all()
    )

    # Bookings (upcoming + recent) — artist can be provider and/or client
    now = datetime.utcnow()

    upcoming_as_provider = (
        Booking.query
        .filter(Booking.provider_id == current_user.id, Booking.event_datetime >= now)
        .order_by(Booking.event_datetime.asc())
        .limit(6)
        .all()
    )
    upcoming_as_client = (
        Booking.query
        .filter(Booking.client_id == current_user.id, Booking.event_datetime >= now)
        .order_by(Booking.event_datetime.asc())
        .limit(6)
        .all()
    )

    recent_bookings = (
        Booking.query
        .filter((Booking.provider_id == current_user.id) | (Booking.client_id == current_user.id))
        .order_by(Booking.created_at.desc())
        .limit(6)
        .all()
    )

    # Counts for small stat chips
    incoming_requests_count = BookingRequest.query.filter_by(provider_id=current_user.id, status=BookingStatus.pending).count()
    outgoing_requests_count = BookingRequest.query.filter_by(client_id=current_user.id).count()

    return render_template(
        "dash_artist.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        portfolio_count=portfolio_count,

        followers_count=followers_count,
        following_count=following_count,

        wallet_balance=wallet_balance,
        recent_txns=recent_txns,

        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        incoming_requests_count=incoming_requests_count,
        outgoing_requests_count=outgoing_requests_count,

        upcoming_as_provider=upcoming_as_provider,
        upcoming_as_client=upcoming_as_client,
        recent_bookings=recent_bookings,
    )


@app.route("/dashboard/producer", endpoint="producer_dashboard")
@role_required("producer")
def producer_dashboard():
    # Producer-specific stats
    total_beats = Beat.query.filter_by(owner_id=current_user.id, is_active=True).count()
    
    # Sales stats
    sales = Order.query.filter_by(seller_id=current_user.id, status=OrderStatus.paid).all()
    sales_count = len(sales)
    revenue_cents = sum(order.amount_cents or 0 for order in sales)
    revenue = revenue_cents / 100.0
    
    # Wallet balance
    w = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(w) / 100.0
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    return render_template(
        "dash_producer.html",
        total_beats=total_beats,
        sales_count=sales_count,
        revenue=revenue,
        wallet_balance=wallet_balance,
        followers_count=followers_count,
        following_count=following_count,
    )


@app.route("/dashboard/provider", endpoint="provider_dashboard")
@login_required
def provider_dashboard():
    if not is_service_provider(current_user):
        flash("This dashboard is only available for service providers.", "error")
        return redirect(url_for("route_to_dashboard"))
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests
    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_provider.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
    )


@app.route("/dashboard/studio", endpoint="studio_dashboard")
@role_required("studio")
def studio_dashboard():
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests
    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_studio.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
    )


@app.route("/studio/profile/toggle-live", methods=["POST"], endpoint="studio_toggle_live")
@role_required("studio")
def studio_toggle_live():
    """Toggle studio profile live/active status"""
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    if not prof:
        flash("Please create your BookMe profile first.", "error")
        return redirect(url_for("bookme_profile"))
    
    # Toggle is_visible status
    prof.is_visible = not prof.is_visible
    db.session.commit()
    
    status = "activated" if prof.is_visible else "deactivated"
    flash(f"Studio profile {status}. {'Your services are now visible on the marketplace.' if prof.is_visible else 'Your services are hidden from the marketplace, but your profile is still visible for following and portfolio viewing.'}", "success")
    
    return redirect(url_for("studio_dashboard"))


@app.route("/profile/toggle-live", methods=["POST"], endpoint="provider_toggle_live")
@login_required
def provider_toggle_live():
    """Toggle service provider profile live/active status (generic for all providers)"""
    if not is_service_provider(current_user):
        flash("This feature is only available for service providers.", "error")
        return redirect(url_for("route_to_dashboard"))
    
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    if not prof:
        flash("Please create your BookMe profile first.", "error")
        return redirect(url_for("bookme_profile"))
    
    # Toggle is_visible status
    prof.is_visible = not prof.is_visible
    db.session.commit()
    
    status = "activated" if prof.is_visible else "deactivated"
    role_name = get_role_display(current_user.role)
    flash(f"Profile {status}. {'Your services are now visible on the marketplace.' if prof.is_visible else 'Your services are hidden from the marketplace, but your profile is still visible for following and portfolio viewing.'}", "success")
    
    # Redirect to appropriate dashboard based on role
    role = current_user.role.value
    if role == "videographer":
        return redirect(url_for("videographer_dashboard"))
    elif role == "designer":
        return redirect(url_for("designer_dashboard"))
    elif role == "engineer":
        return redirect(url_for("engineer_dashboard"))
    elif role == "manager":
        return redirect(url_for("manager_dashboard"))
    elif role == "vendor":
        return redirect(url_for("vendor_dashboard"))
    elif role == "studio":
        return redirect(url_for("studio_dashboard"))
    else:
        return redirect(url_for("provider_dashboard"))


@app.route("/studio/crm", endpoint="studio_crm")
@role_required("studio")
def studio_crm():
    """Studio CRM - Manage all bookings"""
    # Get all bookings as provider
    all_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.event_datetime.desc().nullslast())
        .all()
    )
    
    # Get all booking requests
    all_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .all()
    )
    
    # Statistics
    pending_requests = sum(1 for r in all_requests if r.status == BookingStatus.pending)
    confirmed_bookings = sum(1 for b in all_bookings if b.status == "confirmed")
    upcoming_bookings = [
        b for b in all_bookings 
        if b.event_datetime and b.event_datetime > datetime.utcnow() and b.status in ["pending", "confirmed"]
    ]
    
    # Group bookings by status
    bookings_by_status = {
        "pending": [b for b in all_bookings if b.status == "pending"],
        "confirmed": [b for b in all_bookings if b.status == "confirmed"],
        "completed": [b for b in all_bookings if b.status == "completed"],
        "cancelled": [b for b in all_bookings if b.status == "cancelled"],
    }
    
    return render_template(
        "studio_crm.html",
        all_bookings=all_bookings,
        all_requests=all_requests,
        pending_requests=pending_requests,
        confirmed_bookings=confirmed_bookings,
        upcoming_bookings=upcoming_bookings,
        bookings_by_status=bookings_by_status,
        BookingStatus=BookingStatus,
    )


def is_time_blocked(studio_id: int, date: datetime.date, time_str: str) -> bool:
    """Check if a specific date/time is blocked for a studio"""
    try:
        check_date = date
        check_time = None
        
        # Parse the preferred time string (can be various formats)
        # Try different formats
        if " " in time_str:
            # Format: "YYYY-MM-DD HH:MM" or "YYYY-MM-DD HH:MM AM/PM"
            parts = time_str.split(" ", 1)
            try:
                check_date = datetime.strptime(parts[0], "%Y-%m-%d").date()
                time_part = parts[1]
                # Try 24-hour format first
                try:
                    check_time = datetime.strptime(time_part, "%H:%M").time()
                except ValueError:
                    # Try 12-hour format
                    try:
                        check_time = datetime.strptime(time_part, "%I:%M %p").time()
                    except ValueError:
                        # Try without seconds
                        try:
                            check_time = datetime.strptime(time_part, "%I:%M%p").time()
                        except ValueError:
                            pass
            except ValueError:
                pass
        
        if check_time is None:
            # Try to parse as just time
            try:
                check_time = datetime.strptime(time_str, "%H:%M").time()
            except ValueError:
                try:
                    check_time = datetime.strptime(time_str, "%I:%M %p").time()
                except ValueError:
                    # Can't parse, assume not blocked
                    return False
        
        # Check for blocked slots that overlap with this time
        blocked_slots = StudioAvailability.query.filter_by(
            studio_id=studio_id,
            available_date=check_date,
            is_available=False
        ).all()
        
        for slot in blocked_slots:
            # Check if the requested time falls within a blocked slot
            # Use < for end_time so bookings at the exact end time are allowed
            if slot.start_time <= check_time < slot.end_time:
                return True
        
        return False
    except (ValueError, AttributeError, Exception):
        # If we can't parse the time, assume it's not blocked (let other validation handle it)
        return False


@app.route("/studio/availability", methods=["GET", "POST"], endpoint="studio_availability")
@role_required("studio")
def studio_availability():
    """Studio availability calendar management"""
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "add_slot":
            date_str = request.form.get("date")
            start_time_str = request.form.get("start_time")
            end_time_str = request.form.get("end_time")
            notes = request.form.get("notes", "").strip()
            slot_type = request.form.get("slot_type", "available")  # "available" or "blocked"
            
            try:
                available_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                start_time = datetime.strptime(start_time_str, "%H:%M").time()
                end_time = datetime.strptime(end_time_str, "%H:%M").time()
                
                if end_time <= start_time:
                    flash("End time must be after start time.", "error")
                    return redirect(url_for("studio_availability"))
                
                slot = StudioAvailability(
                    studio_id=current_user.id,
                    available_date=available_date,
                    start_time=start_time,
                    end_time=end_time,
                    notes=notes,
                    is_available=(slot_type == "available"),
                )
                db.session.add(slot)
                db.session.commit()
                flash(f"{'Availability' if slot_type == 'available' else 'Blocked'} slot added.", "success")
            except ValueError as e:
                flash("Invalid date or time format.", "error")
        
        elif action == "delete_slot":
            slot_id = request.form.get("slot_id")
            slot = StudioAvailability.query.filter_by(
                id=slot_id, studio_id=current_user.id
            ).first()
            if slot:
                db.session.delete(slot)
                db.session.commit()
                flash("Availability slot removed.", "success")
            else:
                flash("Slot not found.", "error")
        
        elif action == "toggle_slot":
            slot_id = request.form.get("slot_id")
            slot = StudioAvailability.query.filter_by(
                id=slot_id, studio_id=current_user.id
            ).first()
            if slot:
                slot.is_available = not slot.is_available
                db.session.commit()
                flash("Availability slot updated.", "success")
            else:
                flash("Slot not found.", "error")
        
        return redirect(url_for("studio_availability"))
    
    # Get all availability slots
    availability_slots = (
        StudioAvailability.query
        .filter_by(studio_id=current_user.id)
        .order_by(StudioAvailability.available_date.asc(), StudioAvailability.start_time.asc())
        .all()
    )
    
    # Group by date
    slots_by_date = {}
    for slot in availability_slots:
        date_key = slot.available_date.isoformat()
        if date_key not in slots_by_date:
            slots_by_date[date_key] = []
        slots_by_date[date_key].append(slot)
    
    return render_template(
        "studio_availability.html",
        availability_slots=availability_slots,
        slots_by_date=slots_by_date,
    )


@app.route("/dashboard/videographer", endpoint="videographer_dashboard")
@role_required("videographer")
def videographer_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests - detailed list
    incoming_requests_count = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    incoming_requests_list = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .order_by(BookingRequest.created_at.desc())
        .limit(10)
        .all()
    )
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Upcoming bookings (future dates)
    now = datetime.utcnow()
    upcoming_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.event_datetime >= now)
        .filter(Booking.status.in_(["accepted", "confirmed", "pending"]))
        .order_by(Booking.event_datetime.asc())
        .limit(10)
        .all()
    )
    upcoming_bookings_count = len(upcoming_bookings)
    
    # Active projects (accepted bookings)
    active_projects = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed"]))
        .filter(Booking.event_datetime >= now)
        .count()
    )
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Accepted bookings (active & upcoming jobs)
    accepted_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed"]))
        .order_by(Booking.event_datetime.asc())
        .limit(20)
        .all()
    )
    
    # Earnings this month
    start_of_month = datetime(now.year, now.month, 1)
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed", "completed"]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Total earnings
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed", "completed"]))
        .scalar() or 0
    )
    total_earnings = total_earnings_cents / 100.0
    
    # Wallet balance
    w = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(w) / 100.0
    
    # Transaction history (from wallet)
    recent_transactions = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Portfolio items
    portfolio_items = []
    if prof:
        portfolio_items = (
            prof.portfolio_items
            .order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc())
            .limit(12)
            .all()
        )
    
    # Average rating (placeholder - no review system yet)
    average_rating = None
    rating_count = 0
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_videographer.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests_count,
        incoming_requests_list=incoming_requests_list,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
        upcoming_bookings=upcoming_bookings,
        upcoming_bookings_count=upcoming_bookings_count,
        active_projects=active_projects,
        accepted_bookings=accepted_bookings,
        earnings_this_month=earnings_this_month,
        total_earnings=total_earnings,
        wallet_balance=wallet_balance,
        recent_transactions=recent_transactions,
        portfolio_items=portfolio_items,
        average_rating=average_rating,
        rating_count=rating_count,
        BookingStatus=BookingStatus,
    )


@app.route("/dashboard/designer", endpoint="designer_dashboard")
@role_required("designer")
def designer_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests - detailed list
    incoming_requests_count = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    incoming_requests_list = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .order_by(BookingRequest.created_at.desc())
        .limit(10)
        .all()
    )
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Pending approvals (bookings waiting for client approval)
    pending_approvals = Booking.query.filter_by(
        provider_id=current_user.id,
        status="pending"
    ).count()
    
    # Active projects (accepted bookings)
    now = datetime.utcnow()
    active_projects = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed"]))
        .count()
    )
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Accepted bookings (active projects with workflow stages)
    accepted_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed"]))
        .order_by(Booking.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Earnings this month
    start_of_month = datetime(now.year, now.month, 1)
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed", "completed"]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Total earnings
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_(["accepted", "confirmed", "completed"]))
        .scalar() or 0
    )
    total_earnings = total_earnings_cents / 100.0
    
    # Wallet balance
    w = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(w) / 100.0
    
    # Transaction history
    recent_transactions = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Portfolio items
    portfolio_items = []
    if prof:
        portfolio_items = (
            prof.portfolio_items
            .order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc())
            .limit(12)
            .all()
        )
    
    # Average rating (placeholder)
    average_rating = None
    rating_count = 0
    
    # Specialties (from service_types)
    specialties = []
    if prof and prof.service_types:
        specialties = [s.strip() for s in prof.service_types.split(",") if s.strip()]
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_designer.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests_count,
        incoming_requests_list=incoming_requests_list,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        pending_approvals=pending_approvals,
        active_projects=active_projects,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
        accepted_bookings=accepted_bookings,
        earnings_this_month=earnings_this_month,
        total_earnings=total_earnings,
        wallet_balance=wallet_balance,
        recent_transactions=recent_transactions,
        portfolio_items=portfolio_items,
        average_rating=average_rating,
        rating_count=rating_count,
        specialties=specialties,
        BookingStatus=BookingStatus,
    )


@app.route("/dashboard/engineer", endpoint="engineer_dashboard")
@role_required("engineer")
def engineer_dashboard():
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests
    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_engineer.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
    )


@app.route("/dashboard/manager", endpoint="manager_dashboard")
@role_required("manager")
def manager_dashboard():
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests
    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_manager.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
    )


@app.route("/dashboard/vendor", endpoint="vendor_dashboard")
@role_required("vendor")
def vendor_dashboard():
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Booking requests
    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status="pending"
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status="pending"
    ).count()
    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    
    return render_template(
        "dash_vendor.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        followers_count=followers_count,
        following_count=following_count,
        artist_can_take_gigs=artist_can_take_gigs,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        client_recent_bookings=client_recent_bookings,
    )


@app.route("/dashboard/funder", endpoint="funder_dashboard")
@role_required("funder")
def funder_dashboard():
    w = get_or_create_wallet(current_user.id)
    balance = wallet_balance_cents(w) / 100.0
    txns = (LedgerEntry.query.filter_by(wallet_id=w.id)
            .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
            .limit(25).all())
    purchases_count = Order.query.filter_by(buyer_id=current_user.id, status=OrderStatus.paid).count()
    return render_template("dash_funder.html", balance=balance, txns=txns, purchases_count=purchases_count)


@app.route("/dashboard/client", endpoint="client_dashboard")
@role_required("client")
def client_dashboard():
    w = get_or_create_wallet(current_user.id)
    balance = wallet_balance_cents(w) / 100.0

    outgoing_requests_count = BookingRequest.query.filter_by(client_id=current_user.id).count()
    outgoing_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()

    recent_requests = (BookingRequest.query.filter_by(client_id=current_user.id)
                       .order_by(BookingRequest.created_at.desc()).limit(6).all())
    recent_bookings = (Booking.query.filter_by(client_id=current_user.id)
                       .order_by(Booking.event_datetime.desc().nullslast()).limit(6).all())

    purchases_count = Order.query.filter_by(buyer_id=current_user.id, status=OrderStatus.paid).count()

    return render_template(
        "dash_client.html",
        balance=balance,
        outgoing_requests_count=outgoing_requests_count,
        outgoing_bookings_count=outgoing_bookings_count,
        recent_requests=recent_requests,
        recent_bookings=recent_bookings,
        purchases_count=purchases_count,
        BookingStatus=BookingStatus,
    )


# =========================================================
# Opportunities (ONE route only: GET+POST)
# =========================================================
@app.route("/opportunities", methods=["GET", "POST"], endpoint="opportunities")
@login_required
def opportunities():
    if request.method == "POST":
        interest_type = (request.form.get("interest_type") or "").strip().lower()
        goal_amount = (request.form.get("goal_amount") or "").strip()
        program_type = (request.form.get("program_type") or "").strip()
        location = (request.form.get("location") or "").strip()
        details = (request.form.get("details") or "").strip()

        if not interest_type:
            flash("Please choose whether you're interested in Loans or Scholarships.", "error")
            return redirect(url_for("opportunities"))

        if interest_type == "loan":
            subject = f"[OPPORTUNITIES] Creative loan interest from @{current_user.username}"
        elif interest_type == "scholarship":
            subject = f"[OPPORTUNITIES] Scholarship/program interest from @{current_user.username}"
        else:
            subject = f"[OPPORTUNITIES] Interest from @{current_user.username}"

        desc_lines = [f"Interest type: {interest_type}"]
        if goal_amount:
            desc_lines.append(f"Goal amount (approx): {goal_amount}")
        if program_type:
            desc_lines.append(f"Program type: {program_type}")
        if location:
            desc_lines.append(f"Location preference: {location}")
        if details:
            desc_lines.append("")
            desc_lines.append("Details / goals:")
            desc_lines.append(details)

        description = "\n".join(desc_lines)

        admin_user = User.query.filter_by(username="admin").first()
        created_by_id = admin_user.id if admin_user else current_user.id

        ticket = SupportTicket(
            user_id=current_user.id,
            created_by_admin_id=created_by_id,
            type=TicketType.other,
            status=TicketStatus.open,
            priority="low",
            subject=subject,
            description=description,
        )
        db.session.add(ticket)
        db.session.commit()

        flash("Thanks! Track status under “My tickets”.", "success")
        return redirect(url_for("opportunities"))

    meta = _load_opp_video_meta()
    filename = _current_opp_video_filename()
    video_url = url_for("opportunities_video_media") if filename else None
    return render_template("opportunities.html", meta=meta, video_url=video_url)


# =========================================================
# Dev helper
# =========================================================
@app.route("/whoami")
@login_required
def whoami():
    return (
        f"id={current_user.id}, username={current_user.username}, "
        f"role={current_user.role.value}, "
        f"kyc={current_user.kyc_status.value}, "
        f"active={current_user.is_active_col}"
    )


# =========================================================
# Compatibility endpoints (fix template BuildError)
# =========================================================
@app.route("/market/producers", endpoint="market_producer_catalog")
@login_required
def market_producer_catalog():
    # template calls url_for('market_producer_catalog')
    return redirect(url_for("producer_catalog_index"))


@app.route("/dashboard/admin/users", endpoint="admin_users")
@role_required("admin")
def admin_users():
    page = request.args.get("page", 1, type=int)
    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip()
    active = (request.args.get("active") or "").strip()

    query = User.query

    if q:
        like = f"%{q}%"
        query = query.filter(
            (User.username.ilike(like)) |
            (User.email.ilike(like)) |
            (User.full_name.ilike(like)) |
            (User.artist_name.ilike(like))
        )

    if role:
        try:
            query = query.filter(User.role == RoleEnum(role))
        except Exception:
            pass

    if active:
        val = active.lower() in ("1", "true", "yes", "on")
        query = query.filter(User.is_active_col.is_(val))

    if status:
        try:
            query = query.filter(User.kyc_status == KYCStatus(status))
        except Exception:
            pass

    query = query.order_by(User.id.desc())

    # Flask-SQLAlchemy paginate
    pagination = query.paginate(page=page, per_page=25, error_out=False)

    return render_template(
        "admin_users.html",
        users=pagination.items,
        pagination=pagination,
        q=q,
        role=role,
        status=status,
        active=active,
        RoleEnum=RoleEnum,
        KYCStatus=KYCStatus,
    )


@app.route("/dashboard/admin/users/<int:user_id>", endpoint="admin_user_detail")
@app.route("/dashboard/admin/user/<int:user_id>", endpoint="admin_user")
@role_required("admin")
def admin_user_detail(user_id: int):
    u = User.query.get_or_404(user_id)
    return render_template("admin_user_detail.html", user=u, u=u, RoleEnum=RoleEnum, KYCStatus=KYCStatus)


@app.route("/dashboard/admin/kyc", endpoint="admin_kyc")
@role_required("admin")
def admin_kyc():
    """Admin KYC review queue"""
    pending = User.query.filter_by(kyc_status=KYCStatus.pending).order_by(User.id.desc()).all()
    approved = User.query.filter_by(kyc_status=KYCStatus.approved).order_by(User.id.desc()).limit(50).all()
    rejected = User.query.filter_by(kyc_status=KYCStatus.rejected).order_by(User.id.desc()).limit(50).all()
    
    return render_template(
        "admin_kyc.html",
        pending=pending,
        approved=approved,
        rejected=rejected,
        KYCStatus=KYCStatus,
    )


@app.route("/dashboard/admin/kyc/<int:user_id>/<action>", methods=["POST"], endpoint="admin_kyc_update")
@app.route("/dashboard/admin/kyc/<int:user_id>/<action>", methods=["GET", "POST"], endpoint="admin_kyc_action")
@role_required("admin")
def admin_kyc_update(user_id: int, action: str):
    """Update KYC status for a user (handles both admin_kyc_update and admin_kyc_action endpoints)"""
    if request.method == "GET":
        # For GET requests on admin_kyc_action, redirect to KYC page
        return redirect(url_for("admin_kyc"))
    
    user = User.query.get_or_404(user_id)
    
    if action == "approve":
        user.kyc_status = KYCStatus.approved
        flash(f"KYC approved for @{user.username}", "success")
    elif action == "reject":
        user.kyc_status = KYCStatus.rejected
        flash(f"KYC rejected for @{user.username}", "warning")
    else:
        flash("Invalid action", "error")
        return redirect(url_for("admin_kyc"))
    
    db.session.commit()
    return redirect(url_for("admin_kyc"))


@app.route("/dashboard/admin/transactions", endpoint="admin_transactions")
@role_required("admin")
def admin_transactions():
    """Admin transactions and audit view"""
    from sqlalchemy import func
    
    # Get statistics by entry type
    stats_query = (
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id).label('count'),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0).label('sum_cents')
        )
        .group_by(LedgerEntry.entry_type)
        .order_by(LedgerEntry.entry_type)
        .all()
    )
    stats = [(row.entry_type, row.count, row.sum_cents) for row in stats_query]
    
    # Search functionality
    q = (request.args.get("q") or "").strip()
    found_user = None
    if q:
        found_user = User.query.filter(
            func.lower(User.username) == q.lower().lstrip("@")
        ).first()
    
    # Recent audit logs
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()
    
    return render_template(
        "admin_transactions.html",
        stats=stats,
        q=q,
        found_user=found_user,
        audit_logs=audit_logs,
        EntryType=EntryType,
    )


@app.route("/dashboard/admin/tickets", endpoint="admin_tickets")
@role_required("admin")
def admin_tickets():
    """Admin support tickets management"""
    page = request.args.get("page", 1, type=int)
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    
    query = SupportTicket.query
    
    # Filter by username if provided
    if q:
        user = User.query.filter(func.lower(User.username) == q.lower().lstrip("@")).first()
        if user:
            query = query.filter(SupportTicket.user_id == user.id)
        else:
            # If user not found, return empty results
            query = query.filter(SupportTicket.id == -1)
    
    # Filter by status if provided
    if status:
        try:
            query = query.filter(SupportTicket.status == TicketStatus(status))
        except ValueError:
            pass
    
    # Order by creation date (newest first)
    query = query.order_by(SupportTicket.created_at.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=25, error_out=False)
    
    return render_template(
        "admin_tickets.html",
        tickets=pagination.items,
        pagination=pagination,
        q=q,
        status=status,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )


@app.route("/dashboard/admin/reports", endpoint="admin_reports")
@role_required("admin")
def admin_reports():
    """Admin financial and activity reports"""
    from sqlalchemy import func
    
    # Calculate total deposits, withdrawals, and sales
    total_deposits_cents = (
        db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .filter(LedgerEntry.entry_type == EntryType.deposit)
        .scalar() or 0
    )
    total_withdrawals_cents = (
        db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .filter(LedgerEntry.entry_type == EntryType.withdrawal)
        .scalar() or 0
    )
    total_sales_cents = (
        db.session.query(func.coalesce(func.sum(Order.amount_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )
    
    totals = {
        'deposits': total_deposits_cents / 100.0,
        'withdrawals': total_withdrawals_cents / 100.0,
        'sales': total_sales_cents / 100.0,
    }
    
    # Ticket statistics
    ticket_total = SupportTicket.query.count()
    ticket_open = SupportTicket.query.filter_by(status=TicketStatus.open).count()
    ticket_in_review = SupportTicket.query.filter_by(status=TicketStatus.in_review).count()
    ticket_resolved = SupportTicket.query.filter(
        SupportTicket.status.in_([TicketStatus.resolved, TicketStatus.approved, TicketStatus.rejected])
    ).count()
    
    # Wallet activity by entry type
    wallet_stats_query = (
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id).label('count'),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0).label('sum_cents')
        )
        .group_by(LedgerEntry.entry_type)
        .order_by(LedgerEntry.entry_type)
        .all()
    )
    wallet_stats = [(row.entry_type, row.count, row.sum_cents) for row in wallet_stats_query]
    
    # Users by role (excluding admins)
    role_stats_query = (
        db.session.query(
            User.role,
            func.count(User.id).label('count')
        )
        .filter(User.role != RoleEnum.admin)
        .group_by(User.role)
        .order_by(User.role)
        .all()
    )
    role_stats = [(row.role, row.count) for row in role_stats_query]
    
    return render_template(
        "admin_reports.html",
        totals=totals,
        ticket_total=ticket_total,
        ticket_open=ticket_open,
        ticket_in_review=ticket_in_review,
        ticket_resolved=ticket_resolved,
        wallet_stats=wallet_stats,
        role_stats=role_stats,
        EntryType=EntryType,
    )


@app.route("/dashboard/admin/team", methods=["GET", "POST"], endpoint="admin_team")
@superadmin_required
def admin_team():
    """Admin team management - create and manage admin accounts"""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        
        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("admin_team"))
        
        if not password:
            flash("Password is required.", "error")
            return redirect(url_for("admin_team"))
        
        # Check if username already exists
        existing = User.query.filter(func.lower(User.username) == username.lower()).first()
        if existing:
            flash(f"Username @{username} already exists.", "error")
            return redirect(url_for("admin_team"))
        
        # Validate password
        pw_errors = []
        if len(password) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", password):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", password):
            pw_errors.append("Password must contain at least one number.")
        
        if pw_errors:
            for e in pw_errors:
                flash(e, "error")
            return redirect(url_for("admin_team"))
        
        # Create new admin user
        new_admin = User(
            username=username,
            email=f"{username}@beatfund.local",  # Placeholder email
            role=RoleEnum.admin,
            full_name=f"Admin {username}",
            is_superadmin=False  # Regular admin, not superadmin
        )
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        
        flash(f"Admin account @{username} created successfully.", "success")
        return redirect(url_for("admin_team"))
    
    # GET request - show admin team page
    admins = User.query.filter_by(role=RoleEnum.admin).order_by(User.id.desc()).all()
    
    return render_template(
        "admin_team.html",
        admins=admins,
    )


@app.route("/dashboard/admin/users/<int:user_id>/toggle-active", methods=["POST"], endpoint="admin_user_toggle_active")
@superadmin_required
def admin_user_toggle_active(user_id: int):
    """Toggle admin user active/inactive status"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deactivating yourself
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_team"))
    
    # Only allow toggling admin accounts
    if user.role != RoleEnum.admin:
        flash("This endpoint is only for admin accounts.", "error")
        return redirect(url_for("admin_team"))
    
    # Toggle active status
    user.is_active_col = not user.is_active_col
    db.session.commit()
    
    status = "activated" if user.is_active_col else "deactivated"
    flash(f"Admin @{user.username} has been {status}.", "success")
    return redirect(url_for("admin_team"))


@app.route("/dashboard/admin/bookme", endpoint="admin_bookme")
@role_required("admin")
def admin_bookme():
    """Admin BookMe overview - recent booking requests and confirmed bookings"""
    # Get recent booking requests (last 50)
    requests = BookingRequest.query.order_by(BookingRequest.created_at.desc()).limit(50).all()
    
    # Get recent confirmed bookings (last 50)
    # Note: Booking model uses provider_id, but template may reference artist
    bookings = Booking.query.filter(
        Booking.status.in_(["pending", "confirmed", "completed"])
    ).order_by(Booking.event_datetime.desc().nullslast()).limit(50).all()
    
    return render_template(
        "admin_bookme.html",
        requests=requests,
        bookings=bookings,
        BookingStatus=BookingStatus,
    )


# =========================================================
# Errors
# =========================================================
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return render_template("500.html"), 500


# =========================================================
# Run
# =========================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=IS_DEV)
