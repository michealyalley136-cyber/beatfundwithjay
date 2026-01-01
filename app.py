from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify, Response, session, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import UniqueConstraint, inspect, text
from sqlalchemy.sql import func
from functools import wraps
import enum
import os
import uuid
import pathlib
import csv
from io import StringIO
from datetime import datetime, timedelta
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from time import time
import re
from decimal import Decimal, InvalidOperation
from collections import Counter
from calendar import monthrange
from typing import Optional
import json
from markupsafe import Markup
from contextlib import contextmanager
from sqlalchemy.exc import IntegrityError


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

# 🔴🔴🔴 NEW: define INSTANCE_DIR BEFORE using it anywhere
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
# 🔴🔴🔴 END NEW

# 🔥 CREATE FLASK APP (now INSTANCE_DIR exists)
app = Flask(
    __name__,
    instance_path=INSTANCE_DIR,
    instance_relative_config=True,
)

# Required for session/login/flash/CSRF
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")





# In production, force a real secret (prevents weak deployments)
if not IS_DEV and app.config["SECRET_KEY"] == "dev-secret-change-me":
    raise RuntimeError("Set a strong SECRET_KEY environment variable in production.")



# ---------------------------------------------------------
# Superadmin Owner Panel passcode (SECURE)
# ---------------------------------------------------------
# Why this exists:
# - Admin login gets you into /dashboard/admin
# - Owner panel (/dashboard/admin/owner) shows the “platform / owner wallet stats”
#   so it requires an extra unlock step (like a second lock on a safe).
#
# Sources (strongest -> weakest):
# 1) OWNER_PANEL_PASS_HASH in env   (recommended for production)
# 2) instance/owner_passcode.json   (your "2": persisted, can be updated in-app)
# 3) OWNER_PANEL_PASS in env        (plaintext, dev OK; we hash it in memory)
# Dev-only fallback: DEV_OWNER_PANEL_PASS (defaults to Acidrain@0911)
# ---------------------------------------------------------
OWNER_UNLOCK_SESSION_KEY = "owner_panel_unlocked_at"
OWNER_UNLOCK_TTL_SECONDS = 30 * 60  # 30 minutes

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
            json.dump(
                {"pass_hash": pass_hash, "updated_at": datetime.utcnow().isoformat()},
                f,
            )
    except Exception:
        # Don't crash the app if disk write fails
        pass


def _get_effective_owner_pass_hash() -> Optional[str]:
    # (1) strongest: env-managed hash
    env_hash = os.getenv("OWNER_PANEL_PASS_HASH")
    if env_hash and env_hash.strip():
        return env_hash.strip()

    # (2) persisted: instance file hash (THIS IS YOUR “2”)
    inst_hash = _load_owner_pass_hash_from_instance()
    if inst_hash:
        return inst_hash

    # (3) acceptable: plaintext env (we hash it in memory each boot)
    env_plain = os.getenv("OWNER_PANEL_PASS")
    if env_plain and env_plain.strip():
        return generate_password_hash(env_plain.strip())

    # Dev-only fallback so you’re not blocked while building locally
    if IS_DEV:
        dev_default = os.getenv("DEV_OWNER_PANEL_PASS", "Acidrain@0911")
        return generate_password_hash(dev_default)

    # Production must explicitly configure
    return None


# This is the hash your app will actually verify against
OWNER_PANEL_PASS_HASH_EFFECTIVE = _get_effective_owner_pass_hash()
if not OWNER_PANEL_PASS_HASH_EFFECTIVE:
    raise RuntimeError(
        "SECURITY ERROR: Owner passcode is not configured.\n"
        "Production requires one of:\n"
        "- OWNER_PANEL_PASS_HASH (recommended)\n"
        "- OWNER_PANEL_PASS\n"
        "- instance/owner_passcode.json with {'pass_hash': '...'}\n"
    )

# If passcode is managed by environment vars, do NOT allow changing it inside the app
OWNER_PASS_MANAGED_BY_ENV = bool(
    (os.getenv("OWNER_PANEL_PASS_HASH") and os.getenv("OWNER_PANEL_PASS_HASH").strip())
    or (os.getenv("OWNER_PANEL_PASS") and os.getenv("OWNER_PANEL_PASS").strip())
)

# Simple rate limit for unlock attempts (per IP)
OWNER_UNLOCK_ATTEMPTS = {}
OWNER_UNLOCK_WINDOW_SECONDS = 10 * 60  # 10 minutes
OWNER_UNLOCK_MAX_ATTEMPTS = 5


def _owner_unlock_attempts_clean(ts_list):
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

# Optional: CSRF settings (good defaults for dev)
app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)

csrf = CSRFProtect(app)


@app.context_processor
def inject_csrf_token():
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
    # Render sometimes uses old scheme: postgres://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    # Force psycopg v3 driver (you installed psycopg[binary])
    if db_url.startswith("postgresql://") and not db_url.startswith("postgresql+psycopg://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'app.db')}"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ✅ IMPORTANT: db must be created AFTER the DB URI is set
db = SQLAlchemy(app)

# Login manager (if you use Flask-Login)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---- One-time DB bootstrap (for a fresh Postgres DB) ----
# Turn on only once by setting BOOTSTRAP_DB=1 on Render, then remove it.
if os.getenv("BOOTSTRAP_DB") == "1":
    with app.app_context():
        db.create_all()
        print("✅ BOOTSTRAP_DB=1 -> db.create_all() completed")


# Uploads
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_ROOT

ALLOWED_IMAGE = {"png", "jpg", "jpeg"}
ALLOWED_AUDIO = {"mp3", "wav", "m4a", "ogg"}
ALLOWED_STEMS = {"zip", "rar", "7z", "mp3", "wav", "m4a", "ogg"}


# =========================================================
# Opportunities Promo Video (Admin Upload + Public Serve)
#   NOTE: Meta moved into instance/ so it won't need tracking in git.
# =========================================================
OPP_VIDEO_DIR = os.path.join(UPLOAD_ROOT, "opportunities")
OPP_VIDEO_META = os.path.join(INSTANCE_DIR, "opportunities_video.json")
ALLOWED_VIDEO_EXTS = {"mp4", "webm", "mov"}

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
        # don't crash the whole page if disk write fails
        pass


def _current_opp_video_filename() -> str | None:
    return _load_opp_video_meta().get("filename")


def _set_current_opp_video_filename(filename: str) -> None:
    meta = _load_opp_video_meta()
    meta["filename"] = filename
    meta["updated_at"] = datetime.utcnow().isoformat()
    _save_opp_video_meta(meta)


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
        if self.avatar_path:
            return url_for("media_file", filename=self.avatar_path)
        return url_for("static", filename="img/default-avatar.png")

    @property
    def display_name(self) -> str:
        return self.artist_name or self.full_name or self.username

    @property
    def followers_count(self) -> int:
        return UserFollow.query.filter_by(followed_id=self.id).count()

    @property
    def following_count(self) -> int:
        return UserFollow.query.filter_by(follower_id=self.id).count()

# =========================================================
# Social helpers (Followers / Following)
# =========================================================
def get_social_counts(user_id: int) -> tuple[int, int]:
    followers_count = UserFollow.query.filter_by(followed_id=user_id).count()
    following_count = UserFollow.query.filter_by(follower_id=user_id).count()
    return followers_count, following_count


@app.before_request
def _load_my_social_counts():
    """
    Makes follower/following counts available on EVERY page (all roles),
    without having to pass them from each dashboard route.
    """
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

    # Idempotency (prevents duplicates)
    idempotency_key = db.Column(db.String(120), nullable=False, unique=True)

    # External processor IDs (Stripe PaymentIntent, PayPal Order)
    external_id = db.Column(db.String(120), nullable=True, unique=True)

    # Links
    booking_request_id = db.Column(db.Integer, db.ForeignKey("booking_request.id"), nullable=True, unique=True)
    booking_request = db.relationship("BookingRequest", foreign_keys=[booking_request_id])

    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())




# ------- BookMe -------
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
BOOKME_PROVIDER_ROLE_VALUES = {r.value for r in BOOKME_PROVIDER_ROLES}
app.jinja_env.globals["BOOKME_PROVIDER_ROLES"] = BOOKME_PROVIDER_ROLE_VALUES


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

PORTFOLIO_OPTIONAL_ROLES = {
    RoleEnum.manager,
    RoleEnum.security_usher_crowd_control,
}


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


# Make helpers available in ALL templates (fixes UndefinedError)
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

    status = db.Column(
        db.Enum(BookingStatus),
        nullable=False,
        default=BookingStatus.pending,
        index=True,
    )

    created_at = db.Column(db.DateTime, server_default=func.now(), index=True)

    # Link to the "real" Booking created after payment/confirmation
    booking_id = db.Column(
        db.Integer,
        db.ForeignKey("booking.id"),  # matches Booking.__tablename__ = "booking"
        nullable=True,
        unique=True,
        index=True,
    )

    provider = db.relationship("User", foreign_keys=[provider_id])
    client = db.relationship("User", foreign_keys=[client_id])
    booking = db.relationship("Booking", foreign_keys=[booking_id])


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

    def __repr__(self):
        return f"<AuditLog admin={self.admin_id} user={self.user_id} action={self.action}>"


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

    def __repr__(self):
        return f"<SupportTicket id={self.id} user={self.user_id} status={self.status.value}>"


class SupportTicketComment(db.Model):
    __tablename__ = "support_ticket_comment"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_ticket.id"), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

    ticket = db.relationship("SupportTicket", backref=db.backref("comments", lazy="dynamic"))
    admin = db.relationship("User")

    def __repr__(self):
        return f"<SupportTicketComment ticket={self.ticket_id} admin={self.admin_id}>"


app.jinja_env.globals["TicketStatus"] = TicketStatus
app.jinja_env.globals["TicketType"] = TicketType


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

    @property
    def artist_id(self):
        return self.provider_id

    def is_pending(self):
        return self.status == "pending"

    def is_confirmed(self):
        return self.status == "confirmed"

    def is_completed(self):
        return self.status == "completed"

    def is_cancelled(self):
        return self.status == "cancelled"

    def is_disputed(self):
        return self.status == "disputed"


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


# ------- Follows -------
# Standardize on ONE model name: UserFollow
# Standardize on ONE table name: user_follow

class UserFollow(db.Model):
    __tablename__ = "user_follow"

    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("follower_id", "followed_id", name="uq_user_follow_follower_followed"),
    )


# ---- One-time DB bootstrap (for a fresh Postgres DB) ----
# Turn on only once by setting BOOTSTRAP_DB=1 on Render, then remove it.
if os.getenv("BOOTSTRAP_DB") == "1":
    with app.app_context():
        db.create_all()


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
                flash("You don't have access to that page.")
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


def owner_panel_unlocked() -> bool:
    ts = session.get(OWNER_UNLOCK_SESSION_KEY)
    if not ts:
        return False
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False
    return (time() - ts) < OWNER_UNLOCK_TTL_SECONDS


def require_kyc_approved():
    if current_user.kyc_status != KYCStatus.approved:
        flash("Financial features require approved KYC.")
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
            db.session.flush()  # gets w.id without committing
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

    entry = LedgerEntry(
        wallet_id=wallet.id,
        entry_type=entry_type,
        amount_cents=amount_cents,
        meta=meta,
    )
    db.session.add(entry)
    # IMPORTANT: no db.session.commit() here
    return entry

def _ext_ok(filename, allowed):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def _save_file(fs, allowed_set) -> Optional[str]:
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


def _user_has_paid_for_beat(user_id: int, beat_id: int) -> bool:
    return (
        db.session.query(Order.id)
        .filter_by(buyer_id=user_id, beat_id=beat_id, status=OrderStatus.paid)
        .first()
        is not None
    )


def is_service_provider(u: User) -> bool:
    return u.role in BOOKME_PROVIDER_ROLES


def _ensure_bookme_provider():
    if current_user.role not in BOOKME_PROVIDER_ROLES:
        flash("Only service providers can edit a BookMe profile.")
        return False
    return True


def _is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == RoleEnum.admin

def _build_provider_pin_payload(profiles: list[BookMeProfile]) -> list[dict]:
    payload = []
    for p in profiles:
        u = getattr(p, "user", None)
        if not u:
            continue
        if p.lat is None or p.lng is None:
            continue

        payload.append({
            "username": u.username,
            "display_name": p.display_name,
            "role": u.role.value if getattr(u, "role", None) else "",
            "city": p.city or "",
            "state": p.state or "",
            "lat": float(p.lat),
            "lng": float(p.lng),
        })
    return payload

@contextmanager
def db_txn():
    """
    Ensures we either commit EVERYTHING once, or roll back EVERYTHING.
    This is the #1 fix for partial-money-move bugs.
    """
    try:
        yield
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
# =========================================================
# SQLite Dev Auto-Migrations (safe schema fixes)
#   - fixes: missing booking_request.booking_id
#   - fixes: follow table name mismatch (follow -> user_follow)
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
    # Only for SQLite
    if db.engine.url.get_backend_name() != "sqlite":
        return

    if not _sqlite_has_table("booking_request"):
        return

    cols = _sqlite_columns("booking_request")
    if "booking_id" in cols:
        return

    # Add the column (SQLite can't add FK constraint after creation; that's OK for dev)
    db.session.execute(text("ALTER TABLE booking_request ADD COLUMN booking_id INTEGER"))
    # Create a unique index to match your model's unique=True intent
    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_booking_request_booking_id ON booking_request (booking_id)"
    ))
    db.session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_booking_request_booking_id ON booking_request (booking_id)"
    ))
    db.session.commit()


def _ensure_sqlite_follow_table_name_and_indexes():
    # Only for SQLite
    if db.engine.url.get_backend_name() != "sqlite":
        return

    # If you previously created a table called "follow", rename it to "user_follow"
    if _sqlite_has_table("follow") and (not _sqlite_has_table("user_follow")):
        db.session.execute(text('ALTER TABLE "follow" RENAME TO user_follow'))
        db.session.commit()

    if not _sqlite_has_table("user_follow"):
        return

    cols = _sqlite_columns("user_follow")
    # If the table exists but is missing columns, we can't safely auto-fix here.
    if not {"follower_id", "followed_id"}.issubset(cols):
        return

    # Ensure uniqueness and performance indexes
    db.session.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_user_follow_follower_followed ON user_follow (follower_id, followed_id)"
    ))
    db.session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_user_follow_followed_id ON user_follow (followed_id)"
    ))
    db.session.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_user_follow_follower_id ON user_follow (follower_id)"
    ))
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
        # Don't block the app if a dev migration fails
        db.session.rollback()


# =========================================================
# Opportunities promo video routes
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
def opportunities_video_media():
    filename = _current_opp_video_filename()
    if not filename:
        abort(404)
    return send_from_directory(OPP_VIDEO_DIR, filename)


# =========================================================
# BookMe routes
# =========================================================
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
        .filter(BookMeProfile.is_visible == True)
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
    providers_json = json.dumps(providers_payload)

    return render_template(
        "bookme_search.html",
        profiles=profiles,
        BookingStatus=BookingStatus,
        RoleEnum=RoleEnum,
        current_filters=current_filters,
        providers_json=providers_json,
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
            BookMeProfile.is_visible == True,
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
            flash("Display Name is required.")
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
                flash("Latitude/Longitude must be numbers (or leave both blank).")
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
        flash("BookMe profile saved.")
        return redirect(url_for("bookme_search"))

    return render_template("bookme_profile.html", prof=prof)


@app.route("/bookme/request/<int:provider_id>", methods=["GET", "POST"])
@login_required
def bookme_request(provider_id):
    provider = User.query.get_or_404(provider_id)

    if not is_service_provider(provider):
        flash("This user is not available for BookMe bookings.")
        return redirect(url_for("bookme_search"))

    if request.method == "POST":
        msg = (request.form.get("message") or "").strip()
        pref = (request.form.get("preferred_time") or "").strip()

        if not pref:
            flash("Please choose a date and time slot.")
            return redirect(url_for("bookme_request", provider_id=provider_id))

        req = BookingRequest(
            provider_id=provider.id,
            client_id=current_user.id,
            message=msg,
            preferred_time=pref,
        )
        db.session.add(req)
        db.session.commit()
        flash("Booking request sent.")
        return redirect(url_for("bookme_requests"))

    return render_template("bookme_request.html", provider=provider)


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
    )


@app.route("/bookme/requests/<int:req_id>/status", methods=["POST"])
@login_required
def bookme_request_status(req_id):
    action = (request.form.get("action") or "").strip().lower()

    # PROVIDER: accept/decline
    if action in ("accept", "decline"):
        # Atomic “claim”: one UPDATE statement, only succeeds if pending
        if current_user.id is None:
            abort(403)

        # Only provider can accept/decline
        req = BookingRequest.query.get_or_404(req_id)
        if current_user.id != req.provider_id:
            flash("You are not allowed to do that.", "error")
            return redirect(url_for("bookme_requests"))

        if action == "decline":
            # decline allowed only if pending
            updated = (
                BookingRequest.query
                .filter_by(id=req_id, provider_id=current_user.id, status=BookingStatus.pending)
                .update({BookingRequest.status: BookingStatus.declined})
            )
            db.session.commit()
            if updated == 0:
                flash("This request is no longer pending.", "error")
            else:
                flash("Booking request declined.", "success")
            return redirect(url_for("bookme_requests"))

        # ACCEPT
        # Step 1: atomic state change (prevents double-accept races)
        updated = (
            BookingRequest.query
            .filter_by(id=req_id, provider_id=current_user.id, status=BookingStatus.pending)
            .update({BookingRequest.status: BookingStatus.accepted})
        )
        db.session.commit()

        if updated == 0:
            flash("This request is no longer pending.", "error")
            return redirect(url_for("bookme_requests"))

        # Step 2: slot conflict check AFTER accept (still important)
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
            # Roll back acceptance safely by declining this one
            req.status = BookingStatus.declined
            db.session.commit()
            flash("This time slot is already booked.", "error")
            return redirect(url_for("bookme_requests"))

        flash("Accepted. Waiting for client to confirm & pay the hold fee.", "success")
        return redirect(url_for("bookme_requests"))

    # CLIENT: cancel
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
        if not is_provider:
            flash("Only the provider can update this booking.", "error")
            return redirect(url_for("booking_detail", booking_id=booking.id))

        notes_from_provider = (request.form.get("notes_from_provider") or "").strip()
        status_action = (request.form.get("status_action") or "").strip().lower()

        booking.notes_from_provider = notes_from_provider or None

        if status_action == "mark_completed":
            if booking.status == "confirmed":
                booking.status = "completed"
                flash("Booking marked as completed.", "success")
            else:
                flash("Only confirmed bookings can be marked completed.", "error")
        else:
            flash("Booking notes updated.", "success")

        db.session.commit()
        return redirect(url_for("booking_detail", booking_id=booking.id))

    return render_template("booking_detail.html", booking=booking, is_provider=is_provider, is_client=is_client)


@app.route("/bookme/<username>/book", methods=["GET", "POST"])
@login_required
def bookme_book_provider(username):
    return book_artist(username)


@app.route("/artists/<username>/book", methods=["GET", "POST"])
@login_required
def book_artist(username):
    artist = User.query.filter_by(username=username).first_or_404()

    is_owner = current_user.id == artist.id

    if request.method == "POST":
        if is_owner:
            flash("You can’t send a booking request to yourself. Share this booking link with your clients instead.", "error")
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
            flash(
                f"You can only have up to {MAX_PORTFOLIO_ITEMS} items in your portfolio. "
                "Delete one before adding another.",
                "error",
            )
            return redirect(url_for("bookme_portfolio"))

        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        media_type_raw = (request.form.get("media_type") or "image").strip()
        external_url = (request.form.get("external_url") or "").strip()
        file = request.files.get("file")

        if not title:
            flash("Title is required for a portfolio item.", "error")
            return redirect(url_for("bookme_portfolio"))

        # 🔴🔴🔴 NEW: Basic external URL safety (prevents javascript:/data:/file: etc.)
        if external_url and not re.match(r"^https?://", external_url, re.I):
            flash("External URL must start with http:// or https://", "error")
            return redirect(url_for("bookme_portfolio"))
        # 🔴🔴🔴 END NEW

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
                # link (or unknown) — allow common types if they still upload a file
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

    items = prof.portfolio_items.order_by(
        PortfolioItem.sort_order.asc(),
        PortfolioItem.created_at.desc()
    ).all()
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
@login_required  # you can remove this later if you want truly public profiles
def provider_portfolio_public(username):
    user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    prof = (
        BookMeProfile.query
        .filter_by(user_id=user.id, is_visible=True)
        .first_or_404()
    )

    items = prof.portfolio_items.order_by(
        PortfolioItem.sort_order.asc(),
        PortfolioItem.created_at.desc()
    ).all()

    followers_count = UserFollow.query.filter_by(followed_id=user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=user.id).count()

    is_following = (
        UserFollow.query
        .filter_by(follower_id=current_user.id, followed_id=user.id)
        .first() is not None
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
@app.route("/users/<int:user_id>/toggle-follow", methods=["POST"])
@login_required
def toggle_follow(user_id: int):
    target = User.query.get_or_404(user_id)

    # JSON-friendly errors (better for fetch)
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
        # Handles double-click / race safely
        db.session.rollback()

    # Always re-check final state so UI never lies
    following = (
        UserFollow.query.filter_by(
            follower_id=current_user.id,
            followed_id=target.id
        ).first()
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


ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

def _allowed_image(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower().strip()
    return ext in ALLOWED_IMAGE_EXTENSIONS

def _set_first_attr(obj, attr_names, value) -> bool:
    """Set the first attribute in attr_names that exists on obj."""
    for a in attr_names:
        if hasattr(obj, a):
            setattr(obj, a, value)
            return True
    return False

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile_edit():
    if request.method == "POST":
        # Basic fields
        display_name = (request.form.get("display_name") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        bio = (request.form.get("bio") or "").strip()
        city = (request.form.get("city") or "").strip()
        state = (request.form.get("state") or "").strip()

        # Update whatever columns exist on your User model (safe + flexible)
        if display_name:
            _set_first_attr(current_user, ["display_name", "full_name", "name"], display_name)

        if phone:
            _set_first_attr(current_user, ["phone", "phone_number", "contact_phone"], phone)

        _set_first_attr(current_user, ["bio", "about", "description"], bio)

        if city:
            _set_first_attr(current_user, ["city"], city)
        if state:
            _set_first_attr(current_user, ["state"], state)

        # Avatar upload (stored in /static/uploads/avatars)
        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            if not _allowed_image(avatar.filename):
                flash("Avatar must be an image (png/jpg/webp/gif).", "error")
                return redirect(url_for("profile_edit"))

            upload_dir = os.path.join(app.root_path, "static", "uploads", "avatars")
            os.makedirs(upload_dir, exist_ok=True)

            ext = avatar.filename.rsplit(".", 1)[1].lower()
            fname = f"{uuid.uuid4().hex}.{ext}"
            path = os.path.join(upload_dir, secure_filename(fname))
            avatar.save(path)

            # Your templates already use current_user.avatar_url, so keep that consistent:
            current_user.avatar_url = url_for("static", filename=f"uploads/avatars/{fname}")

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile_edit"))

    return render_template("profile_edit.html")

# =========================================================
# Core / Auth
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

        existing_user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if existing_user:
            flash("That username is already taken.", "error")
            return redirect(url_for("register"))

        existing_email = User.query.filter(func.lower(User.email) == email.lower()).first()
        if existing_email:
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
        flash("Account created! (KYC auto-approved in dev.)", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("register.html")


# =========================================================
# Simple login rate limiting
# =========================================================
LOGIN_ATTEMPTS = {}
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 10


def _clean_attempts(attempts):
    now = time()
    return [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]


def _too_many_failed_logins(remote_addr: str) -> bool:
    if not remote_addr:
        remote_addr = "unknown"
    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    LOGIN_ATTEMPTS[remote_addr] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _register_failed_login(remote_addr: str) -> None:
    if not remote_addr:
        remote_addr = "unknown"
    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    attempts.append(time())
    LOGIN_ATTEMPTS[remote_addr] = attempts


def _clear_failed_logins(remote_addr: str) -> None:
    if not remote_addr:
        remote_addr = "unknown"
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

        user = None
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

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET"])
@login_required
def logout_get():
    # Show confirmation page (NO logout happens on GET)
    return render_template("logout_confirm.html")



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

        user = None
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


@app.route("/reset-password-request", methods=["GET", "POST"])
def reset_password_request():
    return forgot_password()


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
# Wallet
# =========================================================
# =========================================================
# Wallet (Umbrella: Overview + Transactions)
# =========================================================
@app.route("/wallet", endpoint="wallet_home")
@login_required
def wallet_page():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    tab = (request.args.get("tab") or "overview").strip().lower()  # overview | transactions

    w = get_or_create_wallet(current_user.id)
    balance = wallet_balance_cents(w) / 100.0

    # THIS is your "transactions" list (ledger entries)
    txns = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
        .limit(100)
        .all()
    )

    return render_template(
        "wallet_center.html",   # new template (below)
        balance=balance,
        txns=txns,
        tab=tab,
    )

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
    if not year:
        year = now.year
    if not month or month < 1 or month > 12:
        month = now.month

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

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


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
        flash(f"Amount exceeds the maximum allowed (${MAX_TXN_DOLLARS:,.2f}) for a single transaction.", "error")
        return redirect(url_for("wallet_home"))

    cents = int((amt * 100).to_integral_value())
    method = (request.form.get("method") or "").strip()[:50]  # keep meta short/safe

    # IMPORTANT:
    # - post_ledger() does NOT commit
    # - so we must commit using db_txn() (atomic) for every action
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

        # Balance check BEFORE opening txn (still okay)
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
            # (Optional but recommended) re-check balance inside txn for tighter safety
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
            # (Optional) re-check inside txn
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
    # Backwards compatible URL (old links won't 404)
    return redirect(url_for("wallet_home", tab="transactions"))

@app.route("/transactions", endpoint="transactions")
@login_required
def transactions_redirect():
    return redirect(url_for("wallet_home", tab="transactions"))



# =========================================================
# Files
# =========================================================
@app.route("/uploads/<path:filename>")
@login_required
def media_file(filename):
    # If this filename is a beat deliverable (stems), enforce purchase/owner access
    beat = Beat.query.filter_by(stems_path=filename).first()
    if beat:
        if beat.owner_id != current_user.id and not _user_has_paid_for_beat(current_user.id, beat.id):
            abort(403)
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

    # Otherwise allow inline viewing (avatars/covers/previews/etc.)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


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
# Universal profile + follow (FIXES dead @tags + enables follow feature)
# =========================================================
@app.route("/u/<username>", endpoint="user_profile")
@login_required
def user_profile(username):
    profile_user = User.query.filter(func.lower(User.username) == username.lower()).first_or_404()

    # Producers -> producer catalog page (do this first)
    if profile_user.role == RoleEnum.producer:
        return redirect(url_for("producer_catalog_detail", username=profile_user.username))

    # Other providers -> redirect to their BookMe portfolio page (if visible)
    if is_service_provider(profile_user):
        prof = BookMeProfile.query.filter_by(user_id=profile_user.id, is_visible=True).first()
        if prof:
            return redirect(url_for("provider_portfolio_public", username=profile_user.username))

    followers_count = UserFollow.query.filter_by(followed_id=profile_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=profile_user.id).count()
    is_following = (
        UserFollow.query
        .filter_by(follower_id=current_user.id, followed_id=profile_user.id)
        .first() is not None
    )

    return render_template(
        "public_profile.html",
        profile_user=profile_user,
        role_label=get_role_display(profile_user.role),
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
    )


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

    existing = UserFollow.query.filter_by(
        follower_id=current_user.id,
        followed_id=target.id
    ).first()

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
# Marketplace
# =========================================================
@app.route("/market", endpoint="market_index")
@login_required
def market_index():
    items = (
        Beat.query.filter_by(is_active=True)
        .order_by(Beat.is_featured.desc(), Beat.id.desc())
        .all()
    )

    provider_profiles = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(
            BookMeProfile.is_visible == True,
            User.role.in_(list(BOOKME_PROVIDER_ROLES)),
        )
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
    orders = (
        Order.query
        .filter_by(buyer_id=current_user.id, status=OrderStatus.paid)
        .order_by(Order.created_at.desc())
        .all()
    )

    purchases = []
    for o in orders:
        if o.beat:
            purchases.append({
                "order": o,
                "beat": o.beat,
                "producer": User.query.get(o.beat.owner_id),
            })

    return render_template("market_my_purchases.html", purchases=purchases)


@app.route("/market/buy/<int:beat_id>", methods=["POST"])
@login_required
def market_buy(beat_id):
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    beat = Beat.query.get_or_404(beat_id)

    # Optional but recommended safety:
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

    # Prevent duplicate purchases (double-click / refresh)
    if _user_has_paid_for_beat(current_user.id, beat.id):
        flash("You already purchased this beat. Check “My purchases”.", "info")
        return redirect(url_for("market_my_purchases"))

    # Normalize price
    price_cents = int(beat.price_cents or 0)
    if price_cents < 0:
        flash("Invalid beat price.", "error")
        return redirect(url_for("market_index"))

    # If free beat, allow “purchase” without wallet debit
    if price_cents == 0:
        try:
            with db_txn():
                order = Order(
                    beat_id=beat.id,
                    buyer_id=current_user.id,
                    seller_id=seller.id,
                    amount_cents=0,
                    status=OrderStatus.paid,
                )
                db.session.add(order)
        except IntegrityError:
            flash("This purchase was already processed.", "info")
            return redirect(url_for("market_my_purchases"))

        flash("Added to your purchases!", "success")
        return redirect(url_for("market_my_purchases"))

    # Paid beat: move money + create order in ONE atomic transaction
    buyer_w = get_or_create_wallet(current_user.id, commit=False)
    seller_w = get_or_create_wallet(seller.id, commit=False)

    try:
        with db_txn():
            # re-check inside the same transaction window
            if _user_has_paid_for_beat(current_user.id, beat.id):
                raise ValueError("already_purchased")

            if wallet_balance_cents(buyer_w) < price_cents:
                raise ValueError("insufficient_funds")

            post_ledger(
                buyer_w,
                EntryType.purchase_spend,
                price_cents,
                meta=f"buy beat #{beat.id} '{(beat.title or '')[:80]}'",
            )
            post_ledger(
                seller_w,
                EntryType.sale_income,
                price_cents,
                meta=f"sale beat #{beat.id} to @{current_user.username}",
            )

            order = Order(
                beat_id=beat.id,
                buyer_id=current_user.id,
                seller_id=seller.id,
                amount_cents=price_cents,
                status=OrderStatus.paid,
            )
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
        # If you later add a UNIQUE constraint for (buyer_id, beat_id), this catches races safely.
        flash("This purchase was already processed.", "info")
        return redirect(url_for("market_my_purchases"))

    flash("Purchase complete! You now have download access.", "success")
    return redirect(url_for("market_my_purchases"))

@app.route("/market/download/<int:beat_id>")
@login_required
def market_download(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    if (beat.owner_id != current_user.id and not _user_has_paid_for_beat(current_user.id, beat_id)):
        flash("You don’t have access to download this file.")
        return redirect(url_for("market_index"))

    if not beat.stems_path:
        flash("No deliverable file available for this beat.")
        return redirect(url_for("market_index"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], beat.stems_path, as_attachment=True)

@app.route("/market/providers.json", endpoint="market_providers_json")
@login_required
def market_providers_json():
    rows = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(
            BookMeProfile.is_visible == True,
            BookMeProfile.lat.isnot(None),
            BookMeProfile.lng.isnot(None),
            User.role.in_(list(BOOKME_PROVIDER_ROLES)),
        )
        .all()
    )
    return jsonify(_build_provider_pin_payload(rows))



# =========================================================
# Producers Catalog (UPDATED: real followers_count via UserFollow)
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

    return render_template(
        "producer_catalog_detail.html",
        producer=producer_profile,
        beats=beats_for_producer,
        raw_username=username,
    )


@app.route("/producers/<username>/follow", methods=["POST"])
@login_required
def follow_producer(username):
    # keep this route for backward compatibility with your templates;
    # it uses the new universal follow logic.
    return user_follow_toggle(username)


@app.route("/market/producers")
@login_required
def market_producer_catalog():
    beats = Beat.query.all()
    producer_map = {}

    for beat in beats:
        owner = getattr(beat, "owner", None)
        if not owner:
            continue

        pid = owner.id
        if pid not in producer_map:
            producer_map[pid] = {"producer": owner, "beat_count": 0, "genres_counter": Counter()}

        producer_map[pid]["beat_count"] += 1
        if beat.genre:
            producer_map[pid]["genres_counter"][beat.genre] += 1

    producers = []
    for data in producer_map.values():
        producer_user = data["producer"]
        top_genres = [name for name, _ in data["genres_counter"].most_common(3)]
        producers.append({
            "producer": producer_user,
            "beat_count": data["beat_count"],
            "genres": top_genres,
            "followers_count": UserFollow.query.filter_by(followed_id=producer_user.id).count(),
            "rating": None,
        })

    producers.sort(key=lambda row: row["beat_count"], reverse=True)
    return render_template("market_producers.html", producers=producers)


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

        beat = Beat(
            owner_id=current_user.id,
            title=title,
            price_cents=price_cents,
            bpm=bpm,
            genre=genre or None,
            is_active=True,
        )

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
        flash("You can’t delete another producer’s beat.", "error")
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


# =========================================================
# User-facing tickets (FIX: clients can see “in review/approved/etc.”)
# =========================================================
@app.route("/tickets", endpoint="my_tickets")
@login_required
def my_tickets():
    tickets = (
        SupportTicket.query
        .filter(SupportTicket.user_id == current_user.id)
        .order_by(SupportTicket.created_at.desc())
        .all()
    )
    return render_template("my_tickets.html", tickets=tickets, TicketStatus=TicketStatus, TicketType=TicketType)


@app.route("/tickets/<int:ticket_id>", endpoint="my_ticket_detail")
@login_required
def my_ticket_detail(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)

    # user can only see their own tickets; admin can see any
    if (ticket.user_id != current_user.id) and (current_user.role != RoleEnum.admin):
        abort(403)

    comments = ticket.comments.order_by(SupportTicketComment.created_at.asc()).all()
    return render_template(
        "my_ticket_detail.html",
        ticket=ticket,
        comments=comments,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )


# =========================================================
# Admin – Dashboard / Users / KYC / Tickets / Reports
#   (unchanged from your current structure, but kept here)
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


@app.route("/dashboard/admin/users", endpoint="admin_users")
@role_required("admin")
def admin_users():
    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip()
    active = (request.args.get("active") or "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = User.query.filter(User.role != RoleEnum.admin)

    if q:
        like = f"%{q.lower()}%"
        query = query.filter(func.lower(User.username).like(like))

    if role:
        try:
            query = query.filter(User.role == RoleEnum(role))
        except ValueError:
            pass

    if status:
        try:
            query = query.filter(User.kyc_status == KYCStatus(status))
        except ValueError:
            pass

    if active == "active":
        query = query.filter(User.is_active_col.is_(True))
    elif active == "inactive":
        query = query.filter(User.is_active_col.is_(False))

    pagination = query.order_by(User.id.asc()).paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items

    return render_template(
        "admin_users.html",
        users=users,
        pagination=pagination,
        q=q,
        role=role,
        status=status,
        active=active,
        RoleEnum=RoleEnum,
        KYCStatus=KYCStatus,
    )


@app.route("/dashboard/admin/superadmin/unlock", methods=["GET", "POST"], endpoint="superadmin_unlock")
@superadmin_required
def superadmin_unlock():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        if _owner_unlock_blocked(ip):
            flash("Too many incorrect passcode attempts. Please wait a few minutes and try again.", "error")
            return redirect(url_for("superadmin_unlock"))

        passphrase = (
            (request.form.get("owner_pass") or "").strip()  # matches your template
            or (request.form.get("passphrase") or "").strip()  # fallback
        )

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

    # If passcode is managed via environment secrets, do not allow in-app changes.
    if OWNER_PASS_MANAGED_BY_ENV:
        flash(
            "Owner passcode is managed by server environment secrets in this deployment. "
            "To change it, update OWNER_PANEL_PASS_HASH (recommended) or OWNER_PANEL_PASS in your hosting config.",
            "error",
        )
        return redirect(url_for("superadmin_dashboard"))

    if request.method == "POST":
        current_code = (request.form.get("current_passcode") or "").strip()
        new_code = (request.form.get("new_passcode") or "").strip()
        confirm_code = (request.form.get("confirm_passcode") or "").strip()

        # Verify current passcode (hashed compare)
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

        # Store only a hash (never plaintext)
        new_hash = generate_password_hash(new_code)
        _save_owner_pass_hash_to_instance(new_hash)

        # Update in-memory effective hash immediately (no restart needed)
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
        .scalar()
        or 0
    )
    total_withdrawals_cents = (
        db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .filter(LedgerEntry.entry_type == EntryType.withdrawal)
        .scalar()
        or 0
    )
    total_sales_cents = (
        db.session.query(func.coalesce(func.sum(Order.amount_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar()
        or 0
    )

    total_deposits = total_deposits_cents / 100.0
    total_withdrawals = total_withdrawals_cents / 100.0
    total_sales = total_sales_cents / 100.0

    net_wallet_dollars = (total_deposits_cents - total_withdrawals_cents) / 100.0

    bar_labels = ["Users", "Wallets", "Beats", "Orders"]
    bar_values = [total_users, total_wallets, total_beats, total_orders]

    flow_labels = ["Deposits ($)", "Withdrawals ($)", "Sales ($)"]
    flow_values = [total_deposits, total_withdrawals, total_sales]

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
        bar_labels=bar_labels,
        bar_values=bar_values,
        flow_labels=flow_labels,
        flow_values=flow_values,
    )


@app.route("/dashboard/admin/bookme", endpoint="admin_bookme")
@role_required("admin")
def admin_bookme():
    requests = BookingRequest.query.order_by(BookingRequest.created_at.desc()).limit(50).all()
    bookings = Booking.query.order_by(Booking.created_at.desc()).limit(50).all()
    return render_template("admin_bookme.html", requests=requests, bookings=bookings, BookingStatus=BookingStatus)


@app.route("/dashboard/admin/team", methods=["GET", "POST"], endpoint="admin_team")
@superadmin_required
def admin_team():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        if not username:
            flash("Username is required for a new admin.", "error")
            return redirect(url_for("admin_team"))

        pw_errors = []
        if len(password) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", password):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", password):
            pw_errors.append("Password must contain at least one number.")
        if pw_errors:
            flash(" ".join(pw_errors), "error")
            return redirect(url_for("admin_team"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return redirect(url_for("admin_team"))

        new_admin = User(username=username, role=RoleEnum.admin, kyc_status=KYCStatus.approved, is_superadmin=False)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()

        get_or_create_wallet(new_admin.id)

        db.session.add(AuditLog(
            admin_id=current_user.id,
            user_id=new_admin.id,
            action="create_admin_user",
            reason="Superadmin created another admin via Admin Team page.",
        ))
        db.session.commit()

        flash(f"Admin @{username} created.", "success")
        return redirect(url_for("admin_team"))

    admins = User.query.filter(User.role == RoleEnum.admin).order_by(User.id.asc()).all()
    return render_template("admin_team.html", admins=admins)


@app.route("/dashboard/admin/team/<int:user_id>/toggle-active", methods=["POST"], endpoint="admin_team_toggle_active")
@superadmin_required
def admin_team_toggle_active(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't deactivate your own superadmin account.", "error")
        return redirect(url_for("admin_team"))

    if getattr(user, "is_superadmin", False):
        flash("You can't deactivate another superadmin from this page.", "error")
        return redirect(url_for("admin_team"))

    user.is_active_col = not bool(user.is_active_col)
    db.session.commit()

    flash(f"Admin @{user.username} {'reactivated' if user.is_active_col else 'deactivated'}.", "success")
    return redirect(url_for("admin_team"))



@app.route("/dashboard/admin/users/<int:user_id>/toggle-active", methods=["POST"], endpoint="admin_user_toggle_active")
@role_required("admin")
def admin_user_toggle_active(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't deactivate your own account.", "error")
        return redirect(request.referrer or url_for("admin_users"))

    new_active = not bool(user.is_active_col)
    user.is_active_col = new_active

    action = "reactivate_user" if new_active else "deactivate_user"
    reason = "Admin toggled user active flag to " + ("active" if new_active else "inactive") + " from the Users page."

    db.session.add(AuditLog(admin_id=current_user.id, user_id=user.id, action=action, reason=reason))
    db.session.commit()

    flash(f"@{user.username} {'reactivated' if new_active else 'deactivated'}.", "success")
    return redirect(request.referrer or url_for("admin_users"))


@app.route("/dashboard/admin/kyc", endpoint="admin_kyc")
@role_required("admin")
def admin_kyc():
    pending = User.query.filter_by(kyc_status=KYCStatus.pending).all()
    approved = User.query.filter_by(kyc_status=KYCStatus.approved).all()
    rejected = User.query.filter_by(kyc_status=KYCStatus.rejected).all()
    return render_template("admin_kyc.html", pending=pending, approved=approved, rejected=rejected, KYCStatus=KYCStatus)



@app.route("/dashboard/admin/kyc/<int:user_id>/<string:action>", methods=["POST"], endpoint="admin_kyc_update")
@role_required("admin")
def admin_kyc_update(user_id, action):
    user = User.query.get_or_404(user_id)

    if action == "approve":
        user.kyc_status = KYCStatus.approved
        flash(f"KYC approved for @{user.username}.")
    elif action == "reject":
        user.kyc_status = KYCStatus.rejected
        flash(f"KYC rejected for @{user.username}.")
    else:
        flash("Unknown action.")

    db.session.commit()
    return redirect(url_for("admin_kyc"))


@app.route("/dashboard/admin/transactions", endpoint="admin_transactions")
@role_required("admin")
def admin_transactions():
    q = (request.args.get("q") or "").strip()

    found_user = None
    if q:
        found_user = User.query.filter(func.lower(User.username) == q.lower()).first()

    stats = (
        db.session.query(LedgerEntry.entry_type, func.count(LedgerEntry.id), func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .group_by(LedgerEntry.entry_type)
        .all()
    )

    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()

    return render_template(
        "admin_transactions.html",
        q=q,
        stats=stats,
        found_user=found_user,
        audit_logs=audit_logs,
        EntryType=EntryType,
    )


@app.route("/dashboard/admin/audit-log", endpoint="admin_audit_log")
@role_required("admin")
def admin_audit_log():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    lines = [
        f"{log.created_at} | admin_id={log.admin_id} | user_id={log.user_id} | action={log.action} | reason={log.reason}"
        for log in logs
    ]
    return "Admin Audit Log\n" + "\n".join(lines)


@app.route("/dashboard/admin/transactions/user/<int:user_id>/audit", methods=["GET", "POST"], endpoint="admin_audit_access")
@role_required("admin")
def admin_audit_access(user_id):
    customer = User.query.get_or_404(user_id)

    if request.method == "POST":
        reason = (request.form.get("reason") or "").strip()
        if not reason:
            flash("Please enter a reason for accessing this account.", "error")
        else:
            db.session.add(AuditLog(
                admin_id=current_user.id,
                user_id=customer.id,
                action="view_user_transactions",
                reason=reason,
            ))
            db.session.commit()
            flash("Access reason recorded in audit log.", "success")
            return redirect(url_for("admin_transactions_user", user_id=customer.id))

    return render_template("admin_audit_access.html", customer=customer)


@app.route("/dashboard/admin/transactions/user/<int:user_id>", methods=["GET"], endpoint="admin_transactions_user")
@role_required("admin")
def admin_transactions_user(user_id):
    customer = User.query.get_or_404(user_id)

    ledger = (
        LedgerEntry.query
        .join(Wallet, LedgerEntry.wallet_id == Wallet.id)
        .filter(Wallet.user_id == customer.id)
        .order_by(LedgerEntry.created_at.desc())
        .all()
    )

    return render_template("admin_transactions_user.html", customer=customer, ledger=ledger, EntryType=EntryType)


@app.route("/dashboard/admin/transactions/user/<int:user_id>/export", methods=["GET"], endpoint="admin_export_wallet_csv")
@role_required("admin")
def admin_export_wallet_csv(user_id):
    user = User.query.get_or_404(user_id)

    ledger = (
        LedgerEntry.query
        .join(Wallet, LedgerEntry.wallet_id == Wallet.id)
        .filter(Wallet.user_id == user.id)
        .order_by(LedgerEntry.created_at.desc())
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

    for row in ledger:
        is_credit = row.entry_type in credit_types
        direction = "credit" if is_credit else "debit"
        created_str = row.created_at.isoformat(sep=" ") if row.created_at else ""
        amount_dollars = f"{row.amount_cents / 100.0:.2f}"
        writer.writerow([created_str, row.entry_type.value, direction, amount_dollars, row.meta or ""])

    output = si.getvalue()
    filename = f"wallet_{user.username}_ledger.csv"

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/dashboard/admin/reports/export/system-ledger", methods=["GET"], endpoint="admin_export_system_ledger_csv")
@role_required("admin")
def admin_export_system_ledger_csv():
    rows = (
        db.session.query(LedgerEntry, Wallet, User)
        .join(Wallet, LedgerEntry.wallet_id == Wallet.id)
        .join(User, Wallet.user_id == User.id)
        .order_by(LedgerEntry.created_at.desc())
        .all()
    )

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["ledger_id", "created_at", "username", "user_id", "entry_type", "direction", "amount_dollars", "meta"])

    credit_types = {
        EntryType.deposit,
        EntryType.transfer_in,
        EntryType.interest,
        EntryType.adjustment,
        EntryType.sale_income,
    }

    for entry, wallet, user in rows:
        is_credit = entry.entry_type in credit_types
        direction = "credit" if is_credit else "debit"
        created_str = entry.created_at.isoformat(sep=" ") if entry.created_at else ""
        amount_dollars = f"{entry.amount_cents / 100.0:.2f}"
        writer.writerow([entry.id, created_str, user.username if user else "", user.id if user else "", entry.entry_type.value, direction, amount_dollars, entry.meta or ""])

    output = si.getvalue()
    filename = "beatfund_system_wallet_ledger_audit.csv"

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/dashboard/admin/reports/export/admin-audit-log", methods=["GET"], endpoint="admin_export_audit_log_csv")
@role_required("admin")
def admin_export_audit_log_csv():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["log_id", "timestamp", "admin_id", "admin_username", "user_id", "user_username", "action", "reason"])

    for log in logs:
        ts = log.created_at.isoformat(sep=" ") if log.created_at else ""
        admin_username = log.admin.username if log.admin else ""
        user_username = log.user.username if log.user else ""
        writer.writerow([log.id, ts, log.admin_id, admin_username, log.user_id, user_username, log.action, log.reason])

    output = si.getvalue()
    filename = "beatfund_admin_access_audit.csv"

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/dashboard/admin/tickets", methods=["GET"], endpoint="admin_tickets")
@role_required("admin")
def admin_tickets():
    status = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = SupportTicket.query.join(User, SupportTicket.user_id == User.id)

    if status:
        try:
            query = query.filter(SupportTicket.status == TicketStatus(status))
        except ValueError:
            pass

    if q:
        like = f"%{q.lower()}%"
        query = query.filter(func.lower(User.username).like(like))

    pagination = query.order_by(SupportTicket.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    tickets = pagination.items

    return render_template(
        "admin_tickets.html",
        tickets=tickets,
        pagination=pagination,
        status=status,
        q=q,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )



@app.route("/dashboard/admin/tickets/new", methods=["GET", "POST"], endpoint="admin_ticket_new")
@role_required("admin")
def admin_ticket_new():
    user_id = request.args.get("user_id", type=int)
    ledger_id = request.args.get("ledger_id", type=int)

    if not user_id:
        abort(400, description="user_id query parameter is required.")

    customer = User.query.get_or_404(user_id)
    ledger = LedgerEntry.query.get(ledger_id) if ledger_id else None

    if request.method == "POST":
        type_raw = (request.form.get("type") or "other").strip()
        subject = (request.form.get("subject") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority = (request.form.get("priority") or "normal").strip()

        if not subject or not description:
            flash("Subject and description are required for a support ticket.", "error")
            return render_template(
                "admin_ticket_new.html",
                customer=customer,
                ledger=ledger,
                TicketType=TicketType,
                type_value=type_raw,
                subject=subject,
                description=description,
                priority=priority,
            )

        try:
            ticket_type = TicketType(type_raw)
        except ValueError:
            ticket_type = TicketType.other

        ticket = SupportTicket(
            user_id=customer.id,
            created_by_admin_id=current_user.id,
            related_ledger_id=ledger.id if ledger else None,
            type=ticket_type,
            status=TicketStatus.open,
            priority=priority,
            subject=subject,
            description=description,
        )
        db.session.add(ticket)
        db.session.commit()

        flash(f"Support ticket #{ticket.id} created.", "success")
        return redirect(url_for("admin_tickets"))

    return render_template(
        "admin_ticket_new.html",
        customer=customer,
        ledger=ledger,
        TicketType=TicketType,
        type_value="other",
        subject="",
        description="",
        priority="normal",
    )



@app.route("/dashboard/admin/tickets/<int:ticket_id>", methods=["GET", "POST"], endpoint="admin_ticket_detail")
@role_required("admin")
def admin_ticket_detail(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)

    if request.method == "POST":
        new_status_raw = (request.form.get("status") or ticket.status.value).strip()
        new_priority = (request.form.get("priority") or ticket.priority).strip()
        comment_body = (request.form.get("comment_body") or "").strip()

        try:
            new_status = TicketStatus(new_status_raw)
        except ValueError:
            new_status = ticket.status

        ticket.status = new_status
        ticket.priority = new_priority or ticket.priority

        if comment_body:
            db.session.add(SupportTicketComment(ticket_id=ticket.id, admin_id=current_user.id, body=comment_body))

        db.session.commit()

        flash("Ticket updated and note added." if comment_body else "Ticket updated.", "success")
        return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))

    comments = ticket.comments.order_by(SupportTicketComment.created_at.asc()).all() if hasattr(ticket, "comments") else []
    return render_template("admin_ticket_detail.html", ticket=ticket, comments=comments, TicketStatus=TicketStatus, TicketType=TicketType)


@app.route("/dashboard/admin/reports", endpoint="admin_reports")
@role_required("admin")
def admin_reports():
    total_deposits_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(LedgerEntry.entry_type == EntryType.deposit).scalar() or 0
    total_withdrawals_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(LedgerEntry.entry_type == EntryType.withdrawal).scalar() or 0
    total_sales_cents = db.session.query(func.sum(Order.amount_cents)).filter(Order.status == OrderStatus.paid).scalar() or 0

    total_deposits = total_deposits_cents / 100.0
    total_withdrawals = total_withdrawals_cents / 100.0
    total_sales = total_sales_cents / 100.0

    totals = {
        "deposits": total_deposits,
        "withdrawals": total_withdrawals,
        "sales": total_sales,
        "net_wallet": (total_deposits_cents - total_withdrawals_cents) / 100.0,
        "net": (total_deposits_cents - total_withdrawals_cents) / 100.0,
    }

    wallet_stats = (
        db.session.query(LedgerEntry.entry_type, func.count(LedgerEntry.id), func.coalesce(func.sum(LedgerEntry.amount_cents), 0))
        .group_by(LedgerEntry.entry_type)
        .all()
    )

    role_stats = (
        db.session.query(User.role, func.count(User.id))
        .filter(User.role != RoleEnum.admin)
        .group_by(User.role)
        .all()
    )

    ticket_total = SupportTicket.query.count()
    ticket_open = SupportTicket.query.filter_by(status=TicketStatus.open).count()
    ticket_in_review = SupportTicket.query.filter_by(status=TicketStatus.in_review).count()
    ticket_resolved = SupportTicket.query.filter(SupportTicket.status.in_([TicketStatus.resolved, TicketStatus.approved, TicketStatus.rejected])).count()

    return render_template(
        "admin_reports.html",
        total_deposits=total_deposits,
        total_withdrawals=total_withdrawals,
        total_sales=total_sales,
        wallet_stats=wallet_stats,
        role_stats=role_stats,
        ticket_total=ticket_total,
        ticket_open=ticket_open,
        ticket_in_review=ticket_in_review,
        ticket_resolved=ticket_resolved,
        totals=totals,
        EntryType=EntryType,
        RoleEnum=RoleEnum,
        TicketStatus=TicketStatus,
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
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()

    # BookMe profile (gig profile)
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = bool(prof and getattr(prof, "is_visible", False))

    # -----------------------------
    # Requests (optional but useful)
    # -----------------------------
    incoming_requests = (
        db.session.query(func.count())
        .select_from(BookingRequest)
        .filter(BookingRequest.provider_id == current_user.id)
        .scalar()
        or 0
    )
    outgoing_requests = (
        db.session.query(func.count())
        .select_from(BookingRequest)
        .filter(BookingRequest.client_id == current_user.id)
        .scalar()
        or 0
    )

    # -----------------------------
    # Artist as CLIENT (booking others)
    # -----------------------------
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(client_id=current_user.id, status="pending").count()
    client_confirmed_bookings = Booking.query.filter_by(client_id=current_user.id, status="confirmed").count()

    client_recent_bookings = (
        Booking.query
        .filter_by(client_id=current_user.id)
        .order_by(Booking.event_datetime.desc())
        .limit(5)
        .all()
    )

    # -----------------------------
    # Artist as PROVIDER (getting booked for gigs)
    # -----------------------------
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(provider_id=current_user.id, status="pending").count()
    provider_confirmed_bookings = Booking.query.filter_by(provider_id=current_user.id, status="confirmed").count()

    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.event_datetime.desc())
        .limit(5)
        .all()
    )

    role_label = get_role_display(current_user.role)

    return render_template(
        "dash_artist.html",
        role_label=role_label,
        prof=prof,
        artist_can_take_gigs=artist_can_take_gigs,
        followers_count=followers_count,
        following_count=following_count,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,

        # Client side
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        client_confirmed_bookings=client_confirmed_bookings,
        client_recent_bookings=client_recent_bookings,

        # Provider side
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        provider_confirmed_bookings=provider_confirmed_bookings,
        provider_recent_bookings=provider_recent_bookings,
    )

@app.route("/dashboard/provider", endpoint="provider_dashboard")
@login_required
def provider_dashboard():
    if not is_service_provider(current_user):
        flash("You don't have access to the provider dashboard.", "error")
        return redirect(url_for("route_to_dashboard"))

    # -----------------------------
    # Counts
    # -----------------------------
    my_followers_count = (
        db.session.query(func.count())
        .select_from(UserFollow)
        .filter(UserFollow.followed_id == current_user.id)
        .scalar()
        or 0
    )

    my_following_count = (
        db.session.query(func.count())
        .select_from(UserFollow)
        .filter(UserFollow.follower_id == current_user.id)
        .scalar()
        or 0
    )

    incoming_requests = (
        db.session.query(func.count())
        .select_from(BookingRequest)
        .filter(BookingRequest.provider_id == current_user.id)
        .scalar()
        or 0
    )

    outgoing_requests = (
        db.session.query(func.count())
        .select_from(BookingRequest)
        .filter(BookingRequest.client_id == current_user.id)
        .scalar()
        or 0
    )

    incoming_bookings_count = (
        db.session.query(func.count())
        .select_from(Booking)
        .filter(Booking.provider_id == current_user.id)
        .scalar()
        or 0
    )

    outgoing_bookings_count = (
        db.session.query(func.count())
        .select_from(Booking)
        .filter(Booking.client_id == current_user.id)
        .scalar()
        or 0
    )

    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    portfolio_count = prof.portfolio_items.count() if prof else 0
    requires_portfolio = role_requires_portfolio(current_user.role)

    role_label = get_role_display(current_user.role)

    # -----------------------------
    # Profile completion
    # -----------------------------
    completion_points = 0
    next_steps = []

    # 1) BookMe profile exists
    if prof:
        completion_points += 20
    else:
        next_steps.append("Create your BookMe profile (shows you on the map).")

    # 2) Display name (BookMe preferred)
    display_name_val = None
    if prof and getattr(prof, "display_name", None):
        display_name_val = prof.display_name
    elif getattr(current_user, "display_name", None):
        display_name_val = current_user.display_name

    if display_name_val and str(display_name_val).strip():
        completion_points += 10
    else:
        next_steps.append("Add a display name (clients trust real names/brands).")

    # 3) Phone (BookMe preferred) ✅ FIX: uses contact_phone
    phone_val = (
        (getattr(prof, "contact_phone", None) if prof else None)
        or (getattr(prof, "phone", None) if prof else None)
        or (getattr(prof, "phone_number", None) if prof else None)
        or getattr(current_user, "phone", None)
    )

    if phone_val and str(phone_val).strip():
        completion_points += 10
    else:
        next_steps.append("Add a phone number (faster confirmations).")

    # 4) Bio/About
    bio_val = (getattr(prof, "bio", None) if prof else None) or getattr(current_user, "bio", None)
    if bio_val and str(bio_val).strip() and len(str(bio_val).strip()) >= 40:
        completion_points += 20
    else:
        next_steps.append("Write a strong bio (40+ chars) with your style + experience.")

    # 5) Location (city/state OR lat/lng)
    has_city_state = bool(prof and (getattr(prof, "city", None) or getattr(prof, "state", None)))
    has_latlng = bool(prof and getattr(prof, "lat", None) is not None and getattr(prof, "lng", None) is not None)
    if has_city_state or has_latlng:
        completion_points += 20
    else:
        next_steps.append("Set your location (so you appear correctly on the map).")

    # 6) Avatar ✅ FIX: don't rely on avatar_url (it always exists due to fallback)
    avatar_val = (
        getattr(current_user, "avatar_path", None)
        or getattr(current_user, "avatar_filename", None)
        or getattr(current_user, "avatar_file", None)
    )
    if avatar_val and str(avatar_val).strip():
        completion_points += 10
    else:
        next_steps.append("Upload a profile photo/logo (looks more professional).")

    # 7) Portfolio (only if required)
    if requires_portfolio:
        if portfolio_count > 0:
            completion_points += 10
        else:
            next_steps.append("Add at least 1 portfolio item (required for your role).")
    else:
        completion_points += 10

    profile_progress = max(0, min(100, int(completion_points)))

    # -----------------------------
    # Suggested creators/providers
    # -----------------------------
    fc_sub = (
        db.session.query(
            UserFollow.followed_id.label("uid"),
            func.count(UserFollow.followed_id).label("cnt"),
        )
        .group_by(UserFollow.followed_id)
        .subquery()
    )

    following_ids = {
        uid for (uid,) in (
            db.session.query(UserFollow.followed_id)
            .filter(UserFollow.follower_id == current_user.id)
            .all()
        )
    }

    rows = (
        db.session.query(
            User,
            func.coalesce(fc_sub.c.cnt, 0).label("followers_cnt"),
        )
        .outerjoin(fc_sub, fc_sub.c.uid == User.id)
        .filter(
            User.id != current_user.id,
            User.role != RoleEnum.admin,
        )
        .order_by(func.coalesce(fc_sub.c.cnt, 0).desc(), User.id.desc())
        .limit(6)
        .all()
    )

    suggested = []
    for u, fcnt in rows:
        u_prof = BookMeProfile.query.filter_by(user_id=u.id, is_visible=True).first()
        display_name = (u_prof.display_name if u_prof and u_prof.display_name else u.display_name)

        if is_service_provider(u) and u_prof and u_prof.is_visible:
            profile_url = url_for("provider_portfolio_public", username=u.username)
        else:
            profile_url = url_for("user_profile", username=u.username)

        suggested.append({
            "user_id": u.id,
            "username": u.username,
            "display_name": display_name or u.username,
            "role_label": get_role_display(u.role),
            "avatar_url": u.avatar_url,
            "followers_count": int(fcnt or 0),
            "is_following": (u.id in following_ids),
            "profile_url": profile_url,
        })

    return render_template(
        "dash_provider.html",
        prof=prof,
        my_followers_count=my_followers_count,
        my_following_count=my_following_count,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        incoming_bookings_count=incoming_bookings_count,
        outgoing_bookings_count=outgoing_bookings_count,
        portfolio_count=portfolio_count,
        requires_portfolio=requires_portfolio,
        role_label=role_label,
        suggested=suggested,
        profile_progress=profile_progress,
        profile_next_steps=next_steps,
        MAX_PORTFOLIO_ITEMS=MAX_PORTFOLIO_ITEMS,
    )

@app.route("/dashboard/producer", endpoint="producer_dashboard")
@role_required("producer")
def producer_dashboard():
    return redirect(url_for("provider_dashboard"))


@app.route("/dashboard/studio", endpoint="studio_dashboard")
@role_required("studio")
def studio_dashboard():
    return render_template("dash_studio.html")


@app.route("/dashboard/videographer", endpoint="videographer_dashboard")
@role_required("videographer")
def videographer_dashboard():
    return render_template("dash_videographer.html")


@app.route("/dashboard/designer", endpoint="designer_dashboard")
@role_required("designer")
def designer_dashboard():
    return render_template("dash_designer.html")


@app.route("/dashboard/engineer", endpoint="engineer_dashboard")
@role_required("engineer")
def engineer_dashboard():
    return render_template("dash_engineer.html")


@app.route("/dashboard/manager", endpoint="manager_dashboard")
@role_required("manager")
def manager_dashboard():
    return render_template("dash_manager.html")


@app.route("/dashboard/vendor", endpoint="vendor_dashboard")
@role_required("vendor")
def vendor_dashboard():
    return render_template("dash_vendor.html")


@app.route("/dashboard/funder", endpoint="funder_dashboard")
@role_required("funder")
def funder_dashboard():
    return render_template("dash_funder.html")

@app.route("/dashboard/client", endpoint="client_dashboard")
@role_required("client")
def client_dashboard():
    return render_template("dash_client.html")



# =========================================================
# Loans placeholder
# =========================================================
@app.route("/loans", endpoint="loans_home")
@login_required
def loans_home():
    flash("Loans module coming soon.")
    return redirect(url_for("route_to_dashboard"))


# =========================================================
# Opportunities (interest form -> SupportTicket)
# =========================================================
@app.route("/opportunities", methods=["GET", "POST"])
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

        flash("Thanks for sharing your interest! You can track status under “My tickets”.", "success")
        return redirect(url_for("opportunities"))

    return render_template("opportunities.html")


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

def _is_sqlite() -> bool:
    try:
        return str(db.engine.url).startswith("sqlite")
    except Exception:
        return False

def init_db_schema():
    """
    Safe schema initializer:
    - Runs SQLite-specific fixups ONLY if SQLite
    - Creates missing tables (create_all)
    NOTE: In true production, prefer migrations, but this is safe as a baseline.
    """
    with app.app_context():
        if _is_sqlite():
            try:
                _ensure_sqlite_follow_table_name_and_indexes()
                _ensure_sqlite_booking_request_booking_id()
            except Exception:
                db.session.rollback()

        db.create_all()

def seed_demo_data():
    """
    Seeds demo users. Should NOT run automatically in production.
    """
    with app.app_context():
        # ----------------------------
        # Admin
        # ----------------------------
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@example.com",
                role=RoleEnum.admin,
                kyc_status=KYCStatus.approved,
                is_superadmin=True,
            )
            admin.set_password(os.getenv("ADMIN_PASSWORD", "admin123"))
            db.session.add(admin)
            db.session.commit()
            get_or_create_wallet(admin.id)
        else:
            changed = False
            if not getattr(admin, "is_superadmin", False):
                admin.is_superadmin = True
                changed = True
            if not admin.email:
                admin.email = "admin@example.com"
                changed = True
            if changed:
                db.session.commit()

        # ----------------------------
        # Seed producer1 (+$50)
        # ----------------------------
        prod = User.query.filter_by(username="producer1").first()
        if not prod:
            prod = User(
                username="producer1",
                email="producer1@example.com",
                role=RoleEnum.producer,
                kyc_status=KYCStatus.approved,
            )
            prod.set_password(os.getenv("PRODUCER1_PASSWORD", "producer1123"))
            db.session.add(prod)
            db.session.commit()

            with db_txn():
                w = get_or_create_wallet(prod.id, commit=False)
                post_ledger(w, EntryType.deposit, 5_000, meta="seed $50")

        # ----------------------------
        # Seed artist1 (+$100)
        # ----------------------------
        artist = User.query.filter_by(username="artist1").first()
        if not artist:
            artist = User(
                username="artist1",
                email="artist1@example.com",
                role=RoleEnum.artist,
                kyc_status=KYCStatus.approved,
            )
            artist.set_password(os.getenv("ARTIST1_PASSWORD", "artist1123"))
            db.session.add(artist)
            db.session.commit()

            with db_txn():
                w = get_or_create_wallet(artist.id, commit=False)
                post_ledger(w, EntryType.deposit, 10_000, meta="seed $100")


# ============================
# Flask CLI commands (works in dev + prod)
# ============================

@app.cli.command("init-db")
def init_db_command():
    """Initialize DB schema (SQLite fixups + create_all)."""
    init_db_schema()
    click.echo("✅ Database schema initialized.")


@app.cli.command("seed-demo")
@click.option("--force", is_flag=True, help="Allow seeding even if not dev (requires SEED_DEMO=1 or --force).")
def seed_demo_command(force: bool):
    """
    Seed demo users. Protected so it doesn't run accidentally in production.
    Allow if:
      - IS_DEV is true, OR
      - env SEED_DEMO=1, OR
      - --force flag is used
    """
    allow = bool(IS_DEV) or (os.getenv("SEED_DEMO", "0") == "1") or force
    if not allow:
        raise click.ClickException(
            "Refusing to seed demo data. Set SEED_DEMO=1 or run with --force (be careful in production)."
        )

    # Make sure schema exists first
    init_db_schema()
    seed_demo_data()
    click.echo("✅ Demo data seeded.")


# ============================
# Main (no DB writes here)
# ============================
if __name__ == "__main__":
    debug_flag = os.getenv("FLASK_DEBUG", "1" if IS_DEV else "0") == "1"
    app.run(debug=debug_flag)