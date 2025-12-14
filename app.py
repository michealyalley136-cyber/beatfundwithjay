from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify, Response, session
)

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
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
import json  # <-- for providers_json in BookMe directory

HOLD_FEE_CENTS = 2000  # $20 hold fee for accepted bookings
MAX_TXN_DOLLARS = 10_000  # safety cap: max $10k per wallet action in dev
MAX_PORTFOLIO_ITEMS = 8  # max portfolio items per provider

# Password / security settings
PASSWORD_MAX_AGE_DAYS = 90          # admins must change password every 90 days
RESET_TOKEN_MAX_AGE_HOURS = 1       # reset links valid for 1 hour

# =========================================================
# App / DB setup
# =========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ------------------------------------------------------
# Environment / security config
# APP_ENV: "dev" or "prod" (default "dev")
# ------------------------------------------------------
APP_ENV = os.getenv("APP_ENV", "dev").lower()
IS_DEV = APP_ENV != "prod"

# ------------------------------------------------------
# Superadmin Owner Panel passcode
# ------------------------------------------------------
OWNER_PANEL_PASS = "Acidrain@0911"
# Session key + TTL (how long the unlock lasts)
OWNER_UNLOCK_SESSION_KEY = "owner_panel_unlocked_at"
OWNER_UNLOCK_TTL_SECONDS = 30 * 60  # 30 minutes

# ✅ Force absolute paths for templates/static (prevents 404 issues)
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)


# SECRET_KEY: MUST be set via env in production
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")

if not IS_DEV and app.config["SECRET_KEY"] == "change-me":
    raise RuntimeError(
        "SECURITY ERROR: SECRET_KEY must be set via environment variable in production."
    )

# Session / cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # protect against CSRF in most cases
    SESSION_COOKIE_SECURE=not IS_DEV,  # only send cookie over HTTPS in prod
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=not IS_DEV,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),  # 1 hour sessions
)

@app.route("/debug/owner-pass")
def debug_owner_pass():
    return f"OWNER_PANEL_PASS is: {repr(OWNER_PANEL_PASS)}"


# Optional: CSRF settings (good defaults for dev)
app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)   # tokens don't randomly expire on you in dev

# ------------------------------------------------------
# CSRF protection
# ------------------------------------------------------
csrf = CSRFProtect(app)


@app.context_processor
def inject_csrf_token():
    """
    Make csrf_token() available in all templates.

    Usage in templates:
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    """
    return dict(csrf_token=generate_csrf)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """
    Friendly handler for CSRF failures instead of a plain 400 page.
    """
    msg = e.description or "Security error: please refresh the page and try again."
    flash(msg, "error")
    return redirect(request.referrer or url_for("home")), 400


# ---- Fix for Jinja `is None` template error ----
@app.template_test("None")
def jinja_is_None(value):
    """
    Allow legacy usage of `is None` in templates.

    Jinja's built-in test is `is none` (lowercase). If a template uses
    `is None`, Jinja normally throws "No test named 'None' found.".
    This test makes that safe.
    """
    return value is None


os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'app.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File uploads
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_ROOT
ALLOWED_IMAGE = {"png", "jpg", "jpeg"}
ALLOWED_AUDIO = {"mp3", "wav", "m4a", "ogg"}
ALLOWED_STEMS = {"zip", "rar", "7z", "mp3", "wav", "m4a", "ogg"}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# =========================================================
# Opportunities Promo Video (Admin Upload + Public Serve)
# =========================================================
from werkzeug.utils import secure_filename

OPP_VIDEO_DIR = os.path.join(BASE_DIR, "uploads", "opportunities")
OPP_VIDEO_META = os.path.join(BASE_DIR, "data", "opportunities_video.json")
ALLOWED_VIDEO_EXTS = {"mp4", "webm", "mov"}

os.makedirs(OPP_VIDEO_DIR, exist_ok=True)
os.makedirs(os.path.dirname(OPP_VIDEO_META), exist_ok=True)

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
    with open(OPP_VIDEO_META, "w", encoding="utf-8") as f:
        json.dump(data, f)

def _current_opp_video_filename() -> str | None:
    return _load_opp_video_meta().get("filename")

def _set_current_opp_video_filename(filename: str) -> None:
    meta = _load_opp_video_meta()
    meta["filename"] = filename
    meta["updated_at"] = datetime.utcnow().isoformat()
    _save_opp_video_meta(meta)

def _is_admin() -> bool:
    # Use your RoleEnum.admin
    return (current_user.is_authenticated and getattr(current_user, "role", None) == RoleEnum.admin)

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

        # Save with unique filename
        ext = file.filename.rsplit(".", 1)[1].lower()
        new_name = secure_filename(f"opportunities_{uuid.uuid4().hex}.{ext}")
        save_path = os.path.join(OPP_VIDEO_DIR, new_name)
        file.save(save_path)

        # Optional cleanup: delete old file
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
# Models
# =========================================================
class RoleEnum(str, enum.Enum):
    # Core app roles
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

    # Extended industry roles (providers)
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


# ------------------------------------------------------
# Human-friendly labels for roles
# (used in dashboards / templates)
# ------------------------------------------------------
ROLE_DISPLAY_NAMES = {
    RoleEnum.admin: "Admin",
    RoleEnum.artist: "Artist",
    RoleEnum.producer: "Producer",
    RoleEnum.studio: "Studio",
    RoleEnum.videographer: "Videographer",
    RoleEnum.designer: "Designer",
    RoleEnum.engineer: "Engineer",
    RoleEnum.manager: "Manager",
    RoleEnum.vendor: "Vendor",
    RoleEnum.funder: "Funder",
    RoleEnum.client: "Client",

    RoleEnum.dancer_choreographer: "Dancer / Choreographer",
    RoleEnum.makeup_artist: "Makeup Artist",
    RoleEnum.hair_stylist_barber: "Hair Stylist / Barber",
    RoleEnum.wardrobe_stylist: "Wardrobe Stylist",
    RoleEnum.photographer: "Photographer",
    RoleEnum.event_planner: "Event Planner",
    RoleEnum.emcee_host_hypeman: "Host / Hypeman",
    RoleEnum.dj: "DJ",
    RoleEnum.live_sound_engineer: "Live Sound Engineer",
    RoleEnum.mix_master_engineer: "Mix & Master Engineer",
    RoleEnum.lighting_designer: "Lighting Designer",
    RoleEnum.stage_set_designer: "Stage / Set Designer",
    RoleEnum.decor_vendor: "Decor Vendor",
    RoleEnum.caterer_food_truck: "Caterer / Food Truck",
    RoleEnum.brand_pr_consultant: "Brand & PR Consultant",
    RoleEnum.social_media_manager: "Social Media Manager",
    RoleEnum.security_usher_crowd_control: "Security / Usher / Crowd Control",
}


def get_role_display(role: RoleEnum) -> str:
    """
    Return a nice human-readable label for a RoleEnum
    (or for a plain string role value).
    """
    # If it's a RoleEnum already
    if isinstance(role, RoleEnum):
        return ROLE_DISPLAY_NAMES.get(role, role.value.replace("_", " ").title())

    # If someone passes a plain string like "videographer"
    try:
        role_enum = RoleEnum(str(role))
        return ROLE_DISPLAY_NAMES.get(
            role_enum,
            role_enum.value.replace("_", " ").title(),
        )
    except Exception:
        return str(role).replace("_", " ").title()


# Make basic enums + constants available in all Jinja templates
app.jinja_env.globals["RoleEnum"] = RoleEnum
app.jinja_env.globals["KYCStatus"] = KYCStatus
app.jinja_env.globals["MAX_PORTFOLIO_ITEMS"] = MAX_PORTFOLIO_ITEMS
app.jinja_env.globals["get_role_display"] = get_role_display


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Identity
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)

    # Profile names
    full_name = db.Column(db.String(150), nullable=True)
    artist_name = db.Column(db.String(150), nullable=True)

    # Auth / role
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(RoleEnum), nullable=False, default=RoleEnum.artist)
    kyc_status = db.Column(db.Enum(KYCStatus), nullable=False, default=KYCStatus.not_started)
    is_active_col = db.Column("is_active", db.Boolean, nullable=False, default=True)

    # SUPER ADMIN FLAG
    is_superadmin = db.Column(db.Boolean, nullable=False, default=False)

    # Password metadata
    password_changed_at = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_sent_at = db.Column(db.DateTime, nullable=True)

    # Avatar field
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
        if not self.cover_path:
            return None
        return url_for("media_file", filename=self.cover_path)

    @property
    def preview_url(self):
        if not self.preview_path:
            return None
        return url_for("media_file", filename=self.preview_path)

    @property
    def stems_url(self):
        if not self.stems_path:
            return None
        return url_for("media_file", filename=self.stems_path)


class OrderStatus(str, enum.Enum):
    paid = "paid"
    refunded = "refunded"


class Order(db.Model):
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


# ------- BookMe -------

BOOKME_PROVIDER_ROLES = {
    RoleEnum.artist.value,
    RoleEnum.producer.value,
    RoleEnum.studio.value,
    RoleEnum.videographer.value,
    RoleEnum.designer.value,
    RoleEnum.engineer.value,
    RoleEnum.manager.value,
    RoleEnum.vendor.value,
    RoleEnum.dancer_choreographer.value,
    RoleEnum.makeup_artist.value,
    RoleEnum.hair_stylist_barber.value,
    RoleEnum.wardrobe_stylist.value,
    RoleEnum.photographer.value,
    RoleEnum.event_planner.value,
    RoleEnum.emcee_host_hypeman.value,
    RoleEnum.dj.value,
    RoleEnum.live_sound_engineer.value,
    RoleEnum.mix_master_engineer.value,
    RoleEnum.lighting_designer.value,
    RoleEnum.stage_set_designer.value,
    RoleEnum.decor_vendor.value,
    RoleEnum.caterer_food_truck.value,
    RoleEnum.brand_pr_consultant.value,
    RoleEnum.social_media_manager.value,
    RoleEnum.security_usher_crowd_control.value,
}

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
app.jinja_env.globals["BOOKME_PROVIDER_ROLES"] = BOOKME_PROVIDER_ROLES


def role_requires_portfolio(role: RoleEnum) -> bool:
    return role in PORTFOLIO_REQUIRED_ROLES


class BookMeProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False,
    )

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

    user = db.relationship(
        "User",
        backref=db.backref("bookme_profile", uselist=False),
    )


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

    profile = db.relationship(
        "BookMeProfile",
        backref=db.backref("portfolio_items", lazy="dynamic")
    )

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
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.Text, nullable=True)
    preferred_time = db.Column(db.String(120), nullable=False)
    status = db.Column(db.Enum(BookingStatus), nullable=False, default=BookingStatus.pending)
    created_at = db.Column(db.DateTime, server_default=func.now())

    provider = db.relationship("User", foreign_keys=[provider_id])
    client = db.relationship("User", foreign_keys=[client_id])


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

    ticket = db.relationship(
        "SupportTicket",
        backref=db.backref("comments", lazy="dynamic")
    )
    admin = db.relationship("User")

    def __repr__(self):
        return f"<SupportTicketComment ticket={self.ticket_id} admin={self.admin_id}>"


app.jinja_env.globals["TicketStatus"] = TicketStatus
app.jinja_env.globals["TicketType"] = TicketType


class Booking(db.Model):
    __tablename__ = "booking"

    id = db.Column(db.Integer, primary_key=True)

    # provider (artist, DJ, dancer, producer, etc.)
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
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    provider = db.relationship(
        "User",
        foreign_keys=[provider_id],
        backref=db.backref("artist_bookings", lazy="dynamic"),
    )
    client = db.relationship(
        "User",
        foreign_keys=[client_id],
        backref=db.backref("client_bookings", lazy="dynamic"),
    )

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

    booking = db.relationship(
        "Booking",
        backref=db.backref("disputes", lazy="dynamic")
    )
    opened_by = db.relationship("User", foreign_keys=[opened_by_id])


# ------- Follows -------
class UserFollow(db.Model):
    __tablename__ = "user_follow"

    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    follower = db.relationship("User", foreign_keys=[follower_id], backref="following")
    followed = db.relationship("User", foreign_keys=[followed_id], backref="followers")

    def __repr__(self):
        return f"<UserFollow follower={self.follower_id} followed={self.followed_id}>"

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

    age = datetime.utcnow() - user.password_changed_at
    return age > timedelta(days=PASSWORD_MAX_AGE_DAYS)


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
    """
    Returns True if the current superadmin has recently entered
    the correct OWNER_PANEL_PASS in this browser session.
    """
    ts = session.get(OWNER_UNLOCK_SESSION_KEY)
    if not ts:
        return False

    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False

    # still valid?
    return (time() - ts) < OWNER_UNLOCK_TTL_SECONDS


def require_kyc_approved():
    if current_user.kyc_status != KYCStatus.approved:
        flash("Financial features require approved KYC.")
        return False
    return True


def get_or_create_wallet(user_id: int) -> Wallet:
    w = Wallet.query.filter_by(user_id=user_id).first()
    if not w:
        w = Wallet(user_id=user_id)
        db.session.add(w)
        db.session.commit()
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


def post_ledger(wallet: Wallet, entry_type: EntryType, amount_cents: int, meta: str = ""):
    assert amount_cents > 0, "amount must be positive cents"
    db.session.add(
        LedgerEntry(
            wallet_id=wallet.id,
            entry_type=entry_type,
            amount_cents=amount_cents,
            meta=meta,
        )
    )
    db.session.commit()


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
        pathlib.Path(os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)).unlink(
            missing_ok=True
        )
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
    return u.role.value in BOOKME_PROVIDER_ROLES


def get_role_display(role_enum: RoleEnum) -> str:
    """
    Turn a RoleEnum into a nice label for dashboards, etc.
    """
    custom_map = {
        # Core creator roles
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

        # Extended provider roles
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
        RoleEnum.security_usher_crowd_control: "Security / Ushers",
    }
    # Fallback: prettify the enum value if we ever add a new one
    return custom_map.get(role_enum, role_enum.value.replace("_", " ").title())


def _ensure_bookme_provider():
    if current_user.role.value not in BOOKME_PROVIDER_ROLES:
        flash("Only service providers can edit a BookMe profile.")
        return False
    return True



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

    query = (BookMeProfile.query
             .join(User, BookMeProfile.user_id == User.id)
             .filter(BookMeProfile.is_visible == True))

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

    # payload for map pins directly from this view
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
        providers_json=providers_json,  # map data for JS
    )


@app.route("/bookme/data")
@login_required
def bookme_data():
    role = (request.args.get("role") or "").strip().lower()
    zip_code = (request.args.get("zip") or "").strip()
    city = (request.args.get("city") or "").strip()
    state = (request.args.get("state") or "").strip()
    q = (request.args.get("q") or "").strip()

    query = (BookMeProfile.query
             .join(User, BookMeProfile.user_id == User.id)
             .filter(
                 BookMeProfile.is_visible == True,
                 BookMeProfile.lat.isnot(None),
                 BookMeProfile.lng.isnot(None),
             ))

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
    """
    BookMe Requests page.

    - incoming_requests: PENDING BookingRequest rows where you are the provider
    - outgoing_requests: BookingRequest rows you’ve sent (all statuses)
    - incoming_bookings: Booking rows where you are provider
    - outgoing_bookings: Booking rows where you are client
    """

    # Requests TO you (only pending ones – so you just see what needs action)
    incoming_requests = (
        BookingRequest.query
        .filter(
            BookingRequest.provider_id == current_user.id,
            BookingRequest.status == BookingStatus.pending,
        )
        .order_by(BookingRequest.created_at.desc())
        .all()
    )

    # Requests YOU sent to other providers (any status)
    outgoing_requests = (
        BookingRequest.query
        .filter(BookingRequest.client_id == current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .all()
    )

    # Bookings where you are the provider
    incoming_bookings = (
        Booking.query
        .filter(Booking.provider_id == current_user.id)
        .order_by(Booking.event_datetime.desc().nullslast())
        .all()
    )

    # Bookings where you are the client
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
    req = BookingRequest.query.get_or_404(req_id)
    action = (request.form.get("action") or "").strip().lower()

    # Provider actions
    if current_user.id == req.provider_id and action in ("accept", "decline"):

        if action == "decline":
            req.status = BookingStatus.declined
            db.session.commit()
            flash("Booking request declined.", "success")
            return redirect(url_for("bookme_requests"))

        if action == "accept":
            # check slot conflict
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
                flash("This time slot is already booked.", "error")
                return redirect(url_for("bookme_requests"))

            client = User.query.get(req.client_id)
            provider = User.query.get(req.provider_id)

            booking = None

            if client and provider:
                client_wallet = get_or_create_wallet(client.id)
                provider_wallet = get_or_create_wallet(provider.id)

                if wallet_balance_cents(client_wallet) < HOLD_FEE_CENTS:
                    flash(
                        "Client doesn't have enough balance for the $20 hold fee. "
                        "Ask them to add funds to their wallet.",
                        "error",
                    )
                    return redirect(url_for("bookme_requests"))

                post_ledger(
                    client_wallet,
                    EntryType.purchase_spend,
                    HOLD_FEE_CENTS,
                    meta=f"Booking hold fee to @{provider.username} for {req.preferred_time}",
                )
                post_ledger(
                    provider_wallet,
                    EntryType.sale_income,
                    HOLD_FEE_CENTS,
                    meta=f"Booking hold fee from @{client.username} for {req.preferred_time}",
                )

                event_dt = None
                if req.preferred_time:
                    try:
                        event_dt = datetime.strptime(req.preferred_time, "%Y-%m-%d %H:%M")
                    except ValueError:
                        event_dt = None

                if req.message and req.message.strip():
                    title = req.message.strip()[:80]
                else:
                    title = f"BookMe booking with @{provider.username}"

                booking = Booking(
                    provider_id=provider.id,
                    provider_role=provider.role,
                    client_id=client.id,
                    event_title=title,
                    event_datetime=event_dt,
                    duration_minutes=None,
                    location_text=None,
                    total_cents=HOLD_FEE_CENTS,
                    notes_from_client=req.message or None,
                    status="confirmed",
                )
                db.session.add(booking)

            req.status = BookingStatus.accepted
            db.session.commit()

            flash(
                "Booking accepted. Hold fee charged and a booking record created.",
                "success",
            )

            if booking:
                return redirect(url_for("booking_detail", booking_id=booking.id))

            return redirect(url_for("bookme_requests"))

    # Client cancel
    if current_user.id == req.client_id and action == "cancel":
        if req.status in (BookingStatus.pending, BookingStatus.accepted):
            req.status = BookingStatus.cancelled
            db.session.commit()
            flash("Booking request cancelled.", "success")
        else:
            flash("You can only cancel pending or accepted bookings.", "error")
        return redirect(url_for("bookme_requests"))

    flash("You are not allowed to perform this action.", "error")
    return redirect(url_for("bookme_requests"))


@app.route("/bookings/<int:booking_id>", methods=["GET", "POST"])
@login_required
def booking_detail(booking_id):
    """
    Detailed view of a single Booking.

    - Only provider, client, or admin can see it.
    - Provider can add internal notes / mark booking completed.
    """
    booking = Booking.query.get_or_404(booking_id)

    # Access control: provider, client, or admin only
    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        flash("You don't have access to this booking.", "error")
        return redirect(url_for("bookme_requests"))

    if request.method == "POST":
        # For now, only the provider can update details from this page.
        if not is_provider:
            flash("Only the provider can update this booking.", "error")
            return redirect(url_for("booking_detail", booking_id=booking.id))

        notes_from_provider = (request.form.get("notes_from_provider") or "").strip()
        status_action = (request.form.get("status_action") or "").strip().lower()

        # Update provider notes
        booking.notes_from_provider = notes_from_provider or None

        # Optional status transition: mark completed from confirmed
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

    return render_template(
        "booking_detail.html",
        booking=booking,
        is_provider=is_provider,
        is_client=is_client,
    )


# generic booking link for any provider (designer, DJ, artist, etc.)
@app.route("/bookme/<username>/book", methods=["GET", "POST"])
@login_required
def bookme_book_provider(username):
    """
    Generic public booking link for any BookMe provider.

    This simply reuses the same logic as the artist booking page so that
    all providers share the same booking form and flow.
    """
    return book_artist(username)


@app.route("/artists/<username>/book", methods=["GET", "POST"])
@login_required
def book_artist(username):
    artist = User.query.filter_by(username=username).first_or_404()

    is_owner = current_user.id == artist.id

    if request.method == "POST":
        if is_owner:
            flash(
                "You can’t send a booking request to yourself. "
                "Share this booking link with your clients instead.",
                "error",
            )
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
                event_datetime = datetime.strptime(
                    f"{event_date} {event_time}",
                    "%Y-%m-%d %H:%M"
                )
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
            return render_template(
                "artist_booking.html",
                artist=artist,
                form_data=request.form,
                is_owner=is_owner,
            )

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

    return render_template(
        "artist_booking.html",
        artist=artist,
        form_data={},
        is_owner=is_owner,
    )


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
            else:
                allowed = ALLOWED_IMAGE | ALLOWED_AUDIO

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

    items = (
        prof.portfolio_items
        .order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc())
        .all()
    )
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
@login_required  # make public later if desired
def provider_portfolio_public(username):
    user = User.query.filter_by(username=username).first_or_404()

    prof = (
        BookMeProfile.query
        .filter_by(user_id=user.id, is_visible=True)
        .first_or_404()
    )

    items = (
        prof.portfolio_items
        .order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc())
        .all()
    )

    return render_template(
        "provider_portfolio_public.html",
        provider=user,
        prof=prof,
        items=items,
        PortfolioMediaType=PortfolioMediaType,
    )


# =========================================================
# Core / Auth
# =========================================================
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Registration matching the new BeatFund form:

    - name          -> full_name
    - artist_name   -> artist_name
    - email         -> email (required, unique)
    - username      -> username (required, unique; we strip leading "@")
    - password / confirm_password
    - role          -> mapped directly to RoleEnum from the custom dropdown
    """
    if request.method == "POST":
        full_name = (request.form.get("name") or "").strip()
        artist_name = (request.form.get("artist_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        raw_username = (request.form.get("username") or "").strip()
        username = raw_username.lstrip("@").lower()

        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        # 🔴 THIS IS THE KEY CHANGE: read from "role", not "primary_role"
        role_key = (request.form.get("role") or "").strip()

        # Basic required fields
        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("register"))

        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("register"))

        # Very simple email format check (good enough for now)
        if "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        # Password validation
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

        # Username uniqueness
        existing_user = User.query.filter(
            func.lower(User.username) == username.lower()
        ).first()
        if existing_user:
            flash("That username is already taken.", "error")
            return redirect(url_for("register"))

        # Email uniqueness
        if email:
            existing_email = User.query.filter(
                func.lower(User.email) == email.lower()
            ).first()
            if existing_email:
                flash("That email is already registered.", "error")
                return redirect(url_for("register"))

        # 🔴 Validate and map the role from the hidden input
        if not role_key:
            flash("Please select your main role.", "error")
            return redirect(url_for("register"))

        try:
            # role_key should match one of the RoleEnum values, e.g.
            # "artist", "producer", "videographer", "funder", "client", etc.
            chosen_role = RoleEnum(role_key)
        except ValueError:
            flash("Invalid account type. Please pick a role from the list.", "error")
            return redirect(url_for("register"))

        # Create user
        user = User(
            username=username,
            email=email,
            full_name=full_name or None,
            artist_name=artist_name or None,
            role=chosen_role,
        )

        # Dev-only: auto-approve KYC so you can use wallet/marketplace
        if IS_DEV:
            user.kyc_status = KYCStatus.approved

        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Auto-create wallet
        get_or_create_wallet(user.id)

        login_user(user)
        flash("Account created! (KYC auto-approved in dev.)", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login supports BOTH:

    - Email:    admin@example.com
    - Username: admin   or   @admin

    The form can post either:
      - name="identifier"
      - or legacy name="username"
    """
    if request.method == "POST":
        remote_addr = request.remote_addr or "unknown"

        if _too_many_failed_logins(remote_addr):
            flash(
                "Too many failed login attempts. "
                "Please wait a few minutes and try again.",
                "error",
            )
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
        # Very simple heuristic: treat as email if it looks like one
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
            flash(
                "For security, your admin password must be updated before continuing.",
                "error",
            )
            return redirect(url_for("force_password_reset"))

        return redirect(url_for("route_to_dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    Password reset request via email OR username.

    The form can post:
      - name="identifier"   (recommended)
      - or legacy name="username"
    """
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
            # looks like an email
            user = User.query.filter(func.lower(User.email) == identifier).first()
        else:
            # treat as username, allow leading "@"
            handle = identifier.lstrip("@")
            user = User.query.filter(func.lower(User.username) == handle).first()

        if user:
            token = uuid.uuid4().hex
            user.password_reset_token = token
            user.password_reset_sent_at = datetime.utcnow()
            db.session.commit()

            reset_link = url_for("reset_password", token=token, _external=True)
            # DEV-ONLY: print reset link to terminal
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
    """
    Alias endpoint so templates can use url_for('reset_password_request').

    This reuses the same logic as forgot_password().
    """
    return forgot_password()


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(password_reset_token=token).first()
    if not user:
        flash("This reset link is invalid or has already been used.", "error")
        return redirect(url_for("forgot_password"))

    if not user.password_reset_sent_at or (
        datetime.utcnow() - user.password_reset_sent_at
        > timedelta(hours=RESET_TOKEN_MAX_AGE_HOURS)
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
@app.route("/wallet", endpoint="wallet_home")
@login_required
def wallet_page():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    w = get_or_create_wallet(current_user.id)
    balance = wallet_balance_cents(w) / 100.0
    recent = (LedgerEntry.query
              .filter_by(wallet_id=w.id)
              .order_by(LedgerEntry.id.desc())
              .limit(10).all())
    return render_template("wallet.html", balance=balance, recent=recent)


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
        .filter(
            LedgerEntry.created_at >= start_dt,
            LedgerEntry.created_at <= end_dt,
        )
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

        writer.writerow([
            created_str,
            row.entry_type.value,
            direction,
            amount_dollars,
            row.meta or "",
        ])

    output = si.getvalue()
    filename = f"beatfund_statement_{current_user.username}_{year}_{month:02d}.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


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


@app.route("/wallet/action", methods=["POST"])
@login_required
def wallet_action():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    action = (request.form.get("action") or "").strip().lower()
    amount_raw = (request.form.get("amount") or "").strip()

    if not amount_raw:
        flash("Amount is required.")
        return redirect(url_for("wallet_home"))

    if not re.match(r"^\d+(\.\d{1,2})?$", amount_raw):
        flash("Amount must be a positive number with at most 2 decimal places (e.g. 12.50).")
        return redirect(url_for("wallet_home"))

    try:
        amt = Decimal(amount_raw)
    except InvalidOperation:
        flash("Invalid amount format.")
        return redirect(url_for("wallet_home"))

    if amt <= 0:
        flash("Amount must be greater than zero.")
        return redirect(url_for("wallet_home"))

    if amt > Decimal(MAX_TXN_DOLLARS):
        flash(f"Amount exceeds the maximum allowed (${MAX_TXN_DOLLARS:,.2f}) for a single transaction.")
        return redirect(url_for("wallet_home"))

    cents = int((amt * 100).to_integral_value())

    method = (request.form.get("method") or "").strip()
    w = get_or_create_wallet(current_user.id)

    if action == "add":
        meta = f"deposit via {method or 'unknown'}"
        post_ledger(w, EntryType.deposit, cents, meta=meta)
        flash(f"Added ${amt:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    if action == "send":
        handle = (request.form.get("handle") or "").strip().lower()
        recipient = User.query.filter_by(username=handle).first()

        if not recipient:
            flash("Recipient not found.")
            return redirect(url_for("wallet_home"))

        if recipient.id == current_user.id:
            flash("You can't send money to yourself.")
            return redirect(url_for("wallet_home"))

        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.")
            return redirect(url_for("wallet_home"))

        w_recipient = get_or_create_wallet(recipient.id)
        note = (request.form.get("note") or "").strip()

        meta_out = f"to @{recipient.username}"
        meta_in = f"from @{current_user.username}"
        if note:
            meta_out += f" | {note}"
            meta_in += f" | {note}"

        post_ledger(w, EntryType.transfer_out, cents, meta=meta_out)
        post_ledger(w_recipient, EntryType.transfer_in, cents, meta=meta_in)

        flash(f"Sent ${amt:,.2f} to @{recipient.username}.")
        return redirect(url_for("wallet_home"))

    if action == "withdraw":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.")
            return redirect(url_for("wallet_home"))

        post_ledger(w, EntryType.withdrawal, cents, meta="withdraw to bank (demo)")
        flash(f"Withdrew ${amt:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    flash("Unknown wallet action.")
    return redirect(url_for("wallet_home"))


# =========================================================
# Files
# =========================================================
@app.route("/uploads/<path:filename>")
@login_required
def media_file(filename):
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
# Marketplace
# =========================================================
@app.route("/market", endpoint="market_index")
@login_required
def market_index():
    # Top rail: beats
    items = (
        Beat.query.filter_by(is_active=True)
        .order_by(Beat.is_featured.desc(), Beat.id.desc())
        .all()
    )

    # All visible service providers that have a BookMe profile
    provider_profiles = (
        BookMeProfile.query
        .join(User, BookMeProfile.user_id == User.id)
        .filter(
            BookMeProfile.is_visible == True,
            User.role.in_(BOOKME_PROVIDER_ROLES),
        )
        .order_by(BookMeProfile.city.asc(), BookMeProfile.display_name.asc())
        .all()
    )

    # Helper: check if a BookMeProfile's user has any of these roles
    def profile_has_role(profile, roles):
        u = profile.user
        return (u is not None) and (u.role in roles)

    # ---- Rail 1: Studios near you ----
    studios = [
        p for p in provider_profiles
        if profile_has_role(p, {RoleEnum.studio})
    ]

    # ---- Rail 2: Videographers & directors ----
    videographers = [
        p for p in provider_profiles
        if profile_has_role(p, {RoleEnum.videographer})
    ]

    # ---- Rail 3: Talent & video vixens ----
    talent_roles = {
        RoleEnum.artist,
        RoleEnum.dancer_choreographer,
        RoleEnum.emcee_host_hypeman,
        RoleEnum.dj,
    }
    talent_profiles = [
        p for p in provider_profiles
        if profile_has_role(p, talent_roles)
    ]

    # ---- Rail 4: Other providers (everything else) ----
    used_ids = {p.id for p in studios + videographers + talent_profiles}
    other_providers = [p for p in provider_profiles if p.id not in used_ids]

    # NOTE: we still pass provider_profiles for backwards compatibility
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
    orders = (Order.query
              .filter_by(buyer_id=current_user.id, status=OrderStatus.paid)
              .order_by(Order.created_at.desc())
              .all())

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
    seller = User.query.get(beat.owner_id)
    if seller.id == current_user.id:
        flash("You can’t buy your own beat.")
        return redirect(url_for("market_index"))

    buyer_w = get_or_create_wallet(current_user.id)
    seller_w = get_or_create_wallet(seller.id)

    if wallet_balance_cents(buyer_w) < beat.price_cents:
        flash("Insufficient wallet balance.")
        return redirect(url_for("wallet_home"))

    post_ledger(buyer_w, EntryType.purchase_spend, beat.price_cents,
                meta=f"buy beat #{beat.id} '{beat.title}'")
    post_ledger(seller_w, EntryType.sale_income, beat.price_cents,
                meta=f"sale beat #{beat.id} to @{current_user.username}")

    order = Order(
        beat_id=beat.id,
        buyer_id=current_user.id,
        seller_id=seller.id,
        amount_cents=beat.price_cents,
        status=OrderStatus.paid
    )
    db.session.add(order)
    db.session.commit()

    flash("Purchase complete! You now have download access.")
    return redirect(url_for("market_my_purchases"))


@app.route("/market/download/<int:beat_id>")
@login_required
def market_download(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    if (beat.owner_id != current_user.id
            and not _user_has_paid_for_beat(current_user.id, beat_id)):
        flash("You don’t have access to download this file.")
        return redirect(url_for("market_index"))

    if not beat.stems_path:
        flash("No deliverable file available for this beat.")
        return redirect(url_for("market_index"))

    return send_from_directory(app.config["UPLOAD_FOLDER"], beat.stems_path, as_attachment=True)


@app.route("/producers")
@login_required
def producer_catalog_index():
    all_beats = Beat.query.all()
    producers_map = {}

    for beat in all_beats:
        owner = getattr(beat, "owner", None)
        if not owner:
            continue
        user_id = getattr(owner, "id", None)
        if not user_id:
            continue

        if user_id not in producers_map:
            producers_map[user_id] = {
                "user": owner,
                "beats": [],
                "genres": set(),
            }

        producers_map[user_id]["beats"].append(beat)
        genre_val = getattr(beat, "genre", None)
        if genre_val:
            producers_map[user_id]["genres"].add(genre_val)

    producers = []
    for data in producers_map.values():
        user = data["user"]
        beats_for_user = data["beats"]
        genres = list(data["genres"])

        display_name = (
            getattr(user, "display_name", None)
            or getattr(user, "name", None)
            or getattr(user, "username", "Producer")
        )
        avatar_url = getattr(user, "avatar_url", None)
        location = getattr(user, "location", None)
        city = getattr(user, "city", None)
        state = getattr(user, "state", None)
        followers_count = getattr(user, "followers_count", 0) or 0
        rating = getattr(user, "rating", None)
        rating_count = getattr(user, "rating_count", 0) or 0

        producers.append(
            {
                "user": user,
                "display_name": display_name,
                "username": getattr(user, "username", None),
                "avatar_url": avatar_url,
                "location": location,
                "city": city,
                "state": state,
                "followers_count": followers_count,
                "rating": rating,
                "rating_count": rating_count,
                "genres": genres[:3],
                "beats_count": len(beats_for_user),
            }
        )

    producers.sort(key=lambda p: p["beats_count"], reverse=True)

    return render_template("producer_catalog_index.html", producers=producers)


@app.route("/producers/<username>")
@login_required
def producer_catalog_detail(username):
    all_beats = Beat.query.all()
    beats_for_producer = []
    producer_user = None

    for beat in all_beats:
        owner = getattr(beat, "owner", None)
        if not owner:
            continue
        owner_username = getattr(owner, "username", None)
        if not owner_username:
            continue

        if owner_username.lower() == username.lower():
            beats_for_producer.append(beat)
            producer_user = owner

    producer_profile = None
    if producer_user:
        genres = sorted(
            {b.genre for b in beats_for_producer if getattr(b, "genre", None)}
        )

        display_name = (
            getattr(producer_user, "display_name", None)
            or getattr(producer_user, "name", None)
            or getattr(producer_user, "username", "Producer")
        )
        avatar_url = getattr(producer_user, "avatar_url", None)
        location = getattr(producer_user, "location", None)
        city = getattr(producer_user, "city", None)
        state = getattr(producer_user, "state", None)
        followers_count = getattr(producer_user, "followers_count", 0) or 0
        rating = getattr(producer_user, "rating", None)
        rating_count = getattr(producer_user, "rating_count", 0) or 0

        producer_profile = {
            "user": producer_user,
            "display_name": display_name,
            "username": getattr(producer_user, "username", None),
            "avatar_url": avatar_url,
            "location": location,
            "city": city,
            "state": state,
            "followers_count": followers_count,
            "rating": rating,
            "rating_count": rating_count,
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
    producer = User.query.filter_by(username=username, role=RoleEnum.producer).first_or_404()

    if producer.id == current_user.id:
        flash("You can’t follow yourself.", "info")
        return redirect(request.referrer or url_for("producer_catalog_detail", username=username))

    existing = UserFollow.query.filter_by(
        follower_id=current_user.id,
        followed_id=producer.id
    ).first()

    if existing:
        db.session.delete(existing)
        db.session.commit()
        flash(f"You unfollowed @{producer.username}.", "success")
    else:
        follow = UserFollow(follower_id=current_user.id, followed_id=producer.id)
        db.session.add(follow)
        db.session.commit()
        flash(f"You followed @{producer.username}.", "success")

    return redirect(request.referrer or url_for("producer_catalog_detail", username=username))


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
            producer_map[pid] = {
                "producer": owner,
                "beat_count": 0,
                "genres_counter": Counter(),
            }

        producer_map[pid]["beat_count"] += 1

        genre = getattr(beat, "genre", None)
        if genre:
            producer_map[pid]["genres_counter"][genre] += 1

    producers = []
    for data in producer_map.values():
        genres_counter = data["genres_counter"]
        top_genres = [name for name, _ in genres_counter.most_common(3)]

        producers.append({
            "producer": data["producer"],
            "beat_count": data["beat_count"],
            "genres": top_genres,
            "followers_count": 0,
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
            beat.stems_path = _save_file(stems_file, ALLOWED_AUDIO)

        db.session.add(beat)
        db.session.commit()
        flash("Beat saved to your catalog.", "success")
        return redirect(url_for("producer_beats"))

    beats = (
        Beat.query
        .filter_by(owner_id=current_user.id)
        .order_by(Beat.id.desc())
        .all()
    )
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
# Admin – Dashboard / Users / KYC
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
        SupportTicket.status.in_([
            TicketStatus.resolved,
            TicketStatus.approved,
            TicketStatus.rejected,
        ])
    ).count()

    events = []

    audit_rows = (
        AuditLog.query
        .order_by(AuditLog.created_at.desc())
        .limit(8)
        .all()
    )
    for row in audit_rows:
        events.append({
            "ts": row.created_at,
            "kind": "audit",
            "title": "Wallet access logged",
            "body": f"@{row.admin.username} accessed "
                    f"{'@'+row.user.username if row.user else 'an account'} "
                    f"({row.action}).",
        })

    ticket_rows = (
        SupportTicket.query
        .order_by(SupportTicket.created_at.desc())
        .limit(8)
        .all()
    )
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

    # Start with all non-admin users
    query = User.query.filter(User.role != RoleEnum.admin)

    # Text search on username
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(func.lower(User.username).like(like))

    # Filter by role (artist, producer, etc.)
    if role:
        try:
            query = query.filter(User.role == RoleEnum(role))
        except ValueError:
            # Invalid role string; ignore filter
            pass

    # Filter by KYC status
    if status:
        try:
            query = query.filter(User.kyc_status == KYCStatus(status))
        except ValueError:
            # Invalid KYC status; ignore filter
            pass

    # Filter by active / inactive
    if active == "active":
        query = query.filter(User.is_active_col.is_(True))
    elif active == "inactive":
        query = query.filter(User.is_active_col.is_(False))

    pagination = query.order_by(User.id.asc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )
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


@app.route(
    "/dashboard/admin/superadmin/unlock",
    methods=["GET", "POST"],
    endpoint="superadmin_unlock",
)
@superadmin_required
def superadmin_unlock():
    """
    Extra passcode gate for the Owner / Superadmin panel.

    - You must already be logged in as an admin with is_superadmin = True.
    - Then you enter the passphrase: OWNER_PANEL_PASS.
    """
    if request.method == "POST":
        passphrase = (request.form.get("passphrase") or "").strip()

        if passphrase == OWNER_PANEL_PASS:
            # mark as unlocked in this session
            session[OWNER_UNLOCK_SESSION_KEY] = time()
            flash("Owner panel unlocked for this session.", "success")
            return redirect(url_for("superadmin_dashboard"))

        flash("Incorrect passphrase. Please try again.", "error")

    return render_template("superadmin_unlock.html")


@app.route(
    "/dashboard/admin/superadmin/change-passcode",
    methods=["GET", "POST"],
    endpoint="superadmin_change_passcode",
)
@superadmin_required
def superadmin_change_passcode():
    """
    Change the OWNER_PANEL_PASS (Owner Panel passcode).

    Security:
      - Only logged-in admins with is_superadmin = True can access.
      - Must enter the current passcode correctly.
    """
    global OWNER_PANEL_PASS

    if request.method == "POST":
        current_code = (request.form.get("current_passcode") or "").strip()
        new_code = (request.form.get("new_passcode") or "").strip()
        confirm_code = (request.form.get("confirm_passcode") or "").strip()

        # Must match existing passcode
        if current_code != OWNER_PANEL_PASS:
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

        # Update in-memory and process env
        OWNER_PANEL_PASS = new_code
        os.environ["OWNER_PANEL_PASS"] = new_code

        flash(
            "Owner passcode updated for this server instance. "
            "Remember to also update OWNER_PANEL_PASS in your "
            "environment/hosting config for production.",
            "success",
        )
        return redirect(url_for("superadmin_dashboard"))

    return render_template("superadmin_change_passcode.html")


# >>> SUPERADMIN OWNER PANEL (UPDATED)
@app.route("/dashboard/admin/owner", endpoint="superadmin_dashboard")
@superadmin_required
def superadmin_dashboard():
    """
    Owner / Superadmin dashboard.

    Not linked from normal admin navigation and only available to:
      - role = admin
      - is_superadmin = True
      - and the special OWNER_PANEL_PASS has been entered
    """
    # Extra gate: require unlock first
    if not owner_panel_unlocked():
        return redirect(url_for("superadmin_unlock"))

    # -----------------------------
    # Core counts (platform size)
    # -----------------------------
    total_users = User.query.filter(User.role != RoleEnum.admin).count()
    total_wallets = Wallet.query.count()
    total_beats = Beat.query.count()
    total_orders = Order.query.count()

    # -----------------------------
    # Aggregate total wallet balance (sensitive)
    # -----------------------------
    total_wallet_balance_cents = 0
    for w in Wallet.query.join(User, Wallet.user_id == User.id).all():
        total_wallet_balance_cents += wallet_balance_cents(w)
    total_wallet_balance = total_wallet_balance_cents / 100.0

    # -----------------------------
    # Money flows (lifetime totals)
    # -----------------------------
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

    # Same logic as admin_reports "net_wallet"
    net_wallet_dollars = (total_deposits_cents - total_withdrawals_cents) / 100.0

    # -----------------------------
    # Chart data
    # -----------------------------
    # Bar chart: platform snapshot
    bar_labels = ["Users", "Wallets", "Beats", "Orders"]
    bar_values = [total_users, total_wallets, total_beats, total_orders]

    # Doughnut chart: money flows
    flow_labels = ["Deposits ($)", "Withdrawals ($)", "Sales ($)"]
    flow_values = [total_deposits, total_withdrawals, total_sales]

    return render_template(
        "dash_superadmin.html",
        # Environment flags
        APP_ENV=APP_ENV,
        IS_DEV=IS_DEV,

        # Core stats
        total_users=total_users,
        total_wallets=total_wallets,
        total_beats=total_beats,
        total_orders=total_orders,

        # Money stats
        total_wallet_balance=total_wallet_balance,
        total_deposits=total_deposits,
        total_withdrawals=total_withdrawals,
        total_sales=total_sales,
        net_wallet_dollars=net_wallet_dollars,

        # Chart data
        bar_labels=bar_labels,
        bar_values=bar_values,
        flow_labels=flow_labels,
        flow_values=flow_values,
    )
# <<< SUPERADMIN OWNER PANEL (UPDATED)

@app.route("/dashboard/admin/bookme", endpoint="admin_bookme")
@role_required("admin")
def admin_bookme():
    requests = (
        BookingRequest.query
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )

    bookings = (
        Booking.query
        .order_by(Booking.created_at.desc())
        .limit(50)
        .all()
    )

    return render_template(
        "admin_bookme.html",
        requests=requests,
        bookings=bookings,
        BookingStatus=BookingStatus,
    )


# =========================================================
# Admin – Admin Team (superadmin only)
# =========================================================
@app.route(
    "/dashboard/admin/team",
    methods=["GET", "POST"],
    endpoint="admin_team",
)
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

        new_admin = User(
            username=username,
            role=RoleEnum.admin,
            kyc_status=KYCStatus.approved,
            is_superadmin=False,
        )
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()

        get_or_create_wallet(new_admin.id)

        log = AuditLog(
            admin_id=current_user.id,
            user_id=new_admin.id,
            action="create_admin_user",
            reason="Superadmin created another admin via Admin Team page.",
        )
        db.session.add(log)
        db.session.commit()

        flash(f"Admin @{username} created.", "success")
        return redirect(url_for("admin_team"))

    admins = (
        User.query
        .filter(User.role == RoleEnum.admin)
        .order_by(User.id.asc())
        .all()
    )

    return render_template("admin_team.html", admins=admins)


@app.route(
    "/dashboard/admin/team/<int:user_id>/toggle-active",
    methods=["POST"],
    endpoint="admin_team_toggle_active",
)
@superadmin_required
def admin_team_toggle_active(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't deactivate your own superadmin account.", "error")
        return redirect(url_for("admin_team"))

    if getattr(user, "is_superadmin", False):
        flash("You can't deactivate another superadmin from this page.", "error")
        return redirect(url_for("admin_team"))

    new_active = not bool(user.is_active_col)
    user.is_active_col = new_active
    db.session.commit()

    if new_active:
        flash(f"Admin @{user.username} reactivated.", "success")
    else:
        flash(f"Admin @{user.username} deactivated.", "success")

    return redirect(url_for("admin_team"))


@csrf.exempt
@app.route(
    "/dashboard/admin/users/<int:user_id>/toggle-active",
    methods=["POST"],
    endpoint="admin_user_toggle_active",
)
@role_required("admin")
def admin_user_toggle_active(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't deactivate your own account.", "error")
        return redirect(request.referrer or url_for("admin_users"))

    new_active = not bool(user.is_active_col)
    user.is_active_col = new_active

    action = "reactivate_user" if new_active else "deactivate_user"
    reason = (
        "Admin toggled user active flag to "
        + ("active" if new_active else "inactive")
        + " from the Users page."
    )

    log = AuditLog(
        admin_id=current_user.id,
        user_id=user.id,
        action=action,
        reason=reason,
    )
    db.session.add(log)
    db.session.commit()

    if new_active:
        flash(f"@{user.username} reactivated and can log in again.", "success")
    else:
        flash(f"@{user.username} deactivated and can no longer log in.", "success")

    return redirect(request.referrer or url_for("admin_users"))


@app.route("/dashboard/admin/kyc", endpoint="admin_kyc")
@role_required("admin")
def admin_kyc():
    pending = User.query.filter_by(kyc_status=KYCStatus.pending).all()
    approved = User.query.filter_by(kyc_status=KYCStatus.approved).all()
    rejected = User.query.filter_by(kyc_status=KYCStatus.rejected).all()
    return render_template("admin_kyc.html", pending=pending, approved=approved, rejected=rejected, KYCStatus=KYCStatus)


@csrf.exempt
@app.route("/dashboard/admin/kyc/<int:user_id>/<string:action>",
           methods=["POST"], endpoint="admin_kyc_update")
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


# =========================================================
# Admin – Transactions (overview + audit)
# =========================================================
@app.route("/dashboard/admin/transactions", endpoint="admin_transactions")
@role_required("admin")
def admin_transactions():
    q = (request.args.get("q") or "").strip()

    found_user = None
    if q:
        found_user = (
            User.query
            .filter(func.lower(User.username) == q.lower())
            .first()
        )

    stats = (
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0)
        )
        .group_by(LedgerEntry.entry_type)
        .all()
    )

    audit_logs = (
        AuditLog.query
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )

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
    logs = (
        AuditLog.query
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )

    lines = [
        f"{log.created_at} | admin_id={log.admin_id} | "
        f"user_id={log.user_id} | action={log.action} | reason={log.reason}"
        for log in logs
    ]
    return "Admin Audit Log\n" + "\n".join(lines)


@csrf.exempt
@app.route(
    "/dashboard/admin/transactions/user/<int:user_id>/audit",
    methods=["GET", "POST"],
    endpoint="admin_audit_access"
)
@role_required("admin")
def admin_audit_access(user_id):
    customer = User.query.get_or_404(user_id)

    if request.method == "POST":
        reason = (request.form.get("reason") or "").strip()

        if not reason:
            flash("Please enter a reason for accessing this account.", "error")
        else:
            log = AuditLog(
                admin_id=current_user.id,
                user_id=customer.id,
                action="view_user_transactions",
                reason=reason,
            )
            db.session.add(log)
            db.session.commit()

            flash("Access reason recorded in audit log.", "success")
            return redirect(url_for("admin_transactions_user", user_id=customer.id))

    return render_template("admin_audit_access.html", customer=customer)


@app.route(
    "/dashboard/admin/transactions/user/<int:user_id>",
    methods=["GET"],
    endpoint="admin_transactions_user"
)
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

    return render_template(
        "admin_transactions_user.html",
        customer=customer,
        ledger=ledger,
        EntryType=EntryType,
    )


@app.route(
    "/dashboard/admin/transactions/user/<int:user_id>/export",
    methods=["GET"],
    endpoint="admin_export_wallet_csv",
)
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
        writer.writerow([
            created_str,
            row.entry_type.value,
            direction,
            amount_dollars,
            row.meta or "",
        ])

    output = si.getvalue()
    filename = f"wallet_{user.username}_ledger.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


@app.route(
    "/dashboard/admin/reports/export/system-ledger",
    methods=["GET"],
    endpoint="admin_export_system_ledger_csv",
)
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

    writer.writerow([
        "ledger_id",
        "created_at",
        "username",
        "user_id",
        "entry_type",
        "direction",
        "amount_dollars",
        "meta",
    ])

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

        writer.writerow([
            entry.id,
            created_str,
            user.username if user else "",
            user.id if user else "",
            entry.entry_type.value,
            direction,
            amount_dollars,
            entry.meta or "",
        ])

    output = si.getvalue()
    filename = "beatfund_system_wallet_ledger_audit.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


@app.route(
    "/dashboard/admin/reports/export/admin-audit-log",
    methods=["GET"],
    endpoint="admin_export_audit_log_csv",
)
@role_required("admin")
def admin_export_audit_log_csv():
    logs = (
        AuditLog.query
        .order_by(AuditLog.created_at.desc())
        .all()
    )

    si = StringIO()
    writer = csv.writer(si)

    writer.writerow([
        "log_id",
        "timestamp",
        "admin_id",
        "admin_username",
        "user_id",
        "user_username",
        "action",
        "reason",
    ])

    for log in logs:
        ts = log.created_at.isoformat(sep=" ") if log.created_at else ""
        admin_username = log.admin.username if log.admin else ""
        user_username = log.user.username if log.user else ""

        writer.writerow([
            log.id,
            ts,
            log.admin_id,
            admin_username,
            log.user_id,
            user_username,
            log.action,
            log.reason,
        ])

    output = si.getvalue()
    filename = "beatfund_admin_access_audit.csv"

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


# =========================================================
# Admin – Support tickets
# =========================================================
@app.route(
    "/dashboard/admin/tickets",
    methods=["GET"],
    endpoint="admin_tickets"
)
@role_required("admin")
def admin_tickets():
    status = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = (
        SupportTicket.query
        .join(User, SupportTicket.user_id == User.id)
    )

    if status:
        try:
            query = query.filter(SupportTicket.status == TicketStatus(status))
        except ValueError:
            pass

    if q:
        like = f"%{q.lower()}%"
        query = query.filter(func.lower(User.username).like(like))

    pagination = (
        query
        .order_by(SupportTicket.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
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


@csrf.exempt
@app.route(
    "/dashboard/admin/tickets/new",
    methods=["GET", "POST"],
    endpoint="admin_ticket_new"
)
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


@csrf.exempt
@app.route(
    "/dashboard/admin/tickets/<int:ticket_id>",
    methods=["GET", "POST"],
    endpoint="admin_ticket_detail"
)
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
            c = SupportTicketComment(
                ticket_id=ticket.id,
                admin_id=current_user.id,
                body=comment_body,
            )
            db.session.add(c)

        db.session.commit()

        flash(
            "Ticket updated and note added." if comment_body else "Ticket updated.",
            "success"
        )
        return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))

    comments = (
        ticket.comments.order_by(SupportTicketComment.created_at.asc()).all()
        if hasattr(ticket, "comments")
        else []
    )

    return render_template(
        "admin_ticket_detail.html",
        ticket=ticket,
        comments=comments,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )


@app.route("/dashboard/admin/reports", endpoint="admin_reports")
@role_required("admin")
def admin_reports():
    total_deposits_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.deposit
    ).scalar() or 0

    total_withdrawals_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.withdrawal
    ).scalar() or 0

    total_sales_cents = db.session.query(func.sum(Order.amount_cents)).filter(
        Order.status == OrderStatus.paid
    ).scalar() or 0

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
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0),
        )
        .group_by(LedgerEntry.entry_type)
        .all()
    )

    role_stats = (
        db.session.query(
            User.role,
            func.count(User.id)
        )
        .filter(User.role != RoleEnum.admin)
        .group_by(User.role)
        .all()
    )

    ticket_total = SupportTicket.query.count()
    ticket_open = SupportTicket.query.filter_by(status=TicketStatus.open).count()
    ticket_in_review = SupportTicket.query.filter_by(status=TicketStatus.in_review).count()
    ticket_resolved = SupportTicket.query.filter(
        SupportTicket.status.in_([
            TicketStatus.resolved,
            TicketStatus.approved,
            TicketStatus.rejected,
        ])
    ).count()

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
        # All admins (including superadmins) land on the normal admin dashboard.
        # The Superadmin Owner Panel is now a sub-page reached via its own link.
        endpoint = "admin_dashboard"
    elif role == "artist":
        endpoint = "artist_dashboard"
    elif role == "funder":
        endpoint = "funder_dashboard"
    elif role == "client":
        endpoint = "home"
    elif is_service_provider(current_user):
        endpoint = "provider_dashboard"
    else:
        endpoint = "home"

    return redirect(url_for(endpoint))



@app.route("/dashboard/artist", endpoint="artist_dashboard")
@role_required("artist")
def artist_dashboard():
    followers_count = UserFollow.query.filter_by(
        followed_id=current_user.id
    ).count()
    following_count = UserFollow.query.filter_by(
        follower_id=current_user.id
    ).count()

    total_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .count()
    )

    pending_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id, status="pending")
        .count()
    )

    confirmed_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id, status="confirmed")
        .count()
    )

    recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.event_datetime.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dash_artist.html",
        followers_count=followers_count,
        following_count=following_count,
        bookings_count=total_bookings,
        pending_bookings=pending_bookings,
        confirmed_bookings=confirmed_bookings,
        recent_bookings=recent_bookings,
    )


@app.route("/dashboard/provider", endpoint="provider_dashboard")
@login_required
def provider_dashboard():
    if not is_service_provider(current_user):
        flash("You don't have access to the provider dashboard.", "error")
        return redirect(url_for("route_to_dashboard"))

    followers_count = UserFollow.query.filter_by(
        followed_id=current_user.id
    ).count()

    incoming_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id
    ).count()

    outgoing_requests = BookingRequest.query.filter_by(
        client_id=current_user.id
    ).count()

    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    portfolio_count = prof.portfolio_items.count() if prof else 0
    requires_portfolio = role_requires_portfolio(current_user.role)

    incoming_bookings_count = Booking.query.filter_by(
        provider_id=current_user.id
    ).count()

    outgoing_bookings_count = Booking.query.filter_by(
        client_id=current_user.id
    ).count()

    # 👇 Human-friendly label like "Videographer", "Studio", "DJ", etc.
    role_label = get_role_display(current_user.role)

    return render_template(
        "dash_provider.html",
        followers_count=followers_count,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        portfolio_count=portfolio_count,
        requires_portfolio=requires_portfolio,
        incoming_bookings_count=incoming_bookings_count,
        outgoing_bookings_count=outgoing_bookings_count,
        role_label=role_label,
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


# =========================================================
# Loans placeholder
# =========================================================
@app.route("/loans", endpoint="loans_home")
@login_required
def loans_home():
    flash("Loans module coming soon.")
    return redirect(url_for("route_to_dashboard"))

@app.route("/opportunities", methods=["GET", "POST"])
@login_required
def opportunities():
    """
    Funding & Opportunities page.

    - Visually explains Creative Loans + Scholarships & Programs.
    - Lets users submit an "interest" form.
    - For now, each submission becomes a SupportTicket so admins
      can see who is interested in loans / scholarships.
    """
    if request.method == "POST":
        interest_type = (request.form.get("interest_type") or "").strip().lower()
        goal_amount = (request.form.get("goal_amount") or "").strip()
        program_type = (request.form.get("program_type") or "").strip()
        location = (request.form.get("location") or "").strip()
        details = (request.form.get("details") or "").strip()

        if not interest_type:
            flash("Please choose whether you're interested in Loans or Scholarships.", "error")
            return redirect(url_for("opportunities"))

        # Build a subject and description for the admin SupportTicket
        if interest_type == "loan":
            subject = f"Creative loan interest from @{current_user.username}"
        elif interest_type == "scholarship":
            subject = f"Scholarship/program interest from @{current_user.username}"
        else:
            subject = f"Opportunities interest from @{current_user.username}"

        # Compose a description that captures everything the user entered
        desc_lines = [
            f"Interest type: {interest_type}",
        ]
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

        # Associate this ticket with a 'creator' admin if available, otherwise with the user.
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

        flash(
            "Thanks for sharing your interest! "
            "We’ll reach out when Creative Loans and Scholarships go live.",
            "success",
        )
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


# =========================================================
# Main / DB init + seed
# =========================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # ADMIN SEED (superadmin / owner)
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
            # Make sure existing admin has superadmin flag
            if not getattr(admin, "is_superadmin", False):
                admin.is_superadmin = True
                db.session.commit()
            # Optionally backfill email in dev if missing
            if IS_DEV and not admin.email:
                admin.email = "admin@example.com"
                db.session.commit()

        # Sample producer
        prod = User.query.filter_by(username="producer1").first()
        if not prod:
            prod = User(
                username="producer1",
                email="producer1@example.com",
                role=RoleEnum.producer,
                kyc_status=KYCStatus.approved,
            )
            prod.set_password("producer1123")
            db.session.add(prod)
            db.session.commit()
            w = get_or_create_wallet(prod.id)
            post_ledger(w, EntryType.deposit, 5_000, meta="seed $50")
        else:
            if IS_DEV and not prod.email:
                prod.email = "producer1@example.com"
                db.session.commit()

        # Sample artist
        artist = User.query.filter_by(username="artist1").first()
        if not artist:
            artist = User(
                username="artist1",
                email="artist1@example.com",
                role=RoleEnum.artist,
                kyc_status=KYCStatus.approved,
            )
            artist.set_password("artist1123")
            db.session.add(artist)
            db.session.commit()
            w = get_or_create_wallet(artist.id)
            post_ledger(w, EntryType.deposit, 10_000, meta="seed $100")
        else:
            if IS_DEV and not artist.email:
                artist.email = "artist1@example.com"
                db.session.commit()

    debug_flag = os.getenv("FLASK_DEBUG", "1" if IS_DEV else "0") == "1"
    app.run(debug=debug_flag)
