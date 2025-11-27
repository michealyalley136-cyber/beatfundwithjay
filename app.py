from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify, Response
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
from flask_wtf.csrf import generate_csrf
from time import time
import re
from decimal import Decimal, InvalidOperation

HOLD_FEE_CENTS = 2000  # $20 hold fee for accepted bookings
MAX_TXN_DOLLARS = 10_000  # safety cap: max $10k per wallet action in dev


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

app = Flask(__name__, template_folder="templates", static_folder="static")

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

# ------------------------------------------------------
# CSRF protection
# ------------------------------------------------------
csrf = CSRFProtect(app)


@app.context_processor
def inject_csrf_token():
    # Expose a csrf_token() helper to all templates
    return dict(csrf_token=generate_csrf)


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

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

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


class KYCStatus(str, enum.Enum):
    not_started = "not_started"
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


# Make basic enums available in all Jinja templates
app.jinja_env.globals["RoleEnum"] = RoleEnum
app.jinja_env.globals["KYCStatus"] = KYCStatus


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(RoleEnum), nullable=False, default=RoleEnum.artist)
    kyc_status = db.Column(db.Enum(KYCStatus), nullable=False, default=KYCStatus.not_started)
    is_active_col = db.Column("is_active", db.Boolean, nullable=False, default=True)

    @property
    def is_active(self):
        return self.is_active_col

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


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


# Make EntryType available in Jinja
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
    RoleEnum.producer.value,
    RoleEnum.studio.value,
    RoleEnum.videographer.value,
    RoleEnum.designer.value,
    RoleEnum.engineer.value,
    RoleEnum.manager.value,
    RoleEnum.vendor.value,
}


class BookMeProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    display_name = db.Column(db.String(150), nullable=False)
    service_types = db.Column(db.String(255))
    bio = db.Column(db.Text)
    rate_notes = db.Column(db.String(255))
    zip = db.Column(db.String(20))
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    address = db.Column(db.String(255))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    is_visible = db.Column(db.Boolean, nullable=False, default=True)

    user = db.relationship("User", backref=db.backref("bookme_profile", uselist=False))


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

    # which customer this ticket is about
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # which admin/support user created the ticket
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # optional: link to a specific ledger entry (transaction) if relevant
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


# Make ticket enums available in Jinja templates
app.jinja_env.globals["TicketStatus"] = TicketStatus
app.jinja_env.globals["TicketType"] = TicketType

# =========================================================
# Login loader & helpers
# =========================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
            EntryType.deposit, EntryType.transfer_in, EntryType.interest,
            EntryType.adjustment, EntryType.sale_income
        ):
            total += e.amount_cents
        else:
            total -= e.amount_cents
    return total


def post_ledger(wallet: Wallet, entry_type: EntryType, amount_cents: int, meta: str = ""):
    assert amount_cents > 0, "amount must be positive cents"
    db.session.add(
        LedgerEntry(wallet_id=wallet.id, entry_type=entry_type,
                    amount_cents=amount_cents, meta=meta)
    )
    db.session.commit()


def _ext_ok(filename, allowed):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def _save_file(fs, allowed_set) -> str | None:
    if not fs or fs.filename == "":
        return None
    if not _ext_ok(fs.filename, allowed_set):
        return None
    ext = fs.filename.rsplit(".", 1)[1].lower()
    fname = f"{uuid.uuid4().hex}.{ext}"
    fs.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
    return fname


def _safe_remove(stored_filename: str | None):
    if not stored_filename:
        return
    try:
        pathlib.Path(os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)).unlink(missing_ok=True)
    except Exception:
        pass


def _user_has_paid_for_beat(user_id: int, beat_id: int) -> bool:
    return db.session.query(Order.id).filter_by(
        buyer_id=user_id, beat_id=beat_id, status=OrderStatus.paid
    ).first() is not None


def is_service_provider(u: User) -> bool:
    return u.role.value in BOOKME_PROVIDER_ROLES


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

    return render_template(
        "bookme_search.html",
        profiles=profiles,
        BookingStatus=BookingStatus,
        RoleEnum=RoleEnum,
        current_filters=current_filters,
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
        zip_code = (request.form.get("zip") or "").strip()
        city = (request.form.get("city") or "").strip()
        state = (request.form.get("state") or "").strip()
        address = (request.form.get("address") or "").strip()
        lat_raw = (request.form.get("lat") or "").strip()
        lng_raw = (request.form.get("lng") or "").strip()

        if not display_name:
            flash("Display Name is required.")
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
    as_client = (BookingRequest.query
                 .filter_by(client_id=current_user.id)
                 .order_by(BookingRequest.created_at.desc())
                 .all())

    as_provider = (BookingRequest.query
                   .filter_by(provider_id=current_user.id)
                   .order_by(BookingRequest.created_at.desc())
                   .all())

    return render_template(
        "bookme_requests.html",
        as_client=as_client,
        as_provider=as_provider,
        BookingStatus=BookingStatus,
    )


@app.route("/bookme/requests/<int:req_id>/status", methods=["POST"])
@login_required
def bookme_request_status(req_id):
    req = BookingRequest.query.get_or_404(req_id)
    action = (request.form.get("action") or "").strip().lower()

    if current_user.id == req.provider_id and action in ("accept", "decline"):
        if action == "decline":
            req.status = BookingStatus.declined
            db.session.commit()
            flash("Booking request declined.")
            return redirect(url_for("bookme_requests"))

        if action == "accept":
            conflict = (BookingRequest.query
                        .filter(
                            BookingRequest.id != req.id,
                            BookingRequest.provider_id == req.provider_id,
                            BookingRequest.preferred_time == req.preferred_time,
                            BookingRequest.status == BookingStatus.accepted,
                        )
                        .first())
            if conflict:
                flash("This time slot is already booked.")
                return redirect(url_for("bookme_requests"))

            client = User.query.get(req.client_id)
            provider = User.query.get(req.provider_id)

            if client and provider:
                client_wallet = get_or_create_wallet(client.id)
                provider_wallet = get_or_create_wallet(provider.id)

                if wallet_balance_cents(client_wallet) < HOLD_FEE_CENTS:
                    flash("Client doesn't have enough balance for the $20 hold fee.")
                    return redirect(url_for("bookme_requests"))

                post_ledger(client_wallet, EntryType.purchase_spend, HOLD_FEE_CENTS,
                            meta=f"Booking hold fee to @{provider.username} for {req.preferred_time}")
                post_ledger(provider_wallet, EntryType.sale_income, HOLD_FEE_CENTS,
                            meta=f"Booking hold fee from @{client.username} for {req.preferred_time}")

            req.status = BookingStatus.accepted
            db.session.commit()
            flash("Booking accepted. Hold fee charged.")
            return redirect(url_for("bookme_requests"))

    if current_user.id == req.client_id and action == "cancel":
        if req.status in (BookingStatus.pending, BookingStatus.accepted):
            req.status = BookingStatus.cancelled
            db.session.commit()
            flash("Booking cancelled.")
        else:
            flash("You can only cancel pending/accepted bookings.")
        return redirect(url_for("bookme_requests"))

    flash("You are not allowed to perform this action.")
    return redirect(url_for("bookme_requests"))


# =========================================================
# Core / Auth
# =========================================================
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]

        # -------------------------
        # Basic password policy
        # -------------------------
        pw_errors = []
        if len(password) < 8:
            pw_errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", password):
            pw_errors.append("Password must contain at least one letter.")
        if not re.search(r"\d", password):
            pw_errors.append("Password must contain at least one number.")

        if pw_errors:
            flash(" ".join(pw_errors))
            return redirect(url_for("register"))

        # -------------------------
        # Username & role checks
        # -------------------------
        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for("register"))

        if role not in [r.value for r in RoleEnum]:
            flash("Invalid role selected.")
            return redirect(url_for("register"))

        # -------------------------
        # Create user (dev: auto-approve KYC)
        # -------------------------
        user = User(username=username, role=RoleEnum(role))
        user.kyc_status = KYCStatus.approved  # dev only

        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        get_or_create_wallet(user.id)
        login_user(user)

        flash("Account created! (KYC auto-approved in dev.)")
        return redirect(url_for("route_to_dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Identify caller by IP for rate limiting
        remote_addr = request.remote_addr or "unknown"

        # 1) Check if this IP is temporarily blocked
        if _too_many_failed_logins(remote_addr):
            flash(
                "Too many failed login attempts. "
                "Please wait a few minutes and try again."
            )
            return redirect(url_for("login"))

        # 2) Normal credential handling
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            # Register failed attempt and show generic error
            _register_failed_login(remote_addr)
            flash("Invalid credentials.")
            return redirect(url_for("login"))

        if not user.is_active_col:
            flash("This account is disabled.")
            return redirect(url_for("login"))

        # 3) Successful login: clear failure counter for this IP
        _clear_failed_logins(remote_addr)

        login_user(user)
        return redirect(url_for("route_to_dashboard"))

    # GET request, just render the login form
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


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


# =========================================================
# Simple login rate limiting (anti brute-force)
# =========================================================
LOGIN_ATTEMPTS = {}  # key: IP string, value: list of timestamps (float)

LOGIN_WINDOW_SECONDS = 300   # 5-minute rolling window
LOGIN_MAX_ATTEMPTS = 10      # max failed attempts per IP in that window


def _clean_attempts(attempts):
    """Remove attempts older than the window."""
    now = time()
    return [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]


def _too_many_failed_logins(remote_addr: str) -> bool:
    """
    Return True if this IP has too many failed login attempts recently.
    """
    if not remote_addr:
        remote_addr = "unknown"

    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    LOGIN_ATTEMPTS[remote_addr] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _register_failed_login(remote_addr: str) -> None:
    """
    Record a failed login attempt for this IP.
    """
    if not remote_addr:
        remote_addr = "unknown"

    attempts = LOGIN_ATTEMPTS.get(remote_addr, [])
    attempts = _clean_attempts(attempts)
    attempts.append(time())
    LOGIN_ATTEMPTS[remote_addr] = attempts


def _clear_failed_logins(remote_addr: str) -> None:
    """Reset the counter for an IP (e.g., after a successful login)."""
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

    # ---------- Strict amount validation ----------
    if not amount_raw:
        flash("Amount is required.")
        return redirect(url_for("wallet_home"))

    # Allow patterns like "10", "10.5", "10.50" – max 2 decimal places
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

    # Convert to integer cents safely
    cents = int((amt * 100).to_integral_value())

    method = (request.form.get("method") or "").strip()
    w = get_or_create_wallet(current_user.id)

    # ---------- Add funds ----------
    if action == "add":
        meta = f"deposit via {method or 'unknown'}"
        post_ledger(w, EntryType.deposit, cents, meta=meta)
        flash(f"Added ${amt:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    # ---------- Send money ----------
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

    # ---------- Withdraw ----------
    if action == "withdraw":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.")
            return redirect(url_for("wallet_home"))

        post_ledger(w, EntryType.withdrawal, cents, meta="withdraw to bank (demo)")
        flash(f"Withdrew ${amt:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    # ---------- Unknown action ----------
    flash("Unknown wallet action.")
    return redirect(url_for("wallet_home"))


# =========================================================
# Files
# =========================================================
@app.route("/uploads/<path:filename>")
@login_required
def media_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


# =========================================================
# Marketplace
# =========================================================
@app.route("/market", endpoint="market_index")
@login_required
def market_index():
    items = (Beat.query.filter_by(is_active=True)
             .order_by(Beat.is_featured.desc(), Beat.id.desc()).all())
    return render_template("market_index.html", items=items)


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


# =========================================================
# Admin – Dashboard / Users / KYC
# =========================================================
@app.route("/dashboard/admin", endpoint="admin_dashboard")
@role_required("admin")
def admin_dashboard():
    # High-level stats (excluding admin from "users")
    total_users = User.query.filter(User.role != RoleEnum.admin).count()
    total_wallets = Wallet.query.count()
    total_beats = Beat.query.count()
    total_orders = Order.query.count()

    pending_kyc = User.query.filter_by(kyc_status=KYCStatus.pending).count()
    approved_kyc = User.query.filter_by(kyc_status=KYCStatus.approved).count()
    rejected_kyc = User.query.filter_by(kyc_status=KYCStatus.rejected).count()

    total_artists = User.query.filter_by(role=RoleEnum.artist).count()
    total_producers = User.query.filter_by(role=RoleEnum.producer).count()

    # Ticket counters
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

    # Recent events feed: audit logs + tickets
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
    """
    Admin users page with search + filters.
    Hides admin accounts themselves (portal is for managing customers).
    """
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


@app.route(
    "/dashboard/admin/users/<int:user_id>/toggle-active",
    methods=["POST"],
    endpoint="admin_user_toggle_active",
)
@role_required("admin")
def admin_user_toggle_active(user_id):
    """
    Toggle a user's active flag (soft deactivate / reactivate).
    """
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
    """
    Admin overview page.

    - Aggregated wallet activity across the system.
    - Optionally search for a specific user to then open via secure audit flow.
    - Shows recent audit notes.
    """
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
    """
    Global admin audit log listing (simple text view for now).
    """
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


@app.route(
    "/dashboard/admin/transactions/user/<int:user_id>/audit",
    methods=["GET", "POST"],
    endpoint="admin_audit_access"
)
@csrf.exempt          # ✅ CSRF disabled ONLY for this admin-only form
@role_required("admin")
def admin_audit_access(user_id):
    """
    Step 1: admin/support must log WHY they are accessing this customer's account.
    After a valid reason is submitted, we insert an AuditLog row and redirect
    to the detailed transaction view.
    """
    # Use the user_id from the URL, store in `customer`
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
    """
    After logging a reason, show all wallet ledger entries for this user.
    """
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
    """
    Export the selected user's wallet ledger as a simple CSV.
    No date filters, just full history in descending time order.
    """
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
    """
    Export the FULL system wallet ledger (all users) as CSV.
    Useful for internal / external financial audits.
    """
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
    """
    Export the FULL admin audit log as CSV.
    Shows which admin accessed which account, when, and why.
    Useful for compliance & external audits.
    """
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


@app.route(
    "/dashboard/admin/tickets/new",
    methods=["GET", "POST"],
    endpoint="admin_ticket_new"
)
@role_required("admin")
def admin_ticket_new():
    """
    Create a support ticket about a customer (optionally tied to a specific transaction).
    Expects user_id query param; optional ledger_id.
    """
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
    # Top-line wallet + sales numbers (in cents)
    total_deposits_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.deposit
    ).scalar() or 0

    total_withdrawals_cents = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.withdrawal
    ).scalar() or 0

    total_sales_cents = db.session.query(func.sum(Order.amount_cents)).filter(
        Order.status == OrderStatus.paid
    ).scalar() or 0

    # Convert to dollars for display
    total_deposits = total_deposits_cents / 100.0
    total_withdrawals = total_withdrawals_cents / 100.0
    total_sales = total_sales_cents / 100.0

    # Provide an aggregate "totals" object for the template
    totals = {
        "deposits": total_deposits,
        "withdrawals": total_withdrawals,
        "sales": total_sales,
        "net_wallet": (total_deposits_cents - total_withdrawals_cents) / 100.0,
        "net": (total_deposits_cents - total_withdrawals_cents) / 100.0,
    }

    # Wallet activity by type
    wallet_stats = (
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0),
        )
        .group_by(LedgerEntry.entry_type)
        .all()
    )

    # User breakdown by role (excluding admin)
    role_stats = (
        db.session.query(
            User.role,
            func.count(User.id)
        )
        .filter(User.role != RoleEnum.admin)
        .group_by(User.role)
        .all()
    )

    # Ticket summary
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
    mapping = {
        "artist": "artist_dashboard",
        "producer": "producer_dashboard",
        "studio": "studio_dashboard",
        "videographer": "videographer_dashboard",
        "designer": "designer_dashboard",
        "engineer": "engineer_dashboard",
        "manager": "manager_dashboard",
        "vendor": "vendor_dashboard",
        "funder": "funder_dashboard",
        "admin": "admin_dashboard",
    }
    endpoint = mapping.get(current_user.role.value, "home")
    return redirect(url_for(endpoint))


@app.route("/dashboard/artist", endpoint="artist_dashboard")
@role_required("artist")
def artist_dashboard():
    return render_template("dash_artist.html")


@app.route("/dashboard/producer", endpoint="producer_dashboard")
@role_required("producer")
def producer_dashboard():
    return redirect(url_for("market_index"))


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

        # ADMIN SEED
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                role=RoleEnum.admin,
                kyc_status=KYCStatus.approved
            )
            admin.set_password(os.getenv("ADMIN_PASSWORD", "admin123"))
            db.session.add(admin)
            db.session.commit()
            get_or_create_wallet(admin.id)

        # Sample producer
        prod = User.query.filter_by(username="producer1").first()
        if not prod:
            prod = User(
                username="producer1",
                role=RoleEnum.producer,
                kyc_status=KYCStatus.approved
            )
            prod.set_password("producer1123")
            db.session.add(prod)
            db.session.commit()
            w = get_or_create_wallet(prod.id)
            post_ledger(w, EntryType.deposit, 5_000, meta="seed $50")

        # Sample artist
        artist = User.query.filter_by(username="artist1").first()
        if not artist:
            artist = User(
                username="artist1",
                role=RoleEnum.artist,
                kyc_status=KYCStatus.approved
            )
            artist.set_password("artist1123")
            db.session.add(artist)
            db.session.commit()
            w = get_or_create_wallet(artist.id)
            post_ledger(w, EntryType.deposit, 10_000, meta="seed $100")

    # In dev we default to debug=True, in prod we default to debug=False
    debug_flag = os.getenv("FLASK_DEBUG", "1" if IS_DEV else "0") == "1"
    app.run(debug=debug_flag)
