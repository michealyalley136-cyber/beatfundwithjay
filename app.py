from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify
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
from datetime import datetime  # ✅ FIX for created_at default errors

HOLD_FEE_CENTS = 2000  # $20 hold fee for accepted bookings

# =========================================================
# App / DB setup
# =========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")

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


# Make enums available in all Jinja templates
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


class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())  # ✅ safer than datetime.utcnow
    user = db.relationship("User", backref=db.backref("wallet", uselist=False))


class LedgerEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey("wallet.id"), nullable=False, index=True)
    entry_type = db.Column(db.Enum(EntryType), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    meta = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())  # ✅ safer
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
@app.route("/bookme")
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

        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for("register"))

        if role not in [r.value for r in RoleEnum]:
            flash("Invalid role selected.")
            return redirect(url_for("register"))

        user = User(username=username, role=RoleEnum(role))

        # DEV ONLY auto-approve KYC
        user.kyc_status = KYCStatus.approved

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
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.")
            return redirect(url_for("login"))

        if not user.is_active_col:
            flash("This account is disabled.")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("route_to_dashboard"))

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


@app.route("/wallet/action", methods=["POST"])
@login_required
def wallet_action():
    if not require_kyc_approved():
        return redirect(url_for("kyc"))

    action = (request.form.get("action") or "").strip()
    amount_raw = (request.form.get("amount") or "").strip()
    try:
        dollars = float(amount_raw)
        assert dollars > 0
    except Exception:
        flash("Invalid amount.")
        return redirect(url_for("wallet_home"))
    cents = int(dollars * 100)

    method = request.form.get("method")
    w = get_or_create_wallet(current_user.id)

    if action == "add":
        post_ledger(w, EntryType.deposit, cents, meta=f"deposit via {method or 'unknown'}")
        flash(f"Added ${dollars:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    if action == "send":
        handle = (request.form.get("handle") or "").strip().lower()
        recipient = User.query.filter_by(username=handle).first()
        if not recipient:
            flash("Recipient not found.")
            return redirect(url_for("wallet_home"))
        if recipient.id == current_user.id:
            flash("You can't send to yourself.")
            return redirect(url_for("wallet_home"))
        if wallet_balance_cents(w) < cents:
            flash("Insufficient balance.")
            return redirect(url_for("wallet_home"))

        w_recipient = get_or_create_wallet(recipient.id)
        note = (request.form.get("note") or "").strip()
        post_ledger(w, EntryType.transfer_out, cents,
                    meta=f"to @{recipient.username}" + (f" | {note}" if note else ""))
        post_ledger(w_recipient, EntryType.transfer_in, cents,
                    meta=f"from @{current_user.username}" + (f" | {note}" if note else ""))
        flash(f"Sent ${dollars:,.2f} to @{recipient.username}.")
        return redirect(url_for("wallet_home"))

    if action == "withdraw":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient balance.")
            return redirect(url_for("wallet_home"))
        post_ledger(w, EntryType.withdrawal, cents, meta="withdraw to bank")
        flash(f"Withdrew ${dollars:,.2f} (demo).")
        return redirect(url_for("wallet_home"))

    flash("Unknown action.")
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
# Producer backend
# =========================================================
@app.route("/producer/market")
@role_required("producer")
def producer_market_home():
    total_beats = Beat.query.filter_by(owner_id=current_user.id).count()
    revenue_cents = db.session.query(func.sum(Order.amount_cents)).filter(
        Order.seller_id == current_user.id,
        Order.status == OrderStatus.paid
    ).scalar() or 0

    sales_count = Order.query.filter_by(
        seller_id=current_user.id,
        status=OrderStatus.paid
    ).count()

    return render_template(
        "dash_producer.html",
        total_beats=total_beats,
        sales_count=sales_count,
        revenue=float(revenue_cents) / 100.0
    )


@app.route("/producer/market/upload", methods=["GET", "POST"])
@role_required("producer")
def producer_market_upload():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        price = (request.form.get("price") or "0").strip()
        license_kind = (request.form.get("license") or "standard").strip()
        bpm = request.form.get("bpm") or None
        genre = (request.form.get("genre") or "").strip() or None

        if not title:
            flash("Title is required.")
            return redirect(url_for("producer_market_upload"))

        try:
            price_cents = int(float(price) * 100)
            assert price_cents >= 0
        except Exception:
            flash("Invalid price.")
            return redirect(url_for("producer_market_upload"))

        cover_rel = _save_file(request.files.get("cover"), ALLOWED_IMAGE)
        prev_rel = _save_file(request.files.get("preview"), ALLOWED_AUDIO)
        stems_rel = _save_file(request.files.get("stems"), ALLOWED_AUDIO)

        beat = Beat(
            owner_id=current_user.id,
            title=title,
            price_cents=price_cents,
            license=license_kind,
            bpm=int(bpm) if bpm else None,
            genre=genre,
            cover_path=cover_rel,
            preview_path=prev_rel,
            stems_path=stems_rel,
            is_active=True
        )
        db.session.add(beat)
        db.session.commit()

        flash("Beat listed. It now appears in the Marketplace.")
        return redirect(url_for("producer_market_mine"))

    return render_template("producer_market_upload.html")


@app.route("/producer/market/mine")
@role_required("producer")
def producer_market_mine():
    items = Beat.query.filter_by(owner_id=current_user.id).order_by(Beat.id.desc()).all()
    total_sales = Order.query.filter_by(seller_id=current_user.id, status=OrderStatus.paid).count()
    gross_cents = db.session.query(func.sum(Order.amount_cents)).filter_by(
        seller_id=current_user.id,
        status=OrderStatus.paid
    ).scalar() or 0

    return render_template(
        "producer_market_mine.html",
        items=items,
        total_sales=total_sales,
        gross=float(gross_cents) / 100.0
    )


@app.route("/producer/market/sales")
@role_required("producer")
def producer_market_sales():
    orders = (Order.query
              .filter_by(seller_id=current_user.id, status=OrderStatus.paid)
              .order_by(Order.created_at.desc())
              .all())
    return render_template("producer_market_sales.html", orders=orders)


@app.route("/producer/market/delete/<int:beat_id>", methods=["POST"])
@role_required("producer")
def producer_market_delete(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    if beat.owner_id != current_user.id:
        flash("You can only delete your own items.")
        return redirect(url_for("producer_market_mine"))

    _safe_remove(beat.cover_path)
    _safe_remove(beat.preview_path)
    _safe_remove(beat.stems_path)

    db.session.delete(beat)
    db.session.commit()
    flash("Beat deleted.")
    return redirect(url_for("producer_market_mine"))


# =========================================================
# Admin (clean + single set of endpoints)
# =========================================================
@app.route("/dashboard/admin", endpoint="admin_dashboard")
@role_required("admin")
def admin_dashboard():
    total_users = User.query.count()
    total_wallets = Wallet.query.count()
    total_beats = Beat.query.count()
    total_orders = Order.query.count()

    pending_kyc = User.query.filter_by(kyc_status=KYCStatus.pending).count()
    approved_kyc = User.query.filter_by(kyc_status=KYCStatus.approved).count()
    rejected_kyc = User.query.filter_by(kyc_status=KYCStatus.rejected).count()

    total_artists = User.query.filter_by(role=RoleEnum.artist).count()
    total_producers = User.query.filter_by(role=RoleEnum.producer).count()

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
        KYCStatus=KYCStatus,
        RoleEnum=RoleEnum,
    )


@app.route("/dashboard/admin/users", endpoint="admin_users")
@role_required("admin")
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template("admin_users.html", users=users, KYCStatus=KYCStatus, RoleEnum=RoleEnum)


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


# ✅ NEW: Admin Transactions page (ledger + orders)
@app.route("/dashboard/admin/transactions", endpoint="admin_transactions")
@role_required("admin")
def admin_transactions():
    # recent wallet entries
    ledger = (LedgerEntry.query
              .order_by(LedgerEntry.created_at.desc())
              .limit(200).all())

    # recent marketplace orders
    orders = (Order.query
              .order_by(Order.created_at.desc())
              .limit(200).all())

    return render_template(
        "admin_transactions.html",
        ledger=ledger,
        orders=orders
    )


# ✅ NEW: Admin Reports page (simple aggregates for now)
@app.route("/dashboard/admin/reports", endpoint="admin_reports")
@role_required("admin")
def admin_reports():
    total_deposits = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.deposit
    ).scalar() or 0

    total_withdrawals = db.session.query(func.sum(LedgerEntry.amount_cents)).filter(
        LedgerEntry.entry_type == EntryType.withdrawal
    ).scalar() or 0

    total_sales = db.session.query(func.sum(Order.amount_cents)).filter(
        Order.status == OrderStatus.paid
    ).scalar() or 0

    return render_template(
        "admin_reports.html",
        total_deposits=total_deposits / 100.0,
        total_withdrawals=total_withdrawals / 100.0,
        total_sales=total_sales / 100.0
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


@app.route("/dashboard/artist")
@role_required("artist")
def artist_dashboard():
    return render_template("dash_artist.html")


@app.route("/dashboard/producer")
@role_required("producer")
def producer_dashboard():
    return redirect(url_for("producer_market_home"))


@app.route("/dashboard/studio")
@role_required("studio")
def studio_dashboard():
    return render_template("dash_studio.html")


@app.route("/dashboard/videographer")
@role_required("videographer")
def videographer_dashboard():
    return render_template("dash_videographer.html")


@app.route("/dashboard/designer")
@role_required("designer")
def designer_dashboard():
    return render_template("dash_designer.html")


@app.route("/dashboard/engineer")
@role_required("engineer")
def engineer_dashboard():
    return render_template("dash_engineer.html")


@app.route("/dashboard/manager")
@role_required("manager")
def manager_dashboard():
    return render_template("dash_manager.html")


@app.route("/dashboard/vendor")
@role_required("vendor")
def vendor_dashboard():
    return render_template("dash_vendor.html")


@app.route("/dashboard/funder")
@role_required("funder")
def funder_dashboard():
    return render_template("dash_funder.html")


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

        # ✅ ADMIN SEED
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

        # ✅ Sample producer
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

        # ✅ Sample artist
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

    app.run(debug=True)
