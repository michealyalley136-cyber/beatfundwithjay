from __future__ import annotations

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, send_file, abort, jsonify, Response, session, g,
    has_request_context, stream_with_context
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from sqlalchemy import UniqueConstraint, inspect, text, or_, func
from sqlalchemy.sql import func
from sqlalchemy.exc import (
    IntegrityError, ProgrammingError, OperationalError,
    DatabaseError, SQLAlchemyError
)

from functools import wraps
from contextlib import contextmanager
from datetime import datetime, timedelta, time
from time import time
from jinja2 import TemplateNotFound
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, ROUND_UP
from collections import Counter
from calendar import monthrange
from typing import Optional
import enum
import os
import uuid
import secrets
import pathlib
import csv
import mimetypes
from io import StringIO, BytesIO
import re
import json
import logging
from logging.handlers import RotatingFileHandler
import shutil
import subprocess
import tempfile

# Optional production dependencies (only used if env vars set)
# These are intentionally optional - install only if needed for production features
try:
    import redis  # pyright: ignore[reportMissingImports]
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import boto3  # pyright: ignore[reportMissingImports]
    from botocore.exceptions import ClientError  # pyright: ignore[reportMissingImports]
    BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None
    ClientError = None
    BOTO3_AVAILABLE = False

try:
    import sentry_sdk  # pyright: ignore[reportMissingImports]
    from sentry_sdk.integrations.flask import FlaskIntegration  # pyright: ignore[reportMissingImports]
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration  # pyright: ignore[reportMissingImports]
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

try:
    import stripe  # pyright: ignore[reportMissingImports]
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

# Load environment variables from .env file (for local development)
try:
    from dotenv import load_dotenv
    # Override any stale env vars (common during local dev)
    # so .env values reliably take effect after key rotation.
    load_dotenv(override=True)
except ImportError:
    # python-dotenv not installed, skip .env loading
    pass


# =========================================================
# Constants
# =========================================================
MAX_TXN_DOLLARS = 10_000            # safety cap: max $10k per wallet action in dev
MAX_PORTFOLIO_ITEMS = 8             # max portfolio items per provider

PASSWORD_MAX_AGE_DAYS = 90          # admins must change password every 90 days
RESET_TOKEN_MAX_AGE_HOURS = 1       # reset links valid for 1 hour

# Platform service fees
# Note: SERVICE_FEE_RULES and DEFAULT_SERVICE_FEE_RULE are defined after RoleEnum

# BeatFund service fee + processing fee config (service bookings)
def _env_decimal(name: str, default: str) -> Decimal:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return Decimal(str(default))
    try:
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return Decimal(str(default))


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if raw == "":
        return int(default)
    try:
        return int(Decimal(raw))
    except (InvalidOperation, ValueError):
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if raw == "":
        return bool(default)
    return raw in {"1", "true", "yes", "y", "on"}


def require_env(keys: list[str]) -> None:
    missing = [k for k in keys if not (os.getenv(k) or "").strip()]
    if missing:
        raise RuntimeError(f"Missing env: {', '.join(missing)}")

STRIPE_PLATFORM_FEE_PCT = _env_decimal("STRIPE_PLATFORM_FEE_PCT", "0.02")
HOLDING_FEE_CENTS = _env_int("HOLDING_FEE_CENTS", 2000)
if HOLDING_FEE_CENTS <= 0:
    HOLDING_FEE_CENTS = 2000
STRIPE_BOOKING_HOLD_FEE = _env_decimal("STRIPE_BOOKING_HOLD_FEE", "20.00")
AFFILIATE_DEFAULT_PCT = _env_decimal("AFFILIATE_DEFAULT_PCT", "0.30")
AFFILIATE_PAYOUT_DELAY_DAYS = _env_int("AFFILIATE_PAYOUT_DELAY_DAYS", 14)

HOLD_FEE_CENTS = int(HOLDING_FEE_CENTS)
BEAT_FEE_FLAT_CENTS = 0  # Legacy placeholder; platform fee is now percentage-based.
PREVIEW_SECONDS_DEFAULT = _env_int("PREVIEW_SECONDS", 30)
if PREVIEW_SECONDS_DEFAULT <= 0:
    PREVIEW_SECONDS_DEFAULT = 30
FFMPEG_CMD = (os.getenv("FFMPEG_CMD") or "ffmpeg").strip()

BEATFUND_FEE_RATE = _env_decimal("BEATFUND_FEE_RATE", str(STRIPE_PLATFORM_FEE_PCT))
BEATFUND_FEE_MIN_CENTS = _env_int("BEATFUND_FEE_MIN_CENTS", HOLD_FEE_CENTS)
BEATFUND_FEE_CAP_CENTS = _env_int("BEATFUND_FEE_CAP_CENTS", 0)
if BEATFUND_FEE_CAP_CENTS <= 0:
    BEATFUND_FEE_CAP_CENTS = 0  # disabled

STRIPE_PROC_RATE = _env_decimal("STRIPE_PROC_RATE", "0.029")
STRIPE_PROC_FIXED_CENTS = _env_int("STRIPE_PROC_FIXED_CENTS", 30)
ALLOW_REFUND_BF_FEE_ON_PROVIDER_FAULT = _env_bool("ALLOW_REFUND_BF_FEE_ON_PROVIDER_FAULT", True)
BOOKING_BALANCE_DEADLINE_HOURS = _env_int("BOOKING_BALANCE_DEADLINE_HOURS", 48)


# =========================================================
# App / DB setup
# =========================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

APP_ENV = (os.getenv("APP_ENV") or "dev").lower().strip()
STRICT_PROD_CHECKS = _env_bool("STRICT_PROD_CHECKS", False)

def _resolve_env_mode() -> tuple[bool, str | None]:
    sources: list[str] = []
    if APP_ENV in {"prod", "production"}:
        sources.append("APP_ENV")
    if (os.getenv("FLASK_ENV") or "").lower().strip() == "production":
        sources.append("FLASK_ENV")
    if (os.getenv("ENV") or "").lower().strip() == "production":
        sources.append("ENV")
    return (len(sources) > 0, sources[0] if sources else None)

IS_PROD, PROD_ENV_SOURCE = _resolve_env_mode()

def is_prod() -> bool:
    return bool(IS_PROD)

IS_DEV = not IS_PROD
KYC_ENFORCE = _env_bool("KYC_ENFORCE", not IS_DEV)
NOTIF_POLL_SECONDS = _env_int("NOTIF_POLL_SECONDS", 30)
ALLOW_UNSCANNED_UPLOADS = _env_bool("ALLOW_UNSCANNED_UPLOADS", False)
AFFILIATE_CONTACT_EMAIL = (
    (os.getenv("AFFILIATE_CONTACT_EMAIL") or os.getenv("SUPPORT_EMAIL") or "support@beatfund.com").strip()
    or "support@beatfund.com"
)

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
    SESSION_COOKIE_NAME="__Secure-session" if not IS_DEV else "session",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=not IS_DEV,
    REMEMBER_COOKIE_NAME="__Secure-remember_token" if not IS_DEV else "remember_token",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
)
# CSRF Configuration
app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)
app.config.setdefault("WTF_CSRF_ENABLED", True)
app.config.setdefault("WTF_CSRF_CHECK_DEFAULT", True)

# Maximum request size (prevents large uploads from consuming too much memory)
# 120MB = 120 * 1024 * 1024 bytes
app.config["MAX_CONTENT_LENGTH"] = 120 * 1024 * 1024  # 120MB

csrf = CSRFProtect(app)

# ---------------------------------------------------------
# ProxyFix (for reverse proxy deployments)
# ---------------------------------------------------------
if os.getenv("TRUST_PROXY", "0") == "1":
    try:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    except ImportError:
        if not IS_DEV:
            raise RuntimeError("TRUST_PROXY=1 requires werkzeug>=2.0. Install: pip install werkzeug>=2.0")

# ---------------------------------------------------------
# Request ID Middleware
# ---------------------------------------------------------
@app.before_request
def generate_request_id():
    """Generate unique request ID for tracing"""
    g.request_id = str(uuid.uuid4())[:8]


@app.before_request
def ensure_session():
    """
    Ensure session is initialized before CSRF token generation.
    This fixes 'CSRF session token is missing' errors.
    Flask-WTF requires a valid session to store CSRF tokens.
    """
    # Ensure session is marked as permanent (required for CSRF)
    if '_permanent' not in session:
        session.permanent = True
    
    # Initialize session if it's empty (helps with CSRF token generation)
    if not session:
        session['_initialized'] = True


@app.before_request
def test_db_connection_before_request():
    """Test database connection at the start of each request"""
    try:
        # Simple test query to ensure DB is responsive
        db.session.execute(text("SELECT 1"))
    except Exception as e:
        app.logger.error(f"DB connection test failed at start of request {request.path}: {type(e).__name__}: {str(e)}")
        # Don't block the request, let it fail naturally so we can see the real error
        pass

@app.after_request
def add_request_id_header(response):
    """Add request ID to response header"""
    if hasattr(g, 'request_id'):
        response.headers['X-Request-ID'] = g.request_id
    path = request.path or ""
    if path.endswith(".webmanifest"):
        response.headers["Content-Type"] = "application/manifest+json"
        response.headers["Cache-Control"] = "public, max-age=3600"
    elif path == "/static/sw.js":
        response.headers["Cache-Control"] = "no-cache"
    elif path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    return response

# ---------------------------------------------------------
# Sentry Error Tracking
# ---------------------------------------------------------
SENTRY_DSN = os.getenv("SENTRY_DSN", "").strip()
if SENTRY_DSN and SENTRY_AVAILABLE:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            FlaskIntegration(),
            SqlalchemyIntegration(),
        ],
        traces_sample_rate=0.1 if IS_DEV else 0.05,
        environment=APP_ENV,
    )

# ---------------------------------------------------------
# Structured Logging Setup
# ---------------------------------------------------------
def setup_logging():
    """Configure structured logging"""
    log_level = logging.DEBUG if not is_prod() else logging.INFO
    
    if not is_prod():
        # Simple console logging in dev
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
    else:
        # JSON logging in production
        import json as json_module
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                req_id = None
                user_id = None
                route = None
                if has_request_context():
                    try:
                        req_id = getattr(g, 'request_id', None)
                    except Exception:
                        req_id = None
                    try:
                        user_id = current_user.id if current_user.is_authenticated else None
                    except Exception:
                        user_id = None
                    try:
                        route = request.endpoint if request else None
                    except Exception:
                        route = None
                log_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'request_id': req_id,
                    'user_id': user_id,
                    'route': route,
                }
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)
                return json_module.dumps(log_data)
        
        handler = RotatingFileHandler(
            os.path.join(INSTANCE_DIR, 'app.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        handler.setFormatter(JSONFormatter())
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        root_logger.addHandler(handler)

setup_logging()
app.logger = logging.getLogger(__name__)
app.logger.info(
    "Environment resolved: "
    f"prod={IS_PROD} source={PROD_ENV_SOURCE or 'none'} "
    f"app_env={APP_ENV!r} flask_env={(os.getenv('FLASK_ENV') or '')!r} env={(os.getenv('ENV') or '')!r}"
)

@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

# ---------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------
@app.after_request
def set_security_headers(response):
    """Add comprehensive security headers to all responses"""
    # Add request ID if not already added
    if hasattr(g, 'request_id') and 'X-Request-ID' not in response.headers:
        response.headers['X-Request-ID'] = g.request_id
    
    # Prevent XSS attacks
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Content Security Policy - use nonce in production if possible
    nonce = getattr(g, 'csp_nonce', '')
    nonce_src = f"'nonce-{nonce}' " if nonce else ""
    media_src = "'self'"
    if STORAGE_BACKEND == "s3":
        media_src = "'self' https:"
    if IS_DEV:
        csp_policy = (
            "default-src 'self'; "
            f"script-src 'self' 'unsafe-inline' {nonce_src}https://cdn.jsdelivr.net https://js.stripe.com; "
            "script-src-attr 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src 'self' https://js.stripe.com https://hooks.stripe.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
    else:
        # Production: stricter CSP with additional security directives
        csp_policy = (
            "default-src 'self'; "
            f"script-src 'self' {nonce_src}https://cdn.jsdelivr.net https://js.stripe.com; "
            "script-src-attr 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "  # Allow inline styles for compatibility
            "img-src 'self' data: https:; "
            "font-src 'self' data: https:; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src 'self' https://js.stripe.com https://hooks.stripe.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "  # Block plugins (Flash, etc.)
            f"media-src {media_src}; "  # Allow media from same origin (and S3 if configured)
            "worker-src 'self'; "  # Block web workers for security
            "manifest-src 'self'; "  # Allow web app manifests
            "upgrade-insecure-requests;"  # Upgrade HTTP to HTTPS
        )
    response.headers["Content-Security-Policy"] = csp_policy
    
    # Strict Transport Security (HSTS) - only in production
    if not IS_DEV:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # Permissions Policy (Feature Policy)
    response.headers["Permissions-Policy"] = (
        "geolocation=(self), microphone=(), camera=(), payment=(self), usb=()"
    )
    
    return response


@app.context_processor
def inject_csrf_token():
    # templates can do: {{ csrf_token() }}
    return dict(csrf_token=generate_csrf, csp_nonce=getattr(g, "csp_nonce", ""))


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF errors with helpful messages"""
    error_msg = str(e.description) if e.description else "Security error: CSRF token missing or invalid."
    
    # Log the error for debugging
    if IS_DEV:
        app.logger.warning(f"CSRF Error: {error_msg}. Referrer: {request.referrer}, Method: {request.method}, Path: {request.path}")
        app.logger.debug(f"Session keys: {list(session.keys()) if session else 'No session'}")
        app.logger.debug(f"SECRET_KEY set: {bool(app.config.get('SECRET_KEY'))}")
    
    # Provide more helpful error message
    if "session" in error_msg.lower() or "missing" in error_msg.lower():
        msg = "Session expired or invalid. Please refresh the page and try again."
    else:
        msg = error_msg
    
    flash(msg, "error")
    
    # Redirect to the page they came from, or home
    return redirect(request.referrer or url_for("home"))


# ---------------------------------------------------------
# Enhanced Security: Rate Limiting & Input Validation
# ---------------------------------------------------------

# Redis-based rate limiting (fallback to in-memory for dev)
_redis_client = None
_redis_available = False

def _init_redis():
    """Initialize Redis client if REDIS_URL is available"""
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_available
    
    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url or not REDIS_AVAILABLE:
        _redis_available = False
        if is_prod():
            if not redis_url:
                app.logger.warning(
                    "REDIS_URL missing in production; using in-memory rate limiting (not multi-process safe)."
                )
            if not REDIS_AVAILABLE:
                app.logger.warning(
                    "Redis client library not available in production; using in-memory rate limiting."
                )
        else:
            app.logger.warning("Redis not available; using in-memory rate limiting (not multi-process safe).")
        return False
    
    try:
        _redis_client = redis.from_url(redis_url, decode_responses=True)
        _redis_client.ping()
        _redis_available = True
        app.logger.info("Redis rate limiting enabled")
        return True
    except Exception as e:
        _redis_available = False
        if is_prod():
            app.logger.warning(
                f"Redis connection failed in production; using in-memory rate limiting: {e}"
            )
        else:
            app.logger.warning(f"Redis connection failed, using in-memory rate limiting: {e}")
        return False

_init_redis()
app.logger.info(
    "Rate limiting backend: "
    + ("redis" if _redis_available and _redis_client else "memory_fallback")
)

# Fallback in-memory storage (dev only)
_RATE_LIMITS_MEMORY: dict[str, list[float]] = {}
_LOGIN_ATTEMPTS_MEMORY: dict[str, list[float]] = {}
_OWNER_UNLOCK_ATTEMPTS_MEMORY: dict[str, list[float]] = {}

def get_client_id() -> str:
    """Get unique client identifier for rate limiting (ProxyFix-aware)"""
    # Use real client IP (supports ProxyFix if enabled)
    if hasattr(request, 'access_route') and len(request.access_route) > 0:
        ip = request.access_route[0]  # First IP in chain (real client)
    else:
        ip = request.remote_addr or "unknown"
    
    ua = request.headers.get("User-Agent", "")[:50] or "unknown"
    import hashlib
    combined = f"{ip}:{ua}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def check_rate_limit(action: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    """Check if client has exceeded rate limit for an action (Redis or in-memory fallback)"""
    client_id = get_client_id()
    key = f"rate_limit:{action}:{client_id}"
    
    if _redis_available and _redis_client:
        try:
            # Redis sliding window using sorted set
            now = time()
            pipe = _redis_client.pipeline()
            pipe.zremrangebyscore(key, 0, now - window_seconds)  # Remove old entries
            pipe.zcard(key)  # Count current entries
            pipe.zadd(key, {str(now): now})  # Add current timestamp
            pipe.expire(key, window_seconds)  # Auto-expire key
            results = pipe.execute()
            current_count = results[1]
            
            return current_count < max_requests
        except Exception as e:
            app.logger.warning(f"Redis rate limit check failed, falling back to memory: {e}")
            # Fall through to memory fallback
    
    # In-memory fallback (dev or Redis unavailable)
    now = time()
    attempts = _RATE_LIMITS_MEMORY.get(key, [])
    attempts = [t for t in attempts if now - t < window_seconds]
    
    if len(attempts) >= max_requests:
        return False
    
    attempts.append(now)
    _RATE_LIMITS_MEMORY[key] = attempts
    return True


def sanitize_input(value: str, max_length: int = 5000) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not isinstance(value, str):
        return ""
    # Remove null bytes and control characters
    cleaned = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
    # Limit length
    return cleaned[:max_length].strip()


def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 255:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_username(username: str) -> bool:
    """Validate username format - alphanumeric, underscore, dash only"""
    if not username or len(username) < 3 or len(username) > 30:
        return False
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, username))


def _validate_url_optional(url: str) -> bool:
    """Validate optional URL - must be blank or start with http:// or https://, max 500 chars"""
    if not url or not url.strip():
        return True
    url = url.strip()
    if len(url) > 500:
        return False
    return url.startswith("http://") or url.startswith("https://")


_SECURITY_EVENT_TABLE_CHECKED = False
_SECURITY_EVENT_TABLE_EXISTS = False


def _security_event_table_exists() -> bool:
    global _SECURITY_EVENT_TABLE_CHECKED, _SECURITY_EVENT_TABLE_EXISTS
    if _SECURITY_EVENT_TABLE_CHECKED:
        return _SECURITY_EVENT_TABLE_EXISTS
    try:
        _SECURITY_EVENT_TABLE_EXISTS = bool(inspect(db.engine).has_table("security_event"))
    except Exception:
        _SECURITY_EVENT_TABLE_EXISTS = False
    _SECURITY_EVENT_TABLE_CHECKED = True
    return _SECURITY_EVENT_TABLE_EXISTS


def log_security_event(event_type: str, details: str, severity: str = "info", meta: dict | None = None):
    """Log security events (structured, best-effort, never crashes)."""
    try:
        user_id = current_user.id if current_user.is_authenticated else None
    except Exception:
        user_id = None
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:64]
    except Exception:
        ip = None
    try:
        ua = (request.headers.get("User-Agent") or "")[:220]
    except Exception:
        ua = None
    try:
        path = request.path
    except Exception:
        path = None
    req_id = getattr(g, "request_id", None)

    payload = {
        "event_type": event_type,
        "severity": (severity or "info").lower(),
        "user_id": user_id,
        "ip": ip,
        "user_agent": ua,
        "path": path,
        "request_id": req_id,
        "details": details,
        "meta": meta or {},
    }
    try:
        app.logger.info(f"SECURITY_EVENT {json.dumps(payload, default=str)}")
    except Exception:
        pass

    if not _security_event_table_exists():
        return

    try:
        ev = SecurityEvent(
            event_type=str(event_type)[:80],
            severity=str((severity or "info")).lower()[:20],
            user_id=user_id,
            ip=ip,
            user_agent=ua,
            path=path[:200] if path else None,
            request_id=req_id,
            meta_json=_safe_json_dumps({**(meta or {}), "details": details}),
        )
        db.session.add(ev)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


# ---------------------------------------------------------
# Enhanced Error Handling - Don't expose sensitive info
# ---------------------------------------------------------
@app.errorhandler(500)
def handle_500_error(e):
    """Handle 500 errors without exposing sensitive information"""
    # Log full error with traceback for debugging
    import traceback
    tb_str = traceback.format_exc()
    app.logger.error(f"500 ERROR FULL TRACEBACK:\n{tb_str}")
    app.logger.error(f"500 ERROR TYPE: {type(e).__name__}")
    app.logger.error(f"500 ERROR STR: {str(e)}")
    
    try:
        db.session.rollback()
    except Exception as rollback_err:
        # db might not be initialized yet, ignore rollback errors
        app.logger.warning(f"Could not rollback DB session: {rollback_err}")
    
    try:
        log_security_event("server_error", f"Internal server error: {type(e).__name__}", "error")
    except Exception:
        # log_security_event might fail if app not fully initialized
        pass
    
    if IS_DEV:
        # In dev, show the actual error
        raise
    
    # In production, render 500.html if exists, else safe generic message
    try:
        if os.path.exists(os.path.join(BASE_DIR, "templates", "500.html")):
            return render_template("500.html"), 500
    except Exception:
        # Template rendering might fail, fall back to plain text
        pass
    
    return "An error occurred. Our team has been notified.", 500


@app.errorhandler(404)
def handle_404_error(e):
    """Handle 404 errors"""
    if os.path.exists(os.path.join(BASE_DIR, "templates", "404.html")):
        return render_template("404.html"), 404
    return "Page not found", 404


@app.errorhandler(403)
def handle_403_error(e):
    """Handle 403 Forbidden errors"""
    log_security_event("unauthorized_access", f"403 Forbidden: {request.path}", "warning")
    flash("You don't have permission to access this resource.", "error")
    return redirect(request.referrer or url_for("home"))


@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(e):
    """Handle 413 Request Entity Too Large errors (file upload size exceeded)"""
    log_security_event("upload_too_large", f"Request size exceeded limit: {request.path}", "warning")
    flash("Upload too large. Please upload a smaller file.", "error")
    
    # Try to redirect to the referrer, or home page if no referrer
    referrer = request.referrer
    if referrer:
        return redirect(referrer)
    return redirect(url_for("home"))


@app.template_test("None")
def jinja_is_None(value):
    return value is None


# =========================================================
# Database (Railway Postgres in prod, SQLite locally)
# =========================================================
def normalize_database_url(url: str) -> str:
    """
    Normalize database URL to use postgresql+psycopg:// format (psycopg v3).
    Handles postgres:// and postgresql:// formats from Railway.
    Railway provides DATABASE_URL like:
      - postgres://... or postgresql://...
    We convert to postgresql+psycopg:// for SQLAlchemy + psycopg3.
    SSL will be configured via engine options instead of URL to avoid parsing issues.
    """
    if not url:
        return url
    
    # Step 1: Convert postgres:// to postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    
    # Step 2: Replace postgresql:// with postgresql+psycopg:// (psycopg v3)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    
    return url


def get_database_config():
    """
    Configure database connection for Railway Postgres or local SQLite.
    Returns tuple: (database_url, engine_options)
    """
    db_url = os.getenv("DATABASE_URL", "").strip()
    
    if not db_url:
        # Fallback to SQLite for local development
        sqlite_path = os.path.join(INSTANCE_DIR, "app.db")
        return f"sqlite:///{sqlite_path}", {}
    
    # Normalize URL format for Railway or any Postgres provider
    db_url = normalize_database_url(db_url)
    
    # Engine options for PostgreSQL connections with psycopg v3
    engine_options = {
        "pool_pre_ping": True,  # Verify connections before using
        "pool_recycle": 300,    # Recycle connections after 5 minutes
        "pool_size": 5,         # Connection pool size
        "max_overflow": 10,     # Max overflow connections
        "connect_args": {
            "connect_timeout": 10,
            "sslmode": "require",  # Required for Railway Postgres
        },
        # Use psycopg3's default statement cache settings
        "execution_options": {
            "isolation_level": "READ_COMMITTED",  # Standard transaction level
        },
    }
    
    return db_url, engine_options


# Configure database
try:
    db_url, engine_options = get_database_config()
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options
    
    # Log database backend info (safe, no credentials exposed)
    if "postgresql+psycopg://" in db_url:
        app.logger.info("DB: postgres (Railway/Postgres with psycopg v3)")
    else:
        app.logger.info("DB: sqlite (local development)")
        
except Exception as e:
    app.logger.error(f"Failed to configure database: {e}", exc_info=True)
    # Fallback to SQLite on configuration error
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'app.db')}"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
    app.logger.warning("DB: sqlite (fallback after configuration error)")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


def test_database_connection() -> tuple[bool, str]:
    """
    Test database connection and return (success, message).
    Provides helpful error messages for common issues.
    """
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
        return True, "Database connection successful"
    except ProgrammingError as e:
        error_msg = str(e).lower()
        if "does not exist" in error_msg or "database" in error_msg:
            return False, f"Database does not exist. Error: {e}"
        elif "schema" in error_msg or "relation" in error_msg:
            return False, f"Schema/table issue. Error: {e}"
        elif "permission" in error_msg or "access" in error_msg:
            return False, f"Permission denied. Check user privileges. Error: {e}"
        else:
            return False, f"SQL error: {e}"
    except OperationalError as e:
        error_msg = str(e).lower()
        if "could not connect" in error_msg or "connection refused" in error_msg:
            return False, f"Cannot connect to database server. Check DATABASE_URL and network. Error: {e}"
        elif "ssl" in error_msg or "certificate" in error_msg:
            return False, f"SSL connection error. Error: {e}"
        elif "timeout" in error_msg:
            return False, f"Connection timeout. Error: {e}"
        elif "authentication" in error_msg or "password" in error_msg:
            return False, f"Authentication failed. Check username/password in DATABASE_URL. Error: {e}"
        else:
            return False, f"Connection error: {e}"
    except DatabaseError as e:
        return False, f"Database error: {e}"
    except SQLAlchemyError as e:
        return False, f"SQLAlchemy error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {type(e).__name__}: {e}"


# Test database connection on startup (only in dev mode)
if IS_DEV and os.getenv("DATABASE_URL"):
    try:
        with app.app_context():
            success, message = test_database_connection()
            if success:
                app.logger.info(f"[DB] {message}")
            else:
                app.logger.warning(f"[DB] {message}")
    except Exception as e:
        app.logger.warning(f"Could not test database connection: {e}")


def _early_sqlite_bootstrap_columns() -> None:
    """
    Ensure critical SQLite columns exist BEFORE Flask-Login loads current_user.

    Flask-Login registers its own before_request hook at LoginManager(app) time.
    If our SQLAlchemy models include new columns, user_loader() will SELECT them
    immediately and crash if the SQLite schema hasn't been migrated yet.
    """
    try:
        if db.engine.url.get_backend_name() != "sqlite":
            return
    except Exception:
        return

    try:
        import sqlite3
        from pathlib import Path

        # Use the *actual* SQLite file SQLAlchemy is configured to use.
        # (DATABASE_URL may point somewhere other than instance/app.db)
        raw_db_path = getattr(db.engine.url, "database", None)
        if not raw_db_path or raw_db_path == ":memory:":
            return
        db_path = Path(raw_db_path)
        if not db_path.is_absolute():
            # If configured with a relative path, resolve against the repo/app root.
            db_path = (Path(BASE_DIR) / db_path).resolve()
        if not db_path.exists():
            return

        con = None
        try:
            con = sqlite3.connect(str(db_path))
            cur = con.cursor()

            # If the user table doesn't exist yet, don't try to ALTER it.
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
            if cur.fetchone() is None:
                return

            # Check if stripe_account_id exists on user table
            cur.execute('PRAGMA table_info("user")')
            cols = {row[1] for row in cur.fetchall()}
            if "stripe_account_id" not in cols:
                cur.execute('ALTER TABLE "user" ADD COLUMN stripe_account_id VARCHAR(255)')
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS ix_user_stripe_account_id ON user (stripe_account_id)"
                )
                con.commit()
        finally:
            try:
                if con is not None:
                    con.close()
            except Exception:
                pass
    except Exception:
        # Best-effort: don't crash app startup in dev
        try:
            con.close()
        except Exception:
            pass


# Run early bootstrap before LoginManager registers hooks
_early_sqlite_bootstrap_columns()

login_manager = LoginManager(app)
login_manager.login_view = "login"







# =========================================================
# Uploads & Storage Abstraction
# =========================================================
# Storage backend: 'local' or 's3'
# Prefer UPLOAD_PROVIDER (new), fall back to STORAGE_BACKEND (legacy).
STORAGE_BACKEND = (os.getenv("UPLOAD_PROVIDER") or os.getenv("STORAGE_BACKEND") or "local").lower().strip()

# Allow Railway volume path (or any custom path) via env.
UPLOAD_ROOT = (
    os.getenv("UPLOAD_ROOT")
    or os.getenv("RAILWAY_VOLUME_MOUNT")
    or os.path.join(BASE_DIR, "uploads")
)
os.makedirs(UPLOAD_ROOT, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_ROOT

# Signed URL TTL for protected downloads (S3). Default: 15 minutes.
try:
    SIGNED_URL_TTL_SECONDS = int((os.getenv("SIGNED_URL_TTL_SECONDS") or "900").strip())
except Exception:
    SIGNED_URL_TTL_SECONDS = 900
SIGNED_URL_TTL_SECONDS = max(60, min(3600, SIGNED_URL_TTL_SECONDS))

# S3 configuration (only used if STORAGE_BACKEND=s3)
S3_BUCKET_NAME = (os.getenv("S3_BUCKET") or os.getenv("S3_BUCKET_NAME") or "").strip()
S3_REGION = (os.getenv("AWS_REGION") or os.getenv("S3_REGION") or "us-east-1").strip()
S3_PREFIX = (os.getenv("S3_PREFIX") or "").strip().strip("/")

# Initialize S3 client if needed
S3_CLIENT = None
if STORAGE_BACKEND == "s3" and not BOTO3_AVAILABLE:
    raise RuntimeError("S3 storage enabled but boto3 is not installed.")
if STORAGE_BACKEND == "s3" and BOTO3_AVAILABLE and S3_BUCKET_NAME:
    try:
        import boto3
        S3_CLIENT = boto3.client('s3', region_name=S3_REGION)
        # Test S3 connection
        S3_CLIENT.head_bucket(Bucket=S3_BUCKET_NAME)
        app.logger.info(f"S3 storage backend enabled: bucket={S3_BUCKET_NAME}, region={S3_REGION}")
    except Exception as e:
        app.logger.error(f"S3 initialization failed, falling back to local storage: {e}")
        STORAGE_BACKEND = "local"
        S3_CLIENT = None
elif STORAGE_BACKEND == "s3":
    app.logger.warning("S3 storage requested but not properly configured, falling back to local storage")
    STORAGE_BACKEND = "local"

ALLOWED_IMAGE = {"png", "jpg", "jpeg"}
ALLOWED_AUDIO = {"mp3", "wav", "m4a", "ogg"}
ALLOWED_STEMS = {"zip", "rar", "7z", "mp3", "wav", "m4a", "ogg"}

ALLOWED_VIDEO_EXTS = {"mp4", "webm", "mov"}
ALLOWED_RESUME = {"pdf", "doc", "docx"}

# Maximum file sizes (in bytes)
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_AUDIO_SIZE = 50 * 1024 * 1024  # 50MB
MAX_VIDEO_SIZE = 100 * 1024 * 1024  # 100MB
MAX_ARCHIVE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_RESUME_SIZE = 8 * 1024 * 1024  # 8MB


def _ext_ok(filename: str, allowed: set[str]) -> bool:
    """Check if file extension is allowed with security checks"""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    # Additional security: prevent double extensions (e.g., file.php.jpg)
    if filename.count(".") > 1:
        # Only allow one extension
        parts = filename.rsplit(".", 2)
        if len(parts) >= 3 and parts[-2].lower() in {"php", "phtml", "jsp", "asp", "aspx", "exe", "sh", "bat", "cmd", "js", "html", "htm"}:
            log_security_event("suspicious_file_extension", f"Blocked double extension: {filename}", "warning")
            return False
    return ext in allowed


# Storage abstraction classes
class StorageBackend:
    """Abstract storage backend interface"""
    def save_file(self, file_storage, filename: str) -> bool:
        """Save file and return True on success"""
        raise NotImplementedError
    
    def delete_file(self, filename: str) -> bool:
        """Delete file and return True on success"""
        raise NotImplementedError
    
    def get_signed_url(self, filename: str, expires: int = 900) -> Optional[str]:
        """Get signed URL for protected file access (None for public files)"""
        raise NotImplementedError


class LocalStorageBackend(StorageBackend):
    """Local disk storage backend"""
    def __init__(self, upload_folder: str):
        self.upload_folder = upload_folder
        os.makedirs(upload_folder, exist_ok=True)
    
    def save_file(self, file_storage, filename: str) -> bool:
        filepath = os.path.join(self.upload_folder, filename)
        real_upload = os.path.realpath(self.upload_folder)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_upload):
            log_security_event("directory_traversal_attempt", f"Blocked path traversal: {filepath}", "error")
            return False
        file_storage.save(filepath)
        return True
    
    def delete_file(self, filename: str) -> bool:
        filepath = os.path.join(self.upload_folder, filename)
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
        except Exception as e:
            app.logger.error(f"Failed to delete file {filename}: {e}")
        return False
    
    def get_signed_url(self, filename: str, expires: int = 900) -> Optional[str]:
        # Local storage: return None (direct file serving via send_from_directory)
        return None


class S3StorageBackend(StorageBackend):
    """S3 storage backend"""
    def __init__(self, s3_client, bucket_name: str):
        self.s3_client = s3_client
        self.bucket_name = bucket_name
    
    def save_file(self, file_storage, filename: str) -> bool:
        try:
            key = f"{S3_PREFIX}/{filename}" if S3_PREFIX else filename
            file_storage.seek(0)
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=file_storage,
                ContentType=file_storage.content_type or "application/octet-stream"
            )
            return True
        except Exception as e:
            app.logger.error(f"S3 upload failed for {filename}: {e}")
            return False
    
    def delete_file(self, filename: str) -> bool:
        try:
            key = f"{S3_PREFIX}/{filename}" if S3_PREFIX else filename
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            return True
        except Exception as e:
            app.logger.error(f"S3 delete failed for {filename}: {e}")
            return False
    
    def get_signed_url(self, filename: str, expires: int = 900) -> Optional[str]:
        try:
            key = f"{S3_PREFIX}/{filename}" if S3_PREFIX else filename
            url = self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": key},
                ExpiresIn=expires
            )
            return url
        except Exception as e:
            app.logger.error(f"S3 signed URL generation failed for {filename}: {e}")
            return None


# Initialize storage backend
if STORAGE_BACKEND == "s3" and S3_CLIENT and S3_BUCKET_NAME:
    storage_backend: StorageBackend = S3StorageBackend(S3_CLIENT, S3_BUCKET_NAME)
else:
    storage_backend: StorageBackend = LocalStorageBackend(app.config["UPLOAD_FOLDER"])


def _is_production_mode() -> bool:
    return is_prod()


def _parse_coord(raw: str) -> float:
    """
    Parse a latitude/longitude string.
    Accepts decimal degrees, optional N/S/E/W suffix, or DMS-style values.
    """
    if raw is None:
        raise ValueError("empty coordinate")

    s = raw.strip().upper()
    if not s:
        raise ValueError("empty coordinate")

    direction = None
    for d in ("N", "S", "E", "W"):
        if d in s:
            direction = d
            s = s.replace(d, "")

    # If decimal uses comma (e.g., 35,868145), normalize to dot.
    if "," in s and "." not in s:
        s = s.replace(",", ".")

    nums = re.findall(r"[-+]?\d+(?:\.\d+)?", s)
    if not nums:
        raise ValueError("no numeric coordinate")

    if len(nums) >= 3:
        deg = float(nums[0])
        minutes = float(nums[1])
        seconds = float(nums[2])
        val = abs(deg) + minutes / 60.0 + seconds / 3600.0
        if deg < 0:
            val = -val
    elif len(nums) == 2:
        deg = float(nums[0])
        minutes = float(nums[1])
        val = abs(deg) + minutes / 60.0
        if deg < 0:
            val = -val
    else:
        val = float(nums[0])

    if direction:
        if direction in ("S", "W"):
            val = -abs(val)
        else:
            val = abs(val)

    return val


def _parse_lat_lng(lat_raw: str, lng_raw: str) -> tuple[float, float]:
    """
    Parse latitude/longitude pair with basic validation.
    Allows "lat, lng" in a single field if the other is blank.
    """
    lat_raw = (lat_raw or "").strip()
    lng_raw = (lng_raw or "").strip()

    if lat_raw and not lng_raw:
        parts = [p.strip() for p in re.split(r"[;,]", lat_raw) if p.strip()]
        if len(parts) == 2:
            lat_raw, lng_raw = parts[0], parts[1]

    lat = _parse_coord(lat_raw)
    lng = _parse_coord(lng_raw)

    # If user swapped lat/lng, attempt to fix.
    if abs(lat) > 90 and abs(lng) <= 90:
        lat, lng = lng, lat

    if abs(lat) > 90 or abs(lng) > 180:
        raise ValueError("coordinate out of range")

    return lat, lng


def _scan_file_local(path: str) -> tuple[ScanStatus, str | None]:
    """
    Scan a local file using ClamAV if enabled.
    - If CLAMAV_ENABLED=1 and clamscan exists: scan and return CLEAN/INFECTED/FAILED.
    - If not enabled/available: return PENDING in prod, CLEAN in non-prod.
    """
    enabled = (os.getenv("CLAMAV_ENABLED") or "").strip() == "1"
    cmd = (os.getenv("CLAMAV_CMD") or "clamscan").strip()
    if not enabled:
        return (ScanStatus.pending, "scan_disabled") if _is_production_mode() else (ScanStatus.clean, "scan_skipped_dev")
    if not shutil.which(cmd):
        return (ScanStatus.pending, "clamscan_not_found") if _is_production_mode() else (ScanStatus.clean, "clamscan_not_found_dev")
    try:
        # clamscan exits 0 if clean, 1 if infected, >1 on error
        proc = subprocess.run([cmd, "--no-summary", path], capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            return (ScanStatus.clean, "clean")
        if proc.returncode == 1:
            return (ScanStatus.infected, (proc.stdout or proc.stderr or "infected")[:380])
        return (ScanStatus.failed, (proc.stdout or proc.stderr or "scan_failed")[:380])
    except Exception as e:
        return (ScanStatus.failed, (str(e) or "scan_failed")[:380])


def _save_file(
    fs,
    allowed_set: set[str],
    *,
    owner_user_id: int | None = None,
    purpose: UploadedFilePurpose | None = None,
) -> Optional[str]:
    """Save uploaded file with comprehensive security checks using storage backend"""
    if not fs or fs.filename == "":
        return None
    
    # Security: Validate filename
    filename = secure_filename(fs.filename)
    if not filename or not _ext_ok(filename, allowed_set):
        log_security_event("invalid_file_upload", f"Invalid file extension: {fs.filename}", "warning")
        return None

    # Default purpose late (UploadedFilePurpose is defined further down in the module)
    if purpose is None:
        try:
            purpose = UploadedFilePurpose.other
        except Exception:
            purpose = None
    
    # Extract extension from sanitized filename for size checking
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    
    # Security: Check file size based on actual file extension
    if ext in ALLOWED_IMAGE:
        MAX_FILE_SIZE = MAX_IMAGE_SIZE
    elif ext in ALLOWED_VIDEO_EXTS:
        MAX_FILE_SIZE = MAX_VIDEO_SIZE
    elif ext in ALLOWED_RESUME:
        MAX_FILE_SIZE = MAX_RESUME_SIZE
    elif ext in {"zip", "rar", "7z"}:
        # Archive files get archive size limit (important for ALLOWED_STEMS)
        MAX_FILE_SIZE = MAX_ARCHIVE_SIZE
    elif ext in ALLOWED_AUDIO:
        # Audio files (including those in ALLOWED_STEMS)
        MAX_FILE_SIZE = MAX_AUDIO_SIZE
    else:
        # Default to smallest limit for unknown extensions (shouldn't happen due to _ext_ok check)
        MAX_FILE_SIZE = MAX_IMAGE_SIZE
    
    fs.seek(0, 2)  # Seek to end
    size = fs.tell()
    fs.seek(0)  # Reset to beginning
    if size > MAX_FILE_SIZE:
        log_security_event("file_too_large", f"File size: {size} bytes, max: {MAX_FILE_SIZE}, extension: {ext}", "warning")
        return None
    
    # Security: Rate limit file uploads
    if not check_rate_limit("file_upload", max_requests=20, window_seconds=300):
        log_security_event("upload_rate_limit", f"Too many uploads from client", "warning")
        return None
    
    # Generate secure filename (UUID to prevent enumeration attacks)
    fname = f"{uuid.uuid4().hex}.{ext}"

    # Use storage backend to save file.
    # NOTE: In production with S3, we scan BEFORE upload to avoid PENDING deadlocks.
    saved_ok = False
    preupload_scan_status: ScanStatus | None = None
    preupload_scan_msg: str | None = None

    if STORAGE_BACKEND == "s3" and _is_production_mode():
        # Safer MVP: require scanning to be configured and scan locally before uploading to S3.
        enabled = (os.getenv("CLAMAV_ENABLED") or "").strip() == "1"
        cmd = (os.getenv("CLAMAV_CMD") or "clamscan").strip()
        if not enabled or not shutil.which(cmd):
            # Fail closed (avoid stuck PENDING uploads in prod)
            try:
                flash("Uploads are temporarily unavailable while file scanning is not configured.", "error")
            except Exception:
                pass
            try:
                _alert_create(
                    AlertSeverity.high,
                    "UPLOAD_SCAN_NOT_CONFIGURED",
                    "Upload blocked: scanning not configured in production",
                    {"provider": "s3", "clamav_enabled": enabled, "clamscan_found": bool(shutil.which(cmd))},
                )
            except Exception:
                pass
            return None

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="beatfund_upload_", suffix=f".{ext}", delete=False) as tf:
                tmp_path = tf.name
                fs.stream.seek(0)
                shutil.copyfileobj(fs.stream, tf)
            # Scan the temp file
            preupload_scan_status, preupload_scan_msg = _scan_file_local(tmp_path)
            if preupload_scan_status != ScanStatus.clean:
                # Do not upload non-clean files to S3
                try:
                    _alert_create(
                        AlertSeverity.high,
                        "UPLOAD_SCAN_FAILED",
                        "Upload scan failed or infected (preupload)",
                        {"scan_status": preupload_scan_status.value, "message": preupload_scan_msg},
                    )
                except Exception:
                    pass
                try:
                    flash("Upload rejected by security scanning.", "error")
                except Exception:
                    pass
                return None

            # Upload scanned temp file to S3
            try:
                key = f"{S3_PREFIX}/{fname}" if S3_PREFIX else fname
                with open(tmp_path, "rb") as f:
                    (S3_CLIENT or storage_backend.s3_client).put_object(
                        Bucket=S3_BUCKET_NAME,
                        Key=key,
                        Body=f,
                        ContentType=getattr(fs, "content_type", None) or "application/octet-stream",
                    )
                saved_ok = True
            except Exception as e:
                app.logger.error(f"S3 upload failed for {fname}: {e}")
                saved_ok = False
        finally:
            try:
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
    else:
        try:
            saved_ok = bool(storage_backend.save_file(fs, fname))
        except Exception as save_err:
            app.logger.error(f"Storage backend failed to save {fname}: {type(save_err).__name__}: {str(save_err)}", exc_info=True)
            saved_ok = False

    if not saved_ok:
        app.logger.error(f"File save failed for {fname} (saved_ok={saved_ok}, storage_backend={STORAGE_BACKEND})")
        return None

    # Create UploadedFile record + scan status (best-effort).
    try:
        if owner_user_id is None and current_user and getattr(current_user, "is_authenticated", False):
            owner_user_id = int(current_user.id)
    except Exception:
        owner_user_id = owner_user_id

    scan_status = ScanStatus.pending
    scan_msg = None
    try:
        if STORAGE_BACKEND == "s3" and _is_production_mode() and preupload_scan_status is not None:
            # Preupload scanning path (S3 + prod)
            scan_status = preupload_scan_status
            scan_msg = preupload_scan_msg or "preupload_scan"
        elif STORAGE_BACKEND == "local":
            local_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            scan_status, scan_msg = _scan_file_local(local_path)
            if scan_status == ScanStatus.infected:
                storage_backend.delete_file(fname)
        else:
            # S3: if we can't scan inline, default to pending in prod, clean in dev
            scan_status = ScanStatus.pending if _is_production_mode() else ScanStatus.clean
            scan_msg = "pending_scan_s3" if scan_status == ScanStatus.pending else "scan_skipped_dev"
    except Exception as e:
        scan_status = ScanStatus.failed if _is_production_mode() else ScanStatus.clean
        scan_msg = (str(e) or "scan_error")[:380]

    try:
        uf = UploadedFile(
            owner_user_id=owner_user_id,
            purpose=purpose,
            storage_provider=STORAGE_BACKEND,
            key=fname,
            original_filename=filename[:255] if filename else None,
            content_type=(getattr(fs, "content_type", None) or None),
            size=size,
            etag=None,
            scan_status=scan_status,
            scan_message=scan_msg,
        )
        db.session.add(uf)
        db.session.commit()
        if scan_status in (ScanStatus.infected, ScanStatus.failed):
            try:
                _alert_create(AlertSeverity.high, "UPLOAD_SCAN_FAILED", "Upload scan failed or infected", {"file_id": uf.id, "key": fname, "scan_status": scan_status.value, "message": scan_msg})
            except Exception:
                pass
        if scan_status == ScanStatus.infected:
            log_security_event("upload_infected", f"Infected upload blocked: {fname}", "error")
            return None
    except Exception as db_err:
        db.session.rollback()
        app.logger.error(f"Failed to create UploadedFile record for {fname}: {type(db_err).__name__}: {str(db_err)}", exc_info=True)
        # Don't return None here - the file was already saved successfully, just log the metadata error
        # Return the filename so the upload is considered successful even if the metadata record fails
    
    log_security_event("file_upload_success", f"File uploaded: {fname} ({size} bytes)", "info")
    return fname


def _safe_remove(stored_filename: Optional[str]) -> None:
    """Remove file using storage backend abstraction"""
    if not stored_filename:
        return
    try:
        storage_backend.delete_file(stored_filename)
    except Exception as e:
        app.logger.warning(f"Failed to remove file {stored_filename}: {e}")
        pass


def _ffmpeg_available() -> bool:
    if not FFMPEG_CMD:
        return False
    return bool(shutil.which(FFMPEG_CMD))


def _generate_audio_preview_bytes(audio_file: FileStorage, preview_seconds: int) -> tuple[bytes | None, str | None]:
    if not audio_file or not audio_file.filename:
        return None, "missing_audio"
    if not _ffmpeg_available():
        return None, "ffmpeg_missing"

    try:
        seconds = int(preview_seconds or PREVIEW_SECONDS_DEFAULT)
    except Exception:
        seconds = PREVIEW_SECONDS_DEFAULT
    seconds = max(1, seconds)

    ext = "mp3"
    if audio_file.filename and "." in audio_file.filename:
        ext = audio_file.filename.rsplit(".", 1)[-1].lower()

    with tempfile.TemporaryDirectory(prefix="beatfund_preview_") as tmpdir:
        src_path = os.path.join(tmpdir, f"source.{ext}")
        preview_path = os.path.join(tmpdir, "preview.mp3")
        try:
            audio_file.stream.seek(0)
        except Exception:
            pass
        try:
            audio_file.save(src_path)
        except Exception as e:
            return None, f"save_failed:{type(e).__name__}"

        cmd = [
            FFMPEG_CMD,
            "-y",
            "-i", src_path,
            "-t", str(seconds),
            "-vn",
            "-acodec", "libmp3lame",
            "-b:a", "128k",
            preview_path,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as e:
            return None, f"ffmpeg_error:{type(e).__name__}"
        if proc.returncode != 0 or not os.path.exists(preview_path):
            err_msg = (proc.stderr or proc.stdout or "ffmpeg_failed")
            return None, (err_msg[:300] if err_msg else "ffmpeg_failed")

        try:
            with open(preview_path, "rb") as pf:
                return pf.read(), None
        except Exception as e:
            return None, f"preview_read_failed:{type(e).__name__}"


def _generate_audio_preview_from_path(local_path: str, preview_seconds: int) -> tuple[bytes | None, str | None]:
    if not local_path or not os.path.exists(local_path):
        return None, "missing_original"
    if not _ffmpeg_available():
        return None, "ffmpeg_missing"

    try:
        seconds = int(preview_seconds or PREVIEW_SECONDS_DEFAULT)
    except Exception:
        seconds = PREVIEW_SECONDS_DEFAULT
    seconds = max(1, seconds)

    with tempfile.TemporaryDirectory(prefix="beatfund_preview_") as tmpdir:
        preview_path = os.path.join(tmpdir, "preview.mp3")
        cmd = [
            FFMPEG_CMD,
            "-y",
            "-i", local_path,
            "-t", str(seconds),
            "-vn",
            "-acodec", "libmp3lame",
            "-b:a", "128k",
            preview_path,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as e:
            return None, f"ffmpeg_error:{type(e).__name__}"
        if proc.returncode != 0 or not os.path.exists(preview_path):
            err_msg = (proc.stderr or proc.stdout or "ffmpeg_failed")
            return None, (err_msg[:300] if err_msg else "ffmpeg_failed")

        try:
            with open(preview_path, "rb") as pf:
                return pf.read(), None
        except Exception as e:
            return None, f"preview_read_failed:{type(e).__name__}"


def _save_beat_audio_with_preview(
    audio_file: FileStorage,
    *,
    owner_user_id: int | None,
    preview_seconds: int | None = None,
) -> tuple[str | None, str | None, str | None]:
    preview_bytes, err = _generate_audio_preview_bytes(audio_file, preview_seconds or PREVIEW_SECONDS_DEFAULT)
    if not preview_bytes:
        return None, None, err or "preview_generation_failed"

    try:
        audio_file.stream.seek(0)
    except Exception:
        pass

    original_key = _save_file(
        audio_file,
        ALLOWED_AUDIO,
        owner_user_id=owner_user_id,
        purpose=UploadedFilePurpose.beat_deliverable,
    )
    if not original_key:
        return None, None, "original_save_failed"

    preview_fs = FileStorage(
        stream=BytesIO(preview_bytes),
        filename="preview.mp3",
        content_type="audio/mpeg",
    )
    preview_key = _save_file(
        preview_fs,
        ALLOWED_AUDIO,
        owner_user_id=owner_user_id,
        purpose=UploadedFilePurpose.beat_preview,
    )
    if not preview_key:
        _safe_remove(original_key)
        return None, None, "preview_save_failed"

    return original_key, preview_key, None


def _preview_error_message(err: str | None) -> str:
    if err == "ffmpeg_missing":
        return "Audio previews are temporarily unavailable because ffmpeg is not installed. Please contact support."
    if err == "original_save_failed":
        return "Invalid audio file format. Please upload MP3, WAV, M4A, or OGG."
    return "Audio preview generation failed. Please try again or contact support if this keeps happening."


def process_beat_upload(
    *,
    owner_user_id: int,
    title: str,
    price_cents: int,
    currency: str,
    license_type: str,
    bpm: int | None,
    genre: str | None,
    cover_file: FileStorage | None,
    deliverable_file: FileStorage | None,
    preview_file: FileStorage | None,
    stems_file: FileStorage | None,
    preview_seconds: int | None,
    allow_user_preview_upload: bool = True,
) -> tuple[Beat | None, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if not deliverable_file or not deliverable_file.filename:
        errors.append("Original audio file is required.")
        return None, errors, warnings

    if cover_file and cover_file.filename and not _ext_ok(cover_file.filename, ALLOWED_IMAGE):
        errors.append("Cover image must be PNG or JPG.")
    if preview_file and preview_file.filename and not _ext_ok(preview_file.filename, ALLOWED_AUDIO):
        errors.append("Preview file must be MP3, WAV, M4A, or OGG.")
    if stems_file and stems_file.filename and not _ext_ok(stems_file.filename, ALLOWED_STEMS):
        errors.append("Stems file must be ZIP, RAR, 7Z, or audio.")

    if errors:
        return None, errors, warnings

    try:
        seconds = int(preview_seconds or PREVIEW_SECONDS_DEFAULT)
    except Exception:
        seconds = PREVIEW_SECONDS_DEFAULT
    seconds = max(1, seconds)

    preview_key = None
    preview_status = "ready"
    preview_bytes: bytes | None = None
    preview_err: str | None = None

    # Attempt preview generation first to avoid losing stream position.
    if allow_user_preview_upload and preview_file and preview_file.filename:
        preview_key = _save_file(
            preview_file,
            ALLOWED_AUDIO,
            owner_user_id=owner_user_id,
            purpose=UploadedFilePurpose.beat_preview,
        )
        if not preview_key:
            warnings.append("Preview upload failed; we will retry using auto-generated audio.")
    if not preview_key:
        preview_bytes, preview_err = _generate_audio_preview_bytes(deliverable_file, seconds)

    try:
        deliverable_file.stream.seek(0)
    except Exception:
        pass

    deliverable_key = _save_file(
        deliverable_file,
        ALLOWED_AUDIO,
        owner_user_id=owner_user_id,
        purpose=UploadedFilePurpose.beat_deliverable,
    )
    if not deliverable_key:
        errors.append("Invalid audio file format. Please upload MP3, WAV, M4A, or OGG.")
        return None, errors, warnings

    stems_key = None
    if stems_file and stems_file.filename:
        stems_key = _save_file(
            stems_file,
            ALLOWED_STEMS,
            owner_user_id=owner_user_id,
            purpose=UploadedFilePurpose.beat_stems,
        )
        if not stems_key:
            warnings.append("Stems upload failed. You can upload stems later from your beats page.")

    if not preview_key and preview_bytes:
        preview_fs = FileStorage(
            stream=BytesIO(preview_bytes),
            filename="preview.mp3",
            content_type="audio/mpeg",
        )
        preview_key = _save_file(
            preview_fs,
            ALLOWED_AUDIO,
            owner_user_id=owner_user_id,
            purpose=UploadedFilePurpose.beat_preview,
        )

    if not preview_key:
        preview_status = "failed"
        if preview_err == "ffmpeg_missing":
            warnings.append(
                "Preview processing is unavailable. Upload a preview MP3 to publish this beat."
            )
        else:
            warnings.append("Preview generation failed. Upload a preview MP3 to publish this beat.")

    beat = Beat(
        owner_id=owner_user_id,
        title=title,
        price_cents=int(price_cents or 0),
        currency=(currency or "usd"),
        license=license_type or "standard",
        bpm=bpm,
        genre=genre or None,
        is_active=True,
    )

    if cover_file and cover_file.filename:
        cover_key = _save_file(
            cover_file,
            ALLOWED_IMAGE,
            owner_user_id=owner_user_id,
            purpose=UploadedFilePurpose.beat_cover,
        )
        if cover_key:
            beat.cover_path = cover_key
        else:
            warnings.append("Cover image could not be saved; continuing without it.")

    beat.audio_deliverable_key = deliverable_key
    beat.audio_original_key = deliverable_key
    beat.audio_preview_key = preview_key
    beat.preview_seconds = seconds
    beat.preview_status = preview_status
    if preview_key:
        beat.preview_path = preview_key
    if stems_key:
        beat.stems_key = stems_key
        if not beat.stems_path:
            beat.stems_path = stems_key

    return beat, errors, warnings


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
    # Priority A: OWNER_PANEL_PASS_HASH (use as-is)
    env_hash = os.getenv("OWNER_PANEL_PASS_HASH")
    if env_hash and env_hash.strip():
        return env_hash.strip()

    # Priority B: OWNER_PANEL_PASS (generate hash)
    env_plain = os.getenv("OWNER_PANEL_PASS")
    if env_plain and env_plain.strip():
        return generate_password_hash(env_plain.strip())

    # Priority C: instance/owner_passcode.json (allows UI changes to persist)
    inst_hash = _load_owner_pass_hash_from_instance()
    if inst_hash:
        return inst_hash

    # Priority D: DEV_OWNER_PANEL_PASS (dev only, generate hash)
    if IS_DEV:
        dev_plain = os.getenv("DEV_OWNER_PANEL_PASS")
        if dev_plain and dev_plain.strip():
            return generate_password_hash(dev_plain.strip())

    # No valid passcode found
    return None


OWNER_PANEL_PASS_HASH_EFFECTIVE = _get_effective_owner_pass_hash()
if not OWNER_PANEL_PASS_HASH_EFFECTIVE:
    if IS_DEV:
        # Dev UX: allow app to boot even if owner passcode isn't set yet.
        # The superadmin owner panel will remain locked until configured.
        app.logger.warning(
            "Owner panel passcode is not configured; owner panel remains locked. "
            "Set DEV_OWNER_PANEL_PASS (recommended) or OWNER_PANEL_PASS / OWNER_PANEL_PASS_HASH."
        )
    else:
        raise RuntimeError(
            "SECURITY ERROR: Owner passcode is not configured for production.\n"
            "Set one of:\n"
            "- OWNER_PANEL_PASS_HASH (recommended)\n"
            "- OWNER_PANEL_PASS\n"
        )

# OWNER_PASS_MANAGED_BY_ENV is True if using env vars (but NOT DEV_OWNER_PANEL_PASS)
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

# Tiered service fee rules by provider role (defined after RoleEnum)
SERVICE_FEE_RULES = {
    # High-ticket roles: 7% min $4.99 max $49.99
    RoleEnum.studio: {"rate": Decimal("0.07"), "min": 499, "max": 4999},
    RoleEnum.videographer: {"rate": Decimal("0.07"), "min": 499, "max": 4999},
    RoleEnum.photographer: {"rate": Decimal("0.07"), "min": 499, "max": 4999},
    
    # Mid-ticket roles: 8% min $3.99 max $39.99
    RoleEnum.dj: {"rate": Decimal("0.08"), "min": 399, "max": 3999},
    RoleEnum.emcee_host_hypeman: {"rate": Decimal("0.08"), "min": 399, "max": 3999},
    RoleEnum.event_planner: {"rate": Decimal("0.08"), "min": 399, "max": 3999},
    RoleEnum.live_sound_engineer: {"rate": Decimal("0.08"), "min": 399, "max": 3999},
    RoleEnum.lighting_designer: {"rate": Decimal("0.08"), "min": 399, "max": 3999},
    
    # Lower-ticket roles: 10% min $2.99 max $29.99
    RoleEnum.designer: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.engineer: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.mix_master_engineer: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.makeup_artist: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.hair_stylist_barber: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.wardrobe_stylist: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
    RoleEnum.dancer_choreographer: {"rate": Decimal("0.10"), "min": 299, "max": 2999},
}

# Default service fee rule (for roles not in SERVICE_FEE_RULES)
DEFAULT_SERVICE_FEE_RULE = {"rate": Decimal("0.08"), "min": 399, "max": 3999}


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
app.jinja_env.globals["NOTIF_POLL_SECONDS"] = NOTIF_POLL_SECONDS
app.jinja_env.globals["AFFILIATE_CONTACT_EMAIL"] = AFFILIATE_CONTACT_EMAIL
app.jinja_env.globals["AFFILIATE_DEFAULT_PCT"] = AFFILIATE_DEFAULT_PCT

# ✅ Needed if your templates use {{ datetime.utcnow().year }}
app.jinja_env.globals["datetime"] = datetime


@app.context_processor
def inject_kyc_banner_flags():
    kyc_missing = False
    try:
        if current_user.is_authenticated:
            kyc_missing = not _is_kyc_verified(current_user)
    except Exception:
        kyc_missing = False
    return {
        "kyc_enforce": KYC_ENFORCE,
        "kyc_missing": kyc_missing,
        "kyc_bypass_active": (not KYC_ENFORCE and kyc_missing),
    }


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True, index=True)

    full_name = db.Column(db.String(150), nullable=True)
    artist_name = db.Column(db.String(150), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default=RoleEnum.artist.value)  # String for flexibility with new roles
    kyc_status = db.Column(db.String(40), nullable=False, default=KYCStatus.not_started.value)  # String for flexibility
    is_active_col = db.Column("is_active", db.Boolean, nullable=False, default=True)

    is_superadmin = db.Column(db.Boolean, nullable=False, default=False)

    password_changed_at = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_sent_at = db.Column(db.DateTime, nullable=True)

    avatar_path = db.Column(db.String(255), nullable=True)
    email_notifications_enabled = db.Column(db.Boolean, nullable=False, default=True)

    # Stripe Connect (Express) account for payouts/withdrawals
    stripe_account_id = db.Column(db.String(255), nullable=True, index=True)
    referred_by_affiliate_id = db.Column(db.Integer, db.ForeignKey("affiliate.id"), nullable=True, index=True)

    referred_by_affiliate = db.relationship("Affiliate", foreign_keys=[referred_by_affiliate_id])

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
        if self.avatar_path:
            try:
                local_path = os.path.join(app.config["UPLOAD_FOLDER"], self.avatar_path)
                if os.path.exists(local_path):
                    v = f"{self.avatar_path}-{int(os.path.getmtime(local_path))}"
            except Exception:
                pass
        return url_for("user_avatar", user_id=self.id, v=v)

    @property
    def display_name(self) -> str:
        return self.artist_name or self.full_name or self.username
    
    # Make role and kyc_status properties that support .value for backward compatibility
    # since they're now stored as strings instead of enums
    class _StringEnumProxy:
        """Helper to make string fields behave like enum objects with .value property"""
        def __init__(self, value: str):
            self.value = value
        
        def __str__(self):
            return self.value
        
        def __eq__(self, other):
            if isinstance(other, str):
                return self.value == other
            elif hasattr(other, 'value'):
                return self.value == other.value
            return False
        
        def __hash__(self):
            return hash(self.value)
    
    @property 
    def role_obj(self):
        """Get role as object with .value property for backward compatibility"""
        return self._StringEnumProxy(self.role) if isinstance(self.role, str) else self.role
    
    @property
    def kyc_status_obj(self):
        """Get kyc_status as object with .value property for backward compatibility"""
        return self._StringEnumProxy(self.kyc_status) if isinstance(self.kyc_status, str) else self.kyc_status


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
    external_payment = "external_payment"
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
    currency = db.Column(db.String(8), nullable=False, default="usd")
    license = db.Column(db.String(80), nullable=False, default="standard")
    bpm = db.Column(db.Integer, nullable=True)
    genre = db.Column(db.String(80), nullable=True)
    cover_path = db.Column(db.String(255), nullable=True)
    preview_path = db.Column(db.String(255), nullable=True)
    stems_path = db.Column(db.String(255), nullable=True)
    audio_original_key = db.Column(db.String(255), nullable=True)
    audio_deliverable_key = db.Column(db.String(255), nullable=True)
    audio_preview_key = db.Column(db.String(255), nullable=True)
    stems_key = db.Column(db.String(255), nullable=True)
    preview_seconds = db.Column(db.Integer, nullable=True, default=PREVIEW_SECONDS_DEFAULT)
    preview_status = db.Column(db.String(20), nullable=True, default="ready", index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_featured = db.Column(db.Boolean, nullable=False, default=False)
    stripe_product_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    stripe_price_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    owner = db.relationship("User")

    @property
    def cover_url(self):
        return url_for("media_file", filename=self.cover_path) if self.cover_path else None

    @property
    def preview_url(self):
        status = (self.preview_status or "ready").lower()
        if status != "ready":
            return None
        if self.audio_preview_key or self.preview_path:
            return url_for("beat_preview", beat_id=self.id)
        return None

    @property
    def stems_url(self):
        if self.audio_deliverable_key or self.audio_original_key or self.stems_key or self.stems_path:
            return url_for("beat_download", beat_id=self.id)
        return None


class OrderStatus(str, enum.Enum):
    draft = "draft"
    pending_payment = "pending_payment"
    pending = "pending"  # legacy
    partially_paid = "partially_paid"
    paid = "paid"
    failed = "failed"
    refunded = "refunded"
    canceled = "canceled"


class OrderType(str, enum.Enum):
    booking = "booking"
    beat_purchase = "beat_purchase"
    other = "other"


class Order(db.Model):
    __table_args__ = (db.UniqueConstraint("buyer_id", "beat_id", name="uq_order_buyer_beat"),)
    id = db.Column(db.Integer, primary_key=True)
    beat_id = db.Column(db.Integer, db.ForeignKey("beat.id"), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # amount_cents stores the beat subtotal (not including fees)
    amount_cents = db.Column(db.Integer, nullable=False)
    platform_fee_cents = db.Column(db.Integer, nullable=True)
    processing_fee_cents = db.Column(db.Integer, nullable=True)
    total_cents = db.Column(db.Integer, nullable=True)
    currency = db.Column(db.String(8), nullable=False, default="usd")

    # Payment processor used to fund this order (e.g., "wallet" or "stripe")
    processor = db.Column(db.String(20), nullable=False, default="wallet", index=True)
    stripe_session_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    stripe_payment_intent = db.Column(db.String(255), nullable=True, unique=False, index=True)

    status = db.Column(db.Enum(OrderStatus), nullable=False, default=OrderStatus.paid, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    paid_at = db.Column(db.DateTime, nullable=True)

    beat = db.relationship("Beat")
    buyer = db.relationship("User", foreign_keys=[buyer_id], backref=db.backref("purchases", lazy="dynamic"))
    seller = db.relationship("User", foreign_keys=[seller_id])


# ------- Beat Purchases (access control) -------
class BeatPurchaseStatus(str, enum.Enum):
    paid = "paid"
    refunded = "refunded"
    disputed = "disputed"


class BeatPurchase(db.Model):
    __tablename__ = "beat_purchase"
    __table_args__ = (
        UniqueConstraint("beat_id", "buyer_id", "payment_id", name="uq_beat_purchase_buyer_payment"),
        db.Index("ix_beat_purchase_status", "status"),
    )
    id = db.Column(db.Integer, primary_key=True)
    beat_id = db.Column(db.Integer, db.ForeignKey("beat.id"), nullable=False, index=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    payment_id = db.Column(db.String(255), nullable=True, index=True)
    status = db.Column(db.String(20), nullable=False, default=BeatPurchaseStatus.paid.value)
    created_at = db.Column(db.DateTime, server_default=func.now())

    beat = db.relationship("Beat")
    buyer = db.relationship("User", foreign_keys=[buyer_id])


# ------- Stripe Orders + Ledger (new payout system) -------
class PaymentLedgerPhase(str, enum.Enum):
    holding = "holding"
    balance = "balance"
    full = "full"


class PaymentLedgerStatus(str, enum.Enum):
    created = "created"
    succeeded = "succeeded"
    refunded = "refunded"
    disputed = "disputed"
    failed = "failed"


class PaymentOrder(db.Model):
    __tablename__ = "payment_order"
    __table_args__ = (
        db.Index("ix_payment_order_type_status", "order_type", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    order_type = db.Column(db.Enum(OrderType), nullable=False, index=True)
    status = db.Column(db.Enum(OrderStatus), nullable=False, default=OrderStatus.pending_payment, index=True)

    client_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    provider_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    provider_stripe_acct_id = db.Column(db.String(255), nullable=True)

    total_amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(8), nullable=False, default="usd")

    affiliate_id = db.Column(db.Integer, db.ForeignKey("affiliate.id"), nullable=True, index=True)
    beat_id = db.Column(db.Integer, db.ForeignKey("beat.id"), nullable=True, index=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=True, index=True)

    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    client = db.relationship("User", foreign_keys=[client_user_id], backref=db.backref("payment_orders", lazy="dynamic"))
    provider = db.relationship("User", foreign_keys=[provider_user_id])
    affiliate = db.relationship("Affiliate", foreign_keys=[affiliate_id])
    beat = db.relationship("Beat")
    booking = db.relationship("Booking")

    @property
    def amount_cents(self) -> int:
        return int(self.total_amount_cents or 0)

    @property
    def total_cents(self) -> int:
        return int(self.total_amount_cents or 0)

    @property
    def platform_fee_cents(self) -> int:
        if self.order_type == OrderType.beat_purchase:
            return calc_beat_platform_fee_cents(int(self.total_amount_cents or 0))
        return 0


class PaymentLedger(db.Model):
    __tablename__ = "payment_ledger"
    __table_args__ = (
        db.Index("ix_payment_ledger_order_phase", "order_id", "phase"),
        db.Index("ix_payment_ledger_status", "status"),
        db.Index("ix_payment_ledger_created_at", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("payment_order.id"), nullable=False, index=True)
    phase = db.Column(db.Enum(PaymentLedgerPhase), nullable=False)

    gross_amount_cents = db.Column(db.Integer, nullable=False)
    platform_fee_collected_cents = db.Column(db.Integer, nullable=False, default=0)
    provider_amount_routed_cents = db.Column(db.Integer, nullable=False, default=0)

    stripe_checkout_session_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    stripe_charge_id = db.Column(db.String(255), nullable=True, unique=True, index=True)

    status = db.Column(db.Enum(PaymentLedgerStatus), nullable=False, default=PaymentLedgerStatus.created, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

    order = db.relationship("PaymentOrder", backref=db.backref("ledger_entries", lazy="dynamic"))


class ProviderStripeAccount(db.Model):
    __tablename__ = "provider_stripe_account"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True, index=True)
    stripe_account_id = db.Column(db.String(255), nullable=True, unique=True, index=True)
    charges_enabled = db.Column(db.Boolean, nullable=False, default=False)
    payouts_enabled = db.Column(db.Boolean, nullable=False, default=False)
    details_submitted = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    user = db.relationship("User", foreign_keys=[user_id], backref=db.backref("stripe_account", uselist=False))


class AffiliateStatus(str, enum.Enum):
    pending = "pending"
    active = "active"
    suspended = "suspended"


class Affiliate(db.Model):
    __tablename__ = "affiliate"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), nullable=False, unique=True, index=True)
    display_name = db.Column(db.String(160), nullable=False)
    address_line1 = db.Column(db.String(255), nullable=True)
    address_line2 = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(120), nullable=True)
    state = db.Column(db.String(120), nullable=True)
    postal_code = db.Column(db.String(20), nullable=True)
    country = db.Column(db.String(2), nullable=True)
    status = db.Column(db.Enum(AffiliateStatus), nullable=False, default=AffiliateStatus.pending)
    stripe_account_id = db.Column(db.String(255), nullable=True)
    commission_pct = db.Column(db.Numeric(6, 4), nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())


class AffiliateInvite(db.Model):
    __tablename__ = "affiliate_invite"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(120), nullable=False, unique=True, index=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    created_by_admin_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())

    admin = db.relationship("User", foreign_keys=[created_by_admin_user_id])


class AffiliateEarningStatus(str, enum.Enum):
    pending = "pending"
    available = "available"
    paid = "paid"
    reversed = "reversed"


class AffiliateEarning(db.Model):
    __tablename__ = "affiliate_earning"
    __table_args__ = (
        UniqueConstraint("affiliate_id", "payment_ledger_id", name="uq_affiliate_earning_affiliate_ledger"),
        db.Index("ix_affiliate_earning_status", "status"),
        db.Index("ix_affiliate_earning_available_at", "available_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    affiliate_id = db.Column(db.Integer, db.ForeignKey("affiliate.id"), nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey("payment_order.id"), nullable=False, index=True)
    payment_ledger_id = db.Column(db.Integer, db.ForeignKey("payment_ledger.id"), nullable=False, index=True)

    base_platform_fee_cents = db.Column(db.Integer, nullable=False)
    commission_cents = db.Column(db.Integer, nullable=False)

    status = db.Column(db.Enum(AffiliateEarningStatus), nullable=False, default=AffiliateEarningStatus.pending)
    available_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())

    affiliate = db.relationship("Affiliate", foreign_keys=[affiliate_id], backref=db.backref("earnings", lazy="dynamic"))
    order = db.relationship("PaymentOrder", foreign_keys=[order_id])
    ledger = db.relationship("PaymentLedger", foreign_keys=[payment_ledger_id])


# ------- Transaction Idempotency -------
class TransactionIdempotency(db.Model):
    __tablename__ = "transaction_idempotency"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    scope = db.Column(db.String(100), nullable=False, index=True)  # e.g., "wallet_transfer", "beat_purchase"
    result_json = db.Column(db.Text, nullable=True)  # Store result as JSON for replay
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)
    
    user = db.relationship("User")


# ------- Notifications -------
class Notification(db.Model):
    __tablename__ = "notification"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    kind = db.Column(db.String(50), nullable=False, default="info")  # info, success, warning, error
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(400), nullable=True)  # where to send user when clicked
    event_key = db.Column(db.String(120), nullable=True, index=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), index=True)
    emailed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        backref=db.backref("notifications", lazy="dynamic"),
    )
    actor = db.relationship(
        "User",
        foreign_keys=[actor_user_id],
        backref=db.backref("notifications_sent", lazy="dynamic"),
    )


# ------- Marketplace Activity Broadcast (event-driven) -------
class ActivityEventType(str, enum.Enum):
    beat_published = "BEAT_PUBLISHED"
    listing_published = "LISTING_PUBLISHED"
    listing_updated = "LISTING_UPDATED"
    listing_files_uploaded = "LISTING_FILES_UPLOADED"
    chat_message = "CHAT_MESSAGE"

    # Admin-only internal events
    admin_user_role_changed = "ADMIN_USER_ROLE_CHANGED"
    admin_user_disabled = "ADMIN_USER_DISABLED"
    admin_beat_removed = "ADMIN_BEAT_REMOVED"
    admin_beat_approved = "ADMIN_BEAT_APPROVED"
    admin_listing_hidden = "ADMIN_LISTING_HIDDEN"
    admin_booking_canceled = "ADMIN_BOOKING_CANCELED"
    admin_refund_issued = "ADMIN_REFUND_ISSUED"
    admin_wallet_adjusted = "ADMIN_WALLET_ADJUSTED"
    admin_ticket_updated = "ADMIN_TICKET_UPDATED"
    admin_job_post_created = "ADMIN_JOB_POST_CREATED"
    admin_job_post_updated = "ADMIN_JOB_POST_UPDATED"


class ActivityEvent(db.Model):
    __tablename__ = "activity_event"
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.Enum(ActivityEventType), nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    audience = db.Column(db.String(40), nullable=False, default="ALL", index=True)
    payload_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)

    actor = db.relationship("User", foreign_keys=[actor_user_id])


class NotificationRecipient(db.Model):
    __tablename__ = "notification_recipient"
    __table_args__ = (
        UniqueConstraint("event_id", "user_id", name="uq_notification_recipient_event_user"),
        db.Index("ix_notification_recipient_user_read_at", "user_id", "read_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("activity_event.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    read_at = db.Column(db.DateTime, nullable=True, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

    event = db.relationship("ActivityEvent", backref=db.backref("recipients", lazy="dynamic"))
    user = db.relationship("User", foreign_keys=[user_id])


# ------- Bookings (legacy-ish but used) -------
# Standard Booking status values (string constants for consistency)
BOOKING_STATUS_PENDING = "pending"
BOOKING_STATUS_ACCEPTED = "accepted"
BOOKING_STATUS_QUOTED = "quoted"
BOOKING_STATUS_CONFIRMED = "confirmed"
BOOKING_STATUS_HOLD_PAID = "hold_paid"
BOOKING_STATUS_PAID = "paid"
BOOKING_STATUS_COMPLETED = "completed"
BOOKING_STATUS_CANCELLED = "cancelled"
BOOKING_STATUS_DECLINED = "declined"
BOOKING_STATUS_DISPUTED = "disputed"

# Dispute window (days after event time)
DISPUTE_OPEN_WINDOW_DAYS = 30
DISPUTE_STATUSES = {"open", "under_review", "resolved", "closed"}

# Valid booking statuses set
VALID_BOOKING_STATUSES = {
    BOOKING_STATUS_PENDING,
    BOOKING_STATUS_ACCEPTED,
    BOOKING_STATUS_QUOTED,
    BOOKING_STATUS_CONFIRMED,
    BOOKING_STATUS_HOLD_PAID,
    BOOKING_STATUS_PAID,
    BOOKING_STATUS_COMPLETED,
    BOOKING_STATUS_CANCELLED,
    BOOKING_STATUS_DECLINED,
    BOOKING_STATUS_DISPUTED,
}

class Booking(db.Model):
    __tablename__ = "booking"
    id = db.Column(db.Integer, primary_key=True)

    provider_id = db.Column("artist_id", db.Integer, db.ForeignKey("user.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    provider_role = db.Column(db.String(40), nullable=False)  # String for flexibility

    event_title = db.Column(db.String(160), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=True)
    location_text = db.Column(db.String(255), nullable=True)

    total_cents = db.Column(db.Integer, nullable=True)
    quoted_total_cents = db.Column(db.Integer, nullable=True)
    quote_hourly_rate_cents = db.Column(db.Integer, nullable=True)
    quote_billable_minutes = db.Column(db.Integer, nullable=True)
    quote_calculation_text = db.Column(db.Text, nullable=True)
    quote_breakdown_text = db.Column(db.Text, nullable=True)
    deposit_base_cents = db.Column(db.Integer, nullable=True)
    beatfund_fee_total_cents = db.Column(db.Integer, nullable=True)
    beatfund_fee_collected_cents = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=False, default=BOOKING_STATUS_PENDING)

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


# ------- Booking Dispute Messages -------
class BookingDisputeMessage(db.Model):
    __tablename__ = "booking_dispute_message"
    id = db.Column(db.Integer, primary_key=True)
    dispute_id = db.Column(db.Integer, db.ForeignKey("booking_dispute.id"), nullable=False, index=True)
    author_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    dispute = db.relationship("BookingDispute", backref=db.backref("messages", lazy="dynamic"))
    author = db.relationship("User", foreign_keys=[author_user_id])


# ------- Provider Reviews -------
class ReviewVisibility(str, enum.Enum):
    visible = "visible"
    hidden = "hidden"


class ProviderReview(db.Model):
    __tablename__ = "provider_review"
    __table_args__ = (
        UniqueConstraint("booking_id", name="uq_provider_review_booking_id"),
        db.Index("ix_provider_review_provider_user_id", "provider_user_id"),
        db.Index("ix_provider_review_reviewer_user_id", "reviewer_user_id"),
        db.Index("ix_provider_review_status", "status"),
        db.Index("ix_provider_review_created_at", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=False, unique=True, index=True)
    reviewer_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    provider_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    rating = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(160), nullable=True)
    body = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(ReviewVisibility), nullable=False, default=ReviewVisibility.visible, index=True)
    reported_count = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    booking = db.relationship("Booking", foreign_keys=[booking_id])
    reviewer = db.relationship("User", foreign_keys=[reviewer_user_id])
    provider = db.relationship("User", foreign_keys=[provider_user_id])


# Expose review visibility to templates
app.jinja_env.globals["ReviewVisibility"] = ReviewVisibility

# =========================================================
# Booking-Gated Internal Messenger (booking-scoped)
# =========================================================
class ConversationStatus(str, enum.Enum):
    active = "ACTIVE"
    closed = "CLOSED"
    flagged = "FLAGGED"


class MessageDeliveryStatus(str, enum.Enum):
    sent = "SENT"
    blocked = "BLOCKED"


class Conversation(db.Model):
    __tablename__ = "conversation"
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=False, unique=True, index=True)
    status = db.Column(db.Enum(ConversationStatus), nullable=False, default=ConversationStatus.active, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)
    last_message_at = db.Column(db.DateTime, nullable=True, index=True)

    booking = db.relationship("Booking", foreign_keys=[booking_id])


class ConversationParticipant(db.Model):
    __tablename__ = "conversation_participant"
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="uq_conversation_participant_conversation_user"),
        db.Index("ix_conversation_participant_conversation_user", "conversation_id", "user_id"),
    )
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    role_at_time = db.Column(db.String(40), nullable=True)
    is_blocked = db.Column(db.Boolean, nullable=False, default=False, index=True)
    blocked_at = db.Column(db.DateTime, nullable=True)

    conversation = db.relationship("Conversation", backref=db.backref("participants", lazy="dynamic"))
    user = db.relationship("User", foreign_keys=[user_id])


class Message(db.Model):
    __tablename__ = "message"
    __table_args__ = (
        db.Index("ix_message_conversation_created_at", "conversation_id", "created_at"),
        db.Index("ix_message_sender_window", "conversation_id", "sender_user_id", "created_at"),
    )
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False, index=True)
    sender_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)

    is_flagged = db.Column(db.Boolean, nullable=False, default=False, index=True)
    flagged_reason = db.Column(db.String(40), nullable=True)
    delivery_status = db.Column(db.Enum(MessageDeliveryStatus), nullable=False, default=MessageDeliveryStatus.sent, index=True)

    conversation = db.relationship("Conversation", backref=db.backref("messages", lazy="dynamic"))
    sender = db.relationship("User", foreign_keys=[sender_user_id])


class ModerationReason(str, enum.Enum):
    pii_card = "PII_CARD"
    pii_phone = "PII_PHONE"
    pii_email = "PII_EMAIL"
    profanity = "PROFANITY"
    threat = "THREAT"
    rate_limit = "RATE_LIMIT"
    blocked = "BLOCKED"
    report = "REPORT"


class MessageModerationLog(db.Model):
    __tablename__ = "message_moderation_log"
    __table_args__ = (
        db.Index("ix_moderation_log_conversation_created_at", "conversation_id", "created_at"),
    )
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversation.id"), nullable=False, index=True)
    sender_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    attempted_text = db.Column(db.Text, nullable=True)
    reason = db.Column(db.String(40), nullable=False, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)

    conversation = db.relationship("Conversation", foreign_keys=[conversation_id])
    sender = db.relationship("User", foreign_keys=[sender_user_id])


class BookingStatus(str, enum.Enum):
    pending = "pending"
    accepted = "accepted"
    confirmed = "confirmed"
    declined = "declined"
    cancelled = "cancelled"


class BookingRequest(db.Model):
    __tablename__ = "booking_request"

    id = db.Column(db.Integer, primary_key=True)

    provider_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    message = db.Column(db.Text, nullable=True)
    preferred_time = db.Column(db.String(120), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=True)

    status = db.Column(db.Enum(BookingStatus), nullable=False, default=BookingStatus.pending, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), index=True)

    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=True, unique=True, index=True)

    provider = db.relationship("User", foreign_keys=[provider_id])
    client = db.relationship("User", foreign_keys=[client_id])
    booking = db.relationship("Booking", foreign_keys=[booking_id])


# ------- Careers -------
class JobPost(db.Model):
    __tablename__ = "job_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(120), nullable=True)
    location = db.Column(db.String(120), nullable=True)
    employment_type = db.Column(db.String(80), nullable=True)
    level = db.Column(db.String(80), nullable=True)
    description = db.Column(db.Text, nullable=False)
    responsibilities = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=True)
    nice_to_have = db.Column(db.Text, nullable=True)
    how_to_apply = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    applications = db.relationship("JobApplication", backref="job", lazy="dynamic")


class JobApplication(db.Model):
    __tablename__ = "job_application"
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("job_post.id"), nullable=True, index=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    portfolio_url = db.Column(db.String(500), nullable=True)
    linkedin_url = db.Column(db.String(500), nullable=True)
    cover_letter = db.Column(db.Text, nullable=True)
    resume_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(32), nullable=False, default="new", index=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), index=True)


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
    partially_refunded = "partially_refunded"
    refunded = "refunded"


class PaymentPurpose(str, enum.Enum):
    bookme_hold = "bookme_hold"
    beat_purchase = "beat_purchase"
    booking_deposit = "booking_deposit"
    booking_balance = "booking_balance"


class PaymentKind(str, enum.Enum):
    deposit = "deposit"
    balance = "balance"


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    purpose = db.Column(db.Enum(PaymentPurpose), nullable=False)
    processor = db.Column(db.Enum(PaymentProcessor), nullable=False, default=PaymentProcessor.wallet)
    status = db.Column(db.Enum(PaymentStatus), nullable=False, default=PaymentStatus.created)
    kind = db.Column(db.Enum(PaymentKind), nullable=True)

    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(8), nullable=False, default="usd")

    base_amount_cents = db.Column(db.Integer, nullable=True)
    beatfund_fee_cents = db.Column(db.Integer, nullable=True)
    processing_fee_cents = db.Column(db.Integer, nullable=True)
    total_paid_cents = db.Column(db.Integer, nullable=True)
    refunded_base_cents = db.Column(db.Integer, nullable=False, default=0)
    nonrefundable_processing_kept_cents = db.Column(db.Integer, nullable=False, default=0)
    nonrefundable_beatfund_kept_cents = db.Column(db.Integer, nullable=False, default=0)

    idempotency_key = db.Column(db.String(120), nullable=False, unique=True)
    external_id = db.Column(db.String(120), nullable=True, unique=True)

    booking_request_id = db.Column(db.Integer, db.ForeignKey("booking_request.id"), nullable=True, unique=True)
    booking_request = db.relationship("BookingRequest", foreign_keys=[booking_request_id])
    booking_id = db.Column(db.Integer, db.ForeignKey("booking.id"), nullable=True, index=True)
    booking = db.relationship("Booking", foreign_keys=[booking_id])

    stripe_payment_intent_id = db.Column(db.String(255), nullable=True, index=True)
    stripe_charge_id = db.Column(db.String(255), nullable=True, index=True)

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


# ------- Provider Availability (all roles) -------
class ProviderSettings(db.Model):
    __tablename__ = "provider_settings"
    id = db.Column(db.Integer, primary_key=True)
    provider_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True, index=True)

    accepting_new_requests = db.Column(db.Boolean, nullable=False, default=True)
    onsite = db.Column(db.Boolean, nullable=False, default=True)
    remote = db.Column(db.Boolean, nullable=False, default=True)
    travel_radius_miles = db.Column(db.Integer, nullable=True)
    base_location = db.Column(db.String(255), nullable=True)
    tz = db.Column(db.String(64), nullable=False, default="UTC")

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    provider = db.relationship("User", foreign_keys=[provider_user_id])


class ProviderAvailability(db.Model):
    __tablename__ = "provider_availability"
    id = db.Column(db.Integer, primary_key=True)
    provider_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    day_of_week = db.Column(db.Integer, nullable=False, index=True)  # 0=Mon .. 6=Sun
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    tz = db.Column(db.String(64), nullable=False, default="UTC")
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    provider = db.relationship("User", foreign_keys=[provider_user_id])


class ProviderAvailabilityException(db.Model):
    __tablename__ = "provider_availability_exception"
    id = db.Column(db.Integer, primary_key=True)
    provider_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    date = db.Column(db.Date, nullable=False, index=True)
    start_time = db.Column(db.Time, nullable=True)
    end_time = db.Column(db.Time, nullable=True)
    is_unavailable = db.Column(db.Boolean, nullable=False, default=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    provider = db.relationship("User", foreign_keys=[provider_user_id])


# ------- Audit Log -------
class AuditLog(db.Model):
    __tablename__ = "audit_log"
    __table_args__ = (
        # Composite index for common admin lookups
        db.Index("ix_audit_log_target_type_target_id", "target_type", "target_id"),
    )
    id = db.Column(db.Integer, primary_key=True)
    # Legacy: admin_id is required in existing DB schema. For system/webhook events,
    # we will populate this with a designated "system admin" user id.
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # New production audit fields (append-only, migration-ready)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    actor_role = db.Column(db.String(40), nullable=True)
    action_type = db.Column(db.String(80), nullable=True, index=True)  # enum-like string
    target_type = db.Column(db.String(60), nullable=True, index=True)
    target_id = db.Column(db.String(64), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(220), nullable=True)
    before_json = db.Column(db.Text, nullable=True)
    after_json = db.Column(db.Text, nullable=True)
    metadata_json = db.Column(db.Text, nullable=True)

    admin = db.relationship("User", foreign_keys=[admin_id], backref="audit_actions")
    user = db.relationship("User", foreign_keys=[user_id])
    actor_user = db.relationship("User", foreign_keys=[actor_user_id])


# ------- Stripe Webhook Events (idempotency + replay protection) -------
class StripeWebhookEventStatus(str, enum.Enum):
    received = "RECEIVED"
    processing = "PROCESSING"
    processed = "PROCESSED"
    failed = "FAILED"


class StripeWebhookEvent(db.Model):
    __tablename__ = "stripe_webhook_event"
    id = db.Column(db.Integer, primary_key=True)
    stripe_event_id = db.Column(db.String(80), nullable=False, unique=True, index=True)
    type = db.Column(db.String(120), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=True)  # Stripe event created timestamp (converted)
    received_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    processed_at = db.Column(db.DateTime, nullable=True, index=True)
    # Store status as a string for safe rollout without DB enum migrations.
    status = db.Column(db.String(20), nullable=False, default=StripeWebhookEventStatus.received.value, index=True)
    last_error = db.Column(db.String(500), nullable=True)
    payload_json = db.Column(db.Text, nullable=True)


# ------- Alerts (rules-based monitoring) -------
class AlertSeverity(str, enum.Enum):
    low = "LOW"
    med = "MED"
    high = "HIGH"


class Alert(db.Model):
    __tablename__ = "alert"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = db.Column(db.Enum(AlertSeverity), nullable=False, default=AlertSeverity.low, index=True)
    type = db.Column(db.String(80), nullable=False, index=True)
    message = db.Column(db.String(240), nullable=False)
    metadata_json = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True, index=True)


class SecurityEvent(db.Model):
    __tablename__ = "security_event"
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="info", index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(240), nullable=True)
    path = db.Column(db.String(200), nullable=True)
    request_id = db.Column(db.String(40), nullable=True, index=True)
    meta_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = db.relationship("User", foreign_keys=[user_id])


# ------- Uploaded Files (storage + scanning) -------
class ScanStatus(str, enum.Enum):
    pending = "PENDING"
    clean = "CLEAN"
    infected = "INFECTED"
    failed = "FAILED"


class UploadedFilePurpose(str, enum.Enum):
    beat_cover = "BEAT_COVER"
    beat_preview = "BEAT_PREVIEW"
    beat_deliverable = "BEAT_DELIVERABLE"
    beat_stems = "BEAT_STEMS"
    bookme_portfolio = "BOOKME_PORTFOLIO"
    other = "OTHER"


class UploadedFile(db.Model):
    __tablename__ = "uploaded_file"
    id = db.Column(db.Integer, primary_key=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    purpose = db.Column(db.Enum(UploadedFilePurpose), nullable=False, default=UploadedFilePurpose.other, index=True)
    storage_provider = db.Column(db.String(20), nullable=False, default="local", index=True)  # local|s3
    key = db.Column(db.String(500), nullable=False, index=True)  # local path or S3 key
    original_filename = db.Column(db.String(255), nullable=True)
    content_type = db.Column(db.String(120), nullable=True)
    size = db.Column(db.Integer, nullable=True)
    etag = db.Column(db.String(120), nullable=True)
    scan_status = db.Column(db.Enum(ScanStatus), nullable=False, default=ScanStatus.pending, index=True)
    scan_message = db.Column(db.String(400), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    owner = db.relationship("User", foreign_keys=[owner_user_id])


def get_uploaded_file_by_key(key: str) -> UploadedFile | None:
    """Lookup the most recent UploadedFile row for a storage key."""
    if not key:
        return None
    try:
        return UploadedFile.query.filter_by(key=key).order_by(UploadedFile.id.desc()).first()
    except Exception:
        return None


def can_access_uploaded_file(uf: UploadedFile | None, user: "User | None") -> bool:
    """
    Authorization gate for uploaded files.
    - Admin can access all.
    - Owner can access own files.
    - Beat covers/previews are public if the associated Beat is active.
    - Beat deliverables (stems) require owner or paid purchaser.
    - BookMe portfolio files are accessible to authenticated users only if linked to a PortfolioItem.
    - Everything else: deny (explicit allowlist).
    """
    if not uf:
        return False

    try:
        if user and getattr(user, "is_authenticated", False) and getattr(user, "role", None) == RoleEnum.admin:
            return True
    except Exception:
        pass

    try:
        if user and getattr(user, "is_authenticated", False) and uf.owner_user_id and int(uf.owner_user_id) == int(user.id):
            return True
    except Exception:
        pass

    # Beat assets: authorize by DB mapping (covers/previews may be public; stems require ownership/purchase).
    beat = Beat.query.filter(
        or_(
            Beat.cover_path == uf.key,
            Beat.preview_path == uf.key,
            Beat.stems_path == uf.key,
            Beat.audio_preview_key == uf.key,
            Beat.audio_original_key == uf.key,
            Beat.audio_deliverable_key == uf.key,
            Beat.stems_key == uf.key,
        )
    ).first()
    if beat:
        # Stems/deliverables: private
        if uf.key in {
            beat.stems_path,
            beat.audio_original_key,
            beat.audio_deliverable_key,
            beat.stems_key,
        }:
            if not (user and getattr(user, "is_authenticated", False)):
                return False
            return bool(beat.owner_id == user.id or _user_has_paid_for_beat(user.id, beat.id))
        # Covers/previews: allow if beat is active/visible (and preview ready for audio)
        if uf.key in {beat.preview_path, beat.audio_preview_key}:
            status = (beat.preview_status or "ready").lower()
            return bool(beat.is_active and status == "ready")
        return bool(beat.is_active)

    # BookMe portfolio: allow authenticated users if linked to an actual portfolio item.
    if not (user and getattr(user, "is_authenticated", False)):
        return False
    if PortfolioItem.query.filter_by(stored_filename=uf.key).first() is not None:
        return True

    return False


def _download_name_for_beat(beat: Beat | None, key: str | None) -> str:
    ext = "mp3"
    if key and "." in key:
        ext = key.rsplit(".", 1)[-1].lower()
    base = None
    try:
        base = secure_filename((beat.title or "").strip()) if beat else None
    except Exception:
        base = None
    if not base:
        base = f"beat_{getattr(beat, 'id', 'download')}"
    return f"{base}.{ext}"


def _s3_object_key(filename: str) -> str:
    return f"{S3_PREFIX}/{filename}" if S3_PREFIX else filename


def _serve_local_file(local_path: str, *, as_attachment: bool = False, download_name: str | None = None) -> Response:
    if not os.path.exists(local_path):
        abort(404)
    ext = local_path.rsplit(".", 1)[-1].lower() if "." in local_path else ""
    mime_type, _ = mimetypes.guess_type(local_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    range_header = request.headers.get("Range")
    if range_header and ext in ALLOWED_AUDIO:
        size = os.path.getsize(local_path)
        match = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else size - 1
            end = min(end, size - 1)
            if start > end:
                start = 0
                end = size - 1
            length = end - start + 1
            with open(local_path, "rb") as fh:
                fh.seek(start)
                data = fh.read(length)
            resp = Response(data, status=206, mimetype=mime_type, direct_passthrough=True)
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Content-Length"] = str(length)
            if as_attachment:
                resp.headers["Content-Disposition"] = f'attachment; filename="{download_name or os.path.basename(local_path)}"'
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp

    resp = send_file(local_path, as_attachment=as_attachment, download_name=download_name, mimetype=mime_type)
    if ext in ALLOWED_AUDIO:
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _serve_s3_file(filename: str, *, as_attachment: bool = False, download_name: str | None = None) -> Response:
    if not S3_BUCKET_NAME:
        abort(404)
    key = _s3_object_key(filename)
    range_header = request.headers.get("Range")
    try:
        kwargs = {"Bucket": S3_BUCKET_NAME, "Key": key}
        if range_header:
            kwargs["Range"] = range_header
        obj = (S3_CLIENT or getattr(storage_backend, "s3_client", None)).get_object(**kwargs)
    except Exception:
        abort(404)

    content_type = obj.get("ContentType") or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    body = obj.get("Body")
    if range_header and obj.get("ContentRange"):
        data = body.read() if body else b""
        resp = Response(data, status=206, mimetype=content_type, direct_passthrough=True)
        resp.headers["Content-Range"] = obj.get("ContentRange")
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Length"] = str(obj.get("ContentLength") or len(data))
    else:
        if body and hasattr(body, "iter_chunks"):
            resp = Response(stream_with_context(body.iter_chunks(chunk_size=8192)), mimetype=content_type)
            resp.headers["Content-Length"] = str(obj.get("ContentLength") or "")
        else:
            data = body.read() if body else b""
            resp = Response(data, mimetype=content_type)
            resp.headers["Content-Length"] = str(len(data))
        resp.headers["Accept-Ranges"] = "bytes"

    if as_attachment:
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_name or os.path.basename(filename)}"'
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _alert_create(severity: AlertSeverity | str, type: str, message: str, metadata: dict | None = None) -> int:
    """Create an alert for admin review (best-effort)."""
    try:
        sev = severity if isinstance(severity, AlertSeverity) else AlertSeverity(str(severity).upper())
    except Exception:
        sev = AlertSeverity.low
    a = Alert(
        severity=sev,
        type=(type or "GENERAL")[:80],
        message=(message or "")[:240],
        metadata_json=_safe_json_dumps(metadata or {}),
    )
    db.session.add(a)
    db.session.commit()
    return int(a.id)


def _get_request_context() -> dict:
    try:
        return {
            "ip": (request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:64],
            "ua": (request.headers.get("User-Agent") or "")[:220],
        }
    except Exception:
        return {"ip": None, "ua": None}


def _system_audit_admin_id() -> int | None:
    """
    audit_log table currently requires admin_id (legacy). For system/webhook events,
    use a designated admin id (env) or fallback to the first admin user.
    """
    raw = (os.getenv("SYSTEM_AUDIT_ADMIN_ID") or "").strip()
    if raw:
        try:
            return int(raw)
        except Exception:
            pass
    try:
        u = User.query.filter_by(role=RoleEnum.admin).order_by(User.id.asc()).first()
        return int(u.id) if u else None
    except Exception:
        return None


def audit_log_event(
    *,
    action_type: str,
    actor_user: User | None,
    target_type: str | None,
    target_id: str | int | None,
    reason: str,
    before: dict | None = None,
    after: dict | None = None,
    metadata: dict | None = None,
    commit: bool = True,
) -> int:
    """
    Append-only audit event.
    NOTE: legacy schema requires admin_id. We still populate admin_id for system events.
    """
    # Enforce non-empty reasons for admin-authored finance/security actions.
    try:
        if actor_user and getattr(actor_user, "role", None) == RoleEnum.admin and not (reason or "").strip():
            raise ValueError("audit_reason_required")
    except Exception:
        # If anything goes wrong, fail closed for admin-authored audit events.
        if actor_user and getattr(actor_user, "role", None) == RoleEnum.admin:
            raise

    ctx = _get_request_context()
    actor_id = getattr(actor_user, "id", None) if actor_user else None
    actor_role = None
    try:
        actor_role = actor_user.role if actor_user and getattr(actor_user, "role", None) else ("system" if actor_user is None else None)
    except Exception:
        actor_role = "system" if actor_user is None else None

    admin_id = None
    if actor_user and getattr(actor_user, "role", None) == RoleEnum.admin:
        admin_id = int(actor_user.id)
    else:
        admin_id = _system_audit_admin_id()

    if not admin_id:
        # Cannot write to legacy audit_log without admin_id
        return 0

    row = AuditLog(
        admin_id=admin_id,
        user_id=None,
        action=(action_type or "AUDIT")[:80],
        reason=(reason or "").strip(),
        actor_user_id=int(actor_id) if actor_id else None,
        actor_role=(actor_role or "")[:40] if actor_role else None,
        action_type=(action_type or "")[:80] if action_type else None,
        target_type=(target_type or "")[:60] if target_type else None,
        target_id=(str(target_id)[:64] if target_id is not None else None),
        ip_address=ctx.get("ip"),
        user_agent=ctx.get("ua"),
        before_json=_safe_json_dumps(before or {}) if before is not None else None,
        after_json=_safe_json_dumps(after or {}) if after is not None else None,
        metadata_json=_safe_json_dumps(metadata or {}) if metadata is not None else None,
    )
    db.session.add(row)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return int(row.id)


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


class SupportTicketMessage(db.Model):
    __tablename__ = "support_ticket_message"
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_ticket.id"), nullable=False, index=True)
    author_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    ticket = db.relationship("SupportTicket", backref=db.backref("messages", lazy="dynamic"))
    author = db.relationship("User", foreign_keys=[author_user_id])


app.jinja_env.globals["TicketStatus"] = TicketStatus
app.jinja_env.globals["TicketType"] = TicketType


# =========================================================
# Social Media Manager Models
# =========================================================
class SMMClient(db.Model):
    __tablename__ = "smm_client"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_name = db.Column(db.String(200), nullable=False)
    client_email = db.Column(db.String(255), nullable=True)
    client_phone = db.Column(db.String(40), nullable=True)
    platforms = db.Column(db.String(500), nullable=True)  # JSON: ["instagram", "twitter", "tiktok"]
    notes = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_clients", lazy="dynamic"))


class SMMPostStatus(str, enum.Enum):
    draft = "draft"
    scheduled = "scheduled"
    pending_approval = "pending_approval"
    approved = "approved"
    changes_requested = "changes_requested"
    published = "published"
    cancelled = "cancelled"


class SMMPost(db.Model):
    __tablename__ = "smm_post"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=True, index=True)
    
    platform = db.Column(db.String(50), nullable=False)  # instagram, twitter, tiktok, etc.
    content = db.Column(db.Text, nullable=False)
    scheduled_datetime = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.Enum(SMMPostStatus), nullable=False, default=SMMPostStatus.draft)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = db.Column(db.DateTime, nullable=True)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_posts", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("posts", lazy="dynamic"))


class SMMAsset(db.Model):
    __tablename__ = "smm_asset"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=True, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey("smm_post.id"), nullable=True, index=True)
    
    asset_type = db.Column(db.String(50), nullable=False)  # image, video, link
    stored_filename = db.Column(db.String(255), nullable=True)
    external_url = db.Column(db.String(500), nullable=True)
    title = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_assets", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("assets", lazy="dynamic"))
    post = db.relationship("SMMPost", backref=db.backref("assets", lazy="dynamic"))


class SMMApproval(db.Model):
    __tablename__ = "smm_approval"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("smm_post.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=False, index=True)
    
    status = db.Column(db.String(50), nullable=False, default="pending")  # pending, approved, changes_requested
    feedback = db.Column(db.Text, nullable=True)
    requested_changes = db.Column(db.Text, nullable=True)
    
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    post = db.relationship("SMMPost", backref=db.backref("approvals", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("approvals", lazy="dynamic"))


class SMMAnalytics(db.Model):
    __tablename__ = "smm_analytics"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=False, index=True)
    platform = db.Column(db.String(50), nullable=False)
    
    period_start = db.Column(db.Date, nullable=False)
    period_end = db.Column(db.Date, nullable=False)
    
    followers = db.Column(db.Integer, nullable=True, default=0)
    reach = db.Column(db.Integer, nullable=True, default=0)
    engagement = db.Column(db.Integer, nullable=True, default=0)
    impressions = db.Column(db.Integer, nullable=True, default=0)
    likes = db.Column(db.Integer, nullable=True, default=0)
    comments = db.Column(db.Integer, nullable=True, default=0)
    shares = db.Column(db.Integer, nullable=True, default=0)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_analytics", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("analytics", lazy="dynamic"))


class SMMCalendarItem(db.Model):
    __tablename__ = "smm_calendar_item"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=True, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey("smm_post.id"), nullable=True, index=True)
    
    scheduled_date = db.Column(db.Date, nullable=False, index=True)
    scheduled_time = db.Column(db.Time, nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    platform = db.Column(db.String(50), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_calendar_items", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("calendar_items", lazy="dynamic"))
    post = db.relationship("SMMPost", backref=db.backref("calendar_items", lazy="dynamic"))


class SMMAvailability(db.Model):
    __tablename__ = "smm_availability"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    
    day_of_week = db.Column(db.Integer, nullable=False)  # 0=Monday, 6=Sunday
    start_time = db.Column(db.Time, nullable=True)
    end_time = db.Column(db.Time, nullable=True)
    is_available = db.Column(db.Boolean, nullable=False, default=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_availability", lazy="dynamic"))


class SMMReview(db.Model):
    __tablename__ = "smm_review"
    id = db.Column(db.Integer, primary_key=True)
    smm_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey("smm_client.id"), nullable=False, index=True)
    
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    comment = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    smm = db.relationship("User", foreign_keys=[smm_id], backref=db.backref("smm_reviews", lazy="dynamic"))
    client = db.relationship("SMMClient", backref=db.backref("reviews", lazy="dynamic"))


app.jinja_env.globals["SMMPostStatus"] = SMMPostStatus


# =========================================================
# Project Vault Models
# =========================================================
class ProjectVault(db.Model):
    __tablename__ = "project_vault"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    target_cents = db.Column(db.Integer, nullable=False)  # Target amount in cents
    current_balance_cents = db.Column(db.Integer, nullable=False, default=0)
    
    # Auto-funding settings
    auto_fund_enabled = db.Column(db.Boolean, nullable=False, default=False)
    auto_fund_percent = db.Column(db.Integer, nullable=True)  # Percentage of incoming funds (0-100)
    auto_fund_min_cents = db.Column(db.Integer, nullable=True)  # Minimum amount before auto-funding
    auto_fund_frequency = db.Column(db.String(50), nullable=True)  # daily, weekly, monthly, on_income
    
    # Lock settings
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    lock_until_date = db.Column(db.DateTime, nullable=True)  # Lock until specific date
    lock_until_goal = db.Column(db.Boolean, nullable=False, default=False)  # Lock until goal reached
    
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_completed = db.Column(db.Boolean, nullable=False, default=False)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship("User", backref=db.backref("project_vaults", lazy="dynamic"))
    
    @property
    def target_dollars(self):
        return self.target_cents / 100.0
    
    @property
    def current_balance_dollars(self):
        return self.current_balance_cents / 100.0
    
    @property
    def progress_percent(self):
        if self.target_cents == 0:
            return 0
        return min(100, (self.current_balance_cents / self.target_cents) * 100)
    
    @property
    def remaining_cents(self):
        return max(0, self.target_cents - self.current_balance_cents)
    
    @property
    def remaining_dollars(self):
        return self.remaining_cents / 100.0
    
    def is_locked_now(self) -> tuple[bool, bool]:
        """
        Check if vault is currently locked. Returns (is_locked, should_auto_unlock).
        Side-effect free - does not modify database.
        """
        if not self.is_locked:
            return False, False
        
        should_unlock = False
        
        # Check date-based lock
        if self.lock_until_date:
            if datetime.utcnow() < self.lock_until_date:
                return True, False
            else:
                # Date passed - should auto-unlock
                should_unlock = True
                return False, True
        
        # Check goal-based lock
        if self.lock_until_goal:
            if not self.is_completed:
                return True, False
            else:
                # Goal reached - should auto-unlock
                should_unlock = True
                return False, True
        
        return False, False
    
    def check_and_auto_unlock(self) -> bool:
        """Check lock status and auto-unlock if needed. Call at route level with transaction."""
        is_locked, should_unlock = self.is_locked_now()
        if should_unlock:
            self.is_locked = False
            if self.lock_until_date:
                self.lock_until_date = None
            if self.lock_until_goal:
                self.lock_until_goal = False
            return True
        return False


class VaultTransaction(db.Model):
    __tablename__ = "vault_transaction"
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey("project_vault.id"), nullable=False, index=True)
    
    amount_cents = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # manual, auto_fund, withdrawal
    source = db.Column(db.String(100), nullable=True)  # wallet, external, etc.
    notes = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    vault = db.relationship("ProjectVault", backref=db.backref("transactions", lazy="dynamic"))


# =========================================================
# Waitlist
# =========================================================
class WaitlistEntry(db.Model):
    __tablename__ = "waitlist_entry"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    full_name = db.Column(db.String(150), nullable=True)
    role_interest = db.Column(db.String(80), nullable=True)  # artist, producer, studio, funder, etc.
    note = db.Column(db.String(300), nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False, index=True)


# =========================================================
# One-time DB Bootstrap (AFTER all models are defined)
# =========================================================
# This must run AFTER all model classes are defined so they're in db.metadata

# Clean up missing avatar paths on startup (handles file loss after deploys)
def _cleanup_missing_avatars():
    """Remove avatar_path from database if files don't exist (e.g., after deploy with local storage)"""
    if STORAGE_BACKEND != "local":
        return  # Only relevant for local storage
    
    try:
        with app.app_context():
            missing_count = 0
            users_with_avatars = User.query.filter(User.avatar_path != None).all()
            for user in users_with_avatars:
                avatar_path = os.path.join(app.config["UPLOAD_FOLDER"], user.avatar_path)
                if not os.path.exists(avatar_path):
                    user.avatar_path = None
                    missing_count += 1
            
            if missing_count > 0:
                db.session.commit()
                app.logger.info(f"Cleaned up {missing_count} missing avatar paths on startup")
    except Exception as e:
        app.logger.warning(f"Could not cleanup missing avatars: {e}")


def _migrate_role_enum_to_string():
    """Migrate role and kyc_status columns from ENUM to STRING if PostgreSQL."""
    try:
        with app.app_context():
            is_postgres = db.engine.url.get_backend_name() == "postgresql"
            if not is_postgres:
                return

            with db.engine.begin() as conn:
                # Check if we need to migrate (role column is still ENUM)
                result = conn.execute(text("""
                    SELECT data_type, udt_name
                    FROM information_schema.columns 
                    WHERE table_name = 'user' AND column_name = 'role'
                """))
                row = result.first()
                if row:
                    data_type = str(row[0] or "").lower()
                    udt_name = str(row[1] or "").lower()
                    is_enum = (data_type == "user-defined") or ("enum" in data_type) or ("roleenum" in udt_name)
                    if is_enum:
                        app.logger.info(
                            f"Migrating role column from ENUM to VARCHAR (data_type={data_type}, udt_name={udt_name})..."
                        )
                        # Convert ENUM to varchar explicitly via USING to avoid datatype mismatch
                        conn.execute(text(
                            "ALTER TABLE \"user\" ALTER COLUMN role TYPE varchar(40) USING role::text"
                        ))
                        conn.execute(text(
                            "ALTER TABLE booking ALTER COLUMN provider_role TYPE varchar(40) USING provider_role::text"
                        ))
                        conn.execute(text(
                            "ALTER TABLE \"user\" ALTER COLUMN kyc_status TYPE varchar(40) USING kyc_status::text"
                        ))
                        app.logger.info("Successfully migrated role columns to VARCHAR")
    except Exception as e:
        app.logger.warning(f"Could not migrate ENUM to VARCHAR: {type(e).__name__}: {str(e)}")

_cleanup_missing_avatars()
_migrate_role_enum_to_string()

if os.getenv("BOOTSTRAP_DB") == "1":
    with app.app_context():
        try:
            # Use engine.begin() which properly supports context manager
            # This ensures DDL statements are committed
            with db.engine.begin() as conn:
                db.metadata.create_all(bind=conn)
                app.logger.info("All table DDL statements executed")
            
            print("[OK] BOOTSTRAP_DB=1 -> db.create_all() completed")
            app.logger.info("Database tables creation attempted")
            
            # Verification: count tables created
            from time import sleep as time_sleep
            time_sleep(0.5)
            
            try:
                with db.engine.begin() as conn:
                    result = conn.execute(text("""
                        SELECT COUNT(*) as table_count
                        FROM information_schema.tables 
                        WHERE table_schema = 'public'
                    """))
                    count = result.scalar()
                    app.logger.info(f"✓ Database has {count} tables created")
                    
                    if count > 0:
                        # List the tables
                        result2 = conn.execute(text("""
                            SELECT string_agg(table_name, ', ' ORDER BY table_name)
                            FROM information_schema.tables 
                            WHERE table_schema = 'public'
                        """))
                        tables = result2.scalar()
                        app.logger.info(f"Tables: {tables}")
                    
            except Exception as verify_err:
                app.logger.warning(f"Could not verify tables: {verify_err}")
                
        except Exception as bootstrap_err:
            print(f"[ERROR] BOOTSTRAP_DB=1 failed: {bootstrap_err}")
            app.logger.error(f"Database bootstrap failed: {bootstrap_err}", exc_info=True)


# Roles that can use project vaults
VAULT_ELIGIBLE_ROLES: set[RoleEnum] = {
    RoleEnum.artist,
    RoleEnum.producer,
    RoleEnum.studio,
    RoleEnum.videographer,
    RoleEnum.designer,
    RoleEnum.engineer,
    RoleEnum.photographer,
    RoleEnum.event_planner,
    RoleEnum.dj,
    RoleEnum.live_sound_engineer,
    RoleEnum.mix_master_engineer,
    RoleEnum.lighting_designer,
    RoleEnum.stage_set_designer,
    RoleEnum.brand_pr_consultant,
    RoleEnum.social_media_manager,
}

def is_vault_eligible(user: User) -> bool:
    """Check if user's role is eligible for project vaults"""
    if not user or not user.role:
        return False
    return user.role in VAULT_ELIGIBLE_ROLES


# =========================================================
# Login loader & helpers
# =========================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def is_password_expired(user: User) -> bool:
    if user.role != "admin":
        return False
    if not user.password_changed_at:
        return True
    return (datetime.utcnow() - user.password_changed_at) > timedelta(days=PASSWORD_MAX_AGE_DAYS)


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                try:
                    log_security_event(
                        "unauthorized_access",
                        f"Role '{current_user.role}' attempted to access {request.path}",
                        "warning",
                        meta={"required_roles": list(roles)},
                    )
                except Exception:
                    pass
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
            try:
                log_security_event(
                    "unauthorized_access",
                    f"Superadmin access denied for {request.path}",
                    "warning",
                    meta={"user_id": getattr(current_user, "id", None)},
                )
            except Exception:
                pass
            flash("You don't have permission to do that.", "error")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return wrapper


def _is_kyc_verified(user: User | None) -> bool:
    if not user:
        return False
    try:
        return str(getattr(user, "kyc_status", "")).lower() == KYCStatus.approved.value
    except Exception:
        return False


def require_kyc_approved(action: str = "payout") -> bool:
    """
    Enforce KYC only when configured and only for provider payout actions.
    action: "payout" enforces for service providers; any other value is non-blocking.
    """
    if not KYC_ENFORCE:
        return True
    if not current_user.is_authenticated:
        return False
    if action == "payout" and not is_service_provider(current_user):
        return True
    if _is_kyc_verified(current_user):
        return True
    flash("Complete KYC to enable payouts and money-moving actions.", "warning")
    return False


def get_or_create_wallet(user_id: int, *, commit: bool = True, lock: bool = False) -> Wallet:
    """
    Get or create a wallet for a user.
    
    Args:
        user_id: User ID
        commit: Whether to commit the transaction (if creating)
        lock: If True and on Postgres, use SELECT ... FOR UPDATE for row-level locking
    """
    query = Wallet.query.filter_by(user_id=user_id)
    
    # Add row-level locking on Postgres if requested
    if lock and db.engine.dialect.name == "postgresql":
        query = query.with_for_update()
    
    w = query.first()
    if not w:
        w = Wallet(user_id=user_id)
        db.session.add(w)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
    return w


def wallet_balance_cents(wallet: Wallet) -> int:
    """Calculate wallet balance using SQL aggregation for performance"""
    # Credits: deposit, external_payment, transfer_in, interest, adjustment, sale_income
    credits = db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)).filter(
        LedgerEntry.wallet_id == wallet.id,
        LedgerEntry.entry_type.in_([
            EntryType.deposit,
            EntryType.external_payment,
            EntryType.transfer_in,
            EntryType.interest,
            EntryType.adjustment,
            EntryType.sale_income,
        ])
    ).scalar() or 0
    
    # Debits: withdrawal, transfer_out, purchase_spend
    debits = db.session.query(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)).filter(
        LedgerEntry.wallet_id == wallet.id,
        LedgerEntry.entry_type.in_([
            EntryType.withdrawal,
            EntryType.transfer_out,
            EntryType.purchase_spend,
        ])
    ).scalar() or 0
    
    return int(credits - debits)


def cents_to_dollars(cents: int) -> float:
    """Convert cents to dollars"""
    return cents / 100.0


def format_cents_dollars(cents: int) -> str:
    """Format cents as dollar string with 2 decimal places"""
    return f"{cents / 100.0:.2f}"


def clamp_cents(x: int, lo: int, hi: int) -> int:
    """Clamp x between lo and hi (inclusive)"""
    return max(lo, min(x, hi))


def calc_beat_platform_fee_cents(subtotal_cents: int) -> int:
    """
    Calculate platform fee for beat purchase (percentage of total).
    """
    if subtotal_cents <= 0:
        return 0
    fee = (Decimal(subtotal_cents) * STRIPE_PLATFORM_FEE_PCT).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    fee_cents = int(fee)
    return min(fee_cents, subtotal_cents)


def calc_service_platform_fee_cents(subtotal_cents: int, provider_role: RoleEnum | str) -> int:
    """
    Calculate platform fee for service booking based on provider role.
    Uses tiered fee structure from SERVICE_FEE_RULES, falls back to DEFAULT_SERVICE_FEE_RULE.
    """
    if subtotal_cents <= 0:
        return 0
    
    # Convert string role to RoleEnum if needed
    if isinstance(provider_role, str):
        try:
            provider_role = RoleEnum(provider_role)
        except ValueError:
            provider_role = None
    
    # Get fee rule for this role, or use default
    rule = SERVICE_FEE_RULES.get(provider_role) if provider_role else None
    if not rule:
        rule = DEFAULT_SERVICE_FEE_RULE
    
    # Calculate fee: rate * subtotal, rounded to nearest cent
    fee_cents = round(Decimal(subtotal_cents) * rule["rate"])
    
    # Apply min/max constraints
    fee_cents = clamp_cents(fee_cents, rule["min"], rule["max"])
    
    # Safety check: fee cannot exceed subtotal
    fee_cents = min(fee_cents, subtotal_cents)
    
    return fee_cents


def calc_beatfund_fee_cents(service_cents: int) -> int:
    """
    BeatFund service fee percentage for bookings (hold fee handled separately).
    """
    if service_cents <= 0:
        return 0
    fee = (Decimal(service_cents) * STRIPE_PLATFORM_FEE_PCT).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    fee_cents = int(fee)
    fee_cents = min(fee_cents, service_cents)
    return fee_cents


def calc_beatfund_fee_total(service_total_cents: int) -> int:
    """Booking BeatFund fee total: hold fee + percentage fee (capped to total)."""
    if service_total_cents <= 0:
        return 0
    pct_fee_cents = calc_beatfund_fee_cents(service_total_cents)
    total_fee = HOLD_FEE_CENTS + pct_fee_cents
    return min(total_fee, service_total_cents)


def calc_total_and_processing(base_cents: int, beatfund_fee_cents: int) -> tuple[int, int]:
    """
    Compute total charge and processing fee so that after Stripe fees:
    base + beatfund_fee remain. Uses ceil on total.
    """
    if base_cents < 0 or beatfund_fee_cents < 0:
        raise ValueError("Amounts must be non-negative")
    gross = Decimal(base_cents + beatfund_fee_cents + STRIPE_PROC_FIXED_CENTS)
    denom = Decimal("1") - STRIPE_PROC_RATE
    if denom <= 0:
        raise ValueError("Invalid Stripe processing rate")
    total_cents = int((gross / denom).to_integral_value(rounding=ROUND_UP))
    processing_cents = total_cents - (base_cents + beatfund_fee_cents)
    return total_cents, processing_cents


def allocate_fee_between_deposit_and_balance(beatfund_fee_total_cents: int) -> tuple[int, int]:
    """Collect minimum fee on deposit, remainder on balance."""
    fee_deposit = min(beatfund_fee_total_cents, BEATFUND_FEE_MIN_CENTS)
    fee_balance = max(0, beatfund_fee_total_cents - fee_deposit)
    return fee_deposit, fee_balance


def estimate_processing_fee_cents(amount_cents: int, method: str = "card") -> int:
    """Estimate payment processing fee. Returns 0 for now since Stripe is not enabled yet."""
    return 0  # Stripe not enabled yet


def fee_breakdown_for_beat(subtotal_cents: int) -> dict:
    """
    Calculate complete fee breakdown for beat purchase.
    Returns dict with: subtotal_cents, platform_fee_cents, processing_fee_cents, total_cents
    """
    platform_fee_cents = calc_beat_platform_fee_cents(subtotal_cents)
    processing_fee_cents = estimate_processing_fee_cents(subtotal_cents)
    total_cents = subtotal_cents
    
    return {
        "subtotal_cents": subtotal_cents,
        "platform_fee_cents": platform_fee_cents,
        "processing_fee_cents": processing_fee_cents,
        "total_cents": total_cents,
    }


def planned_platform_fee_cents(order_type: OrderType, total_cents: int) -> int:
    """Compute total platform fee planned for an order (cap at total)."""
    if total_cents <= 0:
        return 0
    pct_fee = calc_beatfund_fee_cents(total_cents)
    if order_type == OrderType.booking:
        return min(total_cents, HOLD_FEE_CENTS + pct_fee)
    return min(total_cents, pct_fee)


def ledger_sum_platform_fees(order_id: int) -> int:
    """Sum platform fees collected so far for an order (succeeded only)."""
    try:
        rows = PaymentLedger.query.filter_by(
            order_id=order_id,
            status=PaymentLedgerStatus.succeeded,
        ).all()
        return sum(int(r.platform_fee_collected_cents or 0) for r in rows)
    except (ProgrammingError, OperationalError):
        db.session.rollback()
        return 0
    except Exception:
        return 0


def ledger_sum_gross(order_id: int, *, phase: PaymentLedgerPhase | None = None) -> int:
    """Sum gross amounts for succeeded ledger rows (optionally by phase)."""
    try:
        q = PaymentLedger.query.filter_by(
            order_id=order_id,
            status=PaymentLedgerStatus.succeeded,
        )
        if phase is not None:
            q = q.filter_by(phase=phase)
        rows = q.all()
        return sum(int(r.gross_amount_cents or 0) for r in rows)
    except (ProgrammingError, OperationalError):
        db.session.rollback()
        return 0
    except Exception:
        return 0


def fee_remaining_cents(order: PaymentOrder) -> int:
    planned = planned_platform_fee_cents(order.order_type, int(order.total_amount_cents or 0))
    collected = ledger_sum_platform_fees(order.id)
    return max(0, planned - collected)


def booking_hold_fee_effective(total_cents: int) -> int:
    if HOLD_FEE_CENTS <= 0:
        return 0
    return int(HOLD_FEE_CENTS)


def fee_breakdown_for_service(subtotal_cents: int, provider_role: RoleEnum | str) -> dict:
    """
    Calculate complete fee breakdown for service booking.
    Returns dict with: subtotal_cents, platform_fee_cents, processing_fee_cents, total_cents
    """
    platform_fee_cents = calc_beatfund_fee_cents(subtotal_cents)
    processing_fee_cents = 0
    total_cents = subtotal_cents
    return {
        "subtotal_cents": subtotal_cents,
        "platform_fee_cents": platform_fee_cents,
        "processing_fee_cents": processing_fee_cents,
        "total_cents": total_cents,
    }


def _resolve_booking_fee_fields(booking: "Booking") -> tuple[dict, bool]:
    """Return normalized fee context and whether booking fields were updated."""
    changed = False
    quoted_total_cents = booking.quoted_total_cents
    if quoted_total_cents is None and booking.total_cents is not None:
        quoted_total_cents = int(booking.total_cents)
        booking.quoted_total_cents = quoted_total_cents
        changed = True

    deposit_base_cents = booking.deposit_base_cents
    if deposit_base_cents is None:
        deposit_base_cents = HOLD_FEE_CENTS
        booking.deposit_base_cents = int(deposit_base_cents)
        changed = True

    beatfund_fee_total_cents = booking.beatfund_fee_total_cents
    if beatfund_fee_total_cents is None and quoted_total_cents is not None:
        beatfund_fee_total_cents = calc_beatfund_fee_total(int(quoted_total_cents))
        booking.beatfund_fee_total_cents = int(beatfund_fee_total_cents)
        changed = True

    beatfund_fee_collected_cents = booking.beatfund_fee_collected_cents or 0
    return (
        {
            "quoted_total_cents": quoted_total_cents,
            "deposit_base_cents": deposit_base_cents,
            "beatfund_fee_total_cents": beatfund_fee_total_cents,
            "beatfund_fee_collected_cents": beatfund_fee_collected_cents,
        },
        changed,
    )


def compute_booking_payment_breakdown(
    booking: "Booking",
    kind: PaymentKind,
    *,
    base_paid_cents: int | None = None,
    bf_paid_cents: int | None = None,
) -> dict | None:
    ctx, _ = _resolve_booking_fee_fields(booking)
    quoted_total_cents = ctx["quoted_total_cents"]

    deposit_base_cents = HOLD_FEE_CENTS

    if kind == PaymentKind.deposit:
        base_cents = deposit_base_cents
        beatfund_fee_cents = 0
        if base_cents <= 0:
            return None
        total_cents, processing_fee_cents = calc_total_and_processing(base_cents, beatfund_fee_cents)
        return {
            "base_cents": base_cents,
            "beatfund_fee_cents": beatfund_fee_cents,
            "processing_fee_cents": processing_fee_cents,
            "total_cents": total_cents,
            "quoted_total_cents": quoted_total_cents,
            "deposit_base_cents": deposit_base_cents,
            "beatfund_fee_total_cents": int(ctx.get("beatfund_fee_total_cents") or 0),
            "beatfund_fee_collected_cents": int(ctx.get("beatfund_fee_collected_cents") or 0),
        }

    if quoted_total_cents is None or quoted_total_cents <= 0:
        return None

    beatfund_fee_total_cents = int(ctx.get("beatfund_fee_total_cents") or calc_beatfund_fee_total(int(quoted_total_cents)))
    beatfund_fee_collected_cents = int(ctx.get("beatfund_fee_collected_cents") or 0)
    if bf_paid_cents is not None:
        beatfund_fee_collected_cents = max(0, int(bf_paid_cents))

    paid_base = deposit_base_cents if base_paid_cents is None else max(0, int(base_paid_cents))
    base_cents = max(0, int(quoted_total_cents) - paid_base)
    beatfund_fee_cents = max(0, beatfund_fee_total_cents - beatfund_fee_collected_cents)

    if base_cents <= 0 and beatfund_fee_cents <= 0:
        return None

    total_cents, processing_fee_cents = calc_total_and_processing(base_cents, beatfund_fee_cents)
    return {
        "base_cents": base_cents,
        "beatfund_fee_cents": beatfund_fee_cents,
        "processing_fee_cents": processing_fee_cents,
        "total_cents": total_cents,
        "quoted_total_cents": quoted_total_cents,
        "deposit_base_cents": deposit_base_cents,
        "beatfund_fee_total_cents": beatfund_fee_total_cents,
        "beatfund_fee_collected_cents": beatfund_fee_collected_cents,
    }


def sum_successful_payments(booking: "Booking", booking_request: "BookingRequest" | None = None) -> dict:
    """Sum successful payments for a booking (includes legacy booking_request payments)."""
    filters = [Payment.status == PaymentStatus.succeeded]
    if booking_request:
        filters.append(or_(Payment.booking_id == booking.id, Payment.booking_request_id == booking_request.id))
    else:
        filters.append(Payment.booking_id == booking.id)

    payments = Payment.query.filter(*filters).all()
    base_paid = sum(int(p.base_amount_cents or 0) for p in payments)
    bf_paid = sum(int(p.beatfund_fee_cents or 0) for p in payments)
    total_paid = sum(int(p.total_paid_cents or p.amount_cents or 0) for p in payments)
    return {
        "base_paid_cents": base_paid,
        "bf_paid_cents": bf_paid,
        "total_paid_cents": total_paid,
    }


def get_platform_fee_wallet_user_id() -> Optional[int]:
    """Get user_id for platform fee wallet (superadmin > admin > dev fallback)"""
    # Try superadmin first
    superadmin = User.query.filter_by(is_superadmin=True).first()
    if superadmin:
        return superadmin.id
    
    # Try admin
    admin = User.query.filter_by(role=RoleEnum.admin).first()
    if admin:
        return admin.id
    
    # Dev fallback only
    if IS_DEV and current_user.is_authenticated:
        return current_user.id
    
    return None


# Expose fee calculation functions to Jinja templates
app.jinja_env.globals["calc_beat_platform_fee_cents"] = calc_beat_platform_fee_cents
app.jinja_env.globals["calc_beatfund_fee_cents"] = calc_beatfund_fee_cents
app.jinja_env.globals["format_cents_dollars"] = format_cents_dollars
app.jinja_env.globals["cents_to_dollars"] = cents_to_dollars


def fund_vault(vault: ProjectVault, amount_cents: int, transaction_type: str = "manual", notes: str = None) -> bool:
    """Fund a vault from wallet balance. Returns True if successful."""
    if amount_cents <= 0:
        return False
    
    # Check if vault is locked
    if vault.is_locked_now():
        return False
    
    user_wallet = get_or_create_wallet(vault.user_id, commit=False)
    balance_cents = wallet_balance_cents(user_wallet)
    
    if balance_cents < amount_cents:
        return False
    
    try:
        with db_txn():
            # Deduct from wallet (skip auto-funding to avoid recursion)
            post_ledger(user_wallet, EntryType.purchase_spend, amount_cents, meta=f"fund vault '{vault.name[:80]}'", skip_auto_fund=True)
            
            # Add to vault
            vault.current_balance_cents += amount_cents
            vault.updated_at = datetime.utcnow()
            
            # Check if target reached
            if vault.current_balance_cents >= vault.target_cents and not vault.is_completed:
                vault.is_completed = True
                vault.completed_at = datetime.utcnow()
            
            # Create transaction record
            txn = VaultTransaction(
                vault_id=vault.id,
                amount_cents=amount_cents,
                transaction_type=transaction_type,
                source="wallet",
                notes=notes
            )
            db.session.add(txn)
            
        return True
    except Exception:
        db.session.rollback()
        return False


def process_auto_funding(user_id: int, income_cents: int) -> None:
    """Process automatic funding for all active vaults when user receives income"""
    if income_cents <= 0:
        return
    
    vaults = ProjectVault.query.filter_by(
        user_id=user_id,
        is_active=True,
        is_completed=False,
        auto_fund_enabled=True
    ).all()
    
    for vault in vaults:
        if vault.auto_fund_frequency != "on_income":
            continue
        
        # Check minimum threshold
        if vault.auto_fund_min_cents and income_cents < vault.auto_fund_min_cents:
            continue
        
        # Calculate auto-fund amount
        if vault.auto_fund_percent:
            auto_amount_cents = int((income_cents * vault.auto_fund_percent) / 100)
        else:
            auto_amount_cents = income_cents
        
        # Don't exceed remaining target
        if vault.current_balance_cents + auto_amount_cents > vault.target_cents:
            auto_amount_cents = vault.remaining_cents
        
        if auto_amount_cents > 0:
            fund_vault(vault, auto_amount_cents, transaction_type="auto_fund", notes=f"Auto-funded from income")


def post_ledger(wallet: Wallet, entry_type: EntryType, amount_cents: int, meta: str = "", skip_auto_fund: bool = False) -> LedgerEntry:
    if amount_cents <= 0:
        raise ValueError("amount must be positive cents")
    entry = LedgerEntry(wallet_id=wallet.id, entry_type=entry_type, amount_cents=amount_cents, meta=meta)
    db.session.add(entry)
    
    # Trigger auto-funding for income types (unless explicitly skipped)
    if not skip_auto_fund and entry_type in (EntryType.sale_income, EntryType.transfer_in, EntryType.deposit):
        try:
            process_auto_funding(wallet.user_id, amount_cents)
        except Exception:
            # Don't fail the ledger entry if auto-funding fails
            pass
    
    return entry


@contextmanager
def db_txn():
    try:
        yield
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def generate_idempotency_key(scope: str, user_id: int, **kwargs) -> str:
    """Generate a unique idempotency key for a transaction"""
    # Include scope, user_id, and key kwargs for uniqueness
    parts = [scope, str(user_id)]
    for k, v in sorted(kwargs.items()):
        parts.append(f"{k}={v}")
    key_str = ":".join(parts)
    # Hash for consistent length and security
    import hashlib
    return hashlib.sha256(key_str.encode()).hexdigest()


def check_idempotency(key: str, scope: str, user_id: int) -> Optional[dict]:
    """
    Check if an idempotency key already exists. Returns stored result if found, None otherwise.
    """
    existing = TransactionIdempotency.query.filter_by(key=key, scope=scope, user_id=user_id).first()
    if existing and existing.result_json:
        try:
            return json.loads(existing.result_json)
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def store_idempotency_result(key: str, scope: str, user_id: int, result: dict, commit: bool = False) -> TransactionIdempotency:
    """Store idempotency key and result. Returns the TransactionIdempotency record."""
    idempotency = TransactionIdempotency(
        user_id=user_id,
        key=key,
        scope=scope,
        result_json=json.dumps(result)
    )
    db.session.add(idempotency)
    if commit:
        db.session.commit()
    return idempotency


def _user_has_paid_for_beat(user_id: int, beat_id: int) -> bool:
    legacy = (
        db.session.query(Order.id)
        .filter_by(buyer_id=user_id, beat_id=beat_id, status=OrderStatus.paid)
        .first()
        is not None
    )
    if legacy:
        return True
    try:
        beat_purchase_paid = (
            BeatPurchase.query
            .filter_by(buyer_id=user_id, beat_id=beat_id, status=BeatPurchaseStatus.paid.value)
            .first()
            is not None
        )
        if beat_purchase_paid:
            return True
    except Exception:
        pass
    try:
        return (
            PaymentOrder.query
            .filter_by(
                order_type=OrderType.beat_purchase,
                client_user_id=user_id,
                beat_id=beat_id,
                status=OrderStatus.paid,
            )
            .first()
            is not None
        )
    except Exception:
        return False


def _ledger_by_charge_or_intent(charge_id: str | None, payment_intent_id: str | None) -> list["PaymentLedger"]:
    """Lookup PaymentLedger rows by Stripe charge/payment_intent (newest first)."""
    if not charge_id and not payment_intent_id:
        return []
    charge_id = str(charge_id) if charge_id else None
    payment_intent_id = str(payment_intent_id) if payment_intent_id else None
    try:
        filters = []
        if charge_id:
            filters.append(PaymentLedger.stripe_charge_id == charge_id)
        if payment_intent_id:
            filters.append(PaymentLedger.stripe_payment_intent_id == payment_intent_id)
        if not filters:
            return []
        rows = (
            PaymentLedger.query
            .filter(or_(*filters))
            .order_by(PaymentLedger.id.desc())
            .all()
        )
        if rows:
            return rows

        # Fallback: search meta columns if they exist in the DB (legacy/debug rows).
        try:
            cols = {c["name"] for c in inspect(db.engine).get_columns("payment_ledger")}
        except Exception:
            return []
        meta_cols = [c for c in ("meta_json", "meta") if c in cols]
        if not meta_cols:
            return []

        patterns = [p for p in (charge_id, payment_intent_id) if p]
        if not patterns:
            return []

        clauses = []
        params: dict[str, str] = {}
        idx = 0
        for col in meta_cols:
            for p in patterns:
                key = f"p{idx}"
                clauses.append(f"{col} LIKE :{key}")
                params[key] = f"%{p}%"
                idx += 1
        if not clauses:
            return []
        sql = f"SELECT id FROM payment_ledger WHERE {' OR '.join(clauses)} ORDER BY id DESC"
        ids = [r[0] for r in db.session.execute(text(sql), params).fetchall()]
        if not ids:
            return []
        return (
            PaymentLedger.query
            .filter(PaymentLedger.id.in_(ids))
            .order_by(PaymentLedger.id.desc())
            .all()
        )
    except (ProgrammingError, OperationalError):
        db.session.rollback()
        return []
    except Exception:
        return []


def _reverse_affiliate_for_ledger(
    ledger_entries: list["PaymentLedger"],
    reason: str = "stripe_refund_or_dispute",
    stripe_ref: str | None = None,
) -> None:
    """Reverse affiliate earnings associated with ledger entries (best-effort)."""
    if not ledger_entries:
        return
    try:
        attempted = 0
        reversed_count = 0
        reversal_entries = 0
        for ledger in ledger_entries:
            earning = AffiliateEarning.query.filter_by(payment_ledger_id=ledger.id).first()
            if not earning:
                continue
            attempted += 1
            if earning.status == AffiliateEarningStatus.reversed:
                continue
            earning.status = AffiliateEarningStatus.reversed
            reversed_count += 1
            # If affiliates are mapped to wallets in the future, add reversal ledger entries here.
        if reversed_count:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f"Affiliate reversal attempted but failed: {e}")
    else:
        try:
            app.logger.info(
                f"Affiliate reversal processed attempted={attempted} reversed={reversed_count} "
                f"ledger_reversals={reversal_entries} reason={reason} stripe_ref={stripe_ref or ''}"
            )
            if attempted and reversal_entries == 0:
                app.logger.info(
                    "Affiliate reversal ledger entries not created (no affiliate wallet linkage configured)."
                )
        except Exception:
            pass


def _record_beat_purchase(
    *,
    beat_id: int | None,
    buyer_id: int | None,
    payment_id: str | None,
    status: str = BeatPurchaseStatus.paid.value,
    commit: bool = False,
) -> None:
    if not beat_id or not buyer_id:
        return
    try:
        q = BeatPurchase.query.filter_by(beat_id=int(beat_id), buyer_id=int(buyer_id))
        if payment_id:
            q = q.filter_by(payment_id=str(payment_id))
        existing = q.order_by(BeatPurchase.id.desc()).first()
        if existing:
            if status and existing.status != status:
                existing.status = status
            if commit:
                db.session.commit()
            return
        bp = BeatPurchase(
            beat_id=int(beat_id),
            buyer_id=int(buyer_id),
            payment_id=str(payment_id) if payment_id else None,
            status=str(status or BeatPurchaseStatus.paid.value),
        )
        db.session.add(bp)
        if commit:
            db.session.commit()
    except Exception:
        if commit:
            db.session.rollback()


def _set_beat_purchase_status(
    *,
    beat_id: int | None,
    buyer_id: int | None,
    status: str,
    payment_id: str | None = None,
    commit: bool = False,
) -> None:
    if not beat_id or not buyer_id or not status:
        return
    try:
        q = BeatPurchase.query.filter_by(beat_id=int(beat_id), buyer_id=int(buyer_id))
        if payment_id:
            q = q.filter_by(payment_id=str(payment_id))
        bp = q.order_by(BeatPurchase.id.desc()).first()
        if not bp:
            return
        bp.status = str(status)
        if commit:
            db.session.commit()
    except Exception:
        if commit:
            db.session.rollback()


def _is_admin() -> bool:
    return current_user.is_authenticated and current_user.role == "admin"


def get_social_counts(user_id: int) -> tuple[int, int]:
    followers_count = UserFollow.query.filter_by(followed_id=user_id).count()
    following_count = UserFollow.query.filter_by(follower_id=user_id).count()
    return followers_count, following_count


DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def get_provider_settings(user_id: int, *, create: bool = False) -> ProviderSettings | None:
    try:
        s = ProviderSettings.query.filter_by(provider_user_id=user_id).first()
        if not s and create:
            s = ProviderSettings(provider_user_id=user_id)
            db.session.add(s)
            db.session.commit()
        return s
    except Exception:
        return None


def get_provider_review_summary(provider_id: int, *, include_hidden: bool = False) -> dict:
    try:
        q = db.session.query(
            func.avg(ProviderReview.rating),
            func.count(ProviderReview.id),
        ).filter(ProviderReview.provider_user_id == provider_id)
        if not include_hidden:
            q = q.filter(ProviderReview.status == ReviewVisibility.visible)
        avg, count = q.first() or (None, 0)
        avg_val = float(avg) if avg is not None else 0.0
        return {"avg": round(avg_val, 2), "count": int(count or 0)}
    except Exception:
        return {"avg": 0.0, "count": 0}


def _parse_preferred_datetime(preferred_time: str | None) -> datetime | None:
    if not preferred_time:
        return None
    s = str(preferred_time).strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %I:%M %p", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


def _time_window_contains(slot_start: time, slot_end: time, req_start: time, req_end: time) -> bool:
    # Simple same-day containment (no overnight windows)
    if slot_end <= slot_start:
        return False
    if req_end <= req_start:
        return False
    return (slot_start <= req_start) and (req_end <= slot_end)


def get_provider_availability_summary(provider_id: int) -> tuple[list[ProviderAvailability], list[ProviderAvailabilityException]]:
    slots = []
    exceptions = []
    try:
        slots = (
            ProviderAvailability.query
            .filter_by(provider_user_id=provider_id, is_active=True)
            .order_by(ProviderAvailability.day_of_week.asc(), ProviderAvailability.start_time.asc())
            .all()
        )
        exceptions = (
            ProviderAvailabilityException.query
            .filter_by(provider_user_id=provider_id)
            .order_by(ProviderAvailabilityException.date.desc())
            .limit(20)
            .all()
        )
    except Exception:
        pass
    return slots, exceptions


def provider_is_available(provider_id: int, preferred_time: str, duration_minutes: int | None = None) -> tuple[bool, str]:
    settings = get_provider_settings(provider_id, create=False)
    if settings and not settings.accepting_new_requests:
        return False, "This provider is not accepting new requests right now."

    dt = _parse_preferred_datetime(preferred_time)
    if not dt:
        return False, "Please provide a valid date and time (YYYY-MM-DD HH:MM)."

    duration = int(duration_minutes or 60)
    if duration <= 0:
        duration = 60

    end_dt = dt + timedelta(minutes=duration)
    if end_dt.date() != dt.date():
        return False, "Requested time window crosses midnight. Please choose a same-day time slot."

    req_start = dt.time()
    req_end = end_dt.time()
    day = dt.weekday()

    # Check exceptions for that date first
    exceptions = ProviderAvailabilityException.query.filter_by(
        provider_user_id=provider_id,
        date=dt.date(),
    ).all()

    for ex in exceptions:
        ex_start = ex.start_time or time(0, 0)
        ex_end = ex.end_time or time(23, 59)
        if _time_window_contains(ex_start, ex_end, req_start, req_end):
            if ex.is_unavailable:
                return False, "This time is blocked by a provider exception."
            # Explicitly available exception overrides weekly schedule
            return True, ""

    # Weekly slots
    slots = ProviderAvailability.query.filter_by(
        provider_user_id=provider_id,
        day_of_week=day,
        is_active=True,
    ).all()

    if not slots:
        # Backward-compatible default: allow if no schedule is configured
        return True, ""

    for slot in slots:
        if _time_window_contains(slot.start_time, slot.end_time, req_start, req_end):
            return True, ""

    return False, "Requested time is outside the provider's availability."


@app.before_request
def _load_my_social_counts():
    """Load social counts for current user, gracefully handle missing tables during bootstrap"""
    try:
        if current_user.is_authenticated:
            try:
                g.my_followers_count, g.my_following_count = get_social_counts(current_user.id)
            except Exception as e:
                # If table doesn't exist yet (during bootstrap), use defaults
                app.logger.warning(f"Could not load social counts (table might not exist yet): {type(e).__name__}")
                g.my_followers_count, g.my_following_count = 0, 0
        else:
            g.my_followers_count, g.my_following_count = 0, 0
    except Exception as e:
        app.logger.warning(f"Could not load social counts: {type(e).__name__}")
        g.my_followers_count, g.my_following_count = 0, 0


@app.context_processor
def inject_social_counts():
    return dict(
        my_followers_count=getattr(g, "my_followers_count", 0),
        my_following_count=getattr(g, "my_following_count", 0),
    )


@app.context_processor
def inject_unread_count():
    count = 0
    try:
        if current_user.is_authenticated:
            legacy = get_unread_notification_count(current_user.id)
            try:
                broadcast = (
                    NotificationRecipient.query
                    .filter(
                        NotificationRecipient.user_id == current_user.id,
                        NotificationRecipient.read_at.is_(None),
                    )
                    .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
                    .join(User, ActivityEvent.actor_user_id == User.id)
                    .filter(User.role != RoleEnum.admin.value)
                    .filter(ActivityEvent.audience != "ADMINS")
                    .count()
                )
            except Exception:
                broadcast = 0
            count = int(legacy + broadcast)
    except Exception:
        count = 0
    return {"unread_count": count}


@app.context_processor
def inject_provider_review_summary():
    summary = None
    settings = None
    try:
        if current_user.is_authenticated and is_service_provider(current_user):
            summary = get_provider_review_summary(current_user.id)
            settings = get_provider_settings(current_user.id, create=False)
    except Exception:
        summary = None
    return dict(
        provider_rating_summary=summary,
        provider_settings=settings,
        DAY_NAMES=DAY_NAMES,
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
    if "booking_id" not in cols:
        db.session.execute(text("ALTER TABLE booking_request ADD COLUMN booking_id INTEGER"))
        db.session.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_booking_request_booking_id ON booking_request (booking_id)"
        ))
        db.session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_booking_request_booking_id ON booking_request (booking_id)"
        ))
        db.session.commit()
    if "duration_minutes" not in cols:
        db.session.execute(text("ALTER TABLE booking_request ADD COLUMN duration_minutes INTEGER"))
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


def _ensure_sqlite_notifications_table():
    """Create notifications table and add email_notifications_enabled column to user if missing"""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    
    # Create notifications table if missing
    if not _sqlite_has_table("notification"):
        db.session.execute(text("""
            CREATE TABLE notification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                actor_user_id INTEGER,
                kind VARCHAR(50) NOT NULL DEFAULT 'info',
                title VARCHAR(160) NOT NULL,
                body TEXT,
                url VARCHAR(400),
                event_key VARCHAR(120),
                is_read BOOLEAN NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                emailed_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_user_id ON notification (user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_actor_user_id ON notification (actor_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_event_key ON notification (event_key)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_is_read ON notification (is_read)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_created_at ON notification (created_at)"))
        db.session.commit()
    else:
        cols = _sqlite_columns("notification")
        if "actor_user_id" not in cols:
            db.session.execute(text("ALTER TABLE notification ADD COLUMN actor_user_id INTEGER"))
        if "event_key" not in cols:
            db.session.execute(text("ALTER TABLE notification ADD COLUMN event_key VARCHAR(120)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_actor_user_id ON notification (actor_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_event_key ON notification (event_key)"))
        db.session.commit()
    
    # Add email_notifications_enabled to user table if missing
    if _sqlite_has_table("user"):
        cols = _sqlite_columns("user")
        if "email_notifications_enabled" not in cols:
            db.session.execute(text("ALTER TABLE user ADD COLUMN email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1"))
            db.session.commit()


def _ensure_sqlite_user_stripe_connect_columns():
    """Add Stripe Connect columns to user table if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("user"):
        return
    cols = _sqlite_columns("user")
    if "stripe_account_id" not in cols:
        db.session.execute(text("ALTER TABLE user ADD COLUMN stripe_account_id VARCHAR(255)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_user_stripe_account_id ON user (stripe_account_id)"))
        db.session.commit()


def _ensure_sqlite_activity_broadcast_tables():
    """Create ActivityEvent + NotificationRecipient tables if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return

    # activity_event
    if not _sqlite_has_table("activity_event"):
        db.session.execute(text("""
            CREATE TABLE activity_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type VARCHAR(50) NOT NULL,
                actor_user_id INTEGER NOT NULL,
                audience VARCHAR(40) NOT NULL DEFAULT 'ALL',
                payload_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (actor_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_activity_event_created_at ON activity_event (created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_activity_event_event_type ON activity_event (event_type)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_activity_event_actor_user_id ON activity_event (actor_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_activity_event_audience ON activity_event (audience)"))
        db.session.commit()

    # notification_recipient
    if not _sqlite_has_table("notification_recipient"):
        db.session.execute(text("""
            CREATE TABLE notification_recipient (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                read_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (event_id) REFERENCES activity_event (id),
                FOREIGN KEY (user_id) REFERENCES user (id),
                CONSTRAINT uq_notification_recipient_event_user UNIQUE (event_id, user_id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_recipient_event_id ON notification_recipient (event_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_recipient_user_id ON notification_recipient (user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_recipient_read_at ON notification_recipient (read_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_recipient_user_read_at ON notification_recipient (user_id, read_at)"))
        db.session.commit()


def _ensure_sqlite_booking_chat_tables():
    """Create booking-scoped chat tables if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return

    # conversation
    if not _sqlite_has_table("conversation"):
        db.session.execute(text("""
            CREATE TABLE conversation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                booking_id INTEGER NOT NULL UNIQUE,
                status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                last_message_at DATETIME,
                FOREIGN KEY (booking_id) REFERENCES booking (id)
            )
        """))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_conversation_booking_id ON conversation (booking_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_status ON conversation (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_created_at ON conversation (created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_last_message_at ON conversation (last_message_at)"))
        db.session.commit()

    # conversation_participant
    if not _sqlite_has_table("conversation_participant"):
        db.session.execute(text("""
            CREATE TABLE conversation_participant (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role_at_time VARCHAR(40),
                is_blocked BOOLEAN NOT NULL DEFAULT 0,
                blocked_at DATETIME,
                FOREIGN KEY (conversation_id) REFERENCES conversation (id),
                FOREIGN KEY (user_id) REFERENCES user (id),
                CONSTRAINT uq_conversation_participant_conversation_user UNIQUE (conversation_id, user_id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_participant_conversation_id ON conversation_participant (conversation_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_participant_user_id ON conversation_participant (user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_participant_is_blocked ON conversation_participant (is_blocked)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_conversation_participant_conversation_user ON conversation_participant (conversation_id, user_id)"))
        db.session.commit()

    # message
    if not _sqlite_has_table("message"):
        db.session.execute(text("""
            CREATE TABLE message (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                body_text TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                is_flagged BOOLEAN NOT NULL DEFAULT 0,
                flagged_reason VARCHAR(40),
                delivery_status VARCHAR(20) NOT NULL DEFAULT 'SENT',
                FOREIGN KEY (conversation_id) REFERENCES conversation (id),
                FOREIGN KEY (sender_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_conversation_id ON message (conversation_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_sender_user_id ON message (sender_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_created_at ON message (created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_is_flagged ON message (is_flagged)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_delivery_status ON message (delivery_status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_conversation_created_at ON message (conversation_id, created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_sender_window ON message (conversation_id, sender_user_id, created_at)"))
        db.session.commit()

    # message_moderation_log
    if not _sqlite_has_table("message_moderation_log"):
        db.session.execute(text("""
            CREATE TABLE message_moderation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                attempted_text TEXT,
                reason VARCHAR(40) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversation (id),
                FOREIGN KEY (sender_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_moderation_log_conversation_id ON message_moderation_log (conversation_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_moderation_log_sender_user_id ON message_moderation_log (sender_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_moderation_log_reason ON message_moderation_log (reason)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_message_moderation_log_created_at ON message_moderation_log (created_at)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_moderation_log_conversation_created_at ON message_moderation_log (conversation_id, created_at)"))
        db.session.commit()


def _ensure_sqlite_audit_log_finance_columns():
    """Add new AuditLog columns for finance/security auditing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("audit_log"):
        return

    cols = _sqlite_columns("audit_log")
    # Add columns (SQLite supports ADD COLUMN; cannot add NOT NULL constraints safely)
    if "actor_user_id" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN actor_user_id INTEGER"))
    if "actor_role" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN actor_role VARCHAR(40)"))
    if "action_type" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN action_type VARCHAR(80)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_action_type ON audit_log (action_type)"))
    if "target_type" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN target_type VARCHAR(60)"))
    if "target_id" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN target_id VARCHAR(64)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_target_type_target_id ON audit_log (target_type, target_id)"))
    if "ip_address" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN ip_address VARCHAR(64)"))
    if "user_agent" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN user_agent VARCHAR(220)"))
    if "before_json" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN before_json TEXT"))
    if "after_json" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN after_json TEXT"))
    if "metadata_json" not in cols:
        db.session.execute(text("ALTER TABLE audit_log ADD COLUMN metadata_json TEXT"))

    # Ensure indexes exist (created_at, admin_id already existed but ensure created_at index for older DBs)
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_created_at ON audit_log (created_at)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_admin_id ON audit_log (admin_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_actor_user_id ON audit_log (actor_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_log_target_type ON audit_log (target_type)"))
    db.session.commit()


def _ensure_sqlite_stripe_webhook_event_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("stripe_webhook_event"):
        return
    db.session.execute(text("""
        CREATE TABLE stripe_webhook_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stripe_event_id VARCHAR(80) NOT NULL UNIQUE,
            type VARCHAR(120) NOT NULL,
            created_at DATETIME,
            received_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            processed_at DATETIME,
            status VARCHAR(20) NOT NULL DEFAULT 'RECEIVED',
            last_error VARCHAR(500),
            payload_json TEXT
        )
    """))
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_stripe_webhook_event_stripe_event_id ON stripe_webhook_event (stripe_event_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_stripe_webhook_event_type ON stripe_webhook_event (type)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_stripe_webhook_event_received_at ON stripe_webhook_event (received_at)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_stripe_webhook_event_processed_at ON stripe_webhook_event (processed_at)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_stripe_webhook_event_status ON stripe_webhook_event (status)"))
    db.session.commit()


def _ensure_sqlite_security_event_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("security_event"):
        return
    db.session.execute(text("""
        CREATE TABLE security_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type VARCHAR(80) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'info',
            user_id INTEGER,
            ip VARCHAR(64),
            user_agent VARCHAR(240),
            path VARCHAR(200),
            request_id VARCHAR(40),
            meta_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_event_type ON security_event (event_type)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_severity ON security_event (severity)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_user_id ON security_event (user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_request_id ON security_event (request_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_created_at ON security_event (created_at)"))
    db.session.commit()


def _ensure_sqlite_alert_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("alert"):
        return
    db.session.execute(text("""
        CREATE TABLE alert (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            severity VARCHAR(10) NOT NULL DEFAULT 'LOW',
            type VARCHAR(80) NOT NULL,
            message VARCHAR(240) NOT NULL,
            metadata_json TEXT,
            resolved_at DATETIME
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_alert_created_at ON alert (created_at)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_alert_severity ON alert (severity)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_alert_type ON alert (type)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_alert_resolved_at ON alert (resolved_at)"))
    db.session.commit()


def _ensure_sqlite_uploaded_file_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("uploaded_file"):
        return
    db.session.execute(text("""
        CREATE TABLE uploaded_file (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER,
            purpose VARCHAR(40) NOT NULL DEFAULT 'OTHER',
            storage_provider VARCHAR(20) NOT NULL DEFAULT 'local',
            key VARCHAR(500) NOT NULL,
            original_filename VARCHAR(255),
            content_type VARCHAR(120),
            size INTEGER,
            etag VARCHAR(120),
            scan_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
            scan_message VARCHAR(400),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (owner_user_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_owner_user_id ON uploaded_file (owner_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_purpose ON uploaded_file (purpose)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_storage_provider ON uploaded_file (storage_provider)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_key ON uploaded_file (key)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_scan_status ON uploaded_file (scan_status)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_uploaded_file_created_at ON uploaded_file (created_at)"))
    db.session.commit()


def _ensure_sqlite_waitlist_table():
    """Create waitlist_entry table if missing"""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    
    # Create waitlist_entry table if missing
    if not _sqlite_has_table("waitlist_entry"):
        db.session.execute(text("""
            CREATE TABLE waitlist_entry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(255) NOT NULL UNIQUE,
                full_name VARCHAR(150),
                role_interest VARCHAR(80),
                note VARCHAR(300),
                ip VARCHAR(64),
                user_agent VARCHAR(200),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_waitlist_entry_email ON waitlist_entry (email)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_waitlist_entry_created_at ON waitlist_entry (created_at)"))
        db.session.commit()


def _ensure_sqlite_beat_stripe_columns():
    """Add stripe_product_id and stripe_price_id columns to beat table if missing"""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("beat"):
        return
    
    cols = _sqlite_columns("beat")
    
    # Add stripe_product_id if missing
    if "stripe_product_id" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN stripe_product_id VARCHAR(255)"))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_beat_stripe_product_id ON beat (stripe_product_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_stripe_product_id ON beat (stripe_product_id)"))
        db.session.commit()
    
    # Add stripe_price_id if missing
    if "stripe_price_id" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN stripe_price_id VARCHAR(255)"))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_beat_stripe_price_id ON beat (stripe_price_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_stripe_price_id ON beat (stripe_price_id)"))
        db.session.commit()


def _ensure_sqlite_beat_audio_columns():
    """Add audio preview/original columns to beat table if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("beat"):
        return

    cols = _sqlite_columns("beat")
    if "currency" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN currency VARCHAR(8)"))
    if "audio_original_key" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN audio_original_key VARCHAR(255)"))
    if "audio_deliverable_key" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN audio_deliverable_key VARCHAR(255)"))
    if "audio_preview_key" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN audio_preview_key VARCHAR(255)"))
    if "stems_key" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN stems_key VARCHAR(255)"))
    if "preview_seconds" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN preview_seconds INTEGER"))
    if "preview_status" not in cols:
        db.session.execute(text("ALTER TABLE beat ADD COLUMN preview_status VARCHAR(20)"))

    db.session.execute(text("UPDATE beat SET currency = COALESCE(currency, 'usd')"))
    db.session.execute(text("UPDATE beat SET preview_seconds = COALESCE(preview_seconds, :default)"), {"default": PREVIEW_SECONDS_DEFAULT})
    db.session.execute(text("""
        UPDATE beat
        SET audio_preview_key = COALESCE(audio_preview_key, preview_path)
        WHERE preview_path IS NOT NULL AND audio_preview_key IS NULL
    """))
    db.session.execute(text("""
        UPDATE beat
        SET audio_original_key = COALESCE(audio_original_key, stems_path)
        WHERE stems_path IS NOT NULL AND audio_original_key IS NULL
    """))
    db.session.execute(text("""
        UPDATE beat
        SET audio_deliverable_key = COALESCE(audio_deliverable_key, audio_original_key, stems_path)
        WHERE audio_deliverable_key IS NULL
    """))
    db.session.execute(text("""
        UPDATE beat
        SET preview_status = COALESCE(preview_status,
            CASE
                WHEN audio_preview_key IS NOT NULL OR preview_path IS NOT NULL THEN 'ready'
                ELSE 'failed'
            END)
    """))
    db.session.commit()


def _ensure_sqlite_beat_purchase_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("beat_purchase"):
        return
    db.session.execute(text("""
        CREATE TABLE beat_purchase (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            beat_id INTEGER NOT NULL,
            buyer_id INTEGER NOT NULL,
            payment_id VARCHAR(255),
            status VARCHAR(20) NOT NULL DEFAULT 'paid',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (beat_id) REFERENCES beat (id),
            FOREIGN KEY (buyer_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_beat_id ON beat_purchase (beat_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_buyer_id ON beat_purchase (buyer_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_payment_id ON beat_purchase (payment_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_status ON beat_purchase (status)"))
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_beat_purchase_buyer_payment ON beat_purchase (beat_id, buyer_id, payment_id)"))
    db.session.commit()


def _ensure_sqlite_order_payment_columns():
    """Add Stripe/payment columns to order table if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if not _sqlite_has_table("order"):
        return

    cols = _sqlite_columns("order")

    # NOTE: "order" is a reserved word in many DBs; quote it for safety in raw SQL.
    table = '"order"'

    if "platform_fee_cents" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN platform_fee_cents INTEGER"))
        db.session.commit()
    if "processing_fee_cents" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN processing_fee_cents INTEGER"))
        db.session.commit()
    if "total_cents" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN total_cents INTEGER"))
        db.session.commit()
    if "currency" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN currency VARCHAR(8) NOT NULL DEFAULT 'usd'"))
        db.session.commit()
    if "processor" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN processor VARCHAR(20) NOT NULL DEFAULT 'wallet'"))
        db.session.execute(text(f"CREATE INDEX IF NOT EXISTS ix_order_processor ON {table} (processor)"))
        db.session.commit()
    if "stripe_session_id" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN stripe_session_id VARCHAR(255)"))
        db.session.execute(text(f"CREATE UNIQUE INDEX IF NOT EXISTS uq_order_stripe_session_id ON {table} (stripe_session_id)"))
        db.session.execute(text(f"CREATE INDEX IF NOT EXISTS ix_order_stripe_session_id ON {table} (stripe_session_id)"))
        db.session.commit()
    if "stripe_payment_intent" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN stripe_payment_intent VARCHAR(255)"))
        db.session.execute(text(f"CREATE INDEX IF NOT EXISTS ix_order_stripe_payment_intent ON {table} (stripe_payment_intent)"))
        db.session.commit()
    if "paid_at" not in cols:
        db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN paid_at DATETIME"))
        db.session.commit()
    if "status" in cols:
        # Ensure we have an index for status filtering (SQLite won't auto-add it)
        db.session.execute(text(f"CREATE INDEX IF NOT EXISTS ix_order_status ON {table} (status)"))
        db.session.commit()


def _ensure_sqlite_booking_payment_columns():
    """Add booking/payment fee columns for new booking payments (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return

    # Ensure payment table exists
    if not _sqlite_has_table("payment"):
        try:
            Payment.__table__.create(db.engine)
        except Exception:
            pass

    if _sqlite_has_table("payment"):
        cols = _sqlite_columns("payment")
        if "booking_id" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN booking_id INTEGER"))
            db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_booking_id ON payment (booking_id)"))
        if "kind" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN kind VARCHAR(20)"))
        if "base_amount_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN base_amount_cents INTEGER"))
        if "beatfund_fee_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN beatfund_fee_cents INTEGER"))
        if "processing_fee_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN processing_fee_cents INTEGER"))
        if "total_paid_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN total_paid_cents INTEGER"))
        if "refunded_base_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN refunded_base_cents INTEGER DEFAULT 0"))
        if "nonrefundable_processing_kept_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN nonrefundable_processing_kept_cents INTEGER DEFAULT 0"))
        if "nonrefundable_beatfund_kept_cents" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN nonrefundable_beatfund_kept_cents INTEGER DEFAULT 0"))
        if "stripe_payment_intent_id" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN stripe_payment_intent_id VARCHAR(255)"))
            db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_stripe_payment_intent_id ON payment (stripe_payment_intent_id)"))
        if "stripe_charge_id" not in cols:
            db.session.execute(text("ALTER TABLE payment ADD COLUMN stripe_charge_id VARCHAR(255)"))
            db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_stripe_charge_id ON payment (stripe_charge_id)"))

    if _sqlite_has_table("booking"):
        cols = _sqlite_columns("booking")
        if "quoted_total_cents" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN quoted_total_cents INTEGER"))
        if "quote_hourly_rate_cents" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN quote_hourly_rate_cents INTEGER"))
        if "quote_billable_minutes" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN quote_billable_minutes INTEGER"))
        if "quote_calculation_text" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN quote_calculation_text TEXT"))
        if "quote_breakdown_text" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN quote_breakdown_text TEXT"))
        if "deposit_base_cents" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN deposit_base_cents INTEGER"))
        if "beatfund_fee_total_cents" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN beatfund_fee_total_cents INTEGER"))
        if "beatfund_fee_collected_cents" not in cols:
            db.session.execute(text("ALTER TABLE booking ADD COLUMN beatfund_fee_collected_cents INTEGER DEFAULT 0"))


def _ensure_sqlite_payout_affiliate_tables():
    """Create Stripe payout + affiliate tables if missing (SQLite only)."""
    if db.engine.url.get_backend_name() != "sqlite":
        return

    # Affiliate
    if not _sqlite_has_table("affiliate"):
        db.session.execute(text("""
            CREATE TABLE affiliate (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code VARCHAR(40) NOT NULL UNIQUE,
                display_name VARCHAR(160) NOT NULL,
                address_line1 VARCHAR(255),
                address_line2 VARCHAR(255),
                city VARCHAR(120),
                state VARCHAR(120),
                postal_code VARCHAR(20),
                country VARCHAR(2),
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                stripe_account_id VARCHAR(255),
                commission_pct NUMERIC(6,4),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_affiliate_code ON affiliate (code)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_affiliate_status ON affiliate (status)"))
        db.session.commit()

    # Affiliate invite
    if not _sqlite_has_table("affiliate_invite"):
        db.session.execute(text("""
            CREATE TABLE affiliate_invite (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token VARCHAR(120) NOT NULL UNIQUE,
                expires_at DATETIME,
                used_at DATETIME,
                created_by_admin_user_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by_admin_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_affiliate_invite_token ON affiliate_invite (token)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_affiliate_invite_expires_at ON affiliate_invite (expires_at)"))
        db.session.commit()

    # Payment orders
    if not _sqlite_has_table("payment_order"):
        db.session.execute(text("""
            CREATE TABLE payment_order (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_type VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending_payment',
                client_user_id INTEGER NOT NULL,
                provider_user_id INTEGER,
                provider_stripe_acct_id VARCHAR(255),
                total_amount_cents INTEGER NOT NULL,
                currency VARCHAR(8) NOT NULL DEFAULT 'usd',
                affiliate_id INTEGER,
                beat_id INTEGER,
                booking_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_user_id) REFERENCES user (id),
                FOREIGN KEY (provider_user_id) REFERENCES user (id),
                FOREIGN KEY (affiliate_id) REFERENCES affiliate (id),
                FOREIGN KEY (beat_id) REFERENCES beat (id),
                FOREIGN KEY (booking_id) REFERENCES booking (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_type ON payment_order (order_type)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_status ON payment_order (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_client_user_id ON payment_order (client_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_provider_user_id ON payment_order (provider_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_affiliate_id ON payment_order (affiliate_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_beat_id ON payment_order (beat_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_order_booking_id ON payment_order (booking_id)"))
        db.session.commit()

    # Payment ledger
    if not _sqlite_has_table("payment_ledger"):
        db.session.execute(text("""
            CREATE TABLE payment_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                phase VARCHAR(20) NOT NULL,
                gross_amount_cents INTEGER NOT NULL,
                platform_fee_collected_cents INTEGER NOT NULL DEFAULT 0,
                provider_amount_routed_cents INTEGER NOT NULL DEFAULT 0,
                stripe_checkout_session_id VARCHAR(255) UNIQUE,
                stripe_payment_intent_id VARCHAR(255) UNIQUE,
                stripe_charge_id VARCHAR(255) UNIQUE,
                status VARCHAR(20) NOT NULL DEFAULT 'created',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES payment_order (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_ledger_order_id ON payment_ledger (order_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_ledger_phase ON payment_ledger (phase)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_ledger_status ON payment_ledger (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_ledger_created_at ON payment_ledger (created_at)"))
        db.session.commit()

    # Provider Stripe account status
    if not _sqlite_has_table("provider_stripe_account"):
        db.session.execute(text("""
            CREATE TABLE provider_stripe_account (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                stripe_account_id VARCHAR(255) UNIQUE,
                charges_enabled BOOLEAN NOT NULL DEFAULT 0,
                payouts_enabled BOOLEAN NOT NULL DEFAULT 0,
                details_submitted BOOLEAN NOT NULL DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_stripe_account_user_id ON provider_stripe_account (user_id)"))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_stripe_account_stripe_id ON provider_stripe_account (stripe_account_id)"))
        db.session.commit()

    # Affiliate earnings
    if not _sqlite_has_table("affiliate_earning"):
        db.session.execute(text("""
            CREATE TABLE affiliate_earning (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                affiliate_id INTEGER NOT NULL,
                order_id INTEGER NOT NULL,
                payment_ledger_id INTEGER NOT NULL,
                base_platform_fee_cents INTEGER NOT NULL,
                commission_cents INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                available_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (affiliate_id) REFERENCES affiliate (id),
                FOREIGN KEY (order_id) REFERENCES payment_order (id),
                FOREIGN KEY (payment_ledger_id) REFERENCES payment_ledger (id),
                CONSTRAINT uq_affiliate_earning_affiliate_ledger UNIQUE (affiliate_id, payment_ledger_id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_affiliate_earning_affiliate_id ON affiliate_earning (affiliate_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_affiliate_earning_status ON affiliate_earning (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_affiliate_earning_available_at ON affiliate_earning (available_at)"))
        db.session.commit()

    # Add referred_by_affiliate_id to user table if missing
    if _sqlite_has_table("user"):
        cols = _sqlite_columns("user")
        if "referred_by_affiliate_id" not in cols:
            db.session.execute(text("ALTER TABLE user ADD COLUMN referred_by_affiliate_id INTEGER"))
            db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_user_referred_by_affiliate_id ON user (referred_by_affiliate_id)"))
            db.session.commit()


def _ensure_sqlite_provider_review_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("provider_review"):
        return
    db.session.execute(text("""
        CREATE TABLE provider_review (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL UNIQUE,
            reviewer_user_id INTEGER NOT NULL,
            provider_user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            title VARCHAR(160),
            body TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'visible',
            reported_count INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (booking_id) REFERENCES booking (id),
            FOREIGN KEY (reviewer_user_id) REFERENCES user (id),
            FOREIGN KEY (provider_user_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_review_booking_id ON provider_review (booking_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_provider_user_id ON provider_review (provider_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_reviewer_user_id ON provider_review (reviewer_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_status ON provider_review (status)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_created_at ON provider_review (created_at)"))
    db.session.commit()


def _ensure_sqlite_provider_availability_tables():
    if db.engine.url.get_backend_name() != "sqlite":
        return

    if not _sqlite_has_table("provider_settings"):
        db.session.execute(text("""
            CREATE TABLE provider_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_user_id INTEGER NOT NULL UNIQUE,
                accepting_new_requests BOOLEAN NOT NULL DEFAULT 1,
                onsite BOOLEAN NOT NULL DEFAULT 1,
                remote BOOLEAN NOT NULL DEFAULT 1,
                travel_radius_miles INTEGER,
                base_location VARCHAR(255),
                tz VARCHAR(64) NOT NULL DEFAULT 'UTC',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (provider_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_settings_user_id ON provider_settings (provider_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_settings_user_id ON provider_settings (provider_user_id)"))
        db.session.commit()

    if not _sqlite_has_table("provider_availability"):
        db.session.execute(text("""
            CREATE TABLE provider_availability (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_user_id INTEGER NOT NULL,
                day_of_week INTEGER NOT NULL,
                start_time TIME NOT NULL,
                end_time TIME NOT NULL,
                tz VARCHAR(64) NOT NULL DEFAULT 'UTC',
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (provider_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_provider_user_id ON provider_availability (provider_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_day_of_week ON provider_availability (day_of_week)"))
        db.session.commit()

    if not _sqlite_has_table("provider_availability_exception"):
        db.session.execute(text("""
            CREATE TABLE provider_availability_exception (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_user_id INTEGER NOT NULL,
                date DATE NOT NULL,
                start_time TIME,
                end_time TIME,
                is_unavailable BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (provider_user_id) REFERENCES user (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_exception_user_id ON provider_availability_exception (provider_user_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_exception_date ON provider_availability_exception (date)"))
        db.session.commit()


def _ensure_sqlite_support_ticket_message_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("support_ticket_message"):
        return
    db.session.execute(text("""
        CREATE TABLE support_ticket_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            author_user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES support_ticket (id),
            FOREIGN KEY (author_user_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_ticket_id ON support_ticket_message (ticket_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_author_user_id ON support_ticket_message (author_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_created_at ON support_ticket_message (created_at)"))
    db.session.commit()


def _ensure_sqlite_booking_dispute_message_table():
    if db.engine.url.get_backend_name() != "sqlite":
        return
    if _sqlite_has_table("booking_dispute_message"):
        return
    db.session.execute(text("""
        CREATE TABLE booking_dispute_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dispute_id INTEGER NOT NULL,
            author_user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            FOREIGN KEY (dispute_id) REFERENCES booking_dispute (id),
            FOREIGN KEY (author_user_id) REFERENCES user (id)
        )
    """))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_dispute_id ON booking_dispute_message (dispute_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_author_user_id ON booking_dispute_message (author_user_id)"))
    db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_created_at ON booking_dispute_message (created_at)"))
    db.session.commit()


def _ensure_postgres_booking_fee_columns():
    """Add booking fee columns in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'booking'
            """)).fetchall()
            existing = {r[0] for r in rows}
            required = {
                "quoted_total_cents",
                "quote_hourly_rate_cents",
                "quote_billable_minutes",
                "quote_calculation_text",
                "quote_breakdown_text",
                "deposit_base_cents",
                "beatfund_fee_total_cents",
                "beatfund_fee_collected_cents",
            }
            missing = sorted(required - existing)

            if missing:
                conn.execute(text("""
                    ALTER TABLE booking
                      ADD COLUMN IF NOT EXISTS quoted_total_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS quote_hourly_rate_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS quote_billable_minutes INTEGER,
                      ADD COLUMN IF NOT EXISTS quote_calculation_text TEXT,
                      ADD COLUMN IF NOT EXISTS quote_breakdown_text TEXT,
                      ADD COLUMN IF NOT EXISTS deposit_base_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS beatfund_fee_total_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS beatfund_fee_collected_cents INTEGER;
                """))
                app.logger.warning(f"[DB] Added booking fee columns: {', '.join(missing)}")
            else:
                app.logger.info("[DB] Booking fee columns already present")

            needs_backfill = conn.execute(text("""
                SELECT 1
                FROM booking
                WHERE deposit_base_cents IS NULL
                   OR beatfund_fee_total_cents IS NULL
                   OR beatfund_fee_collected_cents IS NULL
                LIMIT 1
            """)).first() is not None

            if needs_backfill:
                conn.execute(text("""
                    UPDATE booking
                    SET deposit_base_cents = COALESCE(deposit_base_cents, :deposit_default),
                        beatfund_fee_total_cents = COALESCE(beatfund_fee_total_cents, 0),
                        beatfund_fee_collected_cents = COALESCE(beatfund_fee_collected_cents, 0)
                    WHERE deposit_base_cents IS NULL
                       OR beatfund_fee_total_cents IS NULL
                       OR beatfund_fee_collected_cents IS NULL
                """), {"deposit_default": HOLD_FEE_CENTS})
                app.logger.info("[DB] Backfilled booking fee columns (defaults applied)")
    except Exception as e:
        app.logger.warning(f"[DB] Postgres booking fee patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_booking_request_duration_column():
    """Add duration_minutes to booking_request in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'booking_request'
            """)).fetchall()
            existing = {r[0] for r in rows}
            if "duration_minutes" not in existing:
                conn.execute(text("""
                    ALTER TABLE booking_request
                      ADD COLUMN IF NOT EXISTS duration_minutes INTEGER;
                """))
                app.logger.warning("[DB] Added booking_request.duration_minutes column")
            else:
                app.logger.info("[DB] booking_request.duration_minutes already present")
    except Exception as e:
        app.logger.warning(f"[DB] Postgres booking_request patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_beat_audio_columns():
    """Add audio preview/original columns to beat table in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'beat'
            """)).fetchall()
            existing = {r[0] for r in rows}
            missing = []

            if "currency" not in existing:
                missing.append("currency")
            if "audio_original_key" not in existing:
                missing.append("audio_original_key")
            if "audio_deliverable_key" not in existing:
                missing.append("audio_deliverable_key")
            if "audio_preview_key" not in existing:
                missing.append("audio_preview_key")
            if "stems_key" not in existing:
                missing.append("stems_key")
            if "preview_seconds" not in existing:
                missing.append("preview_seconds")
            if "preview_status" not in existing:
                missing.append("preview_status")

            if missing:
                conn.execute(text("""
                    ALTER TABLE beat
                      ADD COLUMN IF NOT EXISTS currency VARCHAR(8),
                      ADD COLUMN IF NOT EXISTS audio_original_key VARCHAR(255),
                      ADD COLUMN IF NOT EXISTS audio_deliverable_key VARCHAR(255),
                      ADD COLUMN IF NOT EXISTS audio_preview_key VARCHAR(255),
                      ADD COLUMN IF NOT EXISTS stems_key VARCHAR(255),
                      ADD COLUMN IF NOT EXISTS preview_seconds INTEGER,
                      ADD COLUMN IF NOT EXISTS preview_status VARCHAR(20);
                """))
                app.logger.warning(f"[DB] Added beat audio columns: {', '.join(missing)}")
            else:
                app.logger.info("[DB] Beat audio columns already present")

            conn.execute(text("UPDATE beat SET currency = COALESCE(currency, 'usd')"))
            conn.execute(text("UPDATE beat SET preview_seconds = COALESCE(preview_seconds, :default)"), {"default": PREVIEW_SECONDS_DEFAULT})
            conn.execute(text("""
                UPDATE beat
                SET audio_preview_key = COALESCE(audio_preview_key, preview_path)
                WHERE preview_path IS NOT NULL AND audio_preview_key IS NULL
            """))
            conn.execute(text("""
                UPDATE beat
                SET audio_original_key = COALESCE(audio_original_key, stems_path)
                WHERE stems_path IS NOT NULL AND audio_original_key IS NULL
            """))
            conn.execute(text("""
                UPDATE beat
                SET audio_deliverable_key = COALESCE(audio_deliverable_key, audio_original_key, stems_path)
                WHERE audio_deliverable_key IS NULL
            """))
            conn.execute(text("""
                UPDATE beat
                SET preview_status = COALESCE(preview_status,
                    CASE
                        WHEN audio_preview_key IS NOT NULL OR preview_path IS NOT NULL THEN 'ready'
                        ELSE 'failed'
                    END)
            """))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres beat audio patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_beat_purchase_table():
    """Create beat_purchase table in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            exists = conn.execute(text("""
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'beat_purchase'
            """)).first() is not None
            if exists:
                return
            conn.execute(text("""
                CREATE TABLE beat_purchase (
                    id SERIAL PRIMARY KEY,
                    beat_id INTEGER NOT NULL REFERENCES beat (id),
                    buyer_id INTEGER NOT NULL REFERENCES "user" (id),
                    payment_id VARCHAR(255),
                    status VARCHAR(20) NOT NULL DEFAULT 'paid',
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_beat_id ON beat_purchase (beat_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_buyer_id ON beat_purchase (buyer_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_payment_id ON beat_purchase (payment_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_beat_purchase_status ON beat_purchase (status)"))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_beat_purchase_buyer_payment ON beat_purchase (beat_id, buyer_id, payment_id)"))
            app.logger.warning("[DB] Created beat_purchase table")
    except Exception as e:
        app.logger.warning(f"[DB] Postgres beat_purchase patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_payment_fee_columns():
    """Add payment fee columns in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'payment'
            """)).fetchall()
            existing = {r[0] for r in rows}
            required = {
                "kind",
                "base_amount_cents",
                "beatfund_fee_cents",
                "processing_fee_cents",
                "total_paid_cents",
                "refunded_base_cents",
                "nonrefundable_processing_kept_cents",
                "nonrefundable_beatfund_kept_cents",
                "idempotency_key",
                "external_id",
                "booking_request_id",
                "booking_id",
                "stripe_payment_intent_id",
                "stripe_charge_id",
            }
            missing = sorted(required - existing)

            if missing:
                conn.execute(text("""
                    ALTER TABLE payment
                      ADD COLUMN IF NOT EXISTS kind TEXT,
                      ADD COLUMN IF NOT EXISTS base_amount_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS beatfund_fee_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS processing_fee_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS total_paid_cents INTEGER,
                      ADD COLUMN IF NOT EXISTS refunded_base_cents INTEGER DEFAULT 0,
                      ADD COLUMN IF NOT EXISTS nonrefundable_processing_kept_cents INTEGER DEFAULT 0,
                      ADD COLUMN IF NOT EXISTS nonrefundable_beatfund_kept_cents INTEGER DEFAULT 0,
                      ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
                      ADD COLUMN IF NOT EXISTS external_id TEXT,
                      ADD COLUMN IF NOT EXISTS booking_request_id INTEGER,
                      ADD COLUMN IF NOT EXISTS booking_id INTEGER,
                      ADD COLUMN IF NOT EXISTS stripe_payment_intent_id TEXT,
                      ADD COLUMN IF NOT EXISTS stripe_charge_id TEXT;
                """))
                app.logger.warning(f"[DB] Added payment fee columns: {', '.join(missing)}")
                try:
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_payment_booking_id ON payment (booking_id)"))
                except Exception:
                    pass
            else:
                app.logger.info("[DB] Payment fee columns already present")

            needs_backfill = conn.execute(text("""
                SELECT 1
                FROM payment
                WHERE base_amount_cents IS NULL
                   OR beatfund_fee_cents IS NULL
                   OR processing_fee_cents IS NULL
                   OR total_paid_cents IS NULL
                   OR refunded_base_cents IS NULL
                   OR nonrefundable_processing_kept_cents IS NULL
                   OR nonrefundable_beatfund_kept_cents IS NULL
                LIMIT 1
            """)).first() is not None

            if needs_backfill:
                conn.execute(text("""
                    UPDATE payment
                    SET base_amount_cents = COALESCE(base_amount_cents, amount_cents),
                        beatfund_fee_cents = COALESCE(beatfund_fee_cents, 0),
                        processing_fee_cents = COALESCE(processing_fee_cents, 0),
                        total_paid_cents = COALESCE(total_paid_cents, amount_cents),
                        refunded_base_cents = COALESCE(refunded_base_cents, 0),
                        nonrefundable_processing_kept_cents = COALESCE(nonrefundable_processing_kept_cents, processing_fee_cents),
                        nonrefundable_beatfund_kept_cents = COALESCE(nonrefundable_beatfund_kept_cents, beatfund_fee_cents)
                    WHERE base_amount_cents IS NULL
                       OR beatfund_fee_cents IS NULL
                       OR processing_fee_cents IS NULL
                       OR total_paid_cents IS NULL
                       OR refunded_base_cents IS NULL
                       OR nonrefundable_processing_kept_cents IS NULL
                       OR nonrefundable_beatfund_kept_cents IS NULL
                """))
                app.logger.info("[DB] Backfilled payment fee columns (defaults applied)")
            try:
                conn.execute(text("""
                    UPDATE payment p
                    SET booking_id = br.booking_id
                    FROM booking_request br
                    WHERE p.booking_request_id = br.id
                      AND p.booking_id IS NULL
                      AND br.booking_id IS NOT NULL
                """))
                app.logger.info("[DB] Backfilled payment.booking_id from booking_request")
            except Exception:
                pass
    except Exception as e:
        app.logger.warning(f"[DB] Postgres payment fee patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_notification_columns():
    """Add notification columns in Postgres if missing (safe, idempotent)."""
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return

    try:
        with db.engine.begin() as conn:
            rows = conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'notification'
            """)).fetchall()
            existing = {r[0] for r in rows}
            missing = []
            if "actor_user_id" not in existing:
                missing.append("actor_user_id")
            if "event_key" not in existing:
                missing.append("event_key")

            if missing:
                conn.execute(text("""
                    ALTER TABLE notification
                      ADD COLUMN IF NOT EXISTS actor_user_id INTEGER,
                      ADD COLUMN IF NOT EXISTS event_key TEXT;
                """))
                try:
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_actor_user_id ON notification (actor_user_id)"))
                except Exception:
                    pass
                try:
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_notification_event_key ON notification (event_key)"))
                except Exception:
                    pass
                app.logger.warning(f"[DB] Added notification columns: {', '.join(missing)}")
            else:
                app.logger.info("[DB] Notification columns already present")
    except Exception as e:
        app.logger.warning(f"[DB] Postgres notification patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_security_event_table():
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS security_event (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(80) NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    user_id INTEGER,
                    ip VARCHAR(64),
                    user_agent VARCHAR(240),
                    path VARCHAR(200),
                    request_id VARCHAR(40),
                    meta_json TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_event_type ON security_event (event_type)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_severity ON security_event (severity)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_user_id ON security_event (user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_request_id ON security_event (request_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_security_event_created_at ON security_event (created_at)"))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres security_event patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_provider_review_table():
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS provider_review (
                    id SERIAL PRIMARY KEY,
                    booking_id INTEGER NOT NULL UNIQUE,
                    reviewer_user_id INTEGER NOT NULL,
                    provider_user_id INTEGER NOT NULL,
                    rating INTEGER NOT NULL,
                    title VARCHAR(160),
                    body TEXT,
                    status VARCHAR(20) NOT NULL DEFAULT 'visible',
                    reported_count INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (booking_id) REFERENCES booking (id),
                    FOREIGN KEY (reviewer_user_id) REFERENCES "user" (id),
                    FOREIGN KEY (provider_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_review_booking_id ON provider_review (booking_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_provider_user_id ON provider_review (provider_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_reviewer_user_id ON provider_review (reviewer_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_status ON provider_review (status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_review_created_at ON provider_review (created_at)"))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres provider_review patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_provider_availability_tables():
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS provider_settings (
                    id SERIAL PRIMARY KEY,
                    provider_user_id INTEGER NOT NULL UNIQUE,
                    accepting_new_requests BOOLEAN NOT NULL DEFAULT TRUE,
                    onsite BOOLEAN NOT NULL DEFAULT TRUE,
                    remote BOOLEAN NOT NULL DEFAULT TRUE,
                    travel_radius_miles INTEGER,
                    base_location VARCHAR(255),
                    tz VARCHAR(64) NOT NULL DEFAULT 'UTC',
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (provider_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_provider_settings_user_id ON provider_settings (provider_user_id)"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS provider_availability (
                    id SERIAL PRIMARY KEY,
                    provider_user_id INTEGER NOT NULL,
                    day_of_week INTEGER NOT NULL,
                    start_time TIME NOT NULL,
                    end_time TIME NOT NULL,
                    tz VARCHAR(64) NOT NULL DEFAULT 'UTC',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (provider_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_provider_user_id ON provider_availability (provider_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_day_of_week ON provider_availability (day_of_week)"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS provider_availability_exception (
                    id SERIAL PRIMARY KEY,
                    provider_user_id INTEGER NOT NULL,
                    date DATE NOT NULL,
                    start_time TIME,
                    end_time TIME,
                    is_unavailable BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (provider_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_exception_user_id ON provider_availability_exception (provider_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_provider_availability_exception_date ON provider_availability_exception (date)"))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres provider availability patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_support_ticket_message_table():
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS support_ticket_message (
                    id SERIAL PRIMARY KEY,
                    ticket_id INTEGER NOT NULL,
                    author_user_id INTEGER NOT NULL,
                    body TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (ticket_id) REFERENCES support_ticket (id),
                    FOREIGN KEY (author_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_ticket_id ON support_ticket_message (ticket_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_author_user_id ON support_ticket_message (author_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_support_ticket_message_created_at ON support_ticket_message (created_at)"))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres support_ticket_message patch skipped: {type(e).__name__}: {e}")


def _ensure_postgres_booking_dispute_message_table():
    try:
        if db.engine.url.get_backend_name() != "postgresql":
            return
    except Exception:
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS booking_dispute_message (
                    id SERIAL PRIMARY KEY,
                    dispute_id INTEGER NOT NULL,
                    author_user_id INTEGER NOT NULL,
                    body TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (dispute_id) REFERENCES booking_dispute (id),
                    FOREIGN KEY (author_user_id) REFERENCES "user" (id)
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_dispute_id ON booking_dispute_message (dispute_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_author_user_id ON booking_dispute_message (author_user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_booking_dispute_message_created_at ON booking_dispute_message (created_at)"))
    except Exception as e:
        app.logger.warning(f"[DB] Postgres booking_dispute_message patch skipped: {type(e).__name__}: {e}")


def _ensure_sqlite_careers_tables():
    """Create careers tables (job_post and job_application) if missing"""
    if db.engine.url.get_backend_name() != "sqlite":
        return
    
    # Create job_post table if missing
    if not _sqlite_has_table("job_post"):
        db.session.execute(text("""
            CREATE TABLE job_post (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title VARCHAR(200) NOT NULL,
                department VARCHAR(120),
                location VARCHAR(120),
                employment_type VARCHAR(80),
                level VARCHAR(80),
                description TEXT NOT NULL,
                responsibilities TEXT,
                requirements TEXT,
                nice_to_have TEXT,
                how_to_apply TEXT,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_job_post_is_active ON job_post (is_active)"))
        db.session.commit()
    
    # Create job_application table if missing
    if not _sqlite_has_table("job_application"):
        db.session.execute(text("""
            CREATE TABLE job_application (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                full_name VARCHAR(150) NOT NULL,
                email VARCHAR(255) NOT NULL,
                phone VARCHAR(40),
                portfolio_url VARCHAR(500),
                linkedin_url VARCHAR(500),
                cover_letter TEXT,
                resume_filename VARCHAR(255),
                status VARCHAR(32) NOT NULL DEFAULT 'new',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES job_post (id)
            )
        """))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_job_application_job_id ON job_application (job_id)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_job_application_status ON job_application (status)"))
        db.session.execute(text("CREATE INDEX IF NOT EXISTS ix_job_application_created_at ON job_application (created_at)"))
    db.session.commit()


@app.before_request
def _bootstrap_schema_once():
    """Run SQLite auto-migrations only in dev or if explicitly allowed"""
    global _SCHEMA_BOOTSTRAP_DONE
    if _SCHEMA_BOOTSTRAP_DONE:
        return
    
    # Disable auto-migrations in production
    # In production with Postgres, rely on Alembic migrations only
    try:
        is_sqlite = db.engine.url.get_backend_name() == "sqlite"
    except Exception as e:
        app.logger.warning(f"Could not determine database backend: {e}")
        is_sqlite = False
    
    if is_prod() and not is_sqlite:
        # Production Postgres: check if tables exist, create if not (safety check)
        try:
            with db.engine.begin() as conn:
                result = conn.execute(text("""
                    SELECT COUNT(*) as table_count
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                count = result.scalar() or 0
                if count == 0:
                    app.logger.warning("No tables found in Postgres - creating all tables now")
                    db.metadata.create_all(bind=conn)
                    app.logger.info("✓ Database tables created successfully in production")
        except Exception as e:
            app.logger.warning(f"Could not auto-create tables in production: {type(e).__name__}: {str(e)}")

        try:
            _ensure_postgres_booking_fee_columns()
            _ensure_postgres_booking_request_duration_column()
            _ensure_postgres_beat_audio_columns()
            _ensure_postgres_beat_purchase_table()
            _ensure_postgres_payment_fee_columns()
            _ensure_postgres_notification_columns()
            _ensure_postgres_security_event_table()
            _ensure_postgres_provider_review_table()
            _ensure_postgres_provider_availability_tables()
            _ensure_postgres_support_ticket_message_table()
            _ensure_postgres_booking_dispute_message_table()
        except Exception:
            pass
        
        _SCHEMA_BOOTSTRAP_DONE = True
        return
    
    # Only run auto-migrations in dev, or if SQLite is explicitly allowed in non-prod
    if is_prod() and is_sqlite:
        app.logger.warning("Production mode with SQLite detected - auto-migrations disabled for safety")
        _SCHEMA_BOOTSTRAP_DONE = True
        return
    
    _SCHEMA_BOOTSTRAP_DONE = True
    try:
        _ensure_sqlite_follow_table_name_and_indexes()
        _ensure_sqlite_booking_request_booking_id()
        _ensure_sqlite_notifications_table()
        _ensure_sqlite_activity_broadcast_tables()
        _ensure_sqlite_booking_chat_tables()
        _ensure_sqlite_audit_log_finance_columns()
        _ensure_sqlite_stripe_webhook_event_table()
        _ensure_sqlite_security_event_table()
        _ensure_sqlite_alert_table()
        _ensure_sqlite_uploaded_file_table()
        _ensure_sqlite_user_stripe_connect_columns()
        _ensure_sqlite_careers_tables()
        _ensure_sqlite_waitlist_table()
        _ensure_sqlite_beat_stripe_columns()
        _ensure_sqlite_beat_audio_columns()
        _ensure_sqlite_beat_purchase_table()
        _ensure_sqlite_order_payment_columns()
        _ensure_sqlite_booking_payment_columns()
        _ensure_sqlite_payout_affiliate_tables()
        _ensure_sqlite_provider_review_table()
        _ensure_sqlite_provider_availability_tables()
        _ensure_sqlite_support_ticket_message_table()
        _ensure_sqlite_booking_dispute_message_table()
        _ensure_postgres_booking_fee_columns()
        _ensure_postgres_booking_request_duration_column()
        _ensure_postgres_beat_audio_columns()
        _ensure_postgres_beat_purchase_table()
        _ensure_postgres_payment_fee_columns()
        _ensure_postgres_notification_columns()
        _ensure_postgres_provider_review_table()
        _ensure_postgres_provider_availability_tables()
        _ensure_postgres_support_ticket_message_table()
        _ensure_postgres_booking_dispute_message_table()
    except Exception as e:
        app.logger.error(f"SQLite auto-migration failed: {type(e).__name__}: {str(e)}", exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


# =========================================================
# Notifications System
# =========================================================
def create_notification(
    user_id: int,
    kind: str,
    title: str,
    body: str = None,
    url: str = None,
    *,
    actor_user_id: int | None = None,
    event_key: str | None = None,
    commit: bool = False,
) -> Notification:
    """Create a notification for a user (dedupe by event_key if provided)."""
    if event_key:
        existing = Notification.query.filter_by(user_id=user_id, event_key=event_key).first()
        if existing:
            return existing

    notif = Notification(
        user_id=user_id,
        actor_user_id=actor_user_id,
        kind=kind,
        title=title,
        body=body,
        url=url,
        event_key=event_key,
    )
    db.session.add(notif)
    if commit:
        db.session.commit()
    return notif


def get_unread_notification_count(user_id: int) -> int:
    """Get count of unread notifications for a user"""
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def get_recent_notifications(user_id: int, limit: int = 8) -> list[Notification]:
    """Get recent notifications for a user, latest first"""
    return Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(limit).all()


def mark_notification_read(user_id: int, notif_id: int) -> bool:
    """Mark a notification as read if it belongs to the user"""
    notif = Notification.query.filter_by(id=notif_id, user_id=user_id).first()
    if notif:
        notif.is_read = True
        db.session.commit()
        return True
    return False


def mark_all_notifications_read(user_id: int) -> int:
    """Mark all unread notifications as read for a user, return count"""
    count = Notification.query.filter_by(user_id=user_id, is_read=False).update({"is_read": True})
    db.session.commit()
    return count


def _safe_json_dumps(payload: dict | None) -> str:
    try:
        return json.dumps(payload or {}, ensure_ascii=False, default=str)
    except Exception:
        return "{}"


def _safe_json_loads(payload_json: str | None) -> dict:
    if not payload_json:
        return {}
    try:
        v = json.loads(payload_json)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def _coerce_activity_event_type(event_type: ActivityEventType | str) -> ActivityEventType:
    if isinstance(event_type, ActivityEventType):
        return event_type
    try:
        return ActivityEventType(str(event_type))
    except Exception:
        # Best-effort fallback: treat unknown types as listing_updated
        return ActivityEventType.listing_updated


def build_activity_message(event_type: ActivityEventType | str, payload: dict | None, actor: User | None) -> tuple[str, str, str]:
    """
    Convert (event_type, payload, actor) -> (title, body, url).
    Must be resilient to missing payload fields.
    """
    et = _coerce_activity_event_type(event_type)
    p = payload or {}

    actor_name = "Someone"
    actor_username = None
    try:
        if actor:
            actor_name = getattr(actor, "display_name", None) or getattr(actor, "username", None) or actor_name
            actor_username = getattr(actor, "username", None)
    except Exception:
        pass

    # Defaults
    title = "New Activity"
    body = f"{actor_name} posted an update."
    url = url_for("notifications_page")

    if et == ActivityEventType.beat_published:
        beat_id = p.get("beat_id")
        beat_title = p.get("beat_title") or "a new beat"
        title = "New Beat Uploaded"
        body = f"{actor_name} uploaded “{beat_title}”. Tap to listen."
        try:
            if beat_id:
                url = url_for("market_confirm", beat_id=int(beat_id))
            else:
                url = url_for("market_index")
        except Exception:
            url = "/market"

    elif et == ActivityEventType.listing_published:
        listing_title = p.get("listing_title") or "a new service"
        title = "New Service Listed"
        body = f"{actor_name} added “{listing_title}”."
        url = p.get("listing_url") or url
        if not url and actor_username:
            url = url_for("provider_portfolio_public", username=actor_username)

    elif et == ActivityEventType.listing_updated:
        listing_title = p.get("listing_title") or "a service"
        title = "Listing Updated"
        body = f"{actor_name} updated “{listing_title}”."
        url = p.get("listing_url") or url
        if not url and actor_username:
            url = url_for("provider_portfolio_public", username=actor_username)

    elif et == ActivityEventType.listing_files_uploaded:
        listing_title = p.get("listing_title") or "a service"
        file_count = p.get("file_count")
        try:
            file_count_int = int(file_count) if file_count is not None else 0
        except Exception:
            file_count_int = 0

        title = "New Files Added"
        if file_count_int > 0:
            body = f"{actor_name} added {file_count_int} new files to “{listing_title}”."
        else:
            body = f"{actor_name} added new files to “{listing_title}”."
        url = p.get("listing_url") or url
        if not url and actor_username:
            url = url_for("provider_portfolio_public", username=actor_username)

    elif et == ActivityEventType.chat_message:
        booking_id = p.get("booking_id")
        sender_name = p.get("sender_name") or actor_name
        preview = (p.get("preview") or "").strip()
        title = "New Message"
        body = f"{sender_name}: {preview}" if preview else f"{sender_name} sent you a message."
        try:
            if booking_id:
                url = url_for("booking_chat", booking_id=int(booking_id))
            else:
                url = url_for("notifications_page")
        except Exception:
            url = "/notifications"

    # Enforce internal-only navigation for safety (templates expect this)
    try:
        if url and not str(url).startswith("/"):
            url = url_for("notifications_page")
    except Exception:
        url = "/notifications"

    return title, body, url


def _chat_message_preview(text: str, max_len: int = 80) -> str:
    try:
        s = re.sub(r"\s+", " ", (text or "").strip())
    except Exception:
        s = (text or "").strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _should_create_chat_notification(recipient_user_id: int, conversation_id: int) -> bool:
    """
    Anti-spam: if recipient already has an unread CHAT_MESSAGE notification for
    this same conversation created within the last 2 minutes, skip.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=2)
    rows = (
        NotificationRecipient.query
        .filter(
            NotificationRecipient.user_id == int(recipient_user_id),
            NotificationRecipient.read_at.is_(None),
        )
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .filter(
            ActivityEvent.event_type == ActivityEventType.chat_message,
            ActivityEvent.created_at >= cutoff,
        )
        .order_by(ActivityEvent.created_at.desc())
        .limit(25)
        .all()
    )
    for r in rows:
        p = _safe_json_loads(getattr(r.event, "payload_json", None))
        try:
            if int(p.get("conversation_id") or 0) == int(conversation_id):
                return False
        except Exception:
            continue
    return True


def notify_chat_message(
    *,
    booking_id: int,
    conversation_id: int,
    message_id: int,
    sender_user_id: int,
    recipient_user_id: int,
    message_text: str,
) -> int:
    """
    Create a direct CHAT_MESSAGE notification for recipient via ActivityEvent + NotificationRecipient.
    Returns event_id (or 0 if skipped).
    """
    if int(recipient_user_id) == int(sender_user_id):
        return 0

    # Recipient must be a participant
    recip_part = ConversationParticipant.query.filter_by(
        conversation_id=int(conversation_id),
        user_id=int(recipient_user_id),
    ).first()
    if not recip_part:
        return 0

    # Do not notify if recipient blocked the sender (is_blocked flag belongs to the blocker)
    if bool(getattr(recip_part, "is_blocked", False)):
        return 0

    if not _should_create_chat_notification(int(recipient_user_id), int(conversation_id)):
        return 0

    sender = User.query.get(int(sender_user_id))
    payload = {
        "booking_id": int(booking_id),
        "conversation_id": int(conversation_id),
        "message_id": int(message_id),
        "sender_name": (getattr(sender, "display_name", None) or getattr(sender, "username", None) or "Someone") if sender else "Someone",
        "sender_role": (sender.role if sender and getattr(sender, "role", None) else None),
        "preview": _chat_message_preview(message_text, max_len=80),
        "url": url_for("booking_chat", booking_id=int(booking_id)),
    }

    ev = ActivityEvent(
        event_type=ActivityEventType.chat_message,
        actor_user_id=int(sender_user_id),
        audience="DIRECT",
        payload_json=_safe_json_dumps(payload),
    )
    db.session.add(ev)
    db.session.flush()
    db.session.add(NotificationRecipient(event_id=ev.id, user_id=int(recipient_user_id)))
    db.session.commit()
    return int(ev.id)


def log_admin_action(
    action_type: ActivityEventType | str,
    actor_admin_id: int,
    target_type: str | None = None,
    target_id: int | None = None,
    summary: str | None = None,
    payload_dict: dict | None = None,
    url: str | None = None,
    *,
    include_actor: bool = True,
) -> int:
    """
    Internal admin-only activity log (visible ONLY to admins).
    Creates ActivityEvent(audience="ADMINS") and NotificationRecipient rows for all admin users.
    """
    try:
        actor = User.query.get(int(actor_admin_id))
        if not actor or getattr(actor, "role", None) != RoleEnum.admin:
            return 0
    except Exception:
        return 0

    et = _coerce_activity_event_type(action_type)

    safe_url = None
    try:
        if url and str(url).startswith("/"):
            safe_url = str(url)
    except Exception:
        safe_url = None

    payload = {
        "action_type": (et.value if hasattr(et, "value") else str(action_type)),
        "target_type": target_type,
        "target_id": target_id,
        "summary": summary,
        "url": safe_url,
        "data": payload_dict or {},
        "actor_username": getattr(actor, "username", None),
    }

    ev = ActivityEvent(
        event_type=et,
        actor_user_id=int(actor_admin_id),
        audience="ADMINS",
        payload_json=_safe_json_dumps(payload),
    )
    db.session.add(ev)
    db.session.flush()

    q = db.session.query(User.id).filter(User.role == "admin")
    if not include_actor:
        q = q.filter(User.id != int(actor_admin_id))
    admin_ids = [row[0] for row in q.all()]
    if admin_ids:
        db.session.bulk_save_objects([NotificationRecipient(event_id=ev.id, user_id=uid) for uid in admin_ids])

    db.session.commit()
    return int(ev.id)


def broadcast_event(
    event_type: ActivityEventType | str,
    actor_user_id: int,
    payload_dict: dict | None,
    audience: str = "ALL",
    exclude_actor: bool = True,
) -> int:
    """
    Creates one ActivityEvent + NotificationRecipient rows for all users (except actor by default).
    Always commits and returns event_id.
    """
    # Exclude admin-originated broadcasts (requested behavior)
    try:
        actor = User.query.get(int(actor_user_id))
        if actor and getattr(actor, "role", None) == RoleEnum.admin:
            return 0
    except Exception:
        # Best effort: if we can't resolve actor, continue
        pass

    et = _coerce_activity_event_type(event_type)
    payload_json = _safe_json_dumps(payload_dict)

    ev = ActivityEvent(
        event_type=et,
        actor_user_id=int(actor_user_id),
        audience=(audience or "ALL"),
        payload_json=payload_json,
    )
    db.session.add(ev)
    db.session.flush()  # get ev.id

    # Determine audience
    q = db.session.query(User.id)
    aud = (audience or "ALL").strip().upper()
    if aud.startswith("ROLE:"):
        role_raw = aud.split(":", 1)[1].strip().lower()
        q = q.filter(User.role == role_raw)

    if exclude_actor:
        q = q.filter(User.id != int(actor_user_id))

    user_ids = [row[0] for row in q.all()]
    if user_ids:
        recs = [NotificationRecipient(event_id=ev.id, user_id=uid) for uid in user_ids]
        # bulk insert for speed; safe for simple rows
        db.session.bulk_save_objects(recs)

    db.session.commit()
    return int(ev.id)


# =========================================================
# Booking Chat Helpers (moderation + rate limiting)
# =========================================================
CHAT_ALLOWED_BOOKING_STATUSES: set[str] = {
    BOOKING_STATUS_PENDING,
    BOOKING_STATUS_ACCEPTED,
    BOOKING_STATUS_CONFIRMED,
    BOOKING_STATUS_HOLD_PAID,
    BOOKING_STATUS_PAID,
    BOOKING_STATUS_COMPLETED,
}

CHAT_RATE_LIMIT_PER_MINUTE = 10

# Configurable denylist (keep it short; expand as needed)
PROFANITY_DENYLIST: list[str] = [
    "fuck", "shit", "bitch", "asshole", "cunt", "nigger", "faggot", "retard",
]

THREAT_PHRASES: list[str] = [
    "kill you", "die", "i will kill", "shoot you", "rape", "burn your", "hurt you",
]


def _luhn_check(number: str) -> bool:
    """Return True if number passes Luhn checksum."""
    try:
        digits = [int(c) for c in number if c.isdigit()]
    except Exception:
        return False
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
    return (total % 10) == 0


_CARD_CANDIDATE_RE = re.compile(r"(?:\d[ -]?){13,25}")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[\s\-\.]?)?(?:\(\s*\d{3}\s*\)|\d{3})[\s\-\.]?\d{3}[\s\-\.]?\d{4}(?!\d)"
)
_CONTACT_HINT_RE = re.compile(r"\b(contact me|call me|text me|dm me|email me|reach me)\b", re.I)


def validate_message_text(text: str) -> tuple[bool, str]:
    """
    Returns (ok, reason_code). reason_code is one of ModerationReason.*.value or "".
    """
    if text is None:
        return False, ModerationReason.profanity.value

    body = (text or "").strip()
    if not body:
        return False, "EMPTY"

    # PII: email / contact hints
    if _EMAIL_RE.search(body) or _CONTACT_HINT_RE.search(body) or ("@" in body and " " not in body and _EMAIL_RE.search(body)):
        return False, ModerationReason.pii_email.value

    # PII: phone
    if _PHONE_RE.search(body):
        return False, ModerationReason.pii_phone.value

    # PII: card (regex candidate + Luhn)
    for m in _CARD_CANDIDATE_RE.finditer(body):
        cand = re.sub(r"\D", "", m.group(0))
        if 13 <= len(cand) <= 19 and _luhn_check(cand):
            return False, ModerationReason.pii_card.value

    # Profanity denylist (word boundaries)
    lowered = body.lower()
    for w in PROFANITY_DENYLIST:
        if re.search(rf"\b{re.escape(w)}\b", lowered, re.I):
            return False, ModerationReason.profanity.value

    # Threat phrases
    for phrase in THREAT_PHRASES:
        if phrase.lower() in lowered:
            return False, ModerationReason.threat.value

    return True, ""


def get_or_create_booking_conversation(booking_id: int) -> Conversation:
    """
    Ensure a conversation exists for booking_id and both participants are present.
    """
    booking = Booking.query.get_or_404(int(booking_id))
    conv = Conversation.query.filter_by(booking_id=booking.id).first()
    if not conv:
        conv = Conversation(booking_id=booking.id, status=ConversationStatus.active)
        db.session.add(conv)
        db.session.flush()

    # Ensure participants exist
    for uid in (booking.client_id, booking.provider_id):
        if uid is None:
            continue
        exists = ConversationParticipant.query.filter_by(conversation_id=conv.id, user_id=uid).first()
        if not exists:
            u = User.query.get(uid)
            db.session.add(ConversationParticipant(
                conversation_id=conv.id,
                user_id=uid,
                role_at_time=(u.role if u and getattr(u, "role", None) else None),
            ))

    db.session.commit()
    return conv


def can_send_message(user_id: int, conversation_id: int) -> tuple[bool, str]:
    """
    Enforce participant membership, conversation status, block rules, and rate limit.
    Returns (ok, reason_code).
    """
    conv = Conversation.query.get(int(conversation_id))
    if not conv:
        return False, "NOT_FOUND"
    if conv.status in (ConversationStatus.closed,):
        return False, "CLOSED"

    # Must be a participant (admins allowed to view but not necessarily send; keep strict)
    me = ConversationParticipant.query.filter_by(conversation_id=conv.id, user_id=int(user_id)).first()
    if not me:
        return False, "FORBIDDEN"

    # If the other participant blocked me, stop
    other_block = (
        ConversationParticipant.query
        .filter(
            ConversationParticipant.conversation_id == conv.id,
            ConversationParticipant.user_id != int(user_id),
            ConversationParticipant.is_blocked.is_(True),
        )
        .first()
    )
    if other_block:
        return False, ModerationReason.blocked.value

    # Rate limit: N messages/minute per user per conversation
    window_start = datetime.utcnow() - timedelta(minutes=1)
    recent_count = (
        Message.query
        .filter(
            Message.conversation_id == conv.id,
            Message.sender_user_id == int(user_id),
            Message.created_at >= window_start,
            Message.delivery_status == MessageDeliveryStatus.sent,
        )
        .count()
    )
    if recent_count >= CHAT_RATE_LIMIT_PER_MINUTE:
        return False, ModerationReason.rate_limit.value

    return True, ""


def send_email(to_email: str, subject: str, text_body: str) -> bool:
    """Send email via SMTP or print to console in dev"""
    if IS_DEV and not os.getenv("SMTP_HOST"):
        app.logger.info("EMAIL (dev mode - SMTP not configured) To: %s Subject: %s", to_email, subject)
        app.logger.debug(text_body)
        return True
    
    try:
        import smtplib
        from email.message import EmailMessage
        
        smtp_host = os.getenv("SMTP_HOST", "").strip()
        smtp_from = os.getenv("SMTP_FROM", "").strip()
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_tls = os.getenv("SMTP_TLS", "true").lower() == "true"
        smtp_user = os.getenv("SMTP_USER", "").strip()
        smtp_pass = os.getenv("SMTP_PASS", "").strip()
        if not smtp_host:
            if IS_DEV:
                print(f"[DEV] Email not sent - SMTP_HOST not configured")
            return False
        
        
        msg = EmailMessage()
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(text_body)
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        return True
    except Exception as e:
        if IS_DEV:
            app.logger.exception("Email send failed (dev): %s", e)
        return False


def notify_user(
    user: User,
    kind: str,
    title: str,
    body: str = None,
    url: str = None,
    *,
    actor_user_id: int | None = None,
    event_key: str | None = None,
    email: bool = False,
    commit: bool = False,
) -> Notification:
    """Create a notification and optionally send email. Never commits by default - must be committed at route level."""
    notif = create_notification(
        user.id,
        kind,
        title,
        body,
        url,
        actor_user_id=actor_user_id,
        event_key=event_key,
        commit=commit,
    )
    return notif


def send_notification_email(notif: Notification, user: User) -> bool:
    """Send email for a notification. Call this AFTER transaction commit."""
    if not user.email:
        return False
    email_enabled = getattr(user, "email_notifications_enabled", True)
    if not email_enabled:
        return False
    
    app_base_url = os.getenv("APP_BASE_URL", "").strip()
    email_body = f"{notif.title}\n\n"
    if notif.body:
        email_body += f"{notif.body}\n\n"
    if notif.url and app_base_url:
        full_url = f"{app_base_url}{notif.url}" if notif.url.startswith("/") else f"{app_base_url}/{notif.url}"
        email_body += f"View: {full_url}\n"
    email_body += f"\n---\nBeatFund"
    
    if send_email(user.email, notif.title, email_body):
        notif.emailed_at = datetime.utcnow()
        db.session.commit()
        return True
    return False


# =========================================================
# Routes: Core / Auth
# =========================================================
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("route_to_dashboard"))
    return render_template("home.html")


@app.route("/waitlist", methods=["GET"], endpoint="waitlist_page")
def waitlist_page():
    """Waitlist landing page - clone of homepage with waitlist form"""
    if current_user.is_authenticated:
        return redirect(url_for("route_to_dashboard"))
    
    count = WaitlistEntry.query.count()
    return render_template("waitlist.html", waitlist_count=count)


@app.route("/waitlist", methods=["POST"], endpoint="waitlist_signup")
def waitlist_signup():
    """Handle waitlist signup form submission"""
    if current_user.is_authenticated:
        # Allow authenticated users to join waitlist if they want
        pass
    
    # Rate limiting
    if not check_rate_limit("waitlist_signup", max_requests=8, window_seconds=300):
        flash("Too many requests. Please try again later.", "error")
        return redirect(url_for("waitlist_page"))
    
    # Get and validate form data
    email = request.form.get("email", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    role_interest = request.form.get("role_interest", "").strip()
    note = request.form.get("note", "").strip()
    
    # Validate email
    if not email:
        flash("Email is required.", "error")
        return redirect(url_for("waitlist_page"))
    
    if not validate_email(email):
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("waitlist_page"))
    
    # Sanitize inputs
    email = sanitize_input(email, max_length=255)
    full_name = sanitize_input(full_name, max_length=150) if full_name else None
    role_interest = sanitize_input(role_interest, max_length=80) if role_interest else None
    note = sanitize_input(note, max_length=300) if note else None
    
    # Check if email already exists
    existing = WaitlistEntry.query.filter_by(email=email).first()
    if existing:
        flash("You're already on the waitlist!", "info")
        return redirect(url_for("waitlist_page"))
    
    # Create new waitlist entry
    try:
        entry = WaitlistEntry(
            email=email,
            full_name=full_name,
            role_interest=role_interest,
            note=note,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:200]
        )
        db.session.add(entry)
        db.session.commit()
        
        flash("Thanks! You've been added to the waitlist.", "success")
        log_security_event("waitlist_signup", f"New waitlist entry: {email}", "info")
    except IntegrityError:
        db.session.rollback()
        flash("You're already on the waitlist!", "info")
    except Exception as e:
        db.session.rollback()
        log_security_event("waitlist_signup_error", f"Error adding waitlist entry: {str(e)}", "error")
        flash("An error occurred. Please try again.", "error")
    
    return redirect(url_for("waitlist_page"))


# =========================================================
# Policy Pages
# =========================================================

@app.route("/terms")
def terms():
    return render_template("policies/terms.html")


@app.route("/offline")
def offline():
    return render_template("offline.html")


@app.route("/privacy")
def privacy():
    return render_template("policies/privacy.html")


@app.route("/cookies")
def cookies():
    return render_template("policies/cookies.html")


@app.route("/fees")
def fees():
    return render_template("policies/fees.html")


@app.route("/refunds")
def refunds():
    return render_template("policies/refunds.html")


@app.route("/payouts")
def payouts():
    return render_template("policies/payouts.html")


@app.route("/affiliate-marketing", endpoint="affiliate_marketing")
def affiliate_marketing():
    return render_template(
        "policies/affiliate_marketing.html",
        contact_email=AFFILIATE_CONTACT_EMAIL,
    )


@app.route("/affiliate/apply", endpoint="affiliate_apply")
def affiliate_apply():
    return render_template("affiliate_apply.html")


@app.route("/disputes")
def disputes():
    return render_template("policies/disputes.html")


@app.route("/wallet-disclosure")
def wallet_disclosure():
    return render_template("policies/wallet_disclosure.html")


@app.route("/acceptable-use")
def acceptable_use():
    return redirect(url_for("aup"))


@app.route("/risk-disclosures")
def risk_disclosures():
    return redirect(url_for("risk"))


@app.route("/disputes-and-refunds")
def disputes_and_refunds():
    # Simple combined landing page for MVP: reuse disputes page which links out to refunds.
    return redirect(url_for("disputes"))


@app.route("/policies/kyc", endpoint="kyc_policy")
def kyc_policy():
    return render_template("policies/kyc.html")


@app.route("/aml")
def aml():
    return render_template("policies/aml.html")


@app.route("/risk")
def risk():
    return render_template("policies/risk.html")


@app.route("/aup")
def aup():
    return render_template("policies/aup.html")


# =========================================================
# Careers Routes (Public)
# =========================================================
@app.route("/careers")
def careers():
    """List all active job postings"""
    jobs = JobPost.query.filter_by(is_active=True).order_by(JobPost.created_at.desc()).all()
    return render_template("careers/index.html", jobs=jobs)


@app.route("/careers/<int:job_id>")
def careers_detail(job_id):
    """View job details"""
    job = JobPost.query.get_or_404(job_id)
    if not job.is_active:
        flash("This job posting is no longer active.", "error")
        return redirect(url_for("careers"))
    return render_template("careers/detail.html", job=job)


@app.route("/careers/apply", methods=["GET", "POST"])
@app.route("/careers/<int:job_id>/apply", methods=["GET", "POST"])
def careers_apply(job_id=None):
    """Apply for a job (general or specific)"""
    job = None
    if job_id:
        job = JobPost.query.get_or_404(job_id)
        if not job.is_active:
            flash("This job posting is no longer active.", "error")
            return redirect(url_for("careers"))
    
    if request.method == "POST":
        # Rate limiting
        if not check_rate_limit("job_apply", max_requests=6, window_seconds=600):
            flash("Too many applications. Please wait a few minutes before trying again.", "error")
            return render_template("careers/apply.html", job=job)
        
        # Validate inputs
        full_name = sanitize_input(request.form.get("full_name", "").strip(), max_length=150)
        email = request.form.get("email", "").strip()
        phone = sanitize_input(request.form.get("phone", "").strip(), max_length=40)
        portfolio_url = request.form.get("portfolio_url", "").strip()
        linkedin_url = request.form.get("linkedin_url", "").strip()
        cover_letter = sanitize_input(request.form.get("cover_letter", ""), max_length=8000)
        resume_file = request.files.get("resume")
        
        errors = []
        
        if not full_name:
            errors.append("Full name is required.")
        if not email:
            errors.append("Email is required.")
        elif not validate_email(email):
            errors.append("Invalid email format.")
        if phone and not re.match(r'^[\d\s\-\+\(\)]+$', phone):
            errors.append("Invalid phone number format.")
        if portfolio_url and not _validate_url_optional(portfolio_url):
            errors.append("Portfolio URL must start with http:// or https://")
        if linkedin_url and not _validate_url_optional(linkedin_url):
            errors.append("LinkedIn URL must start with http:// or https://")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("careers/apply.html", job=job)
        
        # Handle resume upload
        resume_filename = None
        if resume_file and resume_file.filename:
            resume_filename = _save_file(resume_file, ALLOWED_RESUME)
            if not resume_filename:
                flash("Invalid resume file. Please upload PDF, DOC, or DOCX (max 8MB).", "error")
                return render_template("careers/apply.html", job=job)
        
        # Create application
        application = JobApplication(
            job_id=job.id if job else None,
            full_name=full_name,
            email=email,
            phone=phone if phone else None,
            portfolio_url=portfolio_url if portfolio_url else None,
            linkedin_url=linkedin_url if linkedin_url else None,
            cover_letter=cover_letter if cover_letter else None,
            resume_filename=resume_filename,
            status="new"
        )
        
        db.session.add(application)
        db.session.commit()
        
        # Notify all active admins
        job_title = job.title if job else "General Application"
        admins = User.query.filter_by(role=RoleEnum.admin, is_active_col=True).all()
        for admin in admins:
            notify_user(
                admin,
                kind="info",
                title="New job application",
                body=f"{full_name} applied for {job_title}",
                url=url_for("admin_job_applications"),
                email=admin.email_notifications_enabled and bool(admin.email)
            )
        
        flash("Application submitted successfully! We'll review it and get back to you soon.", "success")
        return redirect(url_for("careers"))
    
    return render_template("careers/apply.html", job=job)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("route_to_dashboard"))
    
    if request.method == "POST":
        full_name = (request.form.get("name") or "").strip()
        artist_name = (request.form.get("artist_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        raw_username = (request.form.get("username") or "").strip()
        username = raw_username.lstrip("@").lower()
        referral_code = (request.form.get("referral_code") or request.args.get("ref") or "").strip()

        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        role_key = (request.form.get("role") or "").strip()

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("register"))
        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("register"))
        if not validate_email(email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))
        if not validate_username(username):
            flash("Username must be 3-30 characters and contain only letters, numbers, underscores, and dashes.", "error")
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

        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name or None,
                artist_name=artist_name or None,
                role=chosen_role.value,
            )

            if referral_code:
                try:
                    affiliate = Affiliate.query.filter(
                        func.lower(Affiliate.code) == referral_code.lower(),
                        Affiliate.status == AffiliateStatus.active,
                    ).first()
                except Exception:
                    affiliate = None
                if affiliate:
                    user.referred_by_affiliate_id = affiliate.id

            if IS_DEV:
                user.kyc_status = KYCStatus.approved.value

            user.set_password(password)
            db.session.add(user)
            db.session.flush()

            get_or_create_wallet(user.id, commit=False)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That email or username is already registered.", "error")
            return redirect(url_for("register"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(
                f"Register failed for {email or 'unknown'}: {type(e).__name__}: {e}",
                exc_info=True,
            )
            flash("We couldn't create your account. Please try again.", "error")
            return redirect(url_for("register"))

        login_user(user)
        flash("Account created!", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("register.html", referral_code=(request.args.get("ref") or "").strip())


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
    if current_user.is_authenticated:
        return redirect(url_for("route_to_dashboard"))
    
    if request.method == "POST":
        try:
            remote_addr = request.remote_addr or "unknown"

            if _too_many_failed_logins(remote_addr):
                flash("Too many failed login attempts. Please wait a few minutes and try again.", "error")
                return redirect(url_for("login"))

            raw_identifier = (
                (request.form.get("identifier") or "").strip()
                or (request.form.get("username") or "").strip()
            )
            password = (request.form.get("password") or "").strip()

            # Security: Sanitize input
            raw_identifier = sanitize_input(raw_identifier, max_length=255)
            password = sanitize_input(password, max_length=500)

            if not raw_identifier or not password:
                flash("Please enter your email/username and password.", "error")
                return redirect(url_for("login"))
            
            # Security: Additional rate limiting on login attempts
            if not check_rate_limit("login", max_requests=5, window_seconds=300):
                log_security_event("login_rate_limit", f"Rate limited login attempt from {remote_addr}", "warning")
                flash("Too many login attempts. Please wait a few minutes and try again.", "error")
                return redirect(url_for("login"))

            identifier = raw_identifier.lower().strip()

            app.logger.info(f"[LOGIN] Starting login attempt for identifier: {identifier}")
            
            if "@" in identifier and "." in identifier:
                app.logger.info(f"[LOGIN] Looking up by email: {identifier}")
                user = User.query.filter(func.lower(User.email) == identifier).first()
                lookup_type = "email"
            else:
                handle = identifier.lstrip("@")
                app.logger.info(f"[LOGIN] Looking up by username: {handle}")
                user = User.query.filter(func.lower(User.username) == handle).first()
                lookup_type = "username"

            app.logger.info(f"[LOGIN] User query completed. User found: {user is not None}")
            
            # Debug logging for login attempts
            if IS_DEV:
                app.logger.debug(f"Login attempt: identifier='{identifier}' (type={lookup_type}), user_found={user is not None}")
                if user:
                    app.logger.debug(f"User found: id={user.id}, username={user.username}, email={user.email}, has_password_hash={bool(user.password_hash)}")

            if not user:
                _register_failed_login(remote_addr)
                if IS_DEV:
                    app.logger.warning(f"Login failed: User not found for identifier '{identifier}' (type={lookup_type})")
                flash("Invalid credentials.", "error")
                return redirect(url_for("login"))
            
            app.logger.info(f"[LOGIN] Checking password for user: {user.username}")
            if not user.check_password(password):
                _register_failed_login(remote_addr)
                if IS_DEV:
                    app.logger.warning(f"Login failed: Password mismatch for user '{user.username}' (ID: {user.id})")
                flash("Invalid credentials.", "error")
                return redirect(url_for("login"))

            app.logger.info(f"[LOGIN] Password matched. Checking if account is active")
            if not user.is_active_col:
                flash("This account is disabled.", "error")
                return redirect(url_for("login"))

            _clear_failed_logins(remote_addr)
            app.logger.info(f"[LOGIN] Logging in user: {user.username}")
            login_user(user)

            if is_password_expired(user):
                flash("For security, your admin password must be updated before continuing.", "error")
                return redirect(url_for("force_password_reset"))

            app.logger.info(f"[LOGIN] Login successful for user: {user.username}")
            return redirect(url_for("route_to_dashboard"))
            
        except Exception as login_error:
            app.logger.error(f"[LOGIN] EXCEPTION during login: {type(login_error).__name__}: {str(login_error)}", exc_info=True)
            flash("An error occurred during login. Please try again.", "error")
            return redirect(url_for("login"))

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
            if IS_DEV:
                app.logger.info("Password reset link (dev): %s", reset_link)

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
def media_file(filename, *, as_attachment: bool = False, download_name: str | None = None):
    """
    Secure media access for uploaded files.
    - Eliminates IDOR: no "serve any filename" default behavior.
    - Uses UploadedFile rows and/or Beat/Portfolio mappings to authorize access.
    - Enforces scan gating in production for ALL files (public + private).
    """

    # --- Determine file record (UploadedFile or known DB mapping) ---
    uf = get_uploaded_file_by_key(filename)
    inferred_purpose: UploadedFilePurpose | None = None
    inferred_owner_id: int | None = None
    beat: Beat | None = None

    if not uf:
        # Infer from known DB mappings (Beat + BookMe portfolio). If it isn't mapped, it is not accessible.
        beat = Beat.query.filter(
            or_(
                Beat.cover_path == filename,
                Beat.preview_path == filename,
                Beat.stems_path == filename,
                Beat.audio_preview_key == filename,
                Beat.audio_original_key == filename,
                Beat.audio_deliverable_key == filename,
                Beat.stems_key == filename,
            )
        ).first()
        if beat:
            inferred_owner_id = int(beat.owner_id)
            if beat.cover_path == filename:
                inferred_purpose = UploadedFilePurpose.beat_cover
            elif beat.preview_path == filename or beat.audio_preview_key == filename:
                inferred_purpose = UploadedFilePurpose.beat_preview
            elif beat.audio_deliverable_key == filename or beat.audio_original_key == filename:
                inferred_purpose = UploadedFilePurpose.beat_deliverable
            elif beat.stems_key == filename or beat.stems_path == filename:
                inferred_purpose = UploadedFilePurpose.beat_stems
        else:
            item = PortfolioItem.query.filter_by(stored_filename=filename).first()
            if item:
                inferred_purpose = UploadedFilePurpose.bookme_portfolio
                try:
                    inferred_owner_id = int(item.profile.user_id) if item.profile else None
                except Exception:
                    inferred_owner_id = None

        if inferred_purpose is None:
            abort(404)

        # In production with local storage, scan once and create an UploadedFile row so scan gating is data-driven.
        if STORAGE_BACKEND == "local" and _is_production_mode():
            local_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            if not os.path.exists(local_path):
                abort(404)
            st, msg = _scan_file_local(local_path)
            if st == ScanStatus.infected:
                abort(404)
            if st != ScanStatus.clean:
                abort(403)
            try:
                uf_row = UploadedFile(
                    owner_user_id=inferred_owner_id,
                    purpose=inferred_purpose,
                    storage_provider=STORAGE_BACKEND,
                    key=filename,
                    scan_status=st,
                    scan_message=(msg or "on_demand_scan")[:400],
                )
                db.session.add(uf_row)
                db.session.commit()
                uf = uf_row
            except Exception:
                db.session.rollback()
                # Fall back to ephemeral record (still clean, since we just scanned)
                uf = UploadedFile(
                    owner_user_id=inferred_owner_id,
                    purpose=inferred_purpose,
                    storage_provider=STORAGE_BACKEND,
                    key=filename,
                    scan_status=ScanStatus.clean,
                    scan_message="on_demand_scan",
                )
        else:
            # Legacy S3 objects may predate UploadedFile rows; create one to keep media playable.
            if STORAGE_BACKEND == "s3" and _is_production_mode():
                try:
                    uf_row = UploadedFile(
                        owner_user_id=inferred_owner_id,
                        purpose=inferred_purpose,
                        storage_provider=STORAGE_BACKEND,
                        key=filename,
                        scan_status=ScanStatus.clean,
                        scan_message="legacy_infer_s3",
                    )
                    db.session.add(uf_row)
                    db.session.commit()
                    uf = uf_row
                except Exception:
                    db.session.rollback()
                    uf = UploadedFile(
                        owner_user_id=inferred_owner_id,
                        purpose=inferred_purpose,
                        storage_provider=STORAGE_BACKEND,
                        key=filename,
                        scan_status=ScanStatus.clean,
                        scan_message="legacy_infer_s3",
                    )
            else:
                # Ephemeral record for non-production or local prod (non-scanned).
                uf = UploadedFile(
                    owner_user_id=inferred_owner_id,
                    purpose=inferred_purpose,
                    storage_provider=STORAGE_BACKEND,
                    key=filename,
                    scan_status=ScanStatus.clean if not _is_production_mode() else ScanStatus.pending,
                    scan_message="legacy_infer",
                )

    # --- Authentication UX: allow public beat covers/previews; otherwise require login.
    user = current_user if getattr(current_user, "is_authenticated", False) else None
    if not user and not can_access_uploaded_file(uf, None):
        return login_manager.unauthorized()

    # --- Authorization (explicit; no default allow) ---
    if not can_access_uploaded_file(uf, user):
        abort(403)

    # --- Scan gating (data-driven; applies to public + private) ---
    if uf.scan_status == ScanStatus.infected:
        try:
            if user and getattr(user, "is_authenticated", False):
                _alert_create(
                    AlertSeverity.high,
                    "UPLOAD_INFECTED_BLOCKED",
                    "Blocked infected download attempt",
                    {"key": uf.key, "user_id": user.id},
                )
        except Exception:
            pass
        abort(404)
    allow_unscanned = False
    if _is_production_mode() and ALLOW_UNSCANNED_UPLOADS:
        if uf.scan_status in (ScanStatus.pending, ScanStatus.failed):
            if uf.purpose in {
                UploadedFilePurpose.beat_cover,
                UploadedFilePurpose.beat_preview,
                UploadedFilePurpose.bookme_portfolio,
            }:
                allow_unscanned = True
            if not allow_unscanned and beat:
                if uf.key in {beat.cover_path, beat.preview_path, beat.audio_preview_key}:
                    allow_unscanned = True
    if _is_production_mode() and uf.scan_status != ScanStatus.clean and not allow_unscanned:
        abort(403)

    # --- Serve content ---
    if not beat:
        beat = Beat.query.filter(
            or_(
                Beat.cover_path == filename,
                Beat.preview_path == filename,
                Beat.stems_path == filename,
                Beat.audio_preview_key == filename,
                Beat.audio_original_key == filename,
                Beat.audio_deliverable_key == filename,
                Beat.stems_key == filename,
            )
        ).first()

    is_deliverable = bool(
        beat and filename in {beat.stems_path, beat.audio_original_key, beat.audio_deliverable_key, beat.stems_key}
    )
    if as_attachment:
        is_deliverable = True
    if download_name is None and is_deliverable:
        download_name = _download_name_for_beat(beat, filename)

    ttl = SIGNED_URL_TTL_SECONDS
    # For S3 storage, use signed URL for public files; proxy private deliverables.
    if STORAGE_BACKEND == "s3" and isinstance(storage_backend, S3StorageBackend):
        if is_deliverable:
            return _serve_s3_file(filename, as_attachment=True, download_name=download_name)
        signed_url = storage_backend.get_signed_url(filename, expires=ttl)
        if signed_url:
            return redirect(signed_url)
        abort(404)

    # Local file serving
    local_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    return _serve_local_file(local_path, as_attachment=is_deliverable, download_name=download_name)

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
                try:
                    resp = send_from_directory(app.config["UPLOAD_FOLDER"], user.avatar_path, as_attachment=False)
                    # In dev, avoid stale caching so new uploads show immediately
                    resp.headers["Cache-Control"] = "no-store"
                    return resp
                except Exception as e:
                    app.logger.warning(f"Error serving avatar {user.avatar_path}: {e}")
            else:
                # File doesn't exist - it was probably lost after a deploy
                # Clear it from DB so we don't keep trying to serve a ghost file
                try:
                    user.avatar_path = None
                    db.session.commit()
                except Exception as cleanup_err:
                    app.logger.warning(f"Could not clear missing avatar path: {cleanup_err}")

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
        try:
            log_security_event(
                "unauthorized_access",
                f"Admin video access blocked: {request.path}",
                "warning",
            )
        except Exception:
            pass
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

    # Get recent transactions for overview tab (last 10)
    recent = txns[:10] if txns else []

    kyc_blocked_payout = bool(KYC_ENFORCE and is_service_provider(current_user) and not _is_kyc_verified(current_user))

    # Stripe Connect status for payout/beat sale flows
    stripe_connect_connected = False
    stripe_connect_payouts_enabled = False
    stripe_connect_charges_enabled = False
    acct_row = _get_or_refresh_provider_stripe_account(current_user.id, refresh=False)
    if acct_row and acct_row.stripe_account_id:
        stripe_connect_connected = True
        stripe_connect_payouts_enabled = bool(acct_row.payouts_enabled)
        stripe_connect_charges_enabled = bool(acct_row.charges_enabled)

    return render_template(
        "wallet_center.html",
        balance=balance,
        transactions=txns,
        txns=txns,
        recent=recent,
        tab=tab,
        kyc_blocked_payout=kyc_blocked_payout,
        stripe_connect_connected=stripe_connect_connected,
        stripe_connect_payouts_enabled=stripe_connect_payouts_enabled,
        stripe_connect_charges_enabled=stripe_connect_charges_enabled,
    )


@app.route("/transactions")
@login_required
def transactions_redirect():
    return redirect(url_for("wallet_home", tab="transactions"))


@app.route("/wallet/statement", endpoint="wallet_statement")
@login_required
def wallet_statement():
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
        EntryType.external_payment,
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
    action = (request.form.get("action") or "").strip().lower()
    amount_raw = (request.form.get("amount") or "").strip()

    if action in ("withdraw", "transfer_out"):
        if not require_kyc_approved("payout"):
            return redirect(url_for("wallet_home"))

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
        app.logger.info(
            f"Wallet add-money requested: user_id={current_user.id} cents={cents} method={method!r} host={request.host if request else ''}"
        )

        # Demo top-up (no Stripe) — keep as a hidden/dev option
        if method == "demo":
            with db_txn():
                post_ledger(w, EntryType.deposit, cents, meta="deposit (demo)")
            flash(f"Added ${amt:,.2f} (demo).", "success")
            return redirect(url_for("wallet_home"))

        # Stripe card top-up
        ok, err_msg = _stripe_env_guard(require_base_url=True)
        if not ok:
            flash(err_msg, "error")
            return redirect(url_for("wallet_home"))

        try:
            base_url = get_stripe_base_url()
            app.logger.info(f"Wallet add-money: creating Stripe Checkout session base_url={base_url!r}")
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[
                    {
                        "price_data": {
                            "currency": "usd",
                            "product_data": {"name": "BeatFund Wallet Top-up"},
                            "unit_amount": cents,
                        },
                        "quantity": 1,
                    }
                ],
                mode="payment",
                success_url=f"{base_url}/payments/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{base_url}/payments/cancel",
                client_reference_id=f"wallet_topup_user_{current_user.id}",
                metadata={
                    "type": "wallet_topup",
                    "purpose": "wallet_topup",
                    "user_id": str(current_user.id),
                    "amount_cents": str(cents),
                },
            )
            app.logger.info(
                f"Wallet add-money: Stripe Checkout session created id={getattr(checkout_session,'id',None)} has_url={bool(getattr(checkout_session,'url',None))}"
            )
            
            # Validate that the session was created successfully with a checkout URL
            if not checkout_session.id:
                app.logger.error(f"Stripe checkout session created but has no ID: {checkout_session}")
                flash("Stripe session creation failed. Please contact support.", "error")
                return redirect(url_for("wallet_home"))
            
            if not checkout_session.url:
                app.logger.error(
                    f"Stripe checkout session created but has no URL. "
                    f"Session ID: {checkout_session.id}, "
                    f"Status: {getattr(checkout_session, 'status', 'unknown')}, "
                    f"Payment Status: {getattr(checkout_session, 'payment_status', 'unknown')}, "
                    f"Session data: {checkout_session}"
                )
                flash("Stripe checkout URL is missing. This may be a configuration issue. Please contact support.", "error")
                return redirect(url_for("wallet_home"))
            
            # Some browsers/extensions can be weird about POST -> 3rd-party redirects.
            # Render an interstitial that both auto-redirects and provides a click-through link.
            return render_template("redirect_to_stripe.html", stripe_url=checkout_session.url)
        except stripe.error.StripeError as e:
            _log_stripe_error(
                "wallet_topup_session_create",
                e,
                user_id=current_user.id,
                amount_cents=cents,
                currency="usd",
            )
            flash("Payment processing error. Please try again.", "error")
            return redirect(url_for("wallet_home"))
        except Exception as e:
            _log_stripe_error(
                "wallet_topup_session_create",
                e,
                user_id=current_user.id,
                amount_cents=cents,
                currency="usd",
            )
            flash("Unable to start Stripe checkout. Please try again.", "error")
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
            # Row-level locking on Postgres for wallet operations
            if db.engine.dialect.name == "postgresql":
                w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
                w_recipient = Wallet.query.filter_by(user_id=recipient.id).with_for_update().first()
            
            # Ensure wallets exist
            if not w:
                w = Wallet(user_id=current_user.id)
                db.session.add(w)
                db.session.flush()
            if not w_recipient:
                w_recipient = Wallet(user_id=recipient.id)
                db.session.add(w_recipient)
                db.session.flush()
            
            if wallet_balance_cents(w) < cents:
                raise ValueError("Insufficient wallet balance.")

            post_ledger(w, EntryType.transfer_out, cents, meta=meta_out)
            post_ledger(w_recipient, EntryType.transfer_in, cents, meta=meta_in)

        try:
            audit_log_event(
                action_type="TRANSFER",
                actor_user=current_user,
                target_type="Wallet",
                target_id=str(w.id),
                reason="User wallet transfer",
                metadata={
                    "from_user_id": current_user.id,
                    "to_user_id": recipient.id,
                    "amount_cents": cents,
                    "note": note or None,
                },
            )
        except Exception:
            pass

        flash(f"Sent ${amt:,.2f} to @{recipient.username}.", "success")
        return redirect(url_for("wallet_home"))

    if action == "withdraw":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.", "error")
            return redirect(url_for("wallet_home"))

        bank_account = (request.form.get("bank_account") or "").strip()[:50]
        destination_note = "bank account" if bank_account == "stripe_connected" else "demo"

        # Stripe Connect payout
        if bank_account == "stripe_connected":
            ok, err_msg = _stripe_env_guard()
            if not ok:
                flash(err_msg, "error")
                return redirect(url_for("wallet_home"))

            acct_id = (getattr(current_user, "stripe_account_id", None) or "").strip()
            if not acct_id:
                flash("Connect your bank account first.", "info")
                return redirect(url_for("stripe_connect_start"))

            try:
                acct = stripe.Account.retrieve(acct_id)
                if not getattr(acct, "details_submitted", False) or not getattr(acct, "payouts_enabled", False):
                    flash("Finish Stripe onboarding to enable payouts.", "info")
                    return redirect(url_for("stripe_connect_start"))
            except stripe.error.StripeError as e:
                _log_stripe_error(
                    "stripe_account_retrieve",
                    e,
                    user_id=current_user.id,
                    stripe_account_id=acct_id,
                )
                flash("Unable to verify Stripe bank connection. Try reconnecting.", "error")
                return redirect(url_for("stripe_connect_start"))
            except Exception as e:
                _log_stripe_error(
                    "stripe_account_retrieve",
                    e,
                    user_id=current_user.id,
                    stripe_account_id=acct_id,
                )
                flash("Unable to verify Stripe bank connection. Try reconnecting.", "error")
                return redirect(url_for("stripe_connect_start"))

            # Move funds from platform to connected account, then attempt payout to bank.
            try:
                transfer = stripe.Transfer.create(
                    amount=cents,
                    currency="usd",
                    destination=acct_id,
                    metadata={"user_id": str(current_user.id), "purpose": "wallet_withdrawal"},
                )
                payout = None
                try:
                    payout = stripe.Payout.create(
                        amount=cents,
                        currency="usd",
                        method="standard",
                        metadata={"user_id": str(current_user.id), "purpose": "wallet_withdrawal"},
                        stripe_account=acct_id,
                    )
                except stripe.error.StripeError as e:
                    _log_stripe_error(
                        "stripe_withdraw_payout",
                        e,
                        user_id=current_user.id,
                        stripe_account_id=acct_id,
                        amount_cents=cents,
                        currency="usd",
                    )
                    # Payout can fail if external account isn't attached yet; transfer still succeeded.
                    app.logger.warning(f"Withdraw: payout create failed after transfer {transfer.id}: {e}")
                except Exception as e:
                    _log_stripe_error(
                        "stripe_withdraw_payout",
                        e,
                        user_id=current_user.id,
                        stripe_account_id=acct_id,
                        amount_cents=cents,
                        currency="usd",
                    )
                    app.logger.warning(f"Withdraw: payout create failed after transfer {transfer.id}: {e}")

                with db_txn():
                    # Lock wallet on Postgres
                    if db.engine.dialect.name == "postgresql":
                        w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
                    else:
                        w = Wallet.query.filter_by(user_id=current_user.id).first()

                    if not w:
                        w = Wallet(user_id=current_user.id)
                        db.session.add(w)
                        db.session.flush()

                    if wallet_balance_cents(w) < cents:
                        raise ValueError("Insufficient wallet balance.")

                    meta = f"withdraw via Stripe Connect transfer {transfer.id}"
                    if payout is not None:
                        meta += f" payout {payout.id}"
                    post_ledger(w, EntryType.withdrawal, cents, meta=meta[:255])

                try:
                    audit_log_event(
                        action_type="WITHDRAWAL_REQUESTED",
                        actor_user=current_user,
                        target_type="Wallet",
                        target_id=str(w.id),
                        reason="User withdrawal requested (Stripe Connect)",
                        metadata={
                            "amount_cents": cents,
                            "stripe_transfer_id": getattr(transfer, "id", None),
                            "stripe_payout_id": getattr(payout, "id", None) if payout is not None else None,
                        },
                    )
                except Exception:
                    pass

                if payout is not None:
                    flash(f"Withdrawal initiated. Processing time: 2–5 business days.", "success")
                else:
                    flash("Funds moved to your connected Stripe account. Finish onboarding / add a bank account to complete payout.", "info")

                return redirect(url_for("wallet_home"))

            except stripe.error.StripeError as e:
                _log_stripe_error(
                    "stripe_withdraw_transfer",
                    e,
                    user_id=current_user.id,
                    stripe_account_id=acct_id,
                    amount_cents=cents,
                    currency="usd",
                )
                try:
                    _alert_create(
                        AlertSeverity.high,
                        "WITHDRAWAL_FAILED",
                        "Stripe Connect withdrawal failed",
                        {"user_id": current_user.id, "amount_cents": cents, "request_id": getattr(g, "request_id", None)},
                    )
                except Exception:
                    pass
                flash("Withdrawal failed. Please try again.", "error")
                return redirect(url_for("wallet_home"))
            except Exception as e:
                _log_stripe_error(
                    "stripe_withdraw_transfer",
                    e,
                    user_id=current_user.id,
                    stripe_account_id=acct_id,
                    amount_cents=cents,
                    currency="usd",
                )
                try:
                    _alert_create(
                        AlertSeverity.high,
                        "WITHDRAWAL_FAILED",
                        "Stripe Connect withdrawal failed",
                        {"user_id": current_user.id, "amount_cents": cents, "request_id": getattr(g, "request_id", None)},
                    )
                except Exception:
                    pass
                flash("Withdrawal failed. Please try again.", "error")
                return redirect(url_for("wallet_home"))

        # Demo fallback
        with db_txn():
            if db.engine.dialect.name == "postgresql":
                w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
            if not w:
                w = Wallet(user_id=current_user.id)
                db.session.add(w)
                db.session.flush()
            if wallet_balance_cents(w) < cents:
                raise ValueError("Insufficient wallet balance.")
            post_ledger(w, EntryType.withdrawal, cents, meta=f"withdraw to {destination_note} (demo)")

        try:
            audit_log_event(
                action_type="WITHDRAWAL_REQUESTED",
                actor_user=current_user,
                target_type="Wallet",
                target_id=str(w.id),
                reason="User withdrawal requested (demo)",
                metadata={"amount_cents": cents, "destination": destination_note},
            )
        except Exception:
            pass

        flash(f"Withdrew ${amt:,.2f} (demo).", "success")
        return redirect(url_for("wallet_home"))

    if action == "transfer_out":
        if wallet_balance_cents(w) < cents:
            flash("Insufficient wallet balance.", "error")
            return redirect(url_for("wallet_home"))

        destination = (request.form.get("destination") or "").strip()[:50]
        destination_note = "main account"
        if destination == "stripe_bank":
            destination_note = "bank account (Stripe ACH)"
        elif destination == "stripe_card":
            destination_note = "debit card (Stripe Instant)"
        
        with db_txn():
            # Row-level locking on Postgres for wallet operations
            if db.engine.dialect.name == "postgresql":
                w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
            
            # Ensure wallet exists
            if not w:
                w = Wallet(user_id=current_user.id)
                db.session.add(w)
                db.session.flush()
            
            if wallet_balance_cents(w) < cents:
                raise ValueError("Insufficient wallet balance.")
            meta = f"transfer to {destination_note}"
            if destination.startswith("stripe_"):
                meta += " (Stripe ready)"
            post_ledger(w, EntryType.withdrawal, cents, meta=meta)

        flash(f"Transferred ${amt:,.2f} to main account (demo - Stripe integration ready).", "success")
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
# Provider Settings & Availability
# =========================================================
def _parse_time_hhmm(value: str | None) -> time | None:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%H:%M").time()
    except Exception:
        return None


@app.route("/provider/settings", methods=["GET", "POST"], endpoint="provider_settings")
@login_required
def provider_settings():
    if not is_service_provider(current_user):
        flash("Only service providers can edit availability settings.", "error")
        return redirect(url_for("route_to_dashboard"))

    settings = get_provider_settings(current_user.id, create=True)
    slots, exceptions = get_provider_availability_summary(current_user.id)

    if request.method == "POST":
        accepting_new_requests = request.form.get("accepting_new_requests") == "on"
        onsite = request.form.get("onsite") == "on"
        remote = request.form.get("remote") == "on"
        tz = sanitize_input((request.form.get("tz") or "").strip(), max_length=64) or "UTC"

        travel_radius_raw = (request.form.get("travel_radius_miles") or "").strip()
        travel_radius = None
        if travel_radius_raw:
            try:
                travel_radius = int(travel_radius_raw)
                if travel_radius < 0:
                    travel_radius = None
            except Exception:
                travel_radius = None

        base_location = sanitize_input((request.form.get("base_location") or "").strip(), max_length=255) or None

        settings.accepting_new_requests = accepting_new_requests
        settings.onsite = onsite
        settings.remote = remote
        settings.travel_radius_miles = travel_radius
        settings.base_location = base_location
        settings.tz = tz

        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("provider_settings"))

    stripe_connect_connected = _producer_has_stripe_connected(current_user.id)

    return render_template(
        "provider_settings.html",
        settings=settings,
        slots=slots,
        exceptions=exceptions,
        DAY_NAMES=DAY_NAMES,
        stripe_connect_connected=stripe_connect_connected,
    )


@app.route("/availability", endpoint="provider_availability_alias")
@login_required
def provider_availability_alias():
    if not is_service_provider(current_user):
        flash("Availability settings are only available for providers.", "error")
        return redirect(url_for("route_to_dashboard"))
    return redirect(url_for("provider_settings"))


@app.route("/provider/availability/add", methods=["POST"], endpoint="provider_availability_add")
@login_required
def provider_availability_add():
    if not is_service_provider(current_user):
        abort(403)

    day_raw = (request.form.get("day_of_week") or "").strip()
    start_raw = (request.form.get("start_time") or "").strip()
    end_raw = (request.form.get("end_time") or "").strip()

    try:
        day = int(day_raw)
    except Exception:
        day = -1

    start_time = _parse_time_hhmm(start_raw)
    end_time = _parse_time_hhmm(end_raw)

    if day < 0 or day > 6 or not start_time or not end_time:
        flash("Please provide a valid day and time range.", "error")
        return redirect(url_for("provider_settings"))
    if end_time <= start_time:
        flash("End time must be after start time.", "error")
        return redirect(url_for("provider_settings"))

    tz = sanitize_input((request.form.get("tz") or "").strip(), max_length=64) or "UTC"
    slot = ProviderAvailability(
        provider_user_id=current_user.id,
        day_of_week=day,
        start_time=start_time,
        end_time=end_time,
        tz=tz,
        is_active=True,
    )
    db.session.add(slot)
    db.session.commit()
    flash("Availability slot added.", "success")
    return redirect(url_for("provider_settings"))


@app.route("/provider/availability/<int:slot_id>/delete", methods=["POST"], endpoint="provider_availability_delete")
@login_required
def provider_availability_delete(slot_id: int):
    slot = ProviderAvailability.query.get_or_404(slot_id)
    if slot.provider_user_id != current_user.id:
        abort(403)
    db.session.delete(slot)
    db.session.commit()
    flash("Availability slot removed.", "success")
    return redirect(url_for("provider_settings"))


@app.route("/provider/availability/exception", methods=["POST"], endpoint="provider_availability_exception_add")
@login_required
def provider_availability_exception_add():
    if not is_service_provider(current_user):
        abort(403)

    date_raw = (request.form.get("date") or "").strip()
    start_raw = (request.form.get("start_time") or "").strip()
    end_raw = (request.form.get("end_time") or "").strip()
    is_unavailable = request.form.get("is_unavailable") == "on"

    try:
        ex_date = datetime.strptime(date_raw, "%Y-%m-%d").date()
    except Exception:
        ex_date = None

    if not ex_date:
        flash("Please provide a valid date.", "error")
        return redirect(url_for("provider_settings"))

    start_time = _parse_time_hhmm(start_raw)
    end_time = _parse_time_hhmm(end_raw)
    if (start_raw or end_raw) and (not start_time or not end_time):
        flash("Please provide a valid time range.", "error")
        return redirect(url_for("provider_settings"))
    if start_time and end_time and end_time <= start_time:
        flash("End time must be after start time.", "error")
        return redirect(url_for("provider_settings"))

    ex = ProviderAvailabilityException(
        provider_user_id=current_user.id,
        date=ex_date,
        start_time=start_time,
        end_time=end_time,
        is_unavailable=is_unavailable,
    )
    db.session.add(ex)
    db.session.commit()
    flash("Exception added.", "success")
    return redirect(url_for("provider_settings"))


@app.route("/provider/availability/exception/<int:exc_id>/delete", methods=["POST"], endpoint="provider_availability_exception_delete")
@login_required
def provider_availability_exception_delete(exc_id: int):
    ex = ProviderAvailabilityException.query.get_or_404(exc_id)
    if ex.provider_user_id != current_user.id:
        abort(403)
    db.session.delete(ex)
    db.session.commit()
    flash("Exception removed.", "success")
    return redirect(url_for("provider_settings"))


# =========================================================
# Follow APIs (JSON + redirect versions)
# =========================================================
@app.route("/users/<int:user_id>/toggle-follow", methods=["POST"])
@login_required
def toggle_follow(user_id: int):
    target = User.query.get_or_404(user_id)
    if target.role == "admin":
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

    if profile_user.role == "producer":
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
                "role": user.role if user.role else None,
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
                "role": user.role if user.role else None,
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
        query = query.filter(User.role == role)

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
            "role": p.user.role if getattr(p.user, "role", None) else "",
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
        query = query.filter(User.role == role)

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
        was_new = prof is None
        prev_visible = bool(getattr(prof, "is_visible", False)) if prof else False

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
                    lat, lng = _parse_lat_lng(lat_raw, lng_raw)
                else:
                    raise ValueError()
            except Exception:
                flash("Latitude/Longitude must be valid coordinates (e.g., 35.868145 and -83.561523).", "error")
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

        # Broadcast only when the listing is public/visible (no drafts)
        try:
            if getattr(prof, "is_visible", False):
                event_type = (
                    ActivityEventType.listing_published
                    if (was_new or (not prev_visible and prof.is_visible))
                    else ActivityEventType.listing_updated
                )
                broadcast_event(
                    event_type,
                    actor_user_id=current_user.id,
                    payload_dict={
                        "listing_kind": "bookme_profile",
                        "listing_id": prof.id,
                        "listing_title": getattr(prof, "display_name", None) or "Service",
                        "listing_url": url_for("provider_portfolio_public", username=current_user.username),
                    },
                    audience="ALL",
                    exclude_actor=True,
                )
        except Exception:
            pass

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

        # Broadcast file uploads only for public listings
        try:
            if getattr(prof, "is_visible", False):
                file_count = 1 if stored_filename else 0
                broadcast_event(
                    ActivityEventType.listing_files_uploaded,
                    actor_user_id=current_user.id,
                    payload_dict={
                        "listing_kind": "bookme_profile",
                        "listing_id": prof.id,
                        "listing_title": getattr(prof, "display_name", None) or "Service",
                        "listing_url": url_for("provider_portfolio_public", username=current_user.username),
                        "file_count": file_count,
                    },
                    audience="ALL",
                    exclude_actor=True,
                )
        except Exception:
            pass

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

    rating_summary = get_provider_review_summary(user.id)
    reviews = (
        ProviderReview.query
        .filter_by(provider_user_id=user.id, status=ReviewVisibility.visible)
        .order_by(ProviderReview.created_at.desc())
        .limit(20)
        .all()
    )
    settings = get_provider_settings(user.id, create=False)
    availability_slots, availability_exceptions = get_provider_availability_summary(user.id)

    return render_template(
        "provider_portfolio_public.html",
        provider=user,
        prof=prof,
        items=items,
        PortfolioMediaType=PortfolioMediaType,
        followers_count=followers_count,
        following_count=following_count,
        is_following=is_following,
        rating_summary=rating_summary,
        reviews=reviews,
        settings=settings,
        availability_slots=availability_slots,
        availability_exceptions=availability_exceptions,
    )


@app.route("/bookme/request/<int:provider_id>/confirm", methods=["GET", "POST"])
@login_required
def bookme_request_confirm(provider_id):
    """Confirmation page for booking request"""
    provider = User.query.get_or_404(provider_id)

    if not is_service_provider(provider):
        flash("This user is not available for BookMe bookings.", "error")
        return redirect(url_for("bookme_search"))

    # Check if profile is active (visible) - inactive profiles can't receive bookings
    prof = BookMeProfile.query.filter_by(user_id=provider.id).first()
    if prof and not prof.is_visible:
        flash("This studio profile is currently inactive and not accepting new bookings. You can still follow and view their portfolio.", "error")
        return redirect(url_for("bookme_search"))

    if request.method == "GET":
        # Get form data from session or query params
        msg = request.args.get("message", "").strip()
        pref = request.args.get("preferred_time", "").strip()
        
        if not pref:
            flash("Please choose a date and time slot.", "error")
            return redirect(url_for("bookme_request", provider_id=provider_id))
        
        # Check if the requested time is blocked (for studios)
        time_blocked = False
        if provider.role == "studio":
            try:
                if " " in pref:
                    date_part = pref.split(" ", 1)[0]
                    check_date = datetime.strptime(date_part, "%Y-%m-%d").date()
                else:
                    check_date = datetime.utcnow().date()
                
                if is_time_blocked(provider_id, check_date, pref):
                    time_blocked = True
            except (ValueError, AttributeError):
                pass

        availability_ok, availability_reason = provider_is_available(provider.id, pref, None)
        settings = get_provider_settings(provider.id, create=False)
        availability_slots, availability_exceptions = get_provider_availability_summary(provider.id)

        return render_template(
            "bookme_request_confirm.html",
            provider=provider,
            message=msg,
            preferred_time=pref,
            time_blocked=time_blocked,
            availability_ok=availability_ok,
            availability_reason=availability_reason,
            settings=settings,
            availability_slots=availability_slots,
            availability_exceptions=availability_exceptions,
            BookingStatus=BookingStatus,
        )

    # POST - process confirmation
    confirmed = request.form.get("confirmed") == "true"
    if not confirmed:
        flash("Please confirm your booking request.", "error")
        return redirect(url_for("bookme_request", provider_id=provider_id))

    msg = (request.form.get("message") or "").strip()
    pref = (request.form.get("preferred_time") or "").strip()

    if not pref:
        flash("Please choose a date and time slot.", "error")
        return redirect(url_for("bookme_request", provider_id=provider_id))
    
    # Check if the requested time is blocked (for studios)
    if provider.role == RoleEnum.studio:
        try:
            if " " in pref:
                date_part = pref.split(" ", 1)[0]
                check_date = datetime.strptime(date_part, "%Y-%m-%d").date()
            else:
                check_date = datetime.utcnow().date()
            
            if is_time_blocked(provider_id, check_date, pref):
                flash("This time slot is blocked and not available for booking.", "error")
                return redirect(url_for("bookme_request", provider_id=provider_id))
        except (ValueError, AttributeError):
            pass

    ok, reason = provider_is_available(provider.id, pref, None)
    if not ok:
        flash(reason or "Requested time is not available.", "error")
        return redirect(url_for("bookme_request", provider_id=provider_id))

    dupe_window = datetime.utcnow() - timedelta(minutes=2)
    existing_req = (
        BookingRequest.query
        .filter(
            BookingRequest.provider_id == provider.id,
            BookingRequest.client_id == current_user.id,
            BookingRequest.preferred_time == pref,
            BookingRequest.created_at >= dupe_window,
        )
        .order_by(BookingRequest.created_at.desc())
        .first()
    )
    if existing_req:
        flash("You already sent a request for this time. Taking you to your requests.", "info")
        return redirect(url_for("bookme_requests"))

    req = BookingRequest(
        provider_id=provider.id,
        client_id=current_user.id,
        message=msg,
        preferred_time=pref,
    )
    db.session.add(req)
    db.session.commit()
    
    # Notify provider
    notify_user(
        provider,
        kind="info",
        title="New booking request",
        body=f"@{current_user.username} requested {pref}",
        url=url_for("bookme_requests"),
        actor_user_id=current_user.id,
        event_key=f"bookme_request_created:{req.id}",
        commit=True,
    )
    
    flash("Booking request sent.", "success")
    return redirect(url_for("bookme_requests"))


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
        # Redirect to confirmation page instead of processing directly
        msg = (request.form.get("message") or "").strip()
        pref = (request.form.get("preferred_time") or "").strip()

        if not pref:
            flash("Please choose a date and time slot.", "error")
            return redirect(url_for("bookme_request", provider_id=provider_id))
        
        # Redirect to confirmation with form data
        return redirect(url_for("bookme_request_confirm", provider_id=provider_id, message=msg, preferred_time=pref))

    settings = get_provider_settings(provider.id, create=False)
    availability_slots, availability_exceptions = get_provider_availability_summary(provider.id)
    return render_template(
        "bookme_request.html",
        provider=provider,
        BookingStatus=BookingStatus,
        settings=settings,
        availability_slots=availability_slots,
        availability_exceptions=availability_exceptions,
    )


@app.route("/bookme/requests")
@login_required
def bookme_requests():
    incoming_requests = (
        BookingRequest.query
        .filter(BookingRequest.provider_id == current_user.id)
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

    request_ids = [r.id for r in (incoming_requests + outgoing_requests)]
    booking_ids = [r.booking_id for r in (incoming_requests + outgoing_requests) if r.booking_id]
    request_deposit_paid = {}
    if request_ids or booking_ids:
        payments = Payment.query.filter(
            Payment.kind == PaymentKind.deposit,
            Payment.status == PaymentStatus.succeeded,
            or_(
                Payment.booking_request_id.in_(request_ids or [0]),
                Payment.booking_id.in_(booking_ids or [0]),
            ),
        ).all()
        booking_to_request = {r.booking_id: r.id for r in (incoming_requests + outgoing_requests) if r.booking_id}
        for p in payments:
            if p.booking_request_id:
                request_deposit_paid[int(p.booking_request_id)] = True
            if p.booking_id and p.booking_id in booking_to_request:
                request_deposit_paid[int(booking_to_request[p.booking_id])] = True

    booking_map = {b.id: b for b in outgoing_bookings}
    hold_actions = []
    for req in outgoing_requests:
        if req.status == BookingStatus.accepted and req.booking_id and not request_deposit_paid.get(req.id, False):
            booking = booking_map.get(req.booking_id)
            hold_actions.append({
                "booking_id": req.booking_id,
                "request_id": req.id,
                "provider_username": req.provider.username if req.provider else "",
                "preferred_time": (booking.event_datetime.strftime("%Y-%m-%d %H:%M") if booking and booking.event_datetime else (req.preferred_time or "")),
            })

    booking_payment_meta = {}
    for b in (incoming_bookings + outgoing_bookings):
        req = BookingRequest.query.filter_by(booking_id=b.id).first()
        sums = sum_successful_payments(b, req)
        base_paid = sums.get("base_paid_cents", 0)
        service_total = b.quoted_total_cents or b.total_cents
        deposit_base = int(b.deposit_base_cents or HOLD_FEE_CENTS)
        deposit_paid = bool(service_total and base_paid >= int(deposit_base)) if service_total else bool(base_paid >= int(deposit_base))
        remaining_base = max(0, int(service_total) - int(base_paid)) if service_total else None
        booking_payment_meta[b.id] = {
            "deposit_paid": deposit_paid,
            "remaining_base_cents": remaining_base,
        }

    stripe_enabled = bool(STRIPE_AVAILABLE and STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY)

    return render_template(
        "bookme_requests.html",
        requests_incoming=incoming_requests,
        requests_sent=outgoing_requests,
        bookings_as_provider=incoming_bookings,
        bookings_as_client=outgoing_bookings,
        request_deposit_paid=request_deposit_paid,
        booking_payment_meta=booking_payment_meta,
        hold_actions=hold_actions,
        HOLD_FEE_CENTS=HOLD_FEE_CENTS,
        BookingStatus=BookingStatus,
        stripe_enabled=stripe_enabled,
        stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
    )


@app.route("/bookme/requests/<int:req_id>/accept/confirm", methods=["GET"])
@login_required
def bookme_request_accept_confirm(req_id):
    """Confirmation page for accepting booking request"""
    req = BookingRequest.query.get_or_404(req_id)
    
    if current_user.id != req.provider_id:
        flash("You are not allowed to do that.", "error")
        return redirect(url_for("bookme_requests"))
    
    if req.status != BookingStatus.pending:
        flash("This request is no longer pending.", "error")
        return redirect(url_for("bookme_requests"))
    
    # Check for conflicts
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
    
    return render_template(
        "bookme_accept_confirm.html",
        request=req,
        conflict=conflict,
        HOLD_FEE_CENTS=HOLD_FEE_CENTS,
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
            
            if updated:
                # Notify client
                req = BookingRequest.query.get(req_id)
                if req:
                    client = User.query.get(req.client_id)
                    if client:
                        notify_user(
                            client,
                            kind="warning",
                            title="Booking request declined",
                            body=f"@{current_user.username} declined your request.",
                            url=url_for("bookme_requests"),
                            actor_user_id=current_user.id,
                            event_key=f"bookme_request_declined:{req.id}",
                            commit=True,
                        )
            
            flash("Booking request declined." if updated else "This request is no longer pending.",
                  "success" if updated else "error")
            return redirect(url_for("bookme_requests"))

        # Accept - require confirmation
        confirmed = request.form.get("confirmed") == "true"
        if not confirmed:
            flash("Please confirm your acceptance on the confirmation page.", "error")
            return redirect(url_for("bookme_request_accept_confirm", req_id=req_id))

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

        # Notify client
        req = BookingRequest.query.get(req_id)
        booking = None
        if req:
            if not req.booking_id:
                event_datetime = None
                try:
                    if " " in req.preferred_time:
                        event_datetime = datetime.strptime(req.preferred_time, "%Y-%m-%d %H:%M")
                    else:
                        event_datetime = datetime.strptime(req.preferred_time, "%Y-%m-%d")
                except Exception:
                    event_datetime = datetime.utcnow()

                booking = Booking(
                    provider_id=req.provider_id,
                    provider_role=current_user.role,
                    client_id=req.client_id,
                    event_title=f"Booking with @{current_user.username}",
                    event_datetime=event_datetime,
                    duration_minutes=req.duration_minutes,
                    total_cents=None,
                    quoted_total_cents=None,
                    deposit_base_cents=HOLD_FEE_CENTS,
                    beatfund_fee_total_cents=None,
                    status=BOOKING_STATUS_ACCEPTED,
                    notes_from_client=req.message,
                )
                db.session.add(booking)
                db.session.flush()
                req.booking_id = booking.id
                try:
                    get_or_create_booking_conversation(booking.id)
                except Exception:
                    pass
                db.session.commit()
            else:
                booking = Booking.query.get(req.booking_id)

            client = User.query.get(req.client_id)
            if client:
                notify_user(
                    client,
                    kind="success",
                    title="Booking request accepted",
                    body=f"@{current_user.username} accepted your request for {req.preferred_time}",
                    url=url_for("booking_detail", booking_id=booking.id) if booking else url_for("bookme_requests"),
                    actor_user_id=current_user.id,
                    event_key=f"bookme_request_accepted:{req.id}",
                    email=True,
                    commit=True,
                )

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
            
            # Notify provider
            provider = User.query.get(req.provider_id)
            if provider:
                notify_user(
                    provider,
                    kind="warning",
                    title="Booking request cancelled",
                    body=f"@{current_user.username} cancelled the request.",
                    url=url_for("bookme_requests"),
                    actor_user_id=current_user.id,
                    event_key=f"bookme_request_cancelled:{req.id}",
                    commit=True,
                )
            
            flash("Booking request cancelled.", "success")
        else:
            flash("You can only cancel pending/accepted requests that aren't already paid.", "error")

        return redirect(url_for("bookme_requests"))

    flash("Unknown action.", "error")
    return redirect(url_for("bookme_requests"))


@app.route("/bookings/<int:booking_id>/payment-intent", methods=["POST"])
@login_required
def booking_payment_intent(booking_id: int):
    ok, err_msg = _stripe_env_guard()
    if not ok:
        return jsonify({"error": err_msg}), 400

    booking = Booking.query.get_or_404(booking_id)
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin
    if not (is_client or is_admin):
        return jsonify({"error": "Not authorized to pay for this booking."}), 403

    kind_raw = ""
    if request.is_json:
        kind_raw = (request.json.get("kind") or "").strip().lower()
    else:
        kind_raw = (request.form.get("kind") or "").strip().lower()

    try:
        kind = PaymentKind(kind_raw)
    except Exception:
        return jsonify({"error": "Invalid payment kind."}), 400

    try:
        payload, status = _create_booking_payment_intent_for_kind(booking, kind)
        return jsonify(payload), status
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "booking_payment_intent",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            kind=kind.value,
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "booking_payment_intent",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            kind=kind.value,
        )
        return jsonify({"error": "Unable to start payment intent."}), 500


def _get_booking_request_for_payment(booking: "Booking") -> "BookingRequest" | None:
    try:
        return BookingRequest.query.filter_by(booking_id=booking.id).first()
    except Exception:
        return None


def _get_booking_service_total_ctx(booking: "Booking") -> tuple[int | None, dict]:
    ctx, changed = _resolve_booking_fee_fields(booking)
    if changed:
        db.session.commit()
    service_total_cents = ctx.get("quoted_total_cents")
    if service_total_cents is None or int(service_total_cents) <= 0:
        return None, ctx
    return int(service_total_cents), ctx


def _find_existing_booking_payment(
    booking: "Booking",
    kind: PaymentKind,
    booking_request: "BookingRequest" | None = None,
) -> "Payment" | None:
    filters = [
        Payment.kind == kind,
        Payment.status.in_([PaymentStatus.created, PaymentStatus.processing, PaymentStatus.succeeded]),
    ]
    if booking_request:
        filters.append(or_(Payment.booking_id == booking.id, Payment.booking_request_id == booking_request.id))
    else:
        filters.append(Payment.booking_id == booking.id)
    return Payment.query.filter(*filters).order_by(Payment.created_at.desc()).first()


def _reuse_payment_intent(payment: "Payment") -> tuple[str | None, str | None]:
    if not payment or not payment.stripe_payment_intent_id:
        return None, None
    try:
        intent = stripe.PaymentIntent.retrieve(payment.stripe_payment_intent_id)
    except Exception:
        return None, None
    intent_status = getattr(intent, "status", None) or intent.get("status")
    if intent_status in ("succeeded", "canceled"):
        return None, intent_status
    client_secret = getattr(intent, "client_secret", None) or intent.get("client_secret")
    return client_secret, intent_status


def _payment_breakdown_response(kind: PaymentKind, base_cents: int, beatfund_fee_cents: int, processing_fee_cents: int, total_cents: int) -> dict:
    breakdown = {
        "base_cents": int(base_cents),
        "beatfund_fee_cents": int(beatfund_fee_cents),
        "processing_fee_cents": int(processing_fee_cents),
        "total_cents": int(total_cents),
    }
    if kind == PaymentKind.deposit:
        breakdown["hold_base_cents"] = int(base_cents)
    if kind == PaymentKind.balance:
        breakdown["remaining_base_cents"] = int(base_cents)
    return breakdown


def _create_booking_payment_intent_for_kind(booking: "Booking", kind: PaymentKind) -> tuple[dict, int]:
    service_total_cents, ctx = _get_booking_service_total_ctx(booking)

    booking_request = _get_booking_request_for_payment(booking)
    sums = sum_successful_payments(booking, booking_request)
    base_paid_cents = sums.get("base_paid_cents", 0)
    bf_paid_cents = sums.get("bf_paid_cents", 0)

    deposit_base_cents = HOLD_FEE_CENTS

    if not service_total_cents:
        if kind != PaymentKind.deposit:
            return {"error": "Booking total must be set before payment."}, 400
        service_total_cents = int(deposit_base_cents or HOLD_FEE_CENTS)

    beatfund_fee_total_cents = int(ctx.get("beatfund_fee_total_cents") or 0)
    if service_total_cents and beatfund_fee_total_cents <= 0:
        beatfund_fee_total_cents = calc_beatfund_fee_total(int(service_total_cents))
    if kind == PaymentKind.balance and service_total_cents:
        beatfund_fee_total_cents = calc_beatfund_fee_total(int(service_total_cents))

    def fallback_breakdown() -> dict:
        if kind == PaymentKind.deposit:
            base_c = deposit_base_cents
            bf_c = 0
        else:
            base_c = max(0, int(service_total_cents) - int(base_paid_cents or 0))
            bf_c = max(0, int(beatfund_fee_total_cents) - int(bf_paid_cents or 0))
        if base_c <= 0 and bf_c <= 0:
            return _payment_breakdown_response(kind, 0, 0, 0, 0)
        if kind == PaymentKind.deposit:
            total_c, proc_c = int(base_c), 0
        else:
            total_c, proc_c = calc_total_and_processing(base_c, bf_c)
        return _payment_breakdown_response(kind, base_c, bf_c, proc_c, total_c)

    if kind == PaymentKind.balance:
        if booking.event_datetime:
            now = datetime.utcnow()
            balance_due_by = booking.event_datetime - timedelta(hours=BOOKING_BALANCE_DEADLINE_HOURS)
            if now >= booking.event_datetime:
                return {"error": "Balance payment is no longer available after the booking time."}, 400
            if now >= balance_due_by:
                return {
                    "error": (
                        f"Balance must be paid at least {BOOKING_BALANCE_DEADLINE_HOURS} hours before the booking time."
                    )
                }, 400

    existing = _find_existing_booking_payment(booking, kind, booking_request)
    if existing:
        if existing.status == PaymentStatus.succeeded:
            if kind == PaymentKind.deposit:
                return {"error": "deposit_already_paid"}, 409
            return {"error": "no_balance_due"}, 409
        reused_secret, intent_status = _reuse_payment_intent(existing)
        if reused_secret:
            breakdown = _payment_breakdown_response(
                kind,
                int(existing.base_amount_cents or 0),
                int(existing.beatfund_fee_cents or 0),
                int(existing.processing_fee_cents or 0),
                int(existing.total_paid_cents or existing.amount_cents or 0),
            )
            if not breakdown or int(breakdown.get("total_cents") or 0) <= 0:
                breakdown = fallback_breakdown()
            return {
                "client_secret": reused_secret,
                "payment_id": existing.id,
                "payment_intent_id": existing.stripe_payment_intent_id,
                "breakdown": breakdown,
                "reuse": True,
            }, 200
        if intent_status == "canceled":
            try:
                existing.status = PaymentStatus.failed
                db.session.commit()
            except Exception:
                db.session.rollback()
        else:
            return {"error": "payment_in_progress"}, 409

    if kind == PaymentKind.deposit:
        if booking.event_datetime and datetime.utcnow() >= booking.event_datetime:
            return {"error": "Deposit payment is no longer available after the booking time."}, 400
        base_cents = deposit_base_cents
        beatfund_fee_cents = 0
    else:
        if deposit_base_cents > 0 and base_paid_cents < deposit_base_cents:
            return {"error": "deposit_required"}, 400
        remaining_base = max(0, int(service_total_cents) - int(base_paid_cents or 0))
        remaining_bf = max(0, int(beatfund_fee_total_cents) - int(bf_paid_cents or 0))
        if remaining_base <= 0 and remaining_bf <= 0:
            return {"error": "no_balance_due"}, 409
        base_cents = remaining_base
        beatfund_fee_cents = remaining_bf

    if kind == PaymentKind.deposit:
        total_cents, processing_fee_cents = int(base_cents), 0
    else:
        total_cents, processing_fee_cents = calc_total_and_processing(base_cents, beatfund_fee_cents)
    breakdown = _payment_breakdown_response(kind, base_cents, beatfund_fee_cents, processing_fee_cents, total_cents)

    idempotency_key = generate_idempotency_key(
        "booking_payment", current_user.id, booking_id=booking.id, kind=kind.value, total=total_cents
    )
    existing_by_key = Payment.query.filter_by(idempotency_key=idempotency_key).first()
    if existing_by_key and existing_by_key.status in (PaymentStatus.created, PaymentStatus.processing, PaymentStatus.succeeded):
        reused_secret, intent_status = _reuse_payment_intent(existing_by_key)
        if reused_secret:
            breakdown = _payment_breakdown_response(
                kind,
                int(existing_by_key.base_amount_cents or 0),
                int(existing_by_key.beatfund_fee_cents or 0),
                int(existing_by_key.processing_fee_cents or 0),
                int(existing_by_key.total_paid_cents or existing_by_key.amount_cents or 0),
            )
            if not breakdown or int(breakdown.get("total_cents") or 0) <= 0:
                breakdown = fallback_breakdown()
            return {
                "client_secret": reused_secret,
                "payment_id": existing_by_key.id,
                "payment_intent_id": existing_by_key.stripe_payment_intent_id,
                "breakdown": breakdown,
                "reuse": True,
            }, 200
        if intent_status == "canceled":
            try:
                existing_by_key.status = PaymentStatus.failed
                db.session.commit()
            except Exception:
                db.session.rollback()
        else:
            return {"error": "payment_in_progress"}, 409

    payment = Payment(
        purpose=PaymentPurpose.booking_deposit if kind == PaymentKind.deposit else PaymentPurpose.booking_balance,
        processor=PaymentProcessor.stripe,
        status=PaymentStatus.processing,
        kind=kind,
        amount_cents=total_cents,
        currency="usd",
        base_amount_cents=base_cents,
        beatfund_fee_cents=beatfund_fee_cents,
        processing_fee_cents=processing_fee_cents,
        total_paid_cents=total_cents,
        idempotency_key=idempotency_key,
        booking_id=booking.id,
    )
    if booking_request and kind == PaymentKind.deposit:
        if not Payment.query.filter_by(booking_request_id=booking_request.id).first():
            payment.booking_request_id = booking_request.id

    try:
        db.session.add(payment)
        db.session.flush()

        metadata = {
            "booking_id": str(booking.id),
            "payment_kind": kind.value,
            "base_cents": str(base_cents),
            "beatfund_fee_cents": str(beatfund_fee_cents),
            "processing_fee_cents": str(processing_fee_cents),
            "total_cents": str(total_cents),
            "payment_id": str(payment.id),
        }

        try:
            intent = stripe.PaymentIntent.create(
                amount=total_cents,
                currency="usd",
                payment_method_types=["card"],
                metadata=metadata,
                idempotency_key=f"booking:{booking.id}:{kind.value}:{total_cents}",
            )
        except stripe.error.StripeError as e:
            db.session.rollback()
            _log_stripe_error(
                "booking_payment_intent_create",
                e,
                user_id=getattr(current_user, "id", None),
                booking_id=booking.id,
                kind=kind.value,
                amount_cents=total_cents,
                currency="usd",
            )
            return {"error": "Stripe error creating payment intent."}, 502
        except Exception as e:
            db.session.rollback()
            _log_stripe_error(
                "booking_payment_intent_create",
                e,
                user_id=getattr(current_user, "id", None),
                booking_id=booking.id,
                kind=kind.value,
                amount_cents=total_cents,
                currency="usd",
            )
            return {"error": "Unable to start payment. Please try again."}, 500

        payment.stripe_payment_intent_id = str(intent.id)
        payment.external_id = str(intent.id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        _log_stripe_error(
            "booking_payment_intent_create",
            e,
            user_id=getattr(current_user, "id", None),
            booking_id=booking.id,
            kind=kind.value,
            amount_cents=total_cents,
            currency="usd",
        )
        return {"error": "Unable to start payment. Please try again."}, 500

    return {
        "client_secret": intent.client_secret,
        "payment_id": payment.id,
        "payment_intent_id": payment.stripe_payment_intent_id,
        "breakdown": breakdown,
    }, 200


def _refund_hold_deposit_for_provider_cancel(booking: "Booking") -> bool:
    """Refund the hold deposit base only (processing fees are non-refundable)."""
    if not STRIPE_AVAILABLE or not STRIPE_SECRET_KEY:
        return False

    deposit_payment = Payment.query.filter_by(
        booking_id=booking.id, kind=PaymentKind.deposit, status=PaymentStatus.succeeded
    ).first()
    if not deposit_payment:
        return False

    refundable = int(deposit_payment.base_amount_cents or 0) - int(deposit_payment.refunded_base_cents or 0)
    refundable = min(refundable, HOLD_FEE_CENTS)
    if refundable <= 0:
        return False

    refund_kwargs = {"amount": refundable, "reason": "requested_by_customer"}
    if deposit_payment.stripe_payment_intent_id:
        refund_kwargs["payment_intent"] = deposit_payment.stripe_payment_intent_id
    elif deposit_payment.stripe_charge_id:
        refund_kwargs["charge"] = deposit_payment.stripe_charge_id
    else:
        return False

    try:
        stripe.Refund.create(**refund_kwargs)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "refund_hold_deposit",
            e,
            booking_id=booking.id,
            amount_cents=refundable,
            currency="usd",
        )
        return False
    except Exception as e:
        _log_stripe_error(
            "refund_hold_deposit",
            e,
            booking_id=booking.id,
            amount_cents=refundable,
            currency="usd",
        )
        return False

    deposit_payment.refunded_base_cents = int(deposit_payment.refunded_base_cents or 0) + refundable
    deposit_payment.nonrefundable_processing_kept_cents = int(deposit_payment.processing_fee_cents or 0)
    deposit_payment.nonrefundable_beatfund_kept_cents = int(deposit_payment.beatfund_fee_cents or 0)
    if deposit_payment.refunded_base_cents >= int(deposit_payment.base_amount_cents or 0):
        deposit_payment.status = PaymentStatus.refunded
    else:
        deposit_payment.status = PaymentStatus.partially_refunded
    db.session.commit()
    return True


@app.route("/api/bookings/<int:booking_id>/pay/deposit", methods=["POST"])
@login_required
def api_pay_booking_deposit(booking_id: int):
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        return jsonify({"error": err_msg}), 400

    booking = Booking.query.get_or_404(booking_id)
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin
    if not (is_client or is_admin):
        return jsonify({"error": "Not authorized to pay for this booking."}), 403

    if booking.event_datetime and datetime.utcnow() >= booking.event_datetime:
        return jsonify({"error": "Deposit payment is no longer available after the booking time."}), 400

    try:
        order, err = get_or_create_payment_order_for_booking(booking)
        if err:
            return jsonify({"error": err}), 400
        payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.holding)
        return jsonify(payload), status
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "api_pay_booking_deposit",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            amount_cents=HOLD_FEE_CENTS,
            currency="usd",
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "api_pay_booking_deposit",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            amount_cents=HOLD_FEE_CENTS,
            currency="usd",
        )
        return jsonify({"error": "Unable to create checkout session."}), 500


@app.route("/api/bookings/<int:booking_id>/pay/balance", methods=["POST"])
@login_required
def api_pay_booking_balance(booking_id: int):
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        return jsonify({"error": err_msg}), 400

    booking = Booking.query.get_or_404(booking_id)
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin
    if not (is_client or is_admin):
        return jsonify({"error": "Not authorized to pay for this booking."}), 403

    if booking.event_datetime:
        now = datetime.utcnow()
        balance_due_by = booking.event_datetime - timedelta(hours=BOOKING_BALANCE_DEADLINE_HOURS)
        if now >= booking.event_datetime:
            return jsonify({"error": "Balance payment is no longer available after the booking time."}), 400
        if now >= balance_due_by:
            return jsonify({"error": f"Balance must be paid at least {BOOKING_BALANCE_DEADLINE_HOURS} hours before the booking time."}), 400

    try:
        order, err = get_or_create_payment_order_for_booking(booking)
        if err:
            return jsonify({"error": err}), 400
        payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.balance)
        return jsonify(payload), status
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "api_pay_booking_balance",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            currency="usd",
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "api_pay_booking_balance",
            e,
            user_id=current_user.id,
            booking_id=booking.id,
            currency="usd",
        )
        return jsonify({"error": "Unable to create checkout session."}), 500


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

    provider_user = booking.provider or User.query.get(booking.provider_id)
    client_user = booking.client or User.query.get(booking.client_id)
    if not provider_user or not client_user:
        flash("Some booking participant details are unavailable. If this persists, contact support.", "warning")

    if request.method == "POST":
        action = (request.form.get("action") or "").strip().lower()
        
        if action == "edit_booking":
            # Both provider and client can edit booking details (for pending/accepted/confirmed bookings)
            if booking.status in [BOOKING_STATUS_COMPLETED, BOOKING_STATUS_CANCELLED, BOOKING_STATUS_DISPUTED]:
                flash("Cannot edit bookings that are completed, cancelled, or disputed.", "error")
                return redirect(url_for("booking_detail", booking_id=booking.id))
            if is_client or is_admin:
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
                if not duration_minutes_raw:
                    flash("Duration is required.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))
                try:
                    booking.duration_minutes = int(duration_minutes_raw)
                except ValueError:
                    flash("Duration must be a number.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))
                if booking.duration_minutes <= 0:
                    flash("Duration must be greater than 0 minutes.", "error")
                    return redirect(url_for("booking_detail", booking_id=booking.id))

                # Update location
                location_text = (request.form.get("location_text") or "").strip()
                booking.location_text = location_text or None

                # Update total amount (client-only)
                total_dollars_raw = (request.form.get("total_dollars") or "").strip()
                if total_dollars_raw:
                    try:
                        total_dollars = float(total_dollars_raw)
                        booking.total_cents = int(total_dollars * 100) if total_dollars >= 0 else None
                        if booking.total_cents is not None:
                            booking.quoted_total_cents = booking.total_cents
                            booking.beatfund_fee_total_cents = calc_beatfund_fee_total(booking.total_cents)
                            if booking.deposit_base_cents is None:
                                booking.deposit_base_cents = HOLD_FEE_CENTS
                    except ValueError:
                        flash("Total amount must be a valid number.", "error")
                        return redirect(url_for("booking_detail", booking_id=booking.id))
                elif total_dollars_raw == "":
                    booking.total_cents = None
                    booking.quoted_total_cents = None
                    booking.beatfund_fee_total_cents = None
            
            # Update notes (provider can update provider notes, client can update client notes)
            if is_provider:
                notes_from_provider = (request.form.get("notes_from_provider") or "").strip()
                booking.notes_from_provider = notes_from_provider or None
            elif is_client:
                notes_from_client = (request.form.get("notes_from_client") or "").strip()
                booking.notes_from_client = notes_from_client or None
            
            # Status updates (only provider can change status to accepted/confirmed/cancelled)
            if is_provider:
                refund_hold = False
                new_status = (request.form.get("status") or "").strip().lower()
                if new_status and new_status in [BOOKING_STATUS_PENDING, BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_CANCELLED]:
                    booking.status = new_status
                    if new_status == BOOKING_STATUS_CANCELLED:
                        refund_hold = True
                        flash("Booking has been cancelled.", "success")
                    elif new_status == BOOKING_STATUS_ACCEPTED:
                        flash("Booking has been accepted.", "success")
                    elif new_status == BOOKING_STATUS_CONFIRMED:
                        flash("Booking has been confirmed.", "success")
            
            db.session.commit()
            if is_provider and locals().get("refund_hold"):
                try:
                    _refund_hold_deposit_for_provider_cancel(booking)
                except Exception:
                    pass
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
                if booking.status in [BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]:
                    booking.status = BOOKING_STATUS_COMPLETED
                    flash("Booking marked as completed.", "success")
                else:
                    flash("Only accepted or confirmed bookings can be marked completed.", "error")
            else:
                flash("Notes updated.", "success")
            
            db.session.commit()
            return redirect(url_for("booking_detail", booking_id=booking.id))

    try:
        req = BookingRequest.query.filter_by(booking_id=booking.id).first()
    except Exception:
        req = None

    deposit_payment = None
    balance_payment = None
    payment_order = None

    deposit_breakdown = None
    balance_breakdown = None
    deposit_due = False
    balance_due = False
    balance_blocked = False
    balance_blocked_reason = None
    balance_due_by = None
    service_total_cents = None
    deposit_base_cents = None
    deposit_credit_cents = None
    remaining_service_cents = None
    base_paid_cents = 0
    bf_paid_cents = 0
    beatfund_fee_total_cents = None
    beatfund_fee_remaining_cents = None

    if is_client:
        ctx, changed = _resolve_booking_fee_fields(booking)
        if changed:
            db.session.commit()
        service_total_cents = ctx.get("quoted_total_cents")
        if service_total_cents is not None:
            service_total_cents = int(service_total_cents)

        if service_total_cents:
            payment_order, order_err = get_or_create_payment_order_for_booking(booking)
            if order_err:
                app.logger.warning(f"Booking order setup failed: {order_err}")
            elif payment_order:
                service_total_cents = int(payment_order.total_amount_cents or service_total_cents)

        deposit_base_cents = booking_hold_fee_effective(int(service_total_cents or 0))

        if payment_order:
            base_paid_cents = ledger_sum_gross(payment_order.id, phase=PaymentLedgerPhase.holding)
            bf_paid_cents = ledger_sum_platform_fees(payment_order.id)

        if service_total_cents:
            deposit_credit_cents = min(deposit_base_cents or 0, base_paid_cents or 0)
            remaining_service_cents = max(0, int(service_total_cents) - int(deposit_credit_cents or 0))
            beatfund_fee_total_cents = planned_platform_fee_cents(OrderType.booking, int(service_total_cents))
            beatfund_fee_remaining_cents = max(0, int(beatfund_fee_total_cents) - int(bf_paid_cents or 0))

        if service_total_cents is not None:
            deposit_breakdown = {
                "base_cents": int(deposit_base_cents or 0),
                "beatfund_fee_cents": 0,
                "processing_fee_cents": 0,
                "total_cents": int(deposit_base_cents or 0),
            }
            if (deposit_base_cents or 0) > 0 and base_paid_cents < (deposit_base_cents or 0):
                deposit_due = True

            balance_breakdown = {
                "base_cents": int(remaining_service_cents or 0),
                "beatfund_fee_cents": 0,
                "processing_fee_cents": 0,
                "total_cents": int(remaining_service_cents or 0),
            }
            balance_paid = payment_order and _ledger_phase_succeeded(payment_order.id, PaymentLedgerPhase.balance)
            if (remaining_service_cents or 0) > 0 and not deposit_due and not balance_paid:
                balance_due = True

        if booking.event_datetime and balance_due:
            now = datetime.utcnow()
            balance_due_by = booking.event_datetime - timedelta(hours=BOOKING_BALANCE_DEADLINE_HOURS)
            if now >= booking.event_datetime:
                balance_blocked = True
                balance_blocked_reason = "Balance payment is no longer available after the booking time."
            elif now >= balance_due_by:
                balance_blocked = True
                balance_blocked_reason = (
                    f"Balance must be paid at least {BOOKING_BALANCE_DEADLINE_HOURS} hours before the booking time."
                )

    # Reviews & disputes
    review = None
    can_leave_review = False
    if is_client:
        review = ProviderReview.query.filter_by(booking_id=booking.id).first()
        if booking.status == BOOKING_STATUS_COMPLETED and not review:
            can_leave_review = True

    dispute = BookingDispute.query.filter_by(booking_id=booking.id).order_by(BookingDispute.created_at.desc()).first()
    can_open_dispute = False
    dispute_window_ok = True
    if (is_client or is_provider) and not dispute:
        # Only allow disputes within a window after event datetime (if known)
        if booking.event_datetime:
            dispute_deadline = booking.event_datetime + timedelta(days=DISPUTE_OPEN_WINDOW_DAYS)
            dispute_window_ok = datetime.utcnow() <= dispute_deadline
        if booking.status in [BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_PAID, BOOKING_STATUS_COMPLETED, BOOKING_STATUS_ACCEPTED]:
            can_open_dispute = dispute_window_ok

    stripe_enabled = bool(STRIPE_AVAILABLE and STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY)

    return render_template(
        "booking_detail.html",
        booking=booking,
        provider_user=provider_user,
        client_user=client_user,
        is_provider=is_provider,
        is_client=is_client,
        is_admin=is_admin,
        deposit_breakdown=deposit_breakdown,
        balance_breakdown=balance_breakdown,
        deposit_due=deposit_due,
        balance_due=balance_due,
        balance_blocked=balance_blocked,
        balance_blocked_reason=balance_blocked_reason,
        balance_due_by=balance_due_by,
        deposit_payment=deposit_payment,
        balance_payment=balance_payment,
        payment_order_id=(payment_order.id if payment_order else None),
        service_total_cents=service_total_cents,
        deposit_base_cents=deposit_base_cents,
        deposit_credit_cents=deposit_credit_cents,
        remaining_service_cents=remaining_service_cents,
        base_paid_cents=base_paid_cents,
        bf_paid_cents=bf_paid_cents,
        beatfund_fee_total_cents=beatfund_fee_total_cents,
        beatfund_fee_remaining_cents=beatfund_fee_remaining_cents,
        stripe_enabled=stripe_enabled,
        stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
        BOOKING_BALANCE_DEADLINE_HOURS=BOOKING_BALANCE_DEADLINE_HOURS,
        review=review,
        can_leave_review=can_leave_review,
        dispute=dispute,
        can_open_dispute=can_open_dispute,
        dispute_window_ok=dispute_window_ok,
        DISPUTE_OPEN_WINDOW_DAYS=DISPUTE_OPEN_WINDOW_DAYS,
    )


@app.route("/bookings/<int:booking_id>/review", methods=["GET", "POST"])
@login_required
def booking_review(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_client or is_admin):
        abort(403)

    if booking.status != BOOKING_STATUS_COMPLETED:
        flash("Reviews are only available after a booking is completed.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    existing = ProviderReview.query.filter_by(booking_id=booking.id).first()
    if existing:
        flash("You already submitted a review for this booking.", "info")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    if request.method == "GET":
        return render_template(
            "booking_review_form.html",
            booking=booking,
            provider=booking.provider,
        )

    rating_raw = (request.form.get("rating") or "").strip()
    title = sanitize_input((request.form.get("title") or "").strip(), max_length=160) or None
    body = sanitize_input((request.form.get("body") or "").strip(), max_length=2000) or None

    try:
        rating = int(rating_raw)
    except Exception:
        rating = 0
    if rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "error")
        return redirect(url_for("booking_review", booking_id=booking.id))

    review = ProviderReview(
        booking_id=booking.id,
        reviewer_user_id=current_user.id,
        provider_user_id=booking.provider_id,
        rating=rating,
        title=title,
        body=body,
        status=ReviewVisibility.visible,
        reported_count=0,
    )
    db.session.add(review)
    db.session.commit()

    flash("Review submitted. Thank you!", "success")
    return redirect(url_for("booking_detail", booking_id=booking.id))


@app.route("/reviews/<int:review_id>/report", methods=["POST"])
@login_required
def review_report(review_id: int):
    review = ProviderReview.query.get_or_404(review_id)
    review.reported_count = int(review.reported_count or 0) + 1
    if review.reported_count >= 3:
        review.status = ReviewVisibility.hidden
    db.session.commit()
    flash("Review reported. Thank you for helping keep the community safe.", "success")
    return redirect(request.referrer or url_for("provider_portfolio_public", username=review.provider.username))


@app.route("/admin/reviews", endpoint="admin_reviews")
@app.route("/dashboard/admin/reviews", endpoint="admin_reviews_dashboard")
@role_required("admin")
def admin_reviews():
    status = (request.args.get("status") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lstrip("@")

    query = ProviderReview.query
    if status in ("visible", "hidden"):
        query = query.filter(ProviderReview.status == ReviewVisibility(status))
    if q:
        provider = User.query.filter(func.lower(User.username) == q.lower()).first()
        if provider:
            query = query.filter(ProviderReview.provider_user_id == provider.id)
        else:
            query = query.filter(ProviderReview.id == -1)

    reviews = query.order_by(ProviderReview.created_at.desc()).limit(200).all()
    return render_template("admin_reviews.html", reviews=reviews, status=status, q=q)


@app.route("/admin/reviews/<int:review_id>/hide", methods=["POST"])
@role_required("admin")
def admin_review_hide(review_id: int):
    review = ProviderReview.query.get_or_404(review_id)
    review.status = ReviewVisibility.hidden
    db.session.commit()
    flash("Review hidden.", "success")
    return redirect(request.referrer or url_for("admin_reviews"))


@app.route("/admin/reviews/<int:review_id>/show", methods=["POST"])
@role_required("admin")
def admin_review_show(review_id: int):
    review = ProviderReview.query.get_or_404(review_id)
    review.status = ReviewVisibility.visible
    db.session.commit()
    flash("Review visible.", "success")
    return redirect(request.referrer or url_for("admin_reviews"))


@app.route("/bookings/<int:booking_id>/dispute", methods=["GET", "POST"])
@login_required
def booking_dispute(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)
    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        abort(403)

    dispute = BookingDispute.query.filter_by(booking_id=booking.id).order_by(BookingDispute.created_at.desc()).first()

    if request.method == "POST":
        if dispute:
            flash("A dispute already exists for this booking.", "error")
            return redirect(url_for("booking_dispute", booking_id=booking.id))

        # Window check
        if booking.event_datetime:
            deadline = booking.event_datetime + timedelta(days=DISPUTE_OPEN_WINDOW_DAYS)
            if datetime.utcnow() > deadline:
                flash("Dispute window has closed for this booking.", "error")
                return redirect(url_for("booking_detail", booking_id=booking.id))

        reason = sanitize_input((request.form.get("reason") or "").strip(), max_length=300)
        details = sanitize_input((request.form.get("details") or "").strip(), max_length=2000)
        if not reason:
            flash("Please provide a dispute reason.", "error")
            return redirect(url_for("booking_dispute", booking_id=booking.id))

        dispute = BookingDispute(
            booking_id=booking.id,
            opened_by_id=current_user.id,
            reason=reason,
            details=details or None,
            status="open",
        )
        db.session.add(dispute)
        db.session.flush()

        if details:
            msg = BookingDisputeMessage(
                dispute_id=dispute.id,
                author_user_id=current_user.id,
                body=details,
            )
            db.session.add(msg)
        db.session.commit()

        flash("Dispute opened. Our team will review it shortly.", "success")
        return redirect(url_for("booking_dispute", booking_id=booking.id))

    messages = []
    if dispute:
        messages = dispute.messages.order_by(BookingDisputeMessage.created_at.asc()).all()

    return render_template(
        "booking_dispute.html",
        booking=booking,
        dispute=dispute,
        messages=messages,
        DISPUTE_STATUSES=DISPUTE_STATUSES,
    )


@app.route("/disputes/<int:dispute_id>/reply", methods=["POST"])
@login_required
def dispute_reply(dispute_id: int):
    dispute = BookingDispute.query.get_or_404(dispute_id)
    booking = dispute.booking
    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        abort(403)

    body = sanitize_input((request.form.get("body") or "").strip(), max_length=2000)
    if not body:
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("booking_dispute", booking_id=booking.id))

    msg = BookingDisputeMessage(
        dispute_id=dispute.id,
        author_user_id=current_user.id,
        body=body,
    )
    db.session.add(msg)
    db.session.commit()
    flash("Reply sent.", "success")
    return redirect(url_for("booking_dispute", booking_id=booking.id))


@app.route("/admin/disputes", endpoint="admin_disputes")
@app.route("/dashboard/admin/disputes", endpoint="admin_disputes_dashboard")
@role_required("admin")
def admin_disputes():
    status = (request.args.get("status") or "").strip().lower()
    query = BookingDispute.query
    if status in DISPUTE_STATUSES:
        query = query.filter(BookingDispute.status == status)
    disputes = query.order_by(BookingDispute.created_at.desc()).limit(200).all()
    return render_template("admin_disputes.html", disputes=disputes, status=status, DISPUTE_STATUSES=DISPUTE_STATUSES)


@app.route("/admin/disputes/<int:dispute_id>", methods=["GET", "POST"], endpoint="admin_dispute_detail")
@role_required("admin")
def admin_dispute_detail(dispute_id: int):
    dispute = BookingDispute.query.get_or_404(dispute_id)

    if request.method == "POST":
        before_status = str(dispute.status)
        new_status = (request.form.get("status") or "").strip().lower()
        if new_status in DISPUTE_STATUSES:
            dispute.status = new_status

        body = sanitize_input((request.form.get("body") or "").strip(), max_length=2000)
        if body:
            msg = BookingDisputeMessage(
                dispute_id=dispute.id,
                author_user_id=current_user.id,
                body=body,
            )
            db.session.add(msg)
        db.session.commit()
        try:
            after_status = str(dispute.status)
            log_admin_action(
                ActivityEventType.admin_ticket_updated,
                actor_admin_id=current_user.id,
                target_type="dispute",
                target_id=dispute.id,
                summary=f"Dispute updated for booking #{dispute.booking_id}",
                payload_dict={"before": {"status": before_status}, "after": {"status": after_status}, "reply_added": bool(body)},
                url=url_for("admin_dispute_detail", dispute_id=dispute.id),
                include_actor=True,
            )
        except Exception:
            pass
        flash("Dispute updated.", "success")
        return redirect(url_for("admin_dispute_detail", dispute_id=dispute.id))

    messages = dispute.messages.order_by(BookingDisputeMessage.created_at.asc()).all()
    return render_template(
        "admin_dispute_detail.html",
        dispute=dispute,
        messages=messages,
        DISPUTE_STATUSES=DISPUTE_STATUSES,
    )

@app.route("/bookings/<int:booking_id>/quote", methods=["POST"])
@login_required
def booking_quote(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)
    is_provider = current_user.id == booking.provider_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_admin):
        flash("You are not allowed to quote this booking.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    duration_minutes = int(booking.duration_minutes or 0)
    if duration_minutes <= 0:
        flash("Duration is required before sending a quote.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    hourly_rate_raw = (request.form.get("hourly_rate_dollars") or "").strip()
    billable_hours_raw = (request.form.get("billable_hours") or "").strip()
    breakdown_text = (request.form.get("quote_breakdown_text") or "").strip()
    calculation_text = (request.form.get("quote_calculation_text") or "").strip()

    if not billable_hours_raw:
        flash("Billable hours are required.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    if not hourly_rate_raw:
        flash("Hourly rate is required.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    try:
        billable_hours_decimal = Decimal(billable_hours_raw)
    except Exception:
        flash("Billable hours must be a valid number.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    try:
        rate_decimal = Decimal(hourly_rate_raw)
    except Exception:
        flash("Hourly rate must be a valid number.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    if billable_hours_decimal <= 0:
        flash("Billable hours must be greater than 0.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    if rate_decimal <= 0:
        flash("Hourly rate must be greater than 0.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    if not breakdown_text:
        flash("Please provide a quote breakdown.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    hourly_rate_cents = int((rate_decimal * 100).to_integral_value(rounding=ROUND_UP))
    billable_minutes = int((billable_hours_decimal * 60).to_integral_value(rounding=ROUND_UP))
    quoted_total_cents = int(
        (Decimal(billable_minutes) * Decimal(hourly_rate_cents) / Decimal(60)).to_integral_value(rounding=ROUND_UP)
    )

    booking.quote_hourly_rate_cents = hourly_rate_cents
    booking.quote_billable_minutes = billable_minutes
    booking.quote_calculation_text = calculation_text or None
    booking.quoted_total_cents = quoted_total_cents
    booking.total_cents = quoted_total_cents
    booking.quote_breakdown_text = breakdown_text
    booking.deposit_base_cents = HOLD_FEE_CENTS
    booking.beatfund_fee_total_cents = calc_beatfund_fee_total(quoted_total_cents)
    booking.status = BOOKING_STATUS_QUOTED

    db.session.commit()
    try:
        client = User.query.get(booking.client_id)
        if client:
            notify_user(
                client,
                kind="success",
                title="Quote ready",
                body=f"@{current_user.username} sent you a quote for booking #{booking.id}.",
                url=url_for("booking_detail", booking_id=booking.id),
                actor_user_id=current_user.id,
                event_key=f"booking:{booking.id}:quote_sent",
                commit=True,
            )
    except Exception:
        pass
    flash("Quote sent to client.", "success")
    return redirect(url_for("booking_detail", booking_id=booking.id))


# =========================================================
# Booking Chat Routes
# =========================================================
@app.route("/bookings/<int:booking_id>/chat", methods=["GET"])
@login_required
def booking_chat(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)

    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        flash("You don't have access to this chat.", "error")
        return redirect(url_for("bookme_requests"))

    if booking.status not in CHAT_ALLOWED_BOOKING_STATUSES:
        flash("Chat is not available for this booking.", "error")
        return redirect(url_for("booking_detail", booking_id=booking.id))

    conv = get_or_create_booking_conversation(booking.id)

    # Paginate last 50 messages (sent only)
    msgs = (
        Message.query
        .filter_by(conversation_id=conv.id, delivery_status=MessageDeliveryStatus.sent)
        .order_by(Message.created_at.desc(), Message.id.desc())
        .limit(50)
        .all()
    )
    msgs.reverse()

    provider = User.query.get(booking.provider_id) if booking.provider_id else None
    client = User.query.get(booking.client_id) if booking.client_id else None

    # Block state (for UI)
    other_blocked_me = (
        ConversationParticipant.query
        .filter(
            ConversationParticipant.conversation_id == conv.id,
            ConversationParticipant.user_id != current_user.id,
            ConversationParticipant.is_blocked.is_(True),
        )
        .first()
        is not None
    )
    i_blocked_other = (
        ConversationParticipant.query
        .filter_by(conversation_id=conv.id, user_id=current_user.id)
        .first()
    )
    i_blocked_other = bool(getattr(i_blocked_other, "is_blocked", False))

    return render_template(
        "chat_booking.html",
        booking=booking,
        conversation=conv,
        messages=msgs,
        provider=provider,
        client=client,
        other_blocked_me=other_blocked_me,
        i_blocked_other=i_blocked_other,
        CHAT_RATE_LIMIT_PER_MINUTE=CHAT_RATE_LIMIT_PER_MINUTE,
    )


@app.route("/bookings/<int:booking_id>/chat/send", methods=["POST"])
@login_required
def booking_chat_send(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)

    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    if booking.status not in CHAT_ALLOWED_BOOKING_STATUSES:
        return jsonify({"success": False, "error": "Chat is not available for this booking."}), 400

    conv = get_or_create_booking_conversation(booking.id)

    # Admins can view, but keep sending limited to participants only
    if is_admin and not (is_provider or is_client):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    text_in = ""
    if request.is_json:
        text_in = (request.json.get("text") or "").strip()
    else:
        text_in = (request.form.get("text") or "").strip()

    ok, reason = validate_message_text(text_in)
    if not ok:
        # Log moderation attempt (do not store blocked content in Message)
        try:
            db.session.add(MessageModerationLog(
                conversation_id=conv.id,
                sender_user_id=current_user.id,
                attempted_text=text_in[:2000],
                reason=reason or ModerationReason.profanity.value,
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

        if reason in (ModerationReason.pii_card.value, ModerationReason.pii_phone.value, ModerationReason.pii_email.value):
            return jsonify({"success": False, "error": "Sharing phone numbers, emails, or payment info is not allowed. Keep communication inside BeatFund."}), 400
        if reason in (ModerationReason.profanity.value, ModerationReason.threat.value):
            return jsonify({"success": False, "error": "Harassment or abusive language is not allowed."}), 400
        if reason == "EMPTY":
            return jsonify({"success": False, "error": "Message cannot be empty."}), 400
        return jsonify({"success": False, "error": "Message rejected."}), 400

    ok2, reason2 = can_send_message(current_user.id, conv.id)
    if not ok2:
        try:
            db.session.add(MessageModerationLog(
                conversation_id=conv.id,
                sender_user_id=current_user.id,
                attempted_text=text_in[:2000],
                reason=reason2 or ModerationReason.rate_limit.value,
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()

        if reason2 == ModerationReason.rate_limit.value:
            return jsonify({"success": False, "error": f"Too many messages. Please slow down (max {CHAT_RATE_LIMIT_PER_MINUTE}/minute)."}), 429
        if reason2 == ModerationReason.blocked.value:
            return jsonify({"success": False, "error": "You cannot send messages in this conversation."}), 403
        return jsonify({"success": False, "error": "You cannot send messages right now."}), 403

    msg = Message(
        conversation_id=conv.id,
        sender_user_id=current_user.id,
        body_text=text_in,
        delivery_status=MessageDeliveryStatus.sent,
    )
    db.session.add(msg)
    conv.last_message_at = datetime.utcnow()
    db.session.commit()

    # Notify the other participant (anti-spam + block-aware)
    try:
        recipient_id = None
        if booking.client_id == current_user.id:
            recipient_id = booking.provider_id
        elif booking.provider_id == current_user.id:
            recipient_id = booking.client_id
        if recipient_id:
            notify_chat_message(
                booking_id=booking.id,
                conversation_id=conv.id,
                message_id=msg.id,
                sender_user_id=current_user.id,
                recipient_user_id=recipient_id,
                message_text=text_in,
            )
    except Exception:
        # Best-effort: message send should succeed even if notification fails
        pass

    return jsonify({"success": True, "message_id": msg.id})


@app.route("/bookings/<int:booking_id>/chat/block", methods=["POST"])
@login_required
def booking_chat_block(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)

    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    conv = get_or_create_booking_conversation(booking.id)

    if is_admin and not (is_provider or is_client):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    me = ConversationParticipant.query.filter_by(conversation_id=conv.id, user_id=current_user.id).first()
    if not me:
        return jsonify({"success": False, "error": "Not allowed."}), 403

    me.is_blocked = True
    me.blocked_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True})


@app.route("/bookings/<int:booking_id>/chat/report", methods=["POST"])
@login_required
def booking_chat_report(booking_id: int):
    booking = Booking.query.get_or_404(booking_id)

    is_provider = current_user.id == booking.provider_id
    is_client = current_user.id == booking.client_id
    is_admin = current_user.role == RoleEnum.admin

    if not (is_provider or is_client or is_admin):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    conv = get_or_create_booking_conversation(booking.id)

    if is_admin and not (is_provider or is_client):
        return jsonify({"success": False, "error": "Not allowed."}), 403

    note = ""
    if request.is_json:
        note = (request.json.get("note") or "").strip()
    else:
        note = (request.form.get("note") or "").strip()

    db.session.add(MessageModerationLog(
        conversation_id=conv.id,
        sender_user_id=current_user.id,
        attempted_text=(note[:2000] if note else None),
        reason=ModerationReason.report.value,
    ))
    try:
        conv.status = ConversationStatus.flagged
    except Exception:
        pass
    db.session.commit()
    try:
        _alert_create(
            AlertSeverity.high,
            "CHAT_REPORTED",
            "Booking chat reported",
            {"booking_id": booking.id, "conversation_id": conv.id, "reporter_user_id": current_user.id, "note_preview": (note[:200] if note else None)},
        )
    except Exception:
        pass
    return jsonify({"success": True})

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

    settings = get_provider_settings(provider.id, create=False)
    availability_slots, availability_exceptions = get_provider_availability_summary(provider.id)

    # Get follower count and follow status for template
    follower_count = UserFollow.query.filter_by(followed_id=provider.id).count()
    is_following = current_user.is_authenticated and UserFollow.query.filter_by(
        follower_id=current_user.id, followed_id=provider.id
    ).first() is not None
    
    if request.method == "POST":
        if settings and not settings.accepting_new_requests:
            flash("This provider is not accepting new requests right now.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following,
                settings=settings,
                availability_slots=availability_slots,
                availability_exceptions=availability_exceptions,
            )

        # Collect all form fields
        event_date = (request.form.get("event_date") or "").strip()
        event_time = (request.form.get("event_time") or "").strip()
        preferred_time_fallback = (request.form.get("preferred_time") or "").strip()
        budget = (request.form.get("budget") or "").strip()
        message = (request.form.get("message") or "").strip()
        duration_hours_raw = (request.form.get("duration_hours") or "").strip()
        duration_minutes_raw = (request.form.get("duration_minutes") or "").strip()
        
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

        duration_hours = 0
        duration_minutes = 0
        try:
            if duration_hours_raw:
                duration_hours = int(duration_hours_raw)
            if duration_minutes_raw:
                duration_minutes = int(duration_minutes_raw)
        except ValueError:
            flash("Duration must be a valid number of hours/minutes.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following
            )

        if duration_hours < 0 or duration_minutes < 0 or duration_minutes > 59:
            flash("Duration minutes must be between 0 and 59.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following
            )

        total_duration_minutes = (duration_hours * 60) + duration_minutes
        if total_duration_minutes <= 0:
            flash("Duration is required.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following
            )
        if total_duration_minutes < 30 or total_duration_minutes > (12 * 60):
            flash("Duration must be between 30 minutes and 12 hours.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following
            )
        
        # Build comprehensive message from role-specific fields
        role_val = (provider.role if provider.role else str(provider.role)).lower()
        message_parts = []
        
        if budget:
            message_parts.append(f"Budget: {budget}")
        message_parts.append(f"Duration: {total_duration_minutes} minutes")
        
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
        
        # Check if the requested time is blocked (for studios)
        if provider.role == RoleEnum.studio:
            try:
                if " " in preferred_time:
                    date_part = preferred_time.split(" ", 1)[0]
                    check_date = datetime.strptime(date_part, "%Y-%m-%d").date()
                else:
                    check_date = datetime.utcnow().date()
                
                if is_time_blocked(provider.id, check_date, preferred_time):
                    flash("This time slot is blocked and not available for booking.", "error")
                    return render_template(
                        "bookme_book_provider.html",
                        provider=provider,
                        form_data=request.form,
                        follower_count=follower_count,
                        is_following=is_following,
                        settings=settings,
                        availability_slots=availability_slots,
                        availability_exceptions=availability_exceptions,
                    )
            except (ValueError, AttributeError):
                pass

        # Availability check for all provider roles
        ok, reason = provider_is_available(provider.id, preferred_time, total_duration_minutes)
        if not ok:
            flash(reason or "Requested time is not available.", "error")
            return render_template(
                "bookme_book_provider.html",
                provider=provider,
                form_data=request.form,
                follower_count=follower_count,
                is_following=is_following,
                settings=settings,
                availability_slots=availability_slots,
                availability_exceptions=availability_exceptions,
            )
        
        # Create booking request
        req = BookingRequest(
            provider_id=provider.id,
            client_id=current_user.id,
            message=full_message or None,
            preferred_time=preferred_time,
            duration_minutes=total_duration_minutes,
        )
        db.session.add(req)
        db.session.commit()
        
        # Notify provider
        notify_user(
            provider,
            kind="info",
            title="New booking request",
            body=f"@{current_user.username} requested {preferred_time}",
            url=url_for("bookme_requests"),
            commit=True,
        )
        
        flash("Booking request sent successfully.", "success")
        return redirect(url_for("bookme_requests"))
    
    return render_template(
        "bookme_book_provider.html",
        provider=provider,
        form_data={},
        follower_count=follower_count,
        is_following=is_following,
        settings=settings,
        availability_slots=availability_slots,
        availability_exceptions=availability_exceptions,
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
        else:
            errors.append("Duration is required.")

        if duration_minutes is not None:
            if duration_minutes <= 0:
                errors.append("Duration must be greater than 0 minutes.")
            elif duration_minutes < 30 or duration_minutes > (12 * 60):
                errors.append("Duration must be between 30 minutes and 12 hours.")

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
            quoted_total_cents=total_cents,
            deposit_base_cents=HOLD_FEE_CENTS,
            beatfund_fee_total_cents=calc_beatfund_fee_total(total_cents) if total_cents else None,
            notes_from_client=notes_from_client or None,
            status=BOOKING_STATUS_PENDING,
        )
        db.session.add(booking)
        db.session.commit()

        # Ensure booking-scoped conversation exists (chat gated to booking)
        try:
            get_or_create_booking_conversation(booking.id)
        except Exception:
            pass

        flash("Booking request submitted. The artist will review and confirm.", "success")
        return redirect(url_for("route_to_dashboard"))

    return render_template("artist_booking.html", artist=artist, form_data={}, is_owner=is_owner)


# =========================================================
# Marketplace
# =========================================================
@app.route("/market", endpoint="market_index")
@login_required
def market_index():
    try:
        items = (
            Beat.query
            .filter_by(is_active=True)
            .filter(or_(Beat.preview_status == "ready", Beat.preview_status.is_(None)))
            .order_by(Beat.is_featured.desc(), Beat.id.desc())
            .all()
        )

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

        # Producers with Stripe Connect (required for beat purchase payouts)
        producer_ids_with_stripe = {
            b.owner_id for b in items
            if b.owner_id and _producer_has_stripe_connected(b.owner_id)
        }

        return render_template(
            "market_index.html",
            items=items,
            provider_profiles=provider_profiles,
            studios=studios,
            videographers=videographers,
            talent_profiles=talent_profiles,
            other_providers=other_providers,
            RoleEnum=RoleEnum,
            producer_ids_with_stripe=producer_ids_with_stripe,
        )
    except Exception as market_err:
        app.logger.error(f"Market page error: {type(market_err).__name__}: {str(market_err)}", exc_info=True)
        # Return empty market with error message
        flash("The marketplace is temporarily unavailable. Please try again.", "warning")
        return render_template(
            "market_index.html",
            items=[],
            provider_profiles=[],
            studios=[],
            videographers=[],
            talent_profiles=[],
            other_providers=[],
            RoleEnum=RoleEnum,
            producer_ids_with_stripe=set(),
        )


@app.route("/market/my-purchases")
@login_required
def market_my_purchases():
    # Query all paid orders for the current user
    from sqlalchemy.orm import joinedload
    
    # Get all orders with eager loading of beat relationship
    # Use explicit filter to ensure we get all paid orders
    # Expire any cached queries to ensure we get fresh data
    db.session.expire_all()
    
    legacy_orders = (
        Order.query
        .options(joinedload(Order.beat))
        .filter(Order.buyer_id == current_user.id)
        .filter(Order.status == OrderStatus.paid)
        .order_by(Order.created_at.desc())
        .all()
    )

    payout_orders = (
        PaymentOrder.query
        .options(joinedload(PaymentOrder.beat))
        .filter(PaymentOrder.client_user_id == current_user.id)
        .filter(PaymentOrder.order_type == OrderType.beat_purchase)
        .filter(PaymentOrder.status == OrderStatus.paid)
        .order_by(PaymentOrder.created_at.desc())
        .all()
    )

    # Debug logging - also check raw count
    raw_count = Order.query.filter_by(buyer_id=current_user.id, status=OrderStatus.paid).count()
    app.logger.info(
        f"My Purchases: Found {len(legacy_orders)} legacy orders and {len(payout_orders)} payout orders "
        f"(raw count: {raw_count}) for user {current_user.id}"
    )

    combined = list(legacy_orders) + list(payout_orders)
    combined.sort(key=lambda o: (o.created_at or datetime.min), reverse=True)

    purchases = []
    for o in combined:
        # Only include orders that have a valid beat
        if o.beat_id:
            # Try to load beat if not already loaded
            if not o.beat:
                o.beat = Beat.query.get(o.beat_id)
            
            if o.beat:
                producer = User.query.get(o.beat.owner_id) if o.beat.owner_id else None
                purchases.append({"order": o, "beat": o.beat, "producer": producer})
            else:
                app.logger.warning(f"Order {o.id} has beat_id {o.beat_id} but beat not found")
        else:
            app.logger.warning(f"Order {o.id} has no beat_id")
    
    app.logger.info(f"My Purchases: Returning {len(purchases)} purchases for user {current_user.id}")
    return render_template("market_my_purchases.html", purchases=purchases)


# =========================================================
# Stripe Configuration
# =========================================================
def _clean_env(name: str) -> str:
    value = os.getenv(name, "")
    return value.strip() if value else ""


def _is_placeholder(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if "placeholder" in lowered or "your_" in lowered:
        return True
    if lowered in {"sk_test_placeholder", "pk_test_placeholder", "whsec_test_placeholder"}:
        return True
    return False


STRIPE_SECRET_KEY = _clean_env("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = _clean_env("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = _clean_env("STRIPE_WEBHOOK_SECRET")
CONNECT_ONBOARDING_RETURN_URL = _clean_env("CONNECT_ONBOARDING_RETURN_URL")
CONNECT_ONBOARDING_REFRESH_URL = _clean_env("CONNECT_ONBOARDING_REFRESH_URL")
APP_BASE_URL = (_clean_env("APP_BASE_URL") or "").rstrip("/")

if _is_placeholder(STRIPE_SECRET_KEY):
    STRIPE_SECRET_KEY = ""
if _is_placeholder(STRIPE_PUBLISHABLE_KEY):
    STRIPE_PUBLISHABLE_KEY = ""
if _is_placeholder(STRIPE_WEBHOOK_SECRET):
    STRIPE_WEBHOOK_SECRET = ""

stripe_enabled = bool(STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY)

if is_prod() and STRICT_PROD_CHECKS:
    require_env(["SECRET_KEY", "APP_BASE_URL"])
    missing_stripe = []
    if not STRIPE_SECRET_KEY:
        missing_stripe.append("STRIPE_SECRET_KEY")
    if not STRIPE_PUBLISHABLE_KEY:
        missing_stripe.append("STRIPE_PUBLISHABLE_KEY")
    if not STRIPE_WEBHOOK_SECRET:
        missing_stripe.append("STRIPE_WEBHOOK_SECRET")
    if missing_stripe:
        raise RuntimeError(f"Missing env: {', '.join(missing_stripe)}")
elif is_prod():
    missing_stripe = []
    if not STRIPE_SECRET_KEY:
        missing_stripe.append("STRIPE_SECRET_KEY")
    if not STRIPE_PUBLISHABLE_KEY:
        missing_stripe.append("STRIPE_PUBLISHABLE_KEY")
    if not STRIPE_WEBHOOK_SECRET:
        missing_stripe.append("STRIPE_WEBHOOK_SECRET")
    if not APP_BASE_URL:
        missing_stripe.append("APP_BASE_URL")
    if missing_stripe:
        app.logger.warning(
            f"Stripe env missing in production (STRICT_PROD_CHECKS=0): {', '.join(missing_stripe)}"
        )

# Base URL for Stripe checkout success/cancel URLs
# Use APP_BASE_URL if set (for production), otherwise fall back to request.host_url
def get_stripe_base_url() -> str:
    """Get base URL for Stripe checkout redirects - must be publicly accessible"""
    # In local dev, prefer the *actual host* the user is browsing (localhost vs 127.0.0.1),
    # otherwise cookies won't be sent on the Stripe redirect and login_required routes won't run.
    try:
        if request and request.host_url:
            host = request.host_url.rstrip("/")
            if host.startswith("http://127.0.0.1") or host.startswith("http://localhost") or host.startswith("https://127.0.0.1") or host.startswith("https://localhost"):
                return host
    except Exception:
        pass

    app_base_url = (APP_BASE_URL or "").strip()
    if app_base_url:
        if not re.match(r"^https?://", app_base_url, re.IGNORECASE):
            app_base_url = f"https://{app_base_url}"
        return app_base_url.rstrip("/")
    # Fallback to request.host_url (works in dev, but should set APP_BASE_URL in production)
    return request.host_url.rstrip("/") if request else ""

if stripe_enabled and STRIPE_AVAILABLE:
    stripe.api_key = STRIPE_SECRET_KEY
elif stripe_enabled and not STRIPE_AVAILABLE:
    app.logger.warning("STRIPE_SECRET_KEY is set but stripe package is not installed. Install with: pip install stripe")
elif not stripe_enabled:
    app.logger.warning("Stripe not configured: missing STRIPE_SECRET_KEY or STRIPE_PUBLISHABLE_KEY")

app.logger.info(
    f"Stripe config: enabled={stripe_enabled} "
    f"publishable_set={bool(STRIPE_PUBLISHABLE_KEY)} "
    f"secret_set={bool(STRIPE_SECRET_KEY)} "
    f"webhook_set={bool(STRIPE_WEBHOOK_SECRET)}"
)
app.logger.info(
    "Stripe readiness: "
    f"STRIPE_SECRET_KEY_present={bool(STRIPE_SECRET_KEY)} "
    f"STRIPE_PUBLISHABLE_KEY_present={bool(STRIPE_PUBLISHABLE_KEY)} "
    f"STRIPE_WEBHOOK_SECRET_present={bool(STRIPE_WEBHOOK_SECRET)} "
    f"APP_BASE_URL_present={bool(APP_BASE_URL)}"
)


def _stripe_env_status(*, require_webhook: bool = False, require_base_url: bool = False) -> tuple[bool, list[str]]:
    missing: list[str] = []
    if not STRIPE_AVAILABLE:
        missing.append("stripe_package")
    if not STRIPE_SECRET_KEY:
        missing.append("STRIPE_SECRET_KEY")
    if not STRIPE_PUBLISHABLE_KEY:
        missing.append("STRIPE_PUBLISHABLE_KEY")
    if require_webhook and not STRIPE_WEBHOOK_SECRET:
        missing.append("STRIPE_WEBHOOK_SECRET")
    if require_base_url and not (APP_BASE_URL or "").strip():
        missing.append("APP_BASE_URL")
    return (len(missing) == 0, missing)


def _stripe_error_payload(err: Exception) -> dict:
    payload = {"error": "Stripe error"}
    if isinstance(err, stripe.error.StripeError):
        payload.update({
            "type": err.__class__.__name__,
            "code": getattr(err, "code", None),
            "http_status": getattr(err, "http_status", None),
            "message": getattr(err, "user_message", None) or str(err),
        })
    else:
        payload["message"] = str(err)
    return payload


def _log_stripe_error(route: str, err: Exception, **ctx: object) -> None:
    payload = {
        "route": route,
        "request_id": getattr(g, "request_id", None),
        "stripe_error": _stripe_error_payload(err),
        "context": ctx,
    }
    try:
        app.logger.error(f"STRIPE_ERROR {json.dumps(payload, default=str)}")
    except Exception:
        app.logger.error("STRIPE_ERROR (failed to serialize context)")


def _stripe_env_guard(*, require_webhook: bool = False, require_base_url: bool = False) -> tuple[bool, str]:
    keys = ["STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY"]
    if require_webhook:
        keys.append("STRIPE_WEBHOOK_SECRET")
    if require_base_url:
        keys.append("APP_BASE_URL")

    missing_from_require: list[str] = []
    try:
        require_env(keys)
    except RuntimeError as e:
        msg = str(e)
        if "Missing env:" in msg:
            missing_from_require = [k.strip() for k in msg.replace("Missing env:", "").split(",") if k.strip()]

    ok, missing = _stripe_env_status(require_webhook=require_webhook, require_base_url=require_base_url)
    if ok and not missing_from_require:
        return True, ""

    missing_all = sorted(set(missing_from_require + missing))
    try:
        app.logger.warning(
            "Stripe env missing at request-time",
            extra={
                "request_id": getattr(g, "request_id", None),
                "route": request.endpoint if request else None,
                "missing": missing_all,
            },
        )
    except Exception:
        app.logger.warning(
            f"Stripe env missing at request-time route={getattr(request, 'endpoint', None)} "
            f"request_id={getattr(g, 'request_id', None)} missing={missing_all}"
        )

    missing_display = ", ".join(missing_all) if missing_all else "unknown"
    return False, f"Stripe is not configured. Missing: {missing_display}"


def _get_active_affiliate_id(user: User | None) -> int | None:
    if not user:
        return None
    try:
        aff_id = int(user.referred_by_affiliate_id or 0)
    except Exception:
        aff_id = 0
    if not aff_id:
        return None
    try:
        affiliate = Affiliate.query.get(aff_id)
    except Exception:
        affiliate = None
    if not affiliate or affiliate.status != AffiliateStatus.active:
        return None
    return affiliate.id


def _get_or_refresh_provider_stripe_account(provider_user_id: int, *, refresh: bool = False) -> ProviderStripeAccount | None:
    acct_row = ProviderStripeAccount.query.filter_by(user_id=provider_user_id).first()
    acct_id = acct_row.stripe_account_id if acct_row else None
    if not acct_id:
        try:
            provider = User.query.get(int(provider_user_id))
        except Exception:
            provider = None
        acct_id = (getattr(provider, "stripe_account_id", None) or "").strip() if provider else None
        if acct_id:
            acct_row = ProviderStripeAccount(
                user_id=int(provider_user_id),
                stripe_account_id=acct_id,
                charges_enabled=False,
                payouts_enabled=False,
                details_submitted=False,
            )
            try:
                db.session.add(acct_row)
                db.session.commit()
            except Exception:
                db.session.rollback()

    if refresh and acct_id and STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
        try:
            acct = stripe.Account.retrieve(acct_id)
            charges_enabled = bool(getattr(acct, "charges_enabled", False) or acct.get("charges_enabled"))
            payouts_enabled = bool(getattr(acct, "payouts_enabled", False) or acct.get("payouts_enabled"))
            details_submitted = bool(getattr(acct, "details_submitted", False) or acct.get("details_submitted"))
            if acct_row:
                acct_row.charges_enabled = charges_enabled
                acct_row.payouts_enabled = payouts_enabled
                acct_row.details_submitted = details_submitted
                db.session.commit()
        except Exception:
            db.session.rollback()
    return acct_row


def _get_provider_acct_id_or_error(provider_user_id: int) -> tuple[str | None, str | None]:
    acct_row = _get_or_refresh_provider_stripe_account(provider_user_id, refresh=KYC_ENFORCE)
    acct_id = (acct_row.stripe_account_id if acct_row else None) or ""
    acct_id = acct_id.strip()
    if not acct_id:
        return None, "Provider has not connected a Stripe account."
    if KYC_ENFORCE and acct_row and not (acct_row.charges_enabled and acct_row.payouts_enabled):
        return None, "Provider Stripe account is not ready for charges/payouts."
    return acct_id, None


def _producer_has_stripe_connected(provider_user_id: int | None) -> bool:
    """Return True if the producer has connected Stripe (required for beat sale payouts)."""
    if not provider_user_id:
        return False
    acct_id, _ = _get_provider_acct_id_or_error(int(provider_user_id))
    return bool(acct_id)


def get_or_create_payment_order_for_booking(booking: Booking) -> tuple[PaymentOrder | None, str | None]:
    if not booking:
        return None, "booking_not_found"
    total_cents = booking.quoted_total_cents or booking.total_cents
    if total_cents is None or int(total_cents) <= 0:
        return None, "Booking total must be set before payment."
    total_cents = int(total_cents)
    client_id = int(booking.client_id)
    provider_id = int(booking.provider_id)
    affiliate_id = _get_active_affiliate_id(User.query.get(client_id))

    existing = (
        PaymentOrder.query
        .filter_by(order_type=OrderType.booking, booking_id=booking.id, client_user_id=client_id)
        .order_by(PaymentOrder.created_at.desc())
        .first()
    )
    acct_id, _ = _get_provider_acct_id_or_error(provider_id)

    if existing:
        existing.total_amount_cents = total_cents
        existing.provider_user_id = provider_id
        existing.provider_stripe_acct_id = acct_id or existing.provider_stripe_acct_id
        existing.affiliate_id = affiliate_id
        if existing.status == OrderStatus.draft:
            existing.status = OrderStatus.pending_payment
        db.session.commit()
        return existing, None

    order = PaymentOrder(
        order_type=OrderType.booking,
        status=OrderStatus.pending_payment,
        client_user_id=client_id,
        provider_user_id=provider_id,
        provider_stripe_acct_id=acct_id or None,
        total_amount_cents=total_cents,
        currency="usd",
        affiliate_id=affiliate_id,
        booking_id=booking.id,
    )
    db.session.add(order)
    db.session.commit()
    return order, None


def get_or_create_payment_order_for_beat(beat: Beat, buyer: User) -> tuple[PaymentOrder | None, str | None]:
    if not beat or not buyer:
        return None, "beat_or_user_missing"
    total_cents = int(beat.price_cents or 0)
    if total_cents < 0:
        return None, "Invalid beat price."
    affiliate_id = _get_active_affiliate_id(buyer)
    provider_id = int(beat.owner_id) if beat.owner_id else None
    acct_id, _ = _get_provider_acct_id_or_error(provider_id) if provider_id else (None, None)

    existing = (
        PaymentOrder.query
        .filter_by(order_type=OrderType.beat_purchase, beat_id=beat.id, client_user_id=buyer.id)
        .order_by(PaymentOrder.created_at.desc())
        .first()
    )
    if existing and existing.status == OrderStatus.paid:
        return existing, None
    if existing and existing.status in (OrderStatus.pending_payment, OrderStatus.partially_paid):
        existing.total_amount_cents = total_cents
        existing.provider_user_id = provider_id
        existing.provider_stripe_acct_id = acct_id or existing.provider_stripe_acct_id
        existing.affiliate_id = affiliate_id
        existing.currency = beat.currency or existing.currency or "usd"
        db.session.commit()
        return existing, None

    order = PaymentOrder(
        order_type=OrderType.beat_purchase,
        status=OrderStatus.pending_payment,
        client_user_id=int(buyer.id),
        provider_user_id=provider_id,
        provider_stripe_acct_id=acct_id or None,
        total_amount_cents=total_cents,
        currency=(beat.currency or "usd"),
        affiliate_id=affiliate_id,
        beat_id=beat.id,
    )
    db.session.add(order)
    db.session.commit()
    return order, None


def _ledger_phase_succeeded(order_id: int, phase: PaymentLedgerPhase) -> bool:
    try:
        return (
            PaymentLedger.query
            .filter_by(order_id=order_id, phase=phase, status=PaymentLedgerStatus.succeeded)
            .first()
            is not None
        )
    except Exception:
        return False


def _create_checkout_session_for_order(order: PaymentOrder, phase: PaymentLedgerPhase) -> tuple[dict, int]:
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        return {"error": err_msg}, 400

    if not order:
        return {"error": "Order not found."}, 404

    base_url = get_stripe_base_url()
    if not base_url:
        return {"error": "Unable to determine base URL. Please set APP_BASE_URL."}, 500

    currency = (order.currency or "usd").lower()
    if not re.match(r"^[a-z]{3}$", currency):
        return {"error": "Invalid currency."}, 400

    if phase == PaymentLedgerPhase.holding and order.order_type != OrderType.booking:
        return {"error": "Invalid order phase."}, 400
    if phase == PaymentLedgerPhase.balance and order.order_type != OrderType.booking:
        return {"error": "Invalid order phase."}, 400
    if phase == PaymentLedgerPhase.full and order.order_type != OrderType.beat_purchase:
        return {"error": "Invalid order phase."}, 400

    if _ledger_phase_succeeded(order.id, phase):
        return {"error": "Payment already completed for this phase."}, 409

    metadata = {
        "order_id": str(order.id),
        "phase": phase.value,
        "order_type": order.order_type.value,
        "client_user_id": str(order.client_user_id),
        "provider_user_id": str(order.provider_user_id or ""),
        "booking_id": str(order.booking_id or ""),
        "beat_id": str(order.beat_id or ""),
    }

    client_ref = f"order_{order.id}_user_{order.client_user_id}"

    if phase == PaymentLedgerPhase.holding:
        amount_cents = booking_hold_fee_effective(int(order.total_amount_cents or 0))
        if amount_cents <= 0:
            return {"error": "Invalid hold fee amount."}, 400

        line_items = [{
            "price_data": {
                "currency": currency,
                "product_data": {"name": "Booking Holding Fee"},
                "unit_amount": int(amount_cents),
            },
            "quantity": 1,
        }]

        success_url = f"{base_url}/payments/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{base_url}/payments/cancel"

        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=line_items,
                mode="payment",
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=client_ref,
                metadata=metadata,
                payment_intent_data={"metadata": metadata},
                idempotency_key=f"order_{order.id}_holding",
            )
        except stripe.error.StripeError as e:
            _log_stripe_error(
                "checkout_session_create_holding",
                e,
                user_id=order.client_user_id,
                booking_id=order.booking_id,
                order_id=order.id,
                amount_cents=amount_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Stripe error creating checkout session."}, 502
        except Exception as e:
            _log_stripe_error(
                "checkout_session_create_holding",
                e,
                user_id=order.client_user_id,
                booking_id=order.booking_id,
                order_id=order.id,
                amount_cents=amount_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Unable to create checkout session."}, 500

    elif phase == PaymentLedgerPhase.balance:
        hold_paid = ledger_sum_gross(order.id, phase=PaymentLedgerPhase.holding)
        hold_required = booking_hold_fee_effective(int(order.total_amount_cents or 0))
        if hold_required > 0 and hold_paid < hold_required:
            return {"error": "deposit_required"}, 409

        balance_due_cents = max(0, int(order.total_amount_cents or 0) - int(hold_paid or 0))
        if balance_due_cents <= 0:
            return {"error": "no_balance_due"}, 409

        acct_id, err = _get_provider_acct_id_or_error(int(order.provider_user_id or 0))
        if err:
            return {"error": err}, 400

        fee_remaining = fee_remaining_cents(order)
        application_fee_cents = min(int(fee_remaining), int(balance_due_cents))

        line_items = [{
            "price_data": {
                "currency": currency,
                "product_data": {"name": "Booking Balance"},
                "unit_amount": int(balance_due_cents),
            },
            "quantity": 1,
        }]

        success_url = f"{base_url}/payments/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{base_url}/payments/cancel"

        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=line_items,
                mode="payment",
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=client_ref,
                metadata=metadata,
                payment_intent_data={
                    "application_fee_amount": int(application_fee_cents),
                    "transfer_data": {"destination": acct_id},
                    "metadata": metadata,
                },
                idempotency_key=f"order_{order.id}_balance",
            )
        except stripe.error.StripeError as e:
            _log_stripe_error(
                "checkout_session_create_balance",
                e,
                user_id=order.client_user_id,
                booking_id=order.booking_id,
                order_id=order.id,
                amount_cents=balance_due_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Stripe error creating checkout session."}, 502
        except Exception as e:
            _log_stripe_error(
                "checkout_session_create_balance",
                e,
                user_id=order.client_user_id,
                booking_id=order.booking_id,
                order_id=order.id,
                amount_cents=balance_due_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Unable to create checkout session."}, 500

    else:
        amount_cents = int(order.total_amount_cents or 0)
        if amount_cents <= 0:
            return {"error": "Invalid order amount."}, 400

        acct_id, err = _get_provider_acct_id_or_error(int(order.provider_user_id or 0))
        if err:
            return {"error": err}, 400

        application_fee_cents = planned_platform_fee_cents(order.order_type, amount_cents)

        line_items = [{
            "price_data": {
                "currency": currency,
                "product_data": {"name": "Beat Purchase"},
                "unit_amount": int(amount_cents),
            },
            "quantity": 1,
        }]

        success_url = f"{base_url}/payments/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{base_url}/payments/cancel"

        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=line_items,
                mode="payment",
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=client_ref,
                metadata=metadata,
                payment_intent_data={
                    "application_fee_amount": int(application_fee_cents),
                    "transfer_data": {"destination": acct_id},
                    "metadata": metadata,
                },
                idempotency_key=f"order_{order.id}_full",
            )
        except stripe.error.StripeError as e:
            _log_stripe_error(
                "checkout_session_create_full",
                e,
                user_id=order.client_user_id,
                beat_id=order.beat_id,
                order_id=order.id,
                amount_cents=amount_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Stripe error creating checkout session."}, 502
        except Exception as e:
            _log_stripe_error(
                "checkout_session_create_full",
                e,
                user_id=order.client_user_id,
                beat_id=order.beat_id,
                order_id=order.id,
                amount_cents=amount_cents,
                currency=currency,
                phase=phase.value,
            )
            return {"error": "Unable to create checkout session."}, 500

    order.status = OrderStatus.pending_payment
    db.session.commit()

    return {
        "session_id": checkout_session.id,
        "checkout_url": checkout_session.url,
        "url": checkout_session.url,
    }, 200


def sync_beat_to_stripe(beat: Beat, commit: bool = True) -> tuple[Optional[str], Optional[str]]:
    """
    Create or update Stripe Product and Price for a beat.
    Returns (product_id, price_id) tuple.
    Prices are calculated server-side to include platform and processing fees.
    """
    if not STRIPE_AVAILABLE or not STRIPE_SECRET_KEY:
        app.logger.warning(f"Stripe not available, skipping sync for beat {beat.id}")
        return (None, None)
    
    if beat.price_cents <= 0:
        # Free beats don't need Stripe products
        app.logger.debug(f"Beat {beat.id} is free, skipping Stripe sync")
        return (None, None)
    
    try:
        # Calculate total price (subtotal + platform fee + processing fee)
        breakdown = fee_breakdown_for_beat(beat.price_cents)
        total_cents = breakdown["total_cents"]
        
        # Build product name and description
        product_name = beat.title or f"Beat #{beat.id}"
        product_description = f"Purchase of beat: {product_name}"
        if beat.genre:
            product_description += f" ({beat.genre})"
        if beat.bpm:
            product_description += f" - {beat.bpm} BPM"
        if beat.license == "exclusive":
            product_description += " [EXCLUSIVE LICENSE]"
        product_description = product_description[:500]  # Stripe limit
        
        # Create or update Stripe Product
        if beat.stripe_product_id:
            try:
                # Update existing product
                product = stripe.Product.retrieve(beat.stripe_product_id)
                product = stripe.Product.modify(
                    beat.stripe_product_id,
                    name=product_name,
                    description=product_description,
                    active=beat.is_active,
                )
                product_id = product.id
            except stripe.error.InvalidRequestError:
                # Product was deleted in Stripe, create new one
                product_id = None
        else:
            product_id = None
        
        if not product_id:
            # Create new product
            product = stripe.Product.create(
                name=product_name,
                description=product_description,
                metadata={
                    "beat_id": str(beat.id),
                    "owner_id": str(beat.owner_id),
                    "license": beat.license,
                },
            )
            product_id = product.id
            beat.stripe_product_id = product_id
        
        # Create or update Stripe Price
        # For prices, we need to check if the total amount changed
        # If it changed, create a new price (Stripe prices are immutable)
        price_needs_update = False
        if beat.stripe_price_id:
            try:
                existing_price = stripe.Price.retrieve(beat.stripe_price_id)
                if existing_price.unit_amount != total_cents or not existing_price.active:
                    price_needs_update = True
                else:
                    price_id = existing_price.id
            except stripe.error.InvalidRequestError:
                price_needs_update = True
        else:
            price_needs_update = True
        
        if price_needs_update:
            # Create new price (prices are immutable in Stripe)
            price = stripe.Price.create(
                product=product_id,
                unit_amount=total_cents,
                currency=(beat.currency or "usd"),
                metadata={
                    "beat_id": str(beat.id),
                    "subtotal_cents": str(breakdown["subtotal_cents"]),
                    "platform_fee_cents": str(breakdown["platform_fee_cents"]),
                    "processing_fee_cents": str(breakdown["processing_fee_cents"]),
                    "total_cents": str(total_cents),
                },
            )
            price_id = price.id
            beat.stripe_price_id = price_id
            
            # Archive old price if it exists
            if beat.stripe_price_id and beat.stripe_price_id != price_id:
                try:
                    old_price = stripe.Price.retrieve(beat.stripe_price_id)
                    if old_price.active:
                        stripe.Price.modify(beat.stripe_price_id, active=False)
                except stripe.error.InvalidRequestError:
                    pass  # Price already deleted or doesn't exist
        
        if commit:
            db.session.commit()
        
        app.logger.info(f"Synced beat {beat.id} to Stripe: product={product_id}, price={price_id}")
        return (product_id, price_id)
        
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "sync_beat_to_stripe",
            e,
            beat_id=beat.id,
            amount_cents=beat.price_cents,
            currency=beat.currency or "usd",
        )
        return (beat.stripe_product_id, beat.stripe_price_id)
    except Exception as e:
        _log_stripe_error(
            "sync_beat_to_stripe",
            e,
            beat_id=beat.id,
            amount_cents=beat.price_cents,
            currency=beat.currency or "usd",
        )
        return (beat.stripe_product_id, beat.stripe_price_id)


@app.route("/check-stripe-config", methods=["GET"])
def check_stripe_config():
    """Debug endpoint to check Stripe configuration"""
    if is_prod():
        abort(404)
    if not (current_user.is_authenticated and current_user.role == RoleEnum.admin):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({
        "STRIPE_AVAILABLE": STRIPE_AVAILABLE,
        "STRIPE_SECRET_KEY_set": bool(STRIPE_SECRET_KEY),
        "STRIPE_PUBLISHABLE_KEY_set": bool(STRIPE_PUBLISHABLE_KEY),
        "STRIPE_WEBHOOK_SECRET_set": bool(STRIPE_WEBHOOK_SECRET),
        "stripe_api_key_set": bool(stripe.api_key) if STRIPE_AVAILABLE else False,
        "APP_BASE_URL_set": bool(APP_BASE_URL),
    }), 200

@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    """Create a Stripe Checkout Session for beat purchase"""
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        return jsonify({"error": err_msg}), 400
    
    # Get beat_id from request
    beat_id = request.json.get("beat_id") if request.is_json else request.form.get("beat_id")
    if not beat_id:
        return jsonify({"error": "beat_id is required"}), 400
    
    try:
        beat_id = int(beat_id)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid beat_id"}), 400
    
    # Validate beat
    beat = Beat.query.get(beat_id)
    if not beat:
        return jsonify({"error": "Beat not found"}), 404
    
    if hasattr(beat, "is_active") and not beat.is_active:
        return jsonify({"error": "This beat is not available for purchase"}), 400
    
    # Check if exclusive beat has already been sold
    if beat.license == "exclusive" and not beat.is_active:
        return jsonify({"error": "This exclusive beat has already been sold"}), 400
    
    seller = User.query.get(beat.owner_id)
    if not seller:
        return jsonify({"error": "Seller account not found"}), 404
    
    if seller.id == current_user.id:
        return jsonify({"error": "You can't buy your own beat"}), 400
    
    if _user_has_paid_for_beat(current_user.id, beat.id):
        return jsonify({"error": "You already purchased this beat"}), 400
    
    subtotal_cents = int(beat.price_cents or 0)
    if subtotal_cents < 0:
        return jsonify({"error": "Invalid beat price"}), 400

    try:
        order, err = get_or_create_payment_order_for_beat(beat, current_user)
        if err:
            return jsonify({"error": err}), 400
        if order.status == OrderStatus.paid:
            return jsonify({"error": "You already purchased this beat"}), 400

        if subtotal_cents == 0:
            order.status = OrderStatus.paid
            db.session.commit()
            return jsonify({"checkout_url": url_for("market_my_purchases"), "url": url_for("market_my_purchases")}), 200

        payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.full)
        return jsonify(payload), status

    except stripe.error.StripeError as e:
        _log_stripe_error(
            "create_checkout_session",
            e,
            user_id=current_user.id,
            beat_id=beat.id,
            amount_cents=subtotal_cents,
            currency=beat.currency or "usd",
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "create_checkout_session",
            e,
            user_id=current_user.id,
            beat_id=beat.id,
            amount_cents=subtotal_cents,
            currency=beat.currency or "usd",
        )
        return jsonify({"error": "Unexpected error creating checkout session."}), 500


@app.route("/create-checkout-session-hold-fee", methods=["POST"])
@login_required
def create_checkout_session_hold_fee():
    """Create a Stripe Checkout Session for booking hold fee payment"""
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        return jsonify({"error": err_msg}), 400

    data = request.get_json(silent=True) or {}
    req_id_raw = data.get("booking_request_id") or request.form.get("booking_request_id")
    booking_id_raw = data.get("booking_id") or request.form.get("booking_id")

    if not req_id_raw and not booking_id_raw:
        return jsonify({"error": "booking_request_id or booking_id is required"}), 400

    req = None
    booking = None

    if req_id_raw:
        try:
            req_id = int(req_id_raw)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid booking_request_id"}), 400
        req = BookingRequest.query.get(req_id)
        if not req:
            return jsonify({"error": "Booking request not found"}), 404
        if req.client_id != current_user.id:
            return jsonify({"error": "You can only pay for your own booking requests"}), 403
        if req.status not in (BookingStatus.accepted, BookingStatus.confirmed):
            return jsonify({"error": "Booking request must be accepted before paying hold fee"}), 400
        if req.booking_id:
            booking = Booking.query.get(req.booking_id)

    if booking_id_raw and not booking:
        try:
            booking_id = int(booking_id_raw)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid booking_id"}), 400
        booking = Booking.query.get(booking_id)
        if not booking:
            return jsonify({"error": "Booking not found"}), 404
        if booking.client_id != current_user.id:
            return jsonify({"error": "You can only pay for your own booking"}), 403
        if not req:
            try:
                req = BookingRequest.query.filter_by(booking_id=booking.id).first()
            except Exception:
                req = None

    if not booking and not req:
        return jsonify({"error": "Unable to find booking context for this payment"}), 400

    try:
        order, err = get_or_create_payment_order_for_booking(booking)
        if err:
            return jsonify({"error": err}), 400
        payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.holding)
        return jsonify(payload), status
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "create_checkout_session_hold_fee",
            e,
            user_id=current_user.id,
            booking_id=booking.id if booking else None,
            request_id=req.id if req else None,
            amount_cents=HOLD_FEE_CENTS,
            currency="usd",
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "create_checkout_session_hold_fee",
            e,
            user_id=current_user.id,
            booking_id=booking.id if booking else None,
            request_id=req.id if req else None,
            amount_cents=HOLD_FEE_CENTS,
            currency="usd",
        )
        return jsonify({"error": "Unable to create checkout session."}), 500


@app.route("/api/orders/<int:order_id>/checkout/holding", methods=["POST"])
@login_required
def api_order_checkout_holding(order_id: int):
    order = PaymentOrder.query.get_or_404(order_id)
    if order.client_user_id != current_user.id and current_user.role != RoleEnum.admin:
        return jsonify({"error": "Not authorized for this order."}), 403
    payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.holding)
    return jsonify(payload), status


@app.route("/api/orders/<int:order_id>/checkout/balance", methods=["POST"])
@login_required
def api_order_checkout_balance(order_id: int):
    order = PaymentOrder.query.get_or_404(order_id)
    if order.client_user_id != current_user.id and current_user.role != RoleEnum.admin:
        return jsonify({"error": "Not authorized for this order."}), 403
    payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.balance)
    return jsonify(payload), status


@app.route("/api/orders/<int:order_id>/checkout/full", methods=["POST"])
@login_required
def api_order_checkout_full(order_id: int):
    order = PaymentOrder.query.get_or_404(order_id)
    if order.client_user_id != current_user.id and current_user.role != RoleEnum.admin:
        return jsonify({"error": "Not authorized for this order."}), 403
    payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.full)
    return jsonify(payload), status


@app.route("/stripe/webhook", methods=["POST"])
@app.route("/webhooks/stripe", methods=["POST"])
@csrf.exempt
def stripe_webhook():
    """
    Stripe webhook endpoint (source of truth for fulfillment).
    Do NOT rely on success redirects for granting access.
    """
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("Webhook secret missing; cannot verify signature.")
        return Response(status=503)

    # --- Config / signature verification ---
    ok, err_msg = _stripe_env_guard(require_webhook=True)
    if not ok:
        app.logger.error(f"Stripe webhook blocked: {err_msg}")
        return jsonify({"error": err_msg}), 400

    payload = request.get_data() or b""
    sig_header = request.headers.get("Stripe-Signature", "")
    if not sig_header:
        app.logger.warning("Stripe webhook: missing Stripe-Signature header")
        return Response(status=400)

    try:
        tolerance_s = int(os.getenv("STRIPE_WEBHOOK_TOLERANCE_SECONDS", "300"))
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET, tolerance=tolerance_s)
    except ValueError as e:
        _log_stripe_error("stripe_webhook_signature", e)
        return Response(status=400)
    except stripe.error.SignatureVerificationError as e:
        _log_stripe_error("stripe_webhook_signature", e)
        return Response(status=400)
    except Exception as e:
        _log_stripe_error("stripe_webhook_signature", e)
        return Response(status=400)

    event_type = event.get("type")
    event_id = event.get("id")
    app.logger.info(f"Stripe webhook received: type={event_type} event_id={event_id}")

    # Record webhook event for replay protection/idempotency
    row: StripeWebhookEvent | None = None
    try:
        payload_text = (payload.decode("utf-8", "replace") if payload else "")[:50_000]
    except Exception:
        payload_text = None
    stripe_created_at = None
    try:
        ts = int(event.get("created") or 0)
        if ts > 0:
            stripe_created_at = datetime.utcfromtimestamp(ts)
    except Exception:
        stripe_created_at = None

    if event_id:
        try:
            row = StripeWebhookEvent.query.filter_by(stripe_event_id=str(event_id)).first()
        except Exception:
            row = None
        if row and row.status == StripeWebhookEventStatus.processed.value:
            return Response(status=200)
        if row and row.status == StripeWebhookEventStatus.processing.value:
            # Another worker is handling this event. Do not re-run fulfillment.
            # Safety valve: if stuck in PROCESSING too long, allow Stripe retry to proceed.
            try:
                if row.processed_at is None and row.received_at and (datetime.utcnow() - row.received_at).total_seconds() > 15 * 60:
                    row.status = StripeWebhookEventStatus.failed.value
                    row.last_error = "processing_timeout"
                    db.session.commit()
                else:
                    return Response(status=200)
            except Exception:
                db.session.rollback()
                return Response(status=200)
        if not row:
            try:
                row = StripeWebhookEvent(
                    stripe_event_id=str(event_id),
                    type=str(event_type or "unknown"),
                    created_at=stripe_created_at,
                    status=StripeWebhookEventStatus.received.value,
                    payload_json=payload_text,
                )
                db.session.add(row)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                row = StripeWebhookEvent.query.filter_by(stripe_event_id=str(event_id)).first()
            except Exception:
                db.session.rollback()
                row = None

        # Concurrency hardening: atomically transition RECEIVED/FAILED -> PROCESSING.
        # If we didn't win the transition, another worker is processing (or already processed).
        if row:
            try:
                updated = (
                    StripeWebhookEvent.query
                    .filter(
                        StripeWebhookEvent.id == row.id,
                        StripeWebhookEvent.status.in_([
                            StripeWebhookEventStatus.received.value,
                            StripeWebhookEventStatus.failed.value,
                        ]),
                    )
                    .update({"status": StripeWebhookEventStatus.processing.value}, synchronize_session=False)
                )
                db.session.commit()
                if updated == 0:
                    # Re-fetch current status and bail out.
                    try:
                        row = StripeWebhookEvent.query.get(row.id)
                    except Exception:
                        row = None
                    return Response(status=200)
                # Refresh row after update
                row = StripeWebhookEvent.query.get(row.id)
            except Exception:
                db.session.rollback()
                # Best-effort: if we can't lock, continue with existing idempotency protections.

    def _mark_row(status: StripeWebhookEventStatus, err: str | None = None) -> None:
        try:
            if not row:
                return
            row.status = status.value
            if status == StripeWebhookEventStatus.processed:
                row.processed_at = datetime.utcnow()
            if err:
                row.last_error = (err or "")[:500]
            db.session.commit()
        except Exception:
            db.session.rollback()

    # Handle additional event types for monitoring (store + alert; no fulfillment)
    if event_type in ("payment_intent.payment_failed", "payment_intent.canceled"):
        try:
            _alert_create(AlertSeverity.med, "PAYMENT_FAILED", "Stripe payment failed", {"stripe_event_id": event_id, "type": event_type})
        except Exception:
            pass
        try:
            pi = (event.get("data") or {}).get("object") or {}
            metadata = pi.get("metadata") or {}
            payment_kind = (metadata.get("payment_kind") or "").strip().lower()
            if payment_kind in {"deposit", "balance"}:
                payment_id = metadata.get("payment_id")
                payment = None
                if payment_id:
                    try:
                        payment = Payment.query.get(int(payment_id))
                    except Exception:
                        payment = None
                if not payment and pi.get("id"):
                    payment = Payment.query.filter_by(stripe_payment_intent_id=str(pi.get("id"))).first()
                if payment and payment.status not in (PaymentStatus.succeeded, PaymentStatus.refunded):
                    payment.status = PaymentStatus.failed if event_type == "payment_intent.payment_failed" else PaymentStatus.cancelled
                    db.session.commit()
        except Exception:
            db.session.rollback()
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    if event_type == "charge.dispute.created":
        try:
            _alert_create(AlertSeverity.high, "STRIPE_DISPUTE", "Stripe dispute created", {"stripe_event_id": event_id})
        except Exception:
            pass
        try:
            charge = (event.get("data") or {}).get("object") or {}
            charge_id = charge.get("id")
            ledgers = _ledger_by_charge_or_intent(charge_id, charge.get("payment_intent"))
            ledger = ledgers[0] if ledgers else None
            if ledger and ledger.status != PaymentLedgerStatus.disputed:
                ledger.status = PaymentLedgerStatus.disputed
                if ledger.order and ledger.order.order_type == OrderType.beat_purchase:
                    _set_beat_purchase_status(
                        beat_id=ledger.order.beat_id,
                        buyer_id=ledger.order.client_user_id,
                        status=BeatPurchaseStatus.disputed.value,
                        payment_id=ledger.stripe_payment_intent_id or ledger.stripe_charge_id,
                    )
                db.session.commit()
                _reverse_affiliate_for_ledger(ledgers, reason="dispute", stripe_ref=charge_id or charge.get("payment_intent"))
        except Exception:
            db.session.rollback()
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    if event_type in ("charge.refunded", "refund.updated"):
        try:
            _alert_create(AlertSeverity.med, "STRIPE_REFUND", "Stripe refund event received", {"stripe_event_id": event_id})
        except Exception:
            pass
        try:
            obj = (event.get("data") or {}).get("object") or {}
            charge_id = obj.get("id") if event_type == "charge.refunded" else obj.get("charge")
            payment_intent_id = obj.get("payment_intent")
            ledgers = _ledger_by_charge_or_intent(charge_id, payment_intent_id)
            ledger = ledgers[0] if ledgers else None
            if ledger and ledger.status != PaymentLedgerStatus.refunded:
                ledger.status = PaymentLedgerStatus.refunded
                if ledger.order and ledger.order.order_type == OrderType.beat_purchase and ledger.phase == PaymentLedgerPhase.full:
                    ledger.order.status = OrderStatus.refunded
                    _set_beat_purchase_status(
                        beat_id=ledger.order.beat_id,
                        buyer_id=ledger.order.client_user_id,
                        status=BeatPurchaseStatus.refunded.value,
                        payment_id=ledger.stripe_payment_intent_id or ledger.stripe_charge_id,
                    )
                db.session.commit()
                _reverse_affiliate_for_ledger(ledgers, reason="refund", stripe_ref=charge_id or payment_intent_id)
        except Exception:
            db.session.rollback()
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    if event_type == "payment_intent.succeeded":
        pi = (event.get("data") or {}).get("object") or {}
        metadata = pi.get("metadata") or {}
        payment_kind = (metadata.get("payment_kind") or "").strip().lower()
        if payment_kind in {"deposit", "balance"}:
            payment_id = metadata.get("payment_id")
            payment = None
            if payment_id:
                try:
                    payment = Payment.query.get(int(payment_id))
                except Exception:
                    payment = None
            if not payment and pi.get("id"):
                payment = Payment.query.filter_by(stripe_payment_intent_id=str(pi.get("id"))).first()

            if not payment:
                app.logger.warning(f"Stripe webhook: booking payment not found (payment_id={payment_id} intent={pi.get('id')})")
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            if payment.status == PaymentStatus.succeeded:
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            try:
                with db_txn():
                    if db.engine.dialect.name == "postgresql":
                        payment = Payment.query.filter_by(id=payment.id).with_for_update().first()
                    else:
                        payment = Payment.query.filter_by(id=payment.id).first()

                    if not payment:
                        _mark_row(StripeWebhookEventStatus.processed)
                        return Response(status=200)

                    if payment.status == PaymentStatus.succeeded:
                        _mark_row(StripeWebhookEventStatus.processed)
                        return Response(status=200)

                    payment.status = PaymentStatus.succeeded
                    if pi.get("id"):
                        payment.stripe_payment_intent_id = str(pi.get("id"))
                    if pi.get("latest_charge"):
                        payment.stripe_charge_id = str(pi.get("latest_charge"))
                    else:
                        charges = (pi.get("charges") or {}).get("data") or []
                        if charges:
                            payment.stripe_charge_id = str(charges[0].get("id") or payment.stripe_charge_id)
                    if payment.total_paid_cents is None and pi.get("amount_received"):
                        try:
                            payment.total_paid_cents = int(pi.get("amount_received"))
                        except Exception:
                            pass
                    payment.nonrefundable_processing_kept_cents = int(payment.processing_fee_cents or 0)
                    payment.nonrefundable_beatfund_kept_cents = int(payment.beatfund_fee_cents or 0)

                    booking = Booking.query.get(payment.booking_id) if payment.booking_id else None
                    if booking:
                        booking.beatfund_fee_collected_cents = (booking.beatfund_fee_collected_cents or 0) + int(payment.beatfund_fee_cents or 0)
                        if booking.quoted_total_cents is None and booking.total_cents is not None:
                            booking.quoted_total_cents = booking.total_cents
                        if booking.beatfund_fee_total_cents is None and booking.quoted_total_cents is not None:
                            booking.beatfund_fee_total_cents = calc_beatfund_fee_total(int(booking.quoted_total_cents))
                        try:
                            provider_wallet = Wallet.query.filter_by(user_id=booking.provider_id).first() if booking.provider_id else None
                            if not provider_wallet and booking.provider_id:
                                provider_wallet = Wallet(user_id=booking.provider_id)
                                db.session.add(provider_wallet)
                                db.session.flush()

                            base_cents = int(payment.base_amount_cents or 0)
                            if provider_wallet and base_cents > 0:
                                kind_label = payment.kind.value if payment.kind else "payment"
                                meta = f"booking #{booking.id} {kind_label} (Stripe)"
                                if not LedgerEntry.query.filter_by(
                                    wallet_id=provider_wallet.id,
                                    entry_type=EntryType.sale_income,
                                    meta=meta,
                                ).first():
                                    post_ledger(provider_wallet, EntryType.sale_income, base_cents, meta=meta)
                        except Exception:
                            app.logger.warning("Stripe webhook: unable to post booking ledger entry")

                        # Booking status + notifications
                        try:
                            if payment.kind == PaymentKind.deposit and booking.status not in (BOOKING_STATUS_COMPLETED, BOOKING_STATUS_CANCELLED):
                                booking.status = BOOKING_STATUS_HOLD_PAID
                                req_link = BookingRequest.query.filter_by(booking_id=booking.id).first()
                                if req_link and req_link.status == BookingStatus.accepted:
                                    req_link.status = BookingStatus.confirmed
                            if payment.kind == PaymentKind.balance:
                                sums = sum_successful_payments(booking, BookingRequest.query.filter_by(booking_id=booking.id).first())
                                total_base_paid = sums.get("base_paid_cents", 0)
                                service_total = booking.quoted_total_cents or booking.total_cents
                                if service_total and total_base_paid >= int(service_total):
                                    booking.status = BOOKING_STATUS_PAID
                        except Exception:
                            pass

                        try:
                            provider = User.query.get(booking.provider_id) if booking.provider_id else None
                            client = User.query.get(booking.client_id) if booking.client_id else None
                            if payment.kind == PaymentKind.deposit:
                                if provider:
                                    notify_user(
                                        provider,
                                        kind="success",
                                        title="Deposit paid",
                                        body=f"Deposit received for booking #{booking.id}.",
                                        url=url_for("booking_detail", booking_id=booking.id),
                                        event_key=f"booking:{booking.id}:deposit_paid",
                                        commit=False,
                                    )
                                if client:
                                    notify_user(
                                        client,
                                        kind="success",
                                        title="Deposit paid",
                                        body=f"Your hold fee was received for booking #{booking.id}.",
                                        url=url_for("booking_detail", booking_id=booking.id),
                                        event_key=f"booking:{booking.id}:deposit_paid_client",
                                        commit=False,
                                    )
                            elif payment.kind == PaymentKind.balance:
                                if provider:
                                    notify_user(
                                        provider,
                                        kind="success",
                                        title="Balance paid",
                                        body=f"Balance payment received for booking #{booking.id}.",
                                        url=url_for("booking_detail", booking_id=booking.id),
                                        event_key=f"booking:{booking.id}:balance_paid",
                                        commit=False,
                                    )
                                if client:
                                    notify_user(
                                        client,
                                        kind="success",
                                        title="Balance paid",
                                        body=f"Your balance payment was received for booking #{booking.id}.",
                                        url=url_for("booking_detail", booking_id=booking.id),
                                        event_key=f"booking:{booking.id}:balance_paid_client",
                                        commit=False,
                                    )
                        except Exception:
                            pass
            except Exception:
                app.logger.exception(f"Stripe webhook: error finalizing booking payment_id={getattr(payment, 'id', None)} intent={pi.get('id')}")
                _mark_row(StripeWebhookEventStatus.failed, "booking_payment_finalize_failed")
                return Response(status=500 if _is_production_mode() else 200)

            _mark_row(StripeWebhookEventStatus.processed)
            return Response(status=200)

    if event_type in ("payment_intent.payment_failed", "payment_intent.canceled"):
        pi = (event.get("data") or {}).get("object") or {}
        metadata = pi.get("metadata") or {}
        payment_id = metadata.get("payment_id")
        payment = None
        if payment_id:
            try:
                payment = Payment.query.get(int(payment_id))
            except Exception:
                payment = None
        if not payment and pi.get("id"):
            payment = Payment.query.filter_by(stripe_payment_intent_id=str(pi.get("id"))).first()
        if payment and payment.status != PaymentStatus.succeeded:
            try:
                payment.status = PaymentStatus.failed if event_type == "payment_intent.payment_failed" else PaymentStatus.cancelled
                db.session.commit()
            except Exception:
                db.session.rollback()
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    # Only process Checkout completion for fulfillment.
    if event_type != "checkout.session.completed":
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    session_obj = (event.get("data") or {}).get("object") or {}
    session_id = session_obj.get("id")
    metadata = session_obj.get("metadata") or {}
    order_id_meta = metadata.get("order_id")
    phase_meta = (metadata.get("phase") or "").strip().lower()

    if order_id_meta and phase_meta in {PaymentLedgerPhase.holding.value, PaymentLedgerPhase.balance.value, PaymentLedgerPhase.full.value}:
        try:
            order = PaymentOrder.query.get(int(order_id_meta))
        except Exception:
            order = None

        if not order:
            app.logger.warning(f"Stripe webhook: payment_order not found (order_id={order_id_meta} session_id={session_id})")
            _mark_row(StripeWebhookEventStatus.processed)
            return Response(status=200)

        try:
            existing = None
            if session_id:
                existing = PaymentLedger.query.filter_by(stripe_checkout_session_id=str(session_id)).first()
            if existing and existing.status == PaymentLedgerStatus.succeeded:
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)
        except Exception:
            db.session.rollback()

        payment_intent_id = session_obj.get("payment_intent")
        pi = None
        if payment_intent_id and STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
            try:
                pi = stripe.PaymentIntent.retrieve(payment_intent_id)
            except Exception:
                pi = None

        gross_amount = int(session_obj.get("amount_total") or 0)
        application_fee_cents = 0
        latest_charge_id = None
        if pi:
            try:
                application_fee_cents = int(getattr(pi, "application_fee_amount", None) or pi.get("application_fee_amount") or 0)
            except Exception:
                application_fee_cents = 0
            latest_charge_id = getattr(pi, "latest_charge", None) or pi.get("latest_charge")
            if not latest_charge_id:
                charges = (pi.get("charges") or {}).get("data") or []
                if charges:
                    latest_charge_id = charges[0].get("id")

        phase_enum = PaymentLedgerPhase(phase_meta)
        if phase_enum == PaymentLedgerPhase.holding:
            platform_fee_collected = gross_amount
            provider_amount_routed = 0
        else:
            platform_fee_collected = int(application_fee_cents or 0)
            provider_amount_routed = max(0, int(gross_amount) - int(platform_fee_collected))

        try:
            ledger = PaymentLedger(
                order_id=order.id,
                phase=phase_enum,
                gross_amount_cents=gross_amount,
                platform_fee_collected_cents=platform_fee_collected,
                provider_amount_routed_cents=provider_amount_routed,
                stripe_checkout_session_id=str(session_id) if session_id else None,
                stripe_payment_intent_id=str(payment_intent_id) if payment_intent_id else None,
                stripe_charge_id=str(latest_charge_id) if latest_charge_id else None,
                status=PaymentLedgerStatus.succeeded,
            )
            db.session.add(ledger)

            if order.order_type == OrderType.booking:
                if phase_enum == PaymentLedgerPhase.holding:
                    order.status = OrderStatus.partially_paid
                elif phase_enum == PaymentLedgerPhase.balance:
                    order.status = OrderStatus.paid
            elif order.order_type == OrderType.beat_purchase:
                order.status = OrderStatus.paid
                if phase_enum == PaymentLedgerPhase.full:
                    _record_beat_purchase(
                        beat_id=order.beat_id,
                        buyer_id=order.client_user_id,
                        payment_id=payment_intent_id or session_id,
                        status=BeatPurchaseStatus.paid.value,
                        commit=False,
                    )

            if order.booking_id:
                booking = Booking.query.get(order.booking_id)
                if booking:
                    if phase_enum == PaymentLedgerPhase.holding:
                        booking.status = BOOKING_STATUS_HOLD_PAID
                        req_link = BookingRequest.query.filter_by(booking_id=booking.id).first()
                        if req_link and req_link.status == BookingStatus.accepted:
                            req_link.status = BookingStatus.confirmed
                    elif phase_enum == PaymentLedgerPhase.balance:
                        booking.status = BOOKING_STATUS_PAID

            db.session.commit()

            if order.affiliate_id:
                try:
                    affiliate = Affiliate.query.get(order.affiliate_id)
                except Exception:
                    affiliate = None
                if affiliate:
                    pct = affiliate.commission_pct if affiliate.commission_pct is not None else AFFILIATE_DEFAULT_PCT
                    try:
                        pct_decimal = Decimal(str(pct))
                    except Exception:
                        pct_decimal = Decimal(str(AFFILIATE_DEFAULT_PCT))
                    commission = int((Decimal(platform_fee_collected) * pct_decimal).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
                    commission = min(commission, int(platform_fee_collected))
                    if commission > 0 and platform_fee_collected > 0:
                        earning = AffiliateEarning(
                            affiliate_id=affiliate.id,
                            order_id=order.id,
                            payment_ledger_id=ledger.id,
                            base_platform_fee_cents=int(platform_fee_collected),
                            commission_cents=int(commission),
                            status=AffiliateEarningStatus.pending,
                            available_at=datetime.utcnow() + timedelta(days=int(AFFILIATE_PAYOUT_DELAY_DAYS or 0)),
                        )
                        try:
                            db.session.add(earning)
                            db.session.commit()
                        except IntegrityError:
                            db.session.rollback()
                        except Exception:
                            db.session.rollback()
        except IntegrityError:
            db.session.rollback()
        except Exception:
            db.session.rollback()
            _mark_row(StripeWebhookEventStatus.failed, "payment_ledger_finalize_failed")
            return Response(status=500 if _is_production_mode() else 200)

        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    purpose = metadata.get("type") or metadata.get("purpose")

    if purpose not in ("beat_purchase", "wallet_topup"):
        app.logger.info(f"Stripe webhook: ignoring checkout.session.completed with purpose={purpose!r} session_id={session_id}")
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    # ---- Wallet top-up fulfillment ----
    if purpose == "wallet_topup":
        try:
            user_id = int(metadata.get("user_id") or 0)
        except Exception:
            user_id = 0
        amount_total = session_obj.get("amount_total")
        try:
            amount_total = int(amount_total or 0)
        except Exception:
            amount_total = 0

        if not user_id or amount_total <= 0:
            app.logger.warning(f"Stripe webhook: invalid wallet_topup metadata (user_id={user_id} amount_total={amount_total} session_id={session_id})")
            _mark_row(StripeWebhookEventStatus.processed)
            return Response(status=200)

        try:
            _finalize_wallet_topup(user_id=user_id, amount_cents=amount_total, session_id=session_id, source="webhook")
            try:
                audit_log_event(
                    action_type="STRIPE_WEBHOOK_APPLIED",
                    actor_user=None,
                    target_type="Wallet",
                    target_id=str(user_id),
                    reason="Stripe webhook applied (wallet_topup)",
                    metadata={"stripe_event_id": event_id, "session_id": session_id, "amount_cents": amount_total, "currency": (session_obj.get("currency") or "usd")},
                )
            except Exception:
                pass
        except Exception:
            # In dev, prefer 200 after logging so Stripe doesn't spam retries
            app.logger.exception(f"Stripe webhook: error finalizing wallet_topup user_id={user_id} session_id={session_id}")
            _mark_row(StripeWebhookEventStatus.failed, "wallet_topup_finalize_failed")
            try:
                _alert_create(AlertSeverity.high, "STRIPE_WEBHOOK_FAILED", "wallet_topup webhook finalize failed", {"stripe_event_id": event_id, "session_id": session_id, "user_id": user_id})
            except Exception:
                pass
            # Important: in production, return 500 so Stripe retries automatically.
            return Response(status=500 if _is_production_mode() else 200)

        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    order_id = metadata.get("order_id")
    user_id = metadata.get("user_id")
    beat_id = metadata.get("beat_id")

    # Find order by order_id, fallback to stripe_session_id
    order = None
    if order_id:
        try:
            order = Order.query.get(int(order_id))
        except Exception:
            order = None
    if not order and session_id:
        order = Order.query.filter_by(stripe_session_id=session_id).first()

    if not order:
        app.logger.warning(f"Stripe webhook: no matching Order (order_id={order_id} session_id={session_id} user_id={user_id} beat_id={beat_id})")
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    # Idempotent: if already paid, do nothing
    if order.status == OrderStatus.paid:
        app.logger.info(f"Stripe webhook processed OK: order_id={order.id} already paid")
        _mark_row(StripeWebhookEventStatus.processed)
        return Response(status=200)

    payment_intent = session_obj.get("payment_intent")
    amount_total = session_obj.get("amount_total")
    currency = (session_obj.get("currency") or "usd").lower()

    try:
        with db_txn():
            # Re-fetch with best-effort locking on Postgres
            if db.engine.dialect.name == "postgresql":
                order = Order.query.filter_by(id=order.id).with_for_update().first()
            else:
                order = Order.query.filter_by(id=order.id).first()

            if not order:
                app.logger.warning(f"Stripe webhook: order disappeared (order_id={order_id} session_id={session_id})")
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            if order.status == OrderStatus.paid:
                app.logger.info(f"Stripe webhook processed OK: order_id={order.id} already paid")
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            beat = Beat.query.get(order.beat_id) if order.beat_id else None
            if not beat:
                app.logger.warning(f"Stripe webhook: beat not found for order_id={order.id} beat_id={order.beat_id}")
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            seller = User.query.get(order.seller_id or beat.owner_id)
            buyer = User.query.get(order.buyer_id)
            if not seller or not buyer:
                app.logger.warning(f"Stripe webhook: missing buyer/seller for order_id={order.id}")
                _mark_row(StripeWebhookEventStatus.processed)
                return Response(status=200)

            # Update order fields from Stripe (safe)
            if amount_total is not None:
                order.total_cents = int(amount_total)
            order.currency = currency
            if session_id:
                order.stripe_session_id = str(session_id)
            if payment_intent:
                order.stripe_payment_intent = str(payment_intent)

            # Wallets
            buyer_w = Wallet.query.filter_by(user_id=buyer.id).first()
            seller_w = Wallet.query.filter_by(user_id=seller.id).first()
            if not buyer_w:
                buyer_w = Wallet(user_id=buyer.id)
                db.session.add(buyer_w)
                db.session.flush()
            if not seller_w:
                seller_w = Wallet(user_id=seller.id)
                db.session.add(seller_w)
                db.session.flush()

            # Compute totals (fallback to stored order values if Stripe didn't include)
            total_cents = int(order.total_cents or 0)
            subtotal_cents = int(order.amount_cents or 0)
            platform_fee_cents = int(order.platform_fee_cents or 0)
            processing_fee_cents = int(order.processing_fee_cents or 0)
            if total_cents <= 0:
                total_cents = subtotal_cents + platform_fee_cents + processing_fee_cents

            # Ledger idempotency (prevent duplicate entries if Stripe retries)
            fund_meta = f"external payment (Stripe) order#{order.id} session {str(session_id)[:18] if session_id else ''}".strip()
            spend_meta = f"buy beat #{beat.id} order#{order.id} via Stripe".strip()
            existing_fund = LedgerEntry.query.filter_by(wallet_id=buyer_w.id, entry_type=EntryType.external_payment, meta=fund_meta).first()
            existing_spend = LedgerEntry.query.filter_by(wallet_id=buyer_w.id, entry_type=EntryType.purchase_spend, meta=spend_meta).first()

            if not existing_fund:
                post_ledger(buyer_w, EntryType.external_payment, total_cents, meta=fund_meta)
            if not existing_spend:
                post_ledger(buyer_w, EntryType.purchase_spend, total_cents, meta=spend_meta)

            # Seller receives subtotal (idempotency via exact meta match)
            if subtotal_cents > 0:
                seller_meta = f"sale beat #{beat.id} order#{order.id} to @{buyer.username} (Stripe)"[:255]
                existing_sale = LedgerEntry.query.filter_by(wallet_id=seller_w.id, entry_type=EntryType.sale_income, meta=seller_meta).first()
                if not existing_sale:
                    post_ledger(seller_w, EntryType.sale_income, subtotal_cents, meta=seller_meta)

            # Mark exclusive beat inactive after confirmation
            if beat.license == "exclusive":
                beat.is_active = False
                beat.updated_at = datetime.utcnow()

            # Finally: mark paid (do this after ledger writes so status doesn't block retries)
            order.status = OrderStatus.paid
            order.paid_at = datetime.utcnow()
            _record_beat_purchase(
                beat_id=order.beat_id,
                buyer_id=order.buyer_id,
                payment_id=payment_intent or session_id,
                status=BeatPurchaseStatus.paid.value,
                commit=False,
            )

    except Exception:
        # In dev, prefer 200 after logging so Stripe doesn't spam retries
        app.logger.exception(f"Stripe webhook: error finalizing order_id={getattr(order, 'id', None)} session_id={session_id}")
        _mark_row(StripeWebhookEventStatus.failed, "beat_purchase_finalize_failed")
        try:
            _alert_create(AlertSeverity.high, "STRIPE_WEBHOOK_FAILED", "beat_purchase webhook finalize failed", {"stripe_event_id": event_id, "order_id": getattr(order, "id", None), "session_id": session_id})
        except Exception:
            pass
        # Important: in production, return 500 so Stripe retries automatically.
        return Response(status=500 if _is_production_mode() else 200)

    app.logger.info(f"Stripe webhook processed OK: order_id={order.id} status=paid")
    try:
        audit_log_event(
            action_type="STRIPE_WEBHOOK_APPLIED",
            actor_user=None,
            target_type="Order",
            target_id=str(order.id),
            reason="Stripe webhook applied (beat_purchase)",
            metadata={"stripe_event_id": event_id, "session_id": session_id, "order_id": order.id, "payment_intent": payment_intent, "amount_total": amount_total, "currency": currency},
        )
    except Exception:
        pass
    _mark_row(StripeWebhookEventStatus.processed)
    return Response(status=200)


@app.route("/stripe/sync-session", methods=["POST"])
@login_required
def stripe_sync_session():
    """
    Fallback confirmation for dev/support when webhook delivery isn't working.
    This still verifies payment server-side via Stripe API (not a blind success redirect).
    """
    ok, err_msg = _stripe_env_guard()
    if not ok:
        return jsonify({"error": err_msg}), 400

    session_id = request.json.get("session_id") if request.is_json else request.form.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "stripe_sync_session",
            e,
            user_id=getattr(current_user, "id", None),
            session_id=session_id,
        )
        return jsonify(_stripe_error_payload(e)), 502
    except Exception as e:
        _log_stripe_error(
            "stripe_sync_session",
            e,
            user_id=getattr(current_user, "id", None),
            session_id=session_id,
        )
        return jsonify({"error": "Unable to retrieve checkout session."}), 500

    metadata = checkout_session.metadata or {}
    purpose = metadata.get("type") or metadata.get("purpose")
    if purpose not in ("beat_purchase", "wallet_topup"):
        return jsonify({"error": "Unsupported session type"}), 400

    # Ensure this session belongs to the logged-in user
    try:
        meta_user_id = int(metadata.get("user_id") or 0)
    except Exception:
        meta_user_id = 0
    if meta_user_id and meta_user_id != current_user.id:
        return jsonify({"error": "This session does not belong to you"}), 403

    if checkout_session.payment_status != "paid":
        return jsonify({"status": "not_paid", "payment_status": checkout_session.payment_status}), 200

    # Wallet top-up (credits wallet)
    if purpose == "wallet_topup":
        amount_total = getattr(checkout_session, "amount_total", None)
        try:
            amount_total_cents = int(amount_total or 0)
        except Exception:
            amount_total_cents = 0

        if amount_total_cents <= 0:
            return jsonify({"error": "Invalid top-up amount"}), 400

        try:
            _finalize_wallet_topup(
                user_id=current_user.id,
                amount_cents=amount_total_cents,
                session_id=str(getattr(checkout_session, "id", session_id)),
                source="sync-session",
            )
        except Exception as e:
            app.logger.error(f"Stripe sync-session: wallet top-up failed for user {current_user.id}: {str(e)}", exc_info=True)
            return jsonify({"error": "Failed to finalize top-up"}), 500

        return jsonify({"status": "paid", "kind": "wallet_topup"}), 200

    order = None
    order_id = metadata.get("order_id")
    if order_id:
        try:
            order = Order.query.get(int(order_id))
        except Exception:
            order = None
    if not order:
        order = Order.query.filter_by(stripe_session_id=session_id, buyer_id=current_user.id).first()

    if not order:
        return jsonify({"error": "Order not found for this session"}), 404

    if order.buyer_id != current_user.id:
        return jsonify({"error": "Order does not belong to you"}), 403

    # Idempotent: if already paid, return success
    if order.status == OrderStatus.paid:
        return jsonify({"status": "paid", "order_id": order.id}), 200

    # Reuse the same fulfillment logic as webhook (inline; verified session data)
    amount_total = getattr(checkout_session, "amount_total", None)
    currency = (getattr(checkout_session, "currency", None) or "usd").lower()
    payment_intent = getattr(checkout_session, "payment_intent", None)

    beat = Beat.query.get(order.beat_id) if order.beat_id else None
    seller = User.query.get(order.seller_id or (beat.owner_id if beat else None))
    buyer = User.query.get(order.buyer_id)
    if not beat or not seller or not buyer:
        return jsonify({"error": "Order references missing user/beat"}), 400

    try:
        with db_txn():
            if db.engine.dialect.name == "postgresql":
                order = Order.query.filter_by(id=order.id).with_for_update().first()
                beat_check = Beat.query.filter_by(id=beat.id).with_for_update().first()
                buyer_w = Wallet.query.filter_by(user_id=buyer.id).with_for_update().first()
                seller_w = Wallet.query.filter_by(user_id=seller.id).with_for_update().first()
            else:
                order = Order.query.filter_by(id=order.id).first()
                beat_check = Beat.query.filter_by(id=beat.id).first()
                buyer_w = Wallet.query.filter_by(user_id=buyer.id).first()
                seller_w = Wallet.query.filter_by(user_id=seller.id).first()

            if not order or not beat_check:
                raise ValueError("missing_order_or_beat")
            if order.status == OrderStatus.paid:
                return jsonify({"status": "paid", "order_id": order.id}), 200

            if amount_total is not None:
                order.total_cents = int(amount_total)
            order.currency = currency
            if payment_intent:
                order.stripe_payment_intent = str(payment_intent)
            order.stripe_session_id = session_id
            order.processor = "stripe"
            order.status = OrderStatus.paid
            order.paid_at = datetime.utcnow()
            _record_beat_purchase(
                beat_id=order.beat_id,
                buyer_id=order.buyer_id,
                payment_id=payment_intent or session_id,
                status=BeatPurchaseStatus.paid.value,
                commit=False,
            )

            total_cents = int(order.total_cents or 0)
            subtotal_cents = int(order.amount_cents or 0)
            platform_fee_cents = int(order.platform_fee_cents or 0)
            processing_fee_cents = int(order.processing_fee_cents or 0)
            if total_cents <= 0:
                total_cents = subtotal_cents + platform_fee_cents + processing_fee_cents

            if not buyer_w:
                buyer_w = Wallet(user_id=buyer.id)
                db.session.add(buyer_w)
                db.session.flush()
            if not seller_w:
                seller_w = Wallet(user_id=seller.id)
                db.session.add(seller_w)
                db.session.flush()

            post_ledger(buyer_w, EntryType.external_payment, total_cents, meta=f"external payment (Stripe) session {session_id[:18]}")
            post_ledger(buyer_w, EntryType.purchase_spend, total_cents, meta=f"buy beat #{beat_check.id} '{(beat_check.title or '')[:80]}' via Stripe")
            if subtotal_cents > 0:
                post_ledger(seller_w, EntryType.sale_income, subtotal_cents, meta=f"sale beat #{beat_check.id} to @{buyer.username} (Stripe)")

            if platform_fee_cents > 0:
                platform_user_id = get_platform_fee_wallet_user_id()
                if platform_user_id:
                    if db.engine.dialect.name == "postgresql":
                        platform_w = Wallet.query.filter_by(user_id=platform_user_id).with_for_update().first()
                    else:
                        platform_w = Wallet.query.filter_by(user_id=platform_user_id).first()
                    if not platform_w:
                        platform_w = Wallet(user_id=platform_user_id)
                        db.session.add(platform_w)
                        db.session.flush()
                    post_ledger(platform_w, EntryType.adjustment, platform_fee_cents, meta=f"platform fee for beat #{beat_check.id} order (Stripe)")

            if beat_check.license == "exclusive":
                beat_check.is_active = False
                beat_check.updated_at = datetime.utcnow()

    except Exception as e:
        app.logger.error(f"Stripe sync-session: fulfillment failed for Order {order.id}: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Failed to finalize purchase"}), 500

    return jsonify({"status": "paid", "order_id": order.id}), 200


@app.route("/wallet/stripe/success", methods=["GET"])
@login_required
def wallet_stripe_success():
    """
    Stripe redirect page for wallet top-ups (NOT the source of truth).
    We verify payment server-side and credit wallet idempotently for good UX in dev.
    """
    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        flash("Invalid checkout session.", "error")
        return redirect(url_for("wallet_home"))

    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("wallet_home"))

    try:
        app.logger.info(f"Wallet stripe success hit: user_id={current_user.id} session_id={session_id[:24]}")
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        metadata = checkout_session.metadata or {}
        purpose = metadata.get("type") or metadata.get("purpose")
        app.logger.info(
            f"Wallet stripe success: purpose={purpose!r} payment_status={getattr(checkout_session,'payment_status',None)!r}"
        )
        if purpose != "wallet_topup":
            flash("This checkout session is not a wallet top-up.", "error")
            return redirect(url_for("wallet_home"))

        # Ensure it belongs to this user
        try:
            meta_user_id = int(metadata.get("user_id") or 0)
        except Exception:
            meta_user_id = 0
        if meta_user_id and meta_user_id != current_user.id:
            flash("This checkout session does not belong to you.", "error")
            return redirect(url_for("wallet_home"))

        if checkout_session.payment_status != "paid":
            flash("Payment not completed yet. Please wait a moment and refresh.", "info")
            return redirect(url_for("wallet_home"))

        amount_total = getattr(checkout_session, "amount_total", None)
        amount_total_cents = int(amount_total or 0)
        _finalize_wallet_topup(user_id=current_user.id, amount_cents=amount_total_cents, session_id=session_id, source="success-redirect")
        flash("Wallet funded successfully.", "success")
        return redirect(url_for("wallet_home"))

    except stripe.error.StripeError as e:
        _log_stripe_error(
            "wallet_stripe_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Error verifying payment. If you were charged, please contact support.", "error")
        return redirect(url_for("wallet_home"))
    except Exception as e:
        _log_stripe_error(
            "wallet_stripe_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Error verifying payment. If you were charged, please contact support.", "error")
        return redirect(url_for("wallet_home"))


def _finalize_wallet_topup(*, user_id: int, amount_cents: int, session_id: str | None, source: str) -> None:
    """
    Credit wallet for a Stripe top-up. Idempotent by Stripe session id.
    """
    if not user_id or amount_cents <= 0:
        raise ValueError("invalid_topup_args")

    sid = (session_id or "").strip()
    if not sid:
        raise ValueError("missing_session_id")

    meta = f"wallet top-up via Stripe session {sid}"[:255]

    with db_txn():
        # Lock wallet row on Postgres to reduce duplicate credits under concurrent webhook retries
        if db.engine.dialect.name == "postgresql":
            wallet = Wallet.query.filter_by(user_id=user_id).with_for_update().first()
        else:
            wallet = Wallet.query.filter_by(user_id=user_id).first()

        if not wallet:
            wallet = Wallet(user_id=user_id)
            db.session.add(wallet)
            db.session.flush()

        existing = LedgerEntry.query.filter_by(wallet_id=wallet.id, entry_type=EntryType.deposit, meta=meta).first()
        if existing:
            return

        post_ledger(wallet, EntryType.deposit, amount_cents, meta=meta)
        app.logger.info(f"Wallet top-up credited: user_id={user_id} amount_cents={amount_cents} source={source} session_id={sid}")


# =========================================================
# Stripe Connect (Payouts / Withdrawals)
# =========================================================
@app.route("/connect/stripe/start", methods=["GET"])
@login_required
def stripe_connect_start():
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("wallet_home"))

    base_url = get_stripe_base_url()
    refresh_url = CONNECT_ONBOARDING_REFRESH_URL or f"{base_url}/connect/stripe/start"
    return_url = CONNECT_ONBOARDING_RETURN_URL or f"{base_url}/connect/stripe/return"

    try:
        # Create account if missing
        acct_id = (getattr(current_user, "stripe_account_id", None) or "").strip()
        if not acct_id:
            acct = stripe.Account.create(
                type="express",
                country="US",
                email=(current_user.email or None),
                capabilities={
                    # Required for transfers from platform to connected account
                    "transfers": {"requested": True},
                },
                business_type="individual",
                metadata={
                    "user_id": str(current_user.id),
                    "purpose": "beatfund_payouts",
                },
            )
            acct_id = acct.id
            with db_txn():
                current_user.stripe_account_id = acct_id
            _get_or_refresh_provider_stripe_account(current_user.id, refresh=True)

        link = stripe.AccountLink.create(
            account=acct_id,
            refresh_url=refresh_url,
            return_url=return_url,
            type="account_onboarding",
        )
        return redirect(link.url)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "stripe_connect_start",
            e,
            user_id=current_user.id,
        )
        flash("Unable to start bank connection. Please try again.", "error")
        return redirect(url_for("wallet_home"))
    except Exception as e:
        _log_stripe_error(
            "stripe_connect_start",
            e,
            user_id=current_user.id,
        )
        flash("Unable to start bank connection. Please try again.", "error")
        return redirect(url_for("wallet_home"))


@app.route("/connect/stripe/return", methods=["GET"])
@login_required
def stripe_connect_return():
    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("wallet_home"))

    acct_id = (getattr(current_user, "stripe_account_id", None) or "").strip()
    if not acct_id:
        flash("No Stripe account found. Please connect again.", "error")
        return redirect(url_for("wallet_home"))

    try:
        acct = stripe.Account.retrieve(acct_id)
        acct_row = _get_or_refresh_provider_stripe_account(current_user.id, refresh=True)
        details_submitted = bool(getattr(acct, "details_submitted", False) or acct.get("details_submitted"))
        payouts_enabled = bool(getattr(acct, "payouts_enabled", False) or acct.get("payouts_enabled"))
        if acct_row:
            acct_row.details_submitted = details_submitted
            acct_row.payouts_enabled = payouts_enabled
            acct_row.charges_enabled = bool(getattr(acct, "charges_enabled", False) or acct.get("charges_enabled"))
            db.session.commit()

        if details_submitted and payouts_enabled:
            flash("Bank account connected! You can now withdraw.", "success")
        else:
            flash("Connection started. Please finish the Stripe onboarding steps to enable payouts.", "info")
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "stripe_connect_return",
            e,
            user_id=current_user.id,
            stripe_account_id=acct_id,
        )
        flash("Error verifying bank connection. Please try again.", "error")
    except Exception as e:
        _log_stripe_error(
            "stripe_connect_return",
            e,
            user_id=current_user.id,
            stripe_account_id=acct_id,
        )
        flash("Error verifying bank connection. Please try again.", "error")

    return redirect(url_for("wallet_home"))


@app.route("/connect/stripe/dashboard", methods=["GET"])
@login_required
def stripe_connect_dashboard():
    """Redirect to Stripe Express Dashboard for managing Connect account (bank details, payouts)."""
    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("wallet_home"))

    acct_id = (getattr(current_user, "stripe_account_id", None) or "").strip()
    if not acct_id:
        flash("Connect your Stripe account first.", "info")
        return redirect(url_for("stripe_connect_start"))

    try:
        link = stripe.Account.create_login_link(acct_id)
        return redirect(link.url)
    except stripe.error.StripeError as e:
        _log_stripe_error("stripe_connect_dashboard", e, user_id=current_user.id, stripe_account_id=acct_id)
        flash("Unable to open Stripe dashboard. Please try again.", "error")
        return redirect(url_for("wallet_home"))
    except Exception as e:
        _log_stripe_error("stripe_connect_dashboard", e, user_id=current_user.id, stripe_account_id=acct_id)
        flash("Unable to open Stripe dashboard. Please try again.", "error")
        return redirect(url_for("wallet_home"))


@app.route("/connect/onboard/provider", methods=["GET"])
@login_required
def connect_onboard_provider():
    """Alias for provider onboarding (Stripe Connect)."""
    return stripe_connect_start()


@app.route("/connect/onboard/affiliate/<int:affiliate_id>", methods=["GET"])
@role_required("admin")
def connect_onboard_affiliate(affiliate_id: int):
    ok, err_msg = _stripe_env_guard(require_base_url=True)
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("admin_dashboard"))

    affiliate = Affiliate.query.get_or_404(affiliate_id)
    base_url = get_stripe_base_url()
    refresh_url = CONNECT_ONBOARDING_REFRESH_URL or f"{base_url}/connect/onboard/affiliate/{affiliate.id}"
    return_url = CONNECT_ONBOARDING_RETURN_URL or f"{base_url}/admin/affiliates"

    try:
        acct_id = (affiliate.stripe_account_id or "").strip()
        if not acct_id:
            acct = stripe.Account.create(
                type="express",
                country="US",
                email=None,
                capabilities={"transfers": {"requested": True}},
                business_type="individual",
                metadata={"affiliate_id": str(affiliate.id), "purpose": "affiliate_payouts"},
            )
            acct_id = acct.id
            affiliate.stripe_account_id = acct_id
            db.session.commit()

        link = stripe.AccountLink.create(
            account=acct_id,
            refresh_url=refresh_url,
            return_url=return_url,
            type="account_onboarding",
        )
        return redirect(link.url)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "affiliate_onboarding",
            e,
            affiliate_id=affiliate.id,
        )
        flash("Unable to start affiliate onboarding. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))
    except Exception as e:
        _log_stripe_error(
            "affiliate_onboarding",
            e,
            affiliate_id=affiliate.id,
        )
        flash("Unable to start affiliate onboarding. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))


@app.route("/checkout/status/<int:order_id>", methods=["GET"])
@login_required
def checkout_status(order_id: int):
    """Lightweight polling endpoint for checkout success page."""
    order = PaymentOrder.query.get(order_id)
    if order:
        if order.client_user_id != current_user.id:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"is_paid": order.status == OrderStatus.paid}), 200

    legacy = Order.query.get(order_id)
    if not legacy or legacy.buyer_id != current_user.id:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"is_paid": legacy.status == OrderStatus.paid}), 200


@app.route("/debug/stripe-env", methods=["GET"])
def debug_stripe_env():
    """
    Health check endpoint to confirm env vars are loaded.
    Do NOT return secret values.
    """
    if is_prod():
        abort(404)
    if not (current_user.is_authenticated and current_user.role == RoleEnum.admin):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({
        "stripe_key_set": bool(STRIPE_SECRET_KEY),
        "webhook_secret_set": bool(STRIPE_WEBHOOK_SECRET),
        "stripe_available": bool(STRIPE_AVAILABLE),
    }), 200


@app.route("/payments/success", methods=["GET"])
@login_required
def payments_success():
    """Universal Stripe success redirect for Checkout sessions."""
    session_id = (request.args.get("session_id") or "").strip()
    if not session_id:
        flash("Invalid checkout session.", "error")
        return redirect(url_for("route_to_dashboard"))

    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("route_to_dashboard"))

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "payments_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Unable to verify payment session. Please contact support if charged.", "error")
        return redirect(url_for("route_to_dashboard"))
    except Exception as e:
        _log_stripe_error(
            "payments_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Unable to verify payment session. Please contact support if charged.", "error")
        return redirect(url_for("route_to_dashboard"))

    metadata = checkout_session.metadata or {}
    purpose = (metadata.get("purpose") or metadata.get("type") or "").strip().lower()
    order_type = (metadata.get("order_type") or "").strip().lower()
    phase = (metadata.get("phase") or "").strip().lower()

    if purpose == "wallet_topup":
        return redirect(url_for("wallet_stripe_success", session_id=session_id))

    if order_type == OrderType.booking.value or order_type == "booking":
        if phase == PaymentLedgerPhase.holding.value:
            return redirect(url_for("checkout_hold_fee_success", session_id=session_id))
        booking_id = metadata.get("booking_id")
        try:
            booking_id = int(booking_id) if booking_id else None
        except Exception:
            booking_id = None
        if booking_id:
            return redirect(url_for("booking_detail", booking_id=booking_id))
        return redirect(url_for("bookme_requests"))

    return redirect(url_for("checkout_success", session_id=session_id))


@app.route("/payments/cancel", methods=["GET"])
@login_required
def payments_cancel():
    flash("Payment canceled.", "info")
    return redirect(url_for("route_to_dashboard"))


@app.route("/checkout/success", methods=["GET"])
@login_required
def checkout_success():
    """
    Stripe success redirect (NOT the source of truth).
    We display a receipt and status, but access is only granted once the Stripe
    webhook marks the Order as paid.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        flash("Invalid checkout session.", "error")
        return redirect(url_for("market_index"))
    
    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("market_index"))
    
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)

        # Best-effort: ensure the session belongs to this logged-in user.
        if checkout_session.client_reference_id and f"user_{current_user.id}" not in checkout_session.client_reference_id:
            flash("This checkout session does not belong to you.", "error")
            return redirect(url_for("market_index"))

        metadata = checkout_session.metadata or {}
        order = None
        payment_order = None

        order_id = metadata.get("order_id")
        if order_id:
            try:
                payment_order = PaymentOrder.query.get(int(order_id))
            except Exception:
                payment_order = None
            if payment_order and payment_order.client_user_id != current_user.id:
                payment_order = None

        if payment_order:
            order = payment_order
        else:
            if order_id:
                try:
                    order = Order.query.get(int(order_id))
                except Exception:
                    order = None

            if not order:
                order = (
                    Order.query
                    .filter_by(stripe_session_id=session_id, buyer_id=current_user.id)
                    .order_by(Order.created_at.desc())
                    .first()
                )

        beat = None
        seller = None
        if order:
            beat = Beat.query.get(order.beat_id) if order.beat_id else None
            if beat and beat.owner_id:
                seller = User.query.get(beat.owner_id)
            elif getattr(order, "seller_id", None):
                seller = User.query.get(order.seller_id)
        else:
            # Fallback: show beat preview even if we can't find the order row yet
            try:
                beat_id = int(metadata.get("beat_id") or 0)
            except Exception:
                beat_id = 0
            if beat_id:
                beat = Beat.query.get(beat_id)
                seller = User.query.get(beat.owner_id) if beat and beat.owner_id else None

        if not beat:
            flash("Beat not found.", "error")
            return redirect(url_for("market_index"))
        if not seller:
            seller = User.query.first()  # fallback for template safety

        # Display amounts: prefer DB values; fall back to Stripe metadata/session totals
        subtotal_cents = int(order.amount_cents or 0) if order else int(metadata.get("subtotal_cents") or 0)
        platform_fee_cents = int(order.platform_fee_cents or 0) if (order and order.platform_fee_cents is not None) else int(metadata.get("platform_fee_cents") or 0)
        processing_fee_cents = int(getattr(order, "processing_fee_cents", 0) or 0) if order else int(metadata.get("processing_fee_cents") or 0)

        total_from_stripe = checkout_session.amount_total if getattr(checkout_session, "amount_total", None) is not None else None
        total_cents = int(getattr(order, "total_cents", 0) or 0) if order else int(metadata.get("total_cents") or (total_from_stripe or 0))
        if total_cents <= 0:
            total_cents = subtotal_cents

        is_paid = bool(order and order.status == OrderStatus.paid)
        return render_template(
            "checkout_success.html",
            order=order,
            order_id=(order.id if order else None),
            beat=beat,
            seller=seller,
            subtotal_cents=subtotal_cents,
            platform_fee_cents=platform_fee_cents,
            processing_fee_cents=processing_fee_cents,
            total_cents=total_cents,
            stripe_session_id=session_id,
            is_paid=is_paid,
            is_payment_order=isinstance(order, PaymentOrder),
        )
        
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "checkout_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Error verifying payment. Please contact support if payment was charged.", "error")
        return redirect(url_for("market_index"))
    except Exception as e:
        _log_stripe_error(
            "checkout_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("We couldn't load your receipt yet. Please check “My Purchases” in a moment.", "warning")
        return redirect(url_for("market_my_purchases"))


@app.route("/checkout/hold-fee/success", methods=["GET"])
@login_required
def checkout_hold_fee_success():
    """
    Handle successful Stripe checkout for hold fee payment.
    This URL is publicly accessible (Stripe can redirect here), but requires
    user authentication to process the payment completion.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        flash("Invalid checkout session.", "error")
        return redirect(url_for("bookme_requests"))
    
    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("bookme_requests"))
    
    try:
        # Retrieve the checkout session from Stripe
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        metadata = checkout_session.metadata or {}

        if metadata.get("order_id") and metadata.get("phase") == PaymentLedgerPhase.holding.value:
            if checkout_session.payment_status != "paid":
                flash("Payment was not completed.", "error")
                return redirect(url_for("bookme_requests"))

            try:
                order = PaymentOrder.query.get(int(metadata.get("order_id")))
            except Exception:
                order = None
            if not order or order.client_user_id != current_user.id:
                flash("This checkout session does not belong to you.", "error")
                return redirect(url_for("bookme_requests"))

            booking = Booking.query.get(order.booking_id) if order.booking_id else None
            if not booking:
                flash("Booking not found.", "error")
                return redirect(url_for("bookme_requests"))
            if booking.client_id != current_user.id:
                flash("You can only view your own booking.", "error")
                return redirect(url_for("bookme_requests"))

            provider = booking.provider or User.query.get(booking.provider_id)
            hold_fee_cents = int(getattr(checkout_session, "amount_total", None) or HOLD_FEE_CENTS)

            return render_template(
                "checkout_hold_fee_success.html",
                booking=booking,
                booking_request=None,
                provider=provider,
                hold_fee_cents=hold_fee_cents,
                beatfund_fee_cents=0,
                processing_fee_cents=0,
                total_cents=hold_fee_cents,
                stripe_session_id=session_id,
            )
        
        # Verify the session belongs to the current user
        if checkout_session.client_reference_id and f"user_{current_user.id}" not in checkout_session.client_reference_id:
            flash("This checkout session does not belong to you.", "error")
            return redirect(url_for("bookme_requests"))
        
        # Check if payment was successful
        if checkout_session.payment_status != "paid":
            flash("Payment was not completed.", "error")
            return redirect(url_for("bookme_requests"))
        
        # Extract metadata
        metadata = checkout_session.metadata or {}
        purpose = metadata.get("purpose")
        req_id_raw = metadata.get("booking_request_id")
        booking_id_raw = metadata.get("booking_id")

        if purpose != "bookme_hold":
            flash("Invalid checkout session metadata.", "error")
            return redirect(url_for("bookme_requests"))

        req_id = None
        booking_id = None
        if req_id_raw:
            try:
                req_id = int(req_id_raw)
            except (ValueError, TypeError):
                req_id = None
        if booking_id_raw:
            try:
                booking_id = int(booking_id_raw)
            except (ValueError, TypeError):
                booking_id = None

        if not req_id and not booking_id:
            flash("Invalid checkout session metadata.", "error")
            return redirect(url_for("bookme_requests"))

        hold_fee_cents = int(metadata.get("hold_fee_cents", HOLD_FEE_CENTS))
        beatfund_fee_cents = 0
        processing_fee_cents = 0
        total_cents = int(hold_fee_cents or 0)

        if booking_id:
            booking = Booking.query.get(booking_id)
            if not booking:
                flash("Booking not found.", "error")
                return redirect(url_for("bookme_requests"))
            if booking.client_id != current_user.id:
                flash("You can only pay for your own booking.", "error")
                return redirect(url_for("bookme_requests"))

            req = None
            if req_id:
                req = BookingRequest.query.get(req_id)
            if not req:
                req = BookingRequest.query.filter_by(booking_id=booking.id).first()

            provider = User.query.get(booking.provider_id)
            if not provider:
                flash("Provider not found.", "error")
                return redirect(url_for("bookme_requests"))

            # Idempotency for booking-based checkout
            idempotency_key = generate_idempotency_key(
                "stripe_hold_fee", current_user.id, booking_id=booking.id, session_id=session_id
            )
            existing_result = check_idempotency(idempotency_key, "stripe_hold_fee", current_user.id)
            if existing_result:
                flash("This hold fee payment was already processed.", "info")
                return redirect(url_for("bookme_requests"))

            try:
                with db_txn():
                    if db.engine.dialect.name == "postgresql":
                        booking = Booking.query.filter_by(id=booking.id).with_for_update().first()
                        client_w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
                        req_check = BookingRequest.query.filter_by(id=req.id).with_for_update().first() if req else None
                    else:
                        booking = Booking.query.filter_by(id=booking.id).first()
                        client_w = Wallet.query.filter_by(user_id=current_user.id).first()
                        req_check = BookingRequest.query.filter_by(id=req.id).first() if req else None

                    if not booking:
                        raise ValueError("booking_not_found")

                    existing_payment = Payment.query.filter_by(
                        booking_id=booking.id,
                        kind=PaymentKind.deposit,
                        status=PaymentStatus.succeeded,
                    ).first()
                    if existing_payment:
                        raise ValueError("already_paid")

                    if not client_w:
                        client_w = Wallet(user_id=current_user.id)
                        db.session.add(client_w)
                        db.session.flush()

                    # Record escrow entry for client
                    try:
                        meta_client = f"hold fee for booking #{booking.id} with @{provider.username} (Stripe payment - held in escrow)"
                        if not LedgerEntry.query.filter_by(
                            wallet_id=client_w.id, entry_type=EntryType.purchase_spend, meta=meta_client
                        ).first():
                            post_ledger(client_w, EntryType.purchase_spend, hold_fee_cents, meta=meta_client)
                    except Exception:
                        pass

                    # Credit provider ledger for hold fee
                    try:
                        provider_w = Wallet.query.filter_by(user_id=provider.id).first()
                        if not provider_w:
                            provider_w = Wallet(user_id=provider.id)
                            db.session.add(provider_w)
                            db.session.flush()
                        meta_income = f"booking #{booking.id} deposit (Stripe)"
                        if not LedgerEntry.query.filter_by(
                            wallet_id=provider_w.id, entry_type=EntryType.sale_income, meta=meta_income
                        ).first():
                            post_ledger(provider_w, EntryType.sale_income, hold_fee_cents, meta=meta_income)
                    except Exception:
                        app.logger.warning("Hold fee: unable to post provider ledger entry")

                    # Store payment breakdown for deposit
                    try:
                        payment_intent_id = getattr(checkout_session, "payment_intent", None)
                        payment = Payment.query.filter_by(
                            booking_id=booking.id, kind=PaymentKind.deposit
                        ).order_by(Payment.created_at.desc()).first()
                        if payment and payment.status in (PaymentStatus.created, PaymentStatus.processing, PaymentStatus.failed):
                            payment.status = PaymentStatus.succeeded
                            payment.amount_cents = total_cents
                            payment.base_amount_cents = hold_fee_cents
                            payment.beatfund_fee_cents = beatfund_fee_cents
                            payment.processing_fee_cents = processing_fee_cents
                            payment.total_paid_cents = total_cents
                            if payment_intent_id:
                                payment.stripe_payment_intent_id = str(payment_intent_id)
                                payment.external_id = str(payment_intent_id)
                            payment.nonrefundable_processing_kept_cents = int(processing_fee_cents or 0)
                            payment.nonrefundable_beatfund_kept_cents = int(beatfund_fee_cents or 0)
                        else:
                            payment = Payment(
                                purpose=PaymentPurpose.booking_deposit,
                                processor=PaymentProcessor.stripe,
                                status=PaymentStatus.succeeded,
                                kind=PaymentKind.deposit,
                                amount_cents=total_cents,
                                currency="usd",
                                base_amount_cents=hold_fee_cents,
                                beatfund_fee_cents=beatfund_fee_cents,
                                processing_fee_cents=processing_fee_cents,
                                total_paid_cents=total_cents,
                                idempotency_key=generate_idempotency_key(
                                    "booking_deposit", current_user.id, booking_id=booking.id, session_id=session_id
                                ),
                                booking_id=booking.id,
                                booking_request_id=(req_check.id if req_check else None),
                                stripe_payment_intent_id=str(payment_intent_id) if payment_intent_id else None,
                                external_id=str(payment_intent_id) if payment_intent_id else None,
                            )
                            payment.nonrefundable_processing_kept_cents = int(processing_fee_cents or 0)
                            payment.nonrefundable_beatfund_kept_cents = int(beatfund_fee_cents or 0)
                            db.session.add(payment)
                    except Exception:
                        pass

                    booking.beatfund_fee_collected_cents = int(booking.beatfund_fee_collected_cents or 0) + int(beatfund_fee_cents or 0)
                    if booking.status not in (BOOKING_STATUS_COMPLETED, BOOKING_STATUS_CANCELLED):
                        booking.status = BOOKING_STATUS_HOLD_PAID
                    if req_check and req_check.status == BookingStatus.accepted:
                        req_check.status = BookingStatus.confirmed

                    try:
                        audit_log_event(
                            action_type="HOLD_CREATED",
                            actor_user=current_user,
                            target_type="Booking",
                            target_id=str(booking.id),
                            reason="Hold fee paid and held in escrow",
                            metadata={
                                "booking_request_id": req_check.id if req_check else None,
                                "booking_id": booking.id,
                                "provider_id": provider.id,
                                "client_id": current_user.id,
                                "hold_fee_cents": hold_fee_cents,
                                "stripe_session_id": session_id,
                            },
                            commit=False,
                        )
                    except Exception:
                        pass

                    store_idempotency_result(
                        idempotency_key,
                        "stripe_hold_fee",
                        current_user.id,
                        {"status": "success", "booking_id": booking.id, "req_id": (req_check.id if req_check else None), "stripe_session_id": session_id},
                        commit=False,
                    )

                    notify_user(
                        provider,
                        kind="success",
                        title="Hold fee paid - Booking confirmed!",
                        body=f"@{current_user.username} paid the hold fee. Booking is now confirmed.",
                        url=url_for("booking_detail", booking_id=booking.id),
                        actor_user_id=current_user.id,
                        event_key=f"booking:{booking.id}:deposit_paid",
                        commit=False,
                    )
                    notify_user(
                        current_user,
                        kind="success",
                        title="Deposit paid",
                        body=f"Your hold fee was received for booking #{booking.id}.",
                        url=url_for("booking_detail", booking_id=booking.id),
                        actor_user_id=current_user.id,
                        event_key=f"booking:{booking.id}:deposit_paid_client",
                        commit=False,
                    )

            except ValueError as e:
                error_msg = str(e)
                if error_msg == "already_paid":
                    flash("Hold fee already paid for this booking.", "info")
                else:
                    flash("Unable to process hold fee payment.", "error")
                return redirect(url_for("bookme_requests"))
            except IntegrityError:
                flash("This hold fee payment was already processed.", "info")
                return redirect(url_for("bookme_requests"))

            db.session.refresh(booking)
            if req:
                try:
                    db.session.refresh(req)
                except Exception:
                    pass

            return render_template(
                "checkout_hold_fee_success.html",
                booking=booking,
                booking_request=req,
                provider=provider,
                hold_fee_cents=hold_fee_cents,
                beatfund_fee_cents=beatfund_fee_cents,
                processing_fee_cents=processing_fee_cents,
                total_cents=total_cents,
                stripe_session_id=session_id,
            )
        
        # Get booking request
        req = BookingRequest.query.get(req_id)
        if not req:
            flash("Booking request not found.", "error")
            return redirect(url_for("bookme_requests"))
        
        if req.client_id != current_user.id:
            flash("You can only pay for your own booking requests.", "error")
            return redirect(url_for("bookme_requests"))
        
        if req.booking_id:
            flash("Hold fee already paid for this booking request.", "info")
            return redirect(url_for("bookme_requests"))
        
        hold_fee_cents = int(metadata.get("hold_fee_cents", HOLD_FEE_CENTS))
        beatfund_fee_cents = 0
        processing_fee_cents = 0
        total_cents = int(hold_fee_cents or 0)
        provider = User.query.get(req.provider_id)
        if not provider:
            flash("Provider not found.", "error")
            return redirect(url_for("bookme_requests"))
        
        # Generate idempotency key
        idempotency_key = generate_idempotency_key("stripe_hold_fee", current_user.id, req_id=req_id, session_id=session_id)
        
        # Check for existing transaction
        existing_result = check_idempotency(idempotency_key, "stripe_hold_fee", current_user.id)
        if existing_result:
            flash("This hold fee payment was already processed.", "info")
            return redirect(url_for("bookme_requests"))
        
        # Process hold fee payment and create booking
        client_w = get_or_create_wallet(current_user.id, commit=False, lock=False)
        
        try:
            with db_txn():
                # Re-check booking request status within transaction
                if db.engine.dialect.name == "postgresql":
                    req_check = BookingRequest.query.filter_by(id=req_id).with_for_update().first()
                    client_w = Wallet.query.filter_by(user_id=current_user.id).with_for_update().first()
                else:
                    req_check = BookingRequest.query.filter_by(id=req_id).first()
                    client_w = Wallet.query.filter_by(user_id=current_user.id).first()
                
                if not req_check:
                    raise ValueError("request_not_found")
                
                if req_check.booking_id:
                    raise ValueError("already_paid")
                
                if req_check.status != BookingStatus.accepted:
                    raise ValueError("not_accepted")
                
                if not client_w:
                    client_w = Wallet(user_id=current_user.id)
                    db.session.add(client_w)
                    db.session.flush()
                
                # Create Booking from BookingRequest
                # Parse preferred_time to get event_datetime
                event_datetime = None
                try:
                    if " " in req_check.preferred_time:
                        event_datetime = datetime.strptime(req_check.preferred_time, "%Y-%m-%d %H:%M")
                    else:
                        event_datetime = datetime.strptime(req_check.preferred_time, "%Y-%m-%d")
                except ValueError:
                    # Fallback to current time if parsing fails
                    event_datetime = datetime.utcnow()
                
                booking = Booking(
                    provider_id=req_check.provider_id,
                    provider_role=provider.role,
                    client_id=current_user.id,
                    event_title=f"Booking with @{provider.username}",
                    event_datetime=event_datetime,
                    duration_minutes=req_check.duration_minutes,
                    total_cents=None,  # Full payment amount set later
                    quoted_total_cents=None,
                    deposit_base_cents=HOLD_FEE_CENTS,
                    beatfund_fee_total_cents=None,
                    status=BOOKING_STATUS_CONFIRMED,  # Confirmed after hold fee payment
                    notes_from_client=req_check.message,
                )
                db.session.add(booking)
                db.session.flush()

                # Ensure booking-scoped conversation exists as soon as booking is created
                try:
                    get_or_create_booking_conversation(booking.id)
                except Exception:
                    pass
                
                # Link booking request to booking
                req_check.booking_id = booking.id
                req_check.status = BookingStatus.confirmed
                
                # Hold fee is held in escrow (deducted from client wallet)
                # This will be released/refunded based on booking completion
                post_ledger(
                    client_w,
                    EntryType.purchase_spend,
                    hold_fee_cents,
                    meta=f"hold fee for booking #{booking.id} with @{provider.username} (Stripe payment - held in escrow)"
                )

                # Credit provider ledger for hold fee (Stripe payment)
                try:
                    provider_w = Wallet.query.filter_by(user_id=provider.id).first()
                    if not provider_w:
                        provider_w = Wallet(user_id=provider.id)
                        db.session.add(provider_w)
                        db.session.flush()
                    meta_income = f"booking #{booking.id} deposit (Stripe)"
                    if not LedgerEntry.query.filter_by(wallet_id=provider_w.id, entry_type=EntryType.sale_income, meta=meta_income).first():
                        post_ledger(provider_w, EntryType.sale_income, hold_fee_cents, meta=meta_income)
                except Exception:
                    app.logger.warning("Hold fee: unable to post provider ledger entry")

                # Store payment breakdown for deposit (Stripe Checkout uses a PaymentIntent internally)
                try:
                    payment_intent_id = getattr(checkout_session, "payment_intent", None)
                    payment = Payment(
                        purpose=PaymentPurpose.booking_deposit,
                        processor=PaymentProcessor.stripe,
                        status=PaymentStatus.succeeded,
                        kind=PaymentKind.deposit,
                        amount_cents=total_cents,
                        currency="usd",
                        base_amount_cents=hold_fee_cents,
                        beatfund_fee_cents=beatfund_fee_cents,
                        processing_fee_cents=processing_fee_cents,
                        total_paid_cents=total_cents,
                        idempotency_key=generate_idempotency_key(
                            "booking_deposit", current_user.id, booking_id=booking.id, session_id=session_id
                        ),
                        booking_id=booking.id,
                        stripe_payment_intent_id=str(payment_intent_id) if payment_intent_id else None,
                        external_id=str(payment_intent_id) if payment_intent_id else None,
                    )
                    payment.nonrefundable_processing_kept_cents = int(processing_fee_cents or 0)
                    payment.nonrefundable_beatfund_kept_cents = int(beatfund_fee_cents or 0)
                    db.session.add(payment)
                except Exception:
                    pass

                # Track BeatFund fee collected on the booking
                booking.beatfund_fee_collected_cents = int(booking.beatfund_fee_collected_cents or 0) + int(beatfund_fee_cents or 0)

                # Finance audit: hold creation (escrow)
                try:
                    audit_log_event(
                        action_type="HOLD_CREATED",
                        actor_user=current_user,
                        target_type="Booking",
                        target_id=str(booking.id),
                        reason="Hold fee paid and held in escrow",
                        metadata={
                            "booking_request_id": req_id,
                            "booking_id": booking.id,
                            "provider_id": provider.id,
                            "client_id": current_user.id,
                            "hold_fee_cents": hold_fee_cents,
                            "stripe_session_id": session_id,
                        },
                        commit=False,
                    )
                except Exception:
                    pass
                
                # Store idempotency result
                store_idempotency_result(
                    idempotency_key,
                    "stripe_hold_fee",
                    current_user.id,
                    {"status": "success", "booking_id": booking.id, "req_id": req_id, "stripe_session_id": session_id},
                    commit=False
                )
                
                # Create notification for provider
                notify_user(
                    provider,
                    kind="success",
                    title="Hold fee paid - Booking confirmed!",
                    body=f"@{current_user.username} paid the hold fee. Booking is now confirmed for {req_check.preferred_time}",
                    url=url_for("booking_detail", booking_id=booking.id),
                    actor_user_id=current_user.id,
                    event_key=f"booking:{booking.id}:deposit_paid",
                    commit=False
                )
                notify_user(
                    current_user,
                    kind="success",
                    title="Deposit paid",
                    body=f"Your hold fee was received for booking #{booking.id}.",
                    url=url_for("booking_detail", booking_id=booking.id),
                    actor_user_id=current_user.id,
                    event_key=f"booking:{booking.id}:deposit_paid_client",
                    commit=False,
                )
        
        except ValueError as e:
            error_msg = str(e)
            if error_msg == "already_paid":
                flash("Hold fee already paid for this booking request.", "info")
            elif error_msg == "not_accepted":
                flash("Booking request must be accepted before paying hold fee.", "error")
            else:
                flash("Unable to process hold fee payment.", "error")
            return redirect(url_for("bookme_requests"))
        except IntegrityError:
            flash("This hold fee payment was already processed.", "info")
            return redirect(url_for("bookme_requests"))
        
        # Refresh booking from database to ensure it's accessible
        db.session.refresh(booking)
        db.session.refresh(req_check)
        
        # Render success page with booking details
        return render_template(
            "checkout_hold_fee_success.html",
            booking=booking,
            booking_request=req_check,
            provider=provider,
            hold_fee_cents=hold_fee_cents,
            beatfund_fee_cents=beatfund_fee_cents,
            processing_fee_cents=processing_fee_cents,
            total_cents=total_cents,
            stripe_session_id=session_id,
        )
        
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "checkout_hold_fee_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("Error verifying payment. Please contact support if payment was charged.", "error")
        return redirect(url_for("bookme_requests"))
    except Exception as e:
        _log_stripe_error(
            "checkout_hold_fee_success",
            e,
            user_id=current_user.id,
            session_id=session_id,
        )
        flash("An error occurred processing your payment.", "error")
        return redirect(url_for("bookme_requests"))


@app.route("/market/confirm/<int:beat_id>", methods=["GET"])
@login_required
def market_confirm(beat_id):
    """Order preview page - shows order details before proceeding to checkout"""
    beat = Beat.query.get_or_404(beat_id)

    if hasattr(beat, "is_active") and not beat.is_active:
        flash("This beat is not available for purchase.", "error")
        return redirect(url_for("market_index"))

    # Check if exclusive beat has already been sold
    if beat.license == "exclusive" and not beat.is_active:
        flash("This exclusive beat has already been sold.", "error")
        return redirect(url_for("market_index"))

    seller = User.query.get(beat.owner_id)
    if not seller:
        flash("Seller account not found.", "error")
        return redirect(url_for("market_index"))

    if seller.id == current_user.id:
        flash("You can't buy your own beat.", "error")
        return redirect(url_for("market_index"))

    if _user_has_paid_for_beat(current_user.id, beat.id):
        flash("You already purchased this beat. Check \"My purchases\".", "info")
        return redirect(url_for("market_my_purchases"))

    subtotal_cents = int(beat.price_cents or 0)
    breakdown = fee_breakdown_for_beat(subtotal_cents)
    platform_fee_cents = breakdown["platform_fee_cents"]
    total_cents = breakdown["total_cents"]
    producer_amount_cents = total_cents - platform_fee_cents  # what artist receives

    # Convert to dollars for template
    total_dollars = cents_to_dollars(total_cents)
    producer_amount_dollars = cents_to_dollars(producer_amount_cents)
    platform_fee_dollars = cents_to_dollars(platform_fee_cents)

    # Beat purchase uses Stripe Connect: producer must have connected Stripe to receive payouts
    producer_stripe_ready = _producer_has_stripe_connected(seller.id) if subtotal_cents > 0 else True

    return render_template(
        "market_confirm.html",
        beat=beat,
        seller=seller,
        total_cents=total_cents,
        total_dollars=total_dollars,
        producer_amount_cents=producer_amount_cents,
        producer_amount_dollars=producer_amount_dollars,
        platform_fee_cents=platform_fee_cents,
        platform_fee_dollars=platform_fee_dollars,
        is_exclusive=(beat.license == "exclusive"),
        producer_stripe_ready=producer_stripe_ready,
    )


@app.route("/market/buy/<int:beat_id>", methods=["POST"])
@login_required
def market_buy(beat_id):
    """Process the purchase - requires confirmation"""
    # Check for confirmation parameter
    confirmed = request.form.get("confirmed") == "true"
    if not confirmed:
        flash("Please confirm your purchase on the confirmation page.", "error")
        return redirect(url_for("market_confirm", beat_id=beat_id))

    beat = Beat.query.get_or_404(beat_id)

    if hasattr(beat, "is_active") and not beat.is_active:
        flash("This beat is not available for purchase.", "error")
        return redirect(url_for("market_index"))

    # Check if exclusive beat has already been sold
    if beat.license == "exclusive" and not beat.is_active:
        flash("This exclusive beat has already been sold.", "error")
        return redirect(url_for("market_index"))

    seller = User.query.get(beat.owner_id)
    if not seller:
        flash("Seller account not found.", "error")
        return redirect(url_for("market_index"))

    if seller.id == current_user.id:
        flash("You can't buy your own beat.", "error")
        return redirect(url_for("market_index"))

    if _user_has_paid_for_beat(current_user.id, beat.id):
        flash("You already purchased this beat. Check \"My purchases\".", "info")
        return redirect(url_for("market_my_purchases"))

    subtotal_cents = int(beat.price_cents or 0)
    if subtotal_cents < 0:
        flash("Invalid beat price.", "error")
        return redirect(url_for("market_index"))

    # Calculate fees using breakdown helper
    breakdown = fee_breakdown_for_beat(subtotal_cents)
    platform_fee_cents = breakdown["platform_fee_cents"]
    processing_fee_cents = breakdown["processing_fee_cents"]
    total_cents = breakdown["total_cents"]
    
    if subtotal_cents == 0:
        try:
            with db_txn():
                # Row-level locking on Postgres for beat (prevents duplicate free purchases)
                if db.engine.dialect.name == "postgresql":
                    beat_check = Beat.query.filter_by(id=beat.id).with_for_update().first()
                else:
                    beat_check = Beat.query.filter_by(id=beat.id).first()
                
                if not beat_check:
                    raise ValueError("beat_not_found")
                
                if beat_check.license == "exclusive" and not beat_check.is_active:
                    raise ValueError("sold_out")
                
                # Check for duplicate purchase
                if _user_has_paid_for_beat(current_user.id, beat.id):
                    raise ValueError("already_purchased")
                
                order = Order(beat_id=beat.id, buyer_id=current_user.id, seller_id=seller.id, amount_cents=0, status=OrderStatus.paid)
                db.session.add(order)
                try:
                    existing_bp = BeatPurchase.query.filter_by(
                        beat_id=beat.id,
                        buyer_id=current_user.id,
                        status=BeatPurchaseStatus.paid.value,
                    ).first()
                except Exception:
                    existing_bp = None
                if not existing_bp:
                    db.session.add(
                        BeatPurchase(
                            beat_id=beat.id,
                            buyer_id=current_user.id,
                            payment_id=None,
                            status=BeatPurchaseStatus.paid.value,
                        )
                    )
                
                # Mark exclusive beat as inactive after purchase
                if beat_check.license == "exclusive":
                    beat_check.is_active = False
                    beat_check.updated_at = datetime.utcnow()
        except ValueError as e:
            if str(e) == "sold_out":
                flash("This exclusive beat has already been sold.", "error")
            else:
                flash("Unable to complete purchase.", "error")
            return redirect(url_for("market_index"))
        except IntegrityError:
            flash("This purchase was already processed.", "info")
            return redirect(url_for("market_my_purchases"))

        flash("Added to your purchases!", "success")
        return redirect(url_for("market_my_purchases"))

    try:
        ok, err_msg = _stripe_env_guard(require_base_url=True)
        if not ok:
            flash(err_msg, "error")
            return redirect(url_for("market_confirm", beat_id=beat.id))

        # Producer must have Stripe Connect to receive payouts
        if not _producer_has_stripe_connected(seller.id):
            flash("This beat is temporarily unavailable for purchase. The producer needs to connect their Stripe account.", "error")
            return redirect(url_for("market_confirm", beat_id=beat.id))

        order, err = get_or_create_payment_order_for_beat(beat, current_user)
        if err:
            flash(err, "error")
            return redirect(url_for("market_confirm", beat_id=beat.id))
        if order.status == OrderStatus.paid:
            flash("You already purchased this beat. Check \"My purchases\".", "info")
            return redirect(url_for("market_my_purchases"))

        payload, status = _create_checkout_session_for_order(order, PaymentLedgerPhase.full)
        checkout_url = (payload or {}).get("checkout_url") or (payload or {}).get("url")
        if status != 200 or not checkout_url:
            err_msg = (payload or {}).get("error", "Unable to start Stripe Checkout.")
            flash(err_msg, "error")
            return redirect(url_for("market_confirm", beat_id=beat.id))

        return redirect(checkout_url)

    except stripe.error.StripeError as e:
        _log_stripe_error(
            "market_confirm_checkout",
            e,
            user_id=current_user.id,
            beat_id=beat.id,
            amount_cents=int(beat.price_cents or 0),
            currency=beat.currency or "usd",
        )
        flash("Payment processing error. Please try again.", "error")
        return redirect(url_for("market_confirm", beat_id=beat.id))
    except Exception as e:
        app.logger.exception(
            "market_buy_checkout unexpected error: %s",
            e,
            extra={"user_id": current_user.id, "beat_id": beat.id},
        )
        flash("An unexpected error occurred. Please try again or contact support.", "error")
        return redirect(url_for("market_confirm", beat_id=beat.id))


@app.route("/beats/<int:beat_id>/preview", endpoint="beat_preview")
def beat_preview(beat_id: int):
    beat = Beat.query.get_or_404(beat_id)
    if hasattr(beat, "is_active") and not beat.is_active:
        abort(404)
    key = beat.audio_preview_key or beat.preview_path
    status = (beat.preview_status or "ready").lower()
    if key and status != "ready":
        beat.preview_status = "ready"
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    if not key:
        original_key = (
            beat.audio_deliverable_key
            or beat.audio_original_key
            or beat.stems_key
            or beat.stems_path
        )
        if STORAGE_BACKEND == "local" and original_key:
            local_path = os.path.join(app.config["UPLOAD_FOLDER"], original_key)
            preview_bytes, err = _generate_audio_preview_from_path(
                local_path,
                beat.preview_seconds or PREVIEW_SECONDS_DEFAULT,
            )
            if preview_bytes:
                preview_fs = FileStorage(
                    stream=BytesIO(preview_bytes),
                    filename="preview.mp3",
                    content_type="audio/mpeg",
                )
                preview_key = _save_file(
                    preview_fs,
                    ALLOWED_AUDIO,
                    owner_user_id=beat.owner_id,
                    purpose=UploadedFilePurpose.beat_preview,
                )
                if preview_key:
                    beat.audio_preview_key = preview_key
                    if not beat.preview_path:
                        beat.preview_path = preview_key
                    beat.preview_status = "ready"
                    try:
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                    key = preview_key
            elif err:
                beat.preview_status = "failed"
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                app.logger.warning(f"Preview generation skipped for beat {beat.id}: {err}")
    if not key:
        abort(404)
    return media_file(key)


@app.route("/beats/<int:beat_id>/download", endpoint="beat_download")
@login_required
def beat_download(beat_id: int):
    beat = Beat.query.get_or_404(beat_id)
    is_admin = current_user.is_authenticated and current_user.role == RoleEnum.admin
    if not (is_admin or beat.owner_id == current_user.id or _user_has_paid_for_beat(current_user.id, beat_id)):
        log_security_event(
            "beat_download_blocked",
            f"Beat download blocked (beat_id={beat_id})",
            "warning",
            meta={"beat_id": beat_id, "user_id": getattr(current_user, "id", None)},
        )
        flash("You don't have access to download this file.", "error")
        return redirect(url_for("market_index"))

    key = (
        beat.audio_deliverable_key
        or beat.audio_original_key
        or beat.stems_key
        or beat.stems_path
    )
    if not key:
        flash("No deliverable file available for this beat.", "error")
        return redirect(url_for("market_index"))

    return media_file(key, as_attachment=True, download_name=_download_name_for_beat(beat, key))


@app.route("/market/download/<int:beat_id>")
@login_required
def market_download(beat_id):
    return beat_download(beat_id)


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
            "role": p.user.role if p.user.role else "",
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
    all_beats = (
        Beat.query
        .filter_by(is_active=True)
        .filter(or_(Beat.preview_status == "ready", Beat.preview_status.is_(None)))
        .all()
    )
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
        
        # Check if current user is following this producer
        is_following = UserFollow.query.filter_by(
            follower_id=current_user.id, 
            followed_id=user.id
        ).first() is not None

        producers.append({
            "user": user,
            "display_name": prof.display_name if prof else user.display_name,
            "username": user.username,
            "avatar_url": user.avatar_url,
            "city": prof.city if prof else "",
            "state": prof.state if prof else "",
            "followers_count": UserFollow.query.filter_by(followed_id=user.id).count(),
            "is_following": is_following,
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

    beats_for_producer = (
        Beat.query
        .filter_by(owner_id=producer_user.id, is_active=True)
        .filter(or_(Beat.preview_status == "ready", Beat.preview_status.is_(None)))
        .order_by(Beat.id.desc())
        .all()
    )
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
        audio_file = request.files.get("audio_file")
        preview_file = request.files.get("preview_file")
        stems_file = request.files.get("stems_file")
        preview_seconds_raw = (request.form.get("preview_seconds") or "").strip()

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

        if not audio_file or not audio_file.filename:
            errors.append("Audio file is required.")

        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("producer_beats"))

        try:
            preview_seconds = int(preview_seconds_raw) if preview_seconds_raw else PREVIEW_SECONDS_DEFAULT
        except Exception:
            preview_seconds = PREVIEW_SECONDS_DEFAULT

        beat, upload_errors, warnings = process_beat_upload(
            owner_user_id=current_user.id,
            title=title,
            price_cents=price_cents,
            currency="usd",
            license_type="standard",
            bpm=bpm,
            genre=genre or None,
            cover_file=cover_file,
            deliverable_file=audio_file,
            preview_file=preview_file,
            stems_file=stems_file,
            preview_seconds=preview_seconds,
            allow_user_preview_upload=True,
        )
        if upload_errors:
            for e in upload_errors:
                flash(e, "error")
            return redirect(url_for("producer_beats"))
        for w in warnings:
            flash(w, "warning")

        db.session.add(beat)
        db.session.commit()

        # Marketplace-wide broadcast (only when public/active)
        try:
            if getattr(beat, "is_active", False):
                broadcast_event(
                    ActivityEventType.beat_published,
                    actor_user_id=current_user.id,
                    payload_dict={"beat_id": beat.id, "beat_title": beat.title},
                    audience="ALL",
                    exclude_actor=True,
                )
        except Exception:
            # Best-effort: never block uploads on broadcast failures
            pass

        flash("Beat saved to your catalog.", "success")
        return redirect(url_for("producer_beats"))

    beats = Beat.query.filter_by(owner_id=current_user.id).order_by(Beat.id.desc()).all()
    producer_stripe_connected = _producer_has_stripe_connected(current_user.id)
    has_paid_beats = any(int(b.price_cents or 0) > 0 for b in beats)
    return render_template(
        "producer_beats.html",
        beats=beats,
        producer_stripe_connected=producer_stripe_connected,
        has_paid_beats=has_paid_beats,
    )


@app.route("/producer/beats/<int:beat_id>/delete", methods=["POST"], endpoint="producer_beats_delete")
@role_required("producer")
def producer_beats_delete(beat_id):
    beat = Beat.query.get_or_404(beat_id)

    if beat.owner_id != current_user.id:
        flash("You can't delete another producer's beat.", "error")
        return redirect(url_for("producer_beats"))

    if beat.cover_path:
        _safe_remove(beat.cover_path)
    if beat.audio_preview_key:
        _safe_remove(beat.audio_preview_key)
    if beat.audio_original_key:
        _safe_remove(beat.audio_original_key)
    if beat.audio_deliverable_key:
        _safe_remove(beat.audio_deliverable_key)
    if beat.stems_key:
        _safe_remove(beat.stems_key)
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


@app.route("/producer/beats/<int:beat_id>/price", methods=["POST"], endpoint="producer_beat_update_price")
@role_required("producer")
def producer_beat_update_price(beat_id: int):
    """Allow a producer to update their beat's price (discounts or increases)."""
    beat = Beat.query.get_or_404(beat_id)
    if beat.owner_id != current_user.id:
        flash("You can only update prices for your own beats.", "error")
        return redirect(url_for("producer_market_mine"))

    price_raw = (request.form.get("price_dollars") or "").strip()
    if price_raw == "":
        flash("Price is required.", "error")
        return redirect(request.form.get("next") or request.referrer or url_for("producer_market_mine"))

    try:
        price = Decimal(price_raw)
    except InvalidOperation:
        flash("Price must be a valid number (e.g. 19.99).", "error")
        return redirect(request.form.get("next") or request.referrer or url_for("producer_market_mine"))

    if price < 0:
        flash("Price cannot be negative.", "error")
        return redirect(request.form.get("next") or request.referrer or url_for("producer_market_mine"))

    # Safety cap (dev/prod)
    if price > Decimal(str(MAX_TXN_DOLLARS)):
        flash(f"Price too large. Max is ${MAX_TXN_DOLLARS:,}.", "error")
        return redirect(request.form.get("next") or request.referrer or url_for("producer_market_mine"))

    # Convert dollars to cents (integer)
    new_price_cents = int((price * 100).to_integral_value())
    beat.price_cents = new_price_cents
    beat.updated_at = datetime.utcnow()
    db.session.commit()

    flash(f"Updated price for '{beat.title}' to ${new_price_cents/100.0:.2f}.", "success")
    return redirect(request.form.get("next") or request.referrer or url_for("producer_market_mine"))


@app.route("/producer/market/delete/<int:beat_id>", methods=["POST"], endpoint="producer_market_delete")
@role_required("producer")
def producer_market_delete(beat_id):
    beat = Beat.query.get_or_404(beat_id)
    
    if beat.owner_id != current_user.id:
        flash("You can only delete your own beats.", "error")
        return redirect(url_for("producer_market_mine"))
    
    # Remove uploaded files before deleting the beat
    if beat.cover_path:
        _safe_remove(beat.cover_path)
    if beat.audio_preview_key:
        _safe_remove(beat.audio_preview_key)
    if beat.audio_original_key:
        _safe_remove(beat.audio_original_key)
    if beat.audio_deliverable_key:
        _safe_remove(beat.audio_deliverable_key)
    if beat.stems_key:
        _safe_remove(beat.stems_key)
    if beat.preview_path:
        _safe_remove(beat.preview_path)
    if beat.stems_path:
        _safe_remove(beat.stems_path)
    
    # Archive Stripe product and price if they exist
    if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
        try:
            if beat.stripe_price_id:
                try:
                    stripe.Price.modify(beat.stripe_price_id, active=False)
                except stripe.error.InvalidRequestError:
                    pass  # Price already deleted
            if beat.stripe_product_id:
                try:
                    stripe.Product.modify(beat.stripe_product_id, active=False)
                except stripe.error.InvalidRequestError:
                    pass  # Product already deleted
        except Exception as e:
            app.logger.warning(f"Error archiving Stripe product/price for beat {beat.id}: {str(e)}")
    
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
        preview_file = request.files.get("preview_file")
        stems_file = request.files.get("stems_file")
        preview_seconds_raw = (request.form.get("preview_seconds") or "").strip()
        
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
        
        # Validate license type
        if license_type not in {"standard", "exclusive"}:
            license_type = "standard"
        
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("market_upload.html")
        
        try:
            preview_seconds = int(preview_seconds_raw) if preview_seconds_raw else PREVIEW_SECONDS_DEFAULT
        except Exception:
            preview_seconds = PREVIEW_SECONDS_DEFAULT

        beat, upload_errors, warnings = process_beat_upload(
            owner_user_id=current_user.id,
            title=title,
            price_cents=price_cents,
            currency="usd",
            license_type=license_type,
            bpm=bpm,
            genre=genre or None,
            cover_file=cover_file,
            deliverable_file=audio_file,
            preview_file=preview_file,
            stems_file=stems_file,
            preview_seconds=preview_seconds,
            allow_user_preview_upload=True,
        )
        if upload_errors:
            for e in upload_errors:
                flash(e, "error")
            return render_template("market_upload.html")
        for w in warnings:
            flash(w, "warning")

        db.session.add(beat)
        db.session.flush()  # Flush to get beat.id before Stripe sync
        
        # Sync to Stripe (create Product and Price)
        if beat.price_cents > 0:
            sync_beat_to_stripe(beat, commit=False)
        
        db.session.commit()

        # Marketplace-wide broadcast (only when public/active)
        try:
            if getattr(beat, "is_active", False):
                broadcast_event(
                    ActivityEventType.beat_published,
                    actor_user_id=current_user.id,
                    payload_dict={"beat_id": beat.id, "beat_title": beat.title},
                    audience="ALL",
                    exclude_actor=True,
                )
        except Exception:
            pass
        
        flash("Beat uploaded successfully to the marketplace!", "success")
        return redirect(url_for("market_index"))
    
    return render_template("market_upload.html")


# =========================================================
# Notifications Routes
# =========================================================
@app.route("/notifications")
@login_required
def notifications_page():
    """Notifications page - list broadcast + legacy notifications (most recent first)."""
    limit = 50

    # Broadcast (event-driven)
    recs = (
        NotificationRecipient.query
        .filter_by(user_id=current_user.id)
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .join(User, ActivityEvent.actor_user_id == User.id)
        .filter(User.role != RoleEnum.admin.value)
        .filter(ActivityEvent.audience != "ADMINS")
        .order_by(ActivityEvent.created_at.desc(), NotificationRecipient.id.desc())
        .limit(limit)
        .all()
    )

    broadcast_items = []
    for r in recs:
        ev = r.event
        actor = getattr(ev, "actor", None)
        payload = _safe_json_loads(getattr(ev, "payload_json", None))
        title, body, url = build_activity_message(getattr(ev, "event_type", None), payload, actor)
        broadcast_items.append({
            "id": r.id,
            "source": "broadcast",
            "event_type": getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else None,
            "kind": "info",
            "title": title,
            "body": body,
            "url": url,
            "is_read": bool(getattr(r, "read_at", None)),
            "created_at": getattr(ev, "created_at", None) or getattr(r, "created_at", None),
            "actor_name": getattr(actor, "display_name", None) or getattr(actor, "username", None) if actor else None,
        })

    # Legacy notifications (system, wallet, etc.)
    legacy = (
        Notification.query
        .filter_by(user_id=current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .all()
    )
    legacy_items = [{
        "id": n.id,
        "source": "legacy",
        "event_type": None,
        "kind": n.kind or "info",
        "title": n.title,
        "body": n.body,
        "url": n.url,
        "is_read": bool(n.is_read),
        "created_at": n.created_at,
        "actor_name": None,
    } for n in legacy]

    # Merge and sort
    items = broadcast_items + legacy_items
    items.sort(key=lambda x: (x["created_at"] is not None, x["created_at"]), reverse=True)
    items = items[:limit]

    return render_template("notifications.html", notifications=items)


@app.route("/notifications/<int:notif_id>/read", methods=["POST"])
@login_required
def mark_notification_read_route(notif_id):
    """Mark a single notification as read (broadcast recipient or legacy notification)."""
    did = False

    # Broadcast recipient
    rec = NotificationRecipient.query.filter_by(id=notif_id, user_id=current_user.id).first()
    if rec and not rec.read_at:
        rec.read_at = datetime.utcnow()
        db.session.commit()
        did = True

    # Legacy notification fallback
    if not did:
        did = mark_notification_read(current_user.id, notif_id)

    if did:
        flash("Notification marked as read.", "success")
    else:
        flash("Notification not found.", "error")
    return redirect(request.referrer or url_for("notifications_page"))


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def mark_all_notifications_read_route():
    """Mark all notifications as read (broadcast recipients + legacy)."""
    # Broadcast
    broadcast_count = (
        NotificationRecipient.query
        .filter(NotificationRecipient.user_id == current_user.id, NotificationRecipient.read_at.is_(None))
        .update({"read_at": datetime.utcnow()})
    )
    db.session.commit()

    # Legacy
    legacy_count = mark_all_notifications_read(current_user.id)

    flash(f"Marked {broadcast_count + legacy_count} notification(s) as read.", "success")
    return redirect(url_for("notifications_page"))


@app.route("/api/notifications/unread-count")
@login_required
def api_notifications_unread_count():
    """API endpoint for unread notification count"""
    legacy = get_unread_notification_count(current_user.id)
    broadcast = (
        NotificationRecipient.query
        .filter(
            NotificationRecipient.user_id == current_user.id,
            NotificationRecipient.read_at.is_(None),
        )
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .join(User, ActivityEvent.actor_user_id == User.id)
        .filter(User.role != RoleEnum.admin.value)
        .filter(ActivityEvent.audience != "ADMINS")
        .count()
    )
    return jsonify({"count": int(legacy + broadcast)})


@app.route("/api/notifications/recent")
@login_required
def api_notifications_recent():
    """API endpoint for recent notifications"""
    limit = 8

    # Broadcast recent
    recs = (
        NotificationRecipient.query
        .filter_by(user_id=current_user.id)
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .join(User, ActivityEvent.actor_user_id == User.id)
        .filter(User.role != RoleEnum.admin.value)
        .filter(ActivityEvent.audience != "ADMINS")
        .order_by(ActivityEvent.created_at.desc(), NotificationRecipient.id.desc())
        .limit(limit)
        .all()
    )
    broadcast_items = []
    for r in recs:
        ev = r.event
        actor = getattr(ev, "actor", None)
        payload = _safe_json_loads(getattr(ev, "payload_json", None))
        title, body, url = build_activity_message(getattr(ev, "event_type", None), payload, actor)
        broadcast_items.append({
            "id": r.id,
            "source": "broadcast",
            "event_type": getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else None,
            "title": title,
            "body": body,
            "actor_name": (getattr(actor, "display_name", None) or getattr(actor, "username", None)) if actor else None,
            "kind": "info",
            "url": url,
            "is_read": bool(getattr(r, "read_at", None)),
            "created_at": (getattr(ev, "created_at", None) or getattr(r, "created_at", None)).isoformat()
            if (getattr(ev, "created_at", None) or getattr(r, "created_at", None))
            else None,
        })

    legacy = get_recent_notifications(current_user.id, limit=limit)
    legacy_items = [{
        "id": n.id,
        "source": "legacy",
        "event_type": None,
        "title": n.title,
        "body": n.body,
        "actor_name": None,
        "kind": n.kind,
        "url": n.url,
        "is_read": n.is_read,
        "created_at": n.created_at.isoformat() if n.created_at else None
    } for n in legacy]

    items = broadcast_items + legacy_items
    items.sort(key=lambda x: (x["created_at"] is not None, x["created_at"]), reverse=True)
    return jsonify(items[:limit])


@app.route("/notifications/unread_count")
@login_required
def notifications_unread_count_alias():
    """Optional alias endpoint for unread badge count."""
    legacy = get_unread_notification_count(current_user.id)
    broadcast = (
        NotificationRecipient.query
        .filter(
            NotificationRecipient.user_id == current_user.id,
            NotificationRecipient.read_at.is_(None),
        )
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .join(User, ActivityEvent.actor_user_id == User.id)
        .filter(User.role != RoleEnum.admin.value)
        .filter(ActivityEvent.audience != "ADMINS")
        .count()
    )
    return jsonify({"count": int(legacy + broadcast)})


# =========================================================
# Admin Notifications (admins only)
# =========================================================
def _admin_bell_event_allowed(ev: ActivityEvent | None, payload: dict | None) -> bool:
    if not ev:
        return False
    et = getattr(ev, "event_type", None)
    if et in {ActivityEventType.admin_ticket_updated, ActivityEventType.admin_wallet_adjusted, ActivityEventType.admin_refund_issued}:
        return True
    if et == ActivityEventType.admin_user_role_changed:
        data = (payload or {}).get("data") or {}
        before = data.get("before") or {}
        after = data.get("after") or {}
        return ("kyc_status" in before) or ("kyc_status" in after)
    return False

@app.route("/dashboard/admin/notifications", endpoint="admin_notifications")
@app.route("/admin/notifications", endpoint="admin_notifications_alias")
@role_required("admin")
def admin_notifications():
    limit = 100
    recs = (
        NotificationRecipient.query
        .filter(NotificationRecipient.user_id == current_user.id)
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .filter(ActivityEvent.audience == "ADMINS")
        .order_by(ActivityEvent.created_at.desc(), NotificationRecipient.id.desc())
        .limit(limit)
        .all()
    )

    items = []
    for r in recs:
        ev = r.event
        actor = getattr(ev, "actor", None)
        payload = _safe_json_loads(getattr(ev, "payload_json", None))

        if not _admin_bell_event_allowed(ev, payload):
            continue

        title = payload.get("summary") or payload.get("action_type") or (getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else "Admin event")
        body = ""
        try:
            data = payload.get("data") or {}
            if isinstance(data, dict) and (data.get("before") or data.get("after")):
                body = json.dumps({"before": data.get("before"), "after": data.get("after")}, ensure_ascii=False, default=str)
        except Exception:
            body = ""

        url = payload.get("url") if isinstance(payload, dict) else None
        if not (url and str(url).startswith("/")):
            url = None

        items.append({
            "id": r.id,
            "event_type": payload.get("action_type") or (getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else None),
            "title": title,
            "body": body,
            "url": url,
            "created_at": getattr(ev, "created_at", None) or getattr(r, "created_at", None),
            "is_read": bool(getattr(r, "read_at", None)),
            "actor_username": payload.get("actor_username") or (getattr(actor, "username", None) if actor else None),
        })

    return render_template("admin_notifications.html", items=items)


@app.route("/dashboard/admin/notifications/<int:recipient_id>/read", methods=["POST"], endpoint="admin_notifications_mark_read")
@app.route("/admin/notifications/<int:recipient_id>/read", methods=["POST"], endpoint="admin_notifications_mark_read_alias")
@role_required("admin")
def admin_notifications_mark_read(recipient_id: int):
    rec = NotificationRecipient.query.filter_by(id=recipient_id, user_id=current_user.id).first()
    if not rec:
        flash("Notification not found.", "error")
        return redirect(url_for("admin_notifications"))

    # Ensure it's an admin audience event
    try:
        if not rec.event or getattr(rec.event, "audience", None) != "ADMINS":
            flash("Notification not found.", "error")
            return redirect(url_for("admin_notifications"))
    except Exception:
        pass

    if not rec.read_at:
        rec.read_at = datetime.utcnow()
        db.session.commit()
    return redirect(request.referrer or url_for("admin_notifications"))


@app.route("/dashboard/admin/notifications/unread_count", endpoint="admin_notifications_unread_count")
@app.route("/admin/notifications/unread_count", endpoint="admin_notifications_unread_count_alias")
@role_required("admin")
def admin_notifications_unread_count():
    allowed_types = {
        ActivityEventType.admin_ticket_updated,
        ActivityEventType.admin_wallet_adjusted,
        ActivityEventType.admin_refund_issued,
        ActivityEventType.admin_user_role_changed,
    }
    recs = (
        NotificationRecipient.query
        .filter(
            NotificationRecipient.user_id == current_user.id,
            NotificationRecipient.read_at.is_(None),
        )
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .filter(ActivityEvent.audience == "ADMINS")
        .filter(ActivityEvent.event_type.in_(list(allowed_types)))
        .order_by(NotificationRecipient.id.desc())
        .limit(500)
        .all()
    )
    count = 0
    for r in recs:
        ev = r.event
        payload = _safe_json_loads(getattr(ev, "payload_json", None))
        if _admin_bell_event_allowed(ev, payload):
            count += 1
    alert_count = 0
    try:
        alert_count = Alert.query.filter(Alert.severity == AlertSeverity.high, Alert.resolved_at.is_(None)).count()
    except Exception:
        alert_count = 0
    return jsonify({"count": int(count + alert_count)})


@app.route("/admin/notifications/recent", endpoint="admin_notifications_recent")
@role_required("admin")
def admin_notifications_recent():
    limit = request.args.get("limit", type=int) or 8
    allowed_types = {
        ActivityEventType.admin_ticket_updated,
        ActivityEventType.admin_wallet_adjusted,
        ActivityEventType.admin_refund_issued,
        ActivityEventType.admin_user_role_changed,
    }
    recs = (
        NotificationRecipient.query
        .filter(NotificationRecipient.user_id == current_user.id)
        .join(ActivityEvent, NotificationRecipient.event_id == ActivityEvent.id)
        .filter(ActivityEvent.audience == "ADMINS")
        .filter(ActivityEvent.event_type.in_(list(allowed_types)))
        .order_by(ActivityEvent.created_at.desc(), NotificationRecipient.id.desc())
        .limit(limit * 5)
        .all()
    )

    items = []
    for r in recs:
        ev = r.event
        actor = getattr(ev, "actor", None)
        payload = _safe_json_loads(getattr(ev, "payload_json", None))
        if not _admin_bell_event_allowed(ev, payload):
            continue

        title = payload.get("summary") or payload.get("action_type") or (getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else "Admin event")
        body = ""
        try:
            data = payload.get("data") or {}
            if isinstance(data, dict) and (data.get("before") or data.get("after")):
                body = json.dumps({"before": data.get("before"), "after": data.get("after")}, ensure_ascii=False, default=str)
        except Exception:
            body = ""

        url = payload.get("url") if isinstance(payload, dict) else None
        if not (url and str(url).startswith("/")):
            url = None

        items.append({
            "id": r.id,
            "event_type": payload.get("action_type") or (getattr(ev, "event_type", None).value if getattr(ev, "event_type", None) else None),
            "title": title,
            "body": body,
            "url": url,
            "created_at": getattr(ev, "created_at", None) or getattr(r, "created_at", None),
            "is_read": bool(getattr(r, "read_at", None)),
            "actor_username": payload.get("actor_username") or (getattr(actor, "username", None) if actor else None),
            "kind": "info",
        })

    # Critical alerts in admin bell
    try:
        alerts = (
            Alert.query
            .filter(Alert.severity == AlertSeverity.high, Alert.resolved_at.is_(None))
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )
        for a in alerts:
            items.append({
                "id": f"alert-{a.id}",
                "event_type": "ALERT",
                "title": "System alert",
                "body": a.message,
                "url": url_for("admin_alerts"),
                "created_at": a.created_at,
                "is_read": False,
                "actor_username": None,
                "kind": "error",
            })
    except Exception:
        pass

    items.sort(key=lambda x: (x.get("created_at") is not None, x.get("created_at")), reverse=True)
    return jsonify(items[:limit])


# =========================================================
# Tickets (User-facing)
# =========================================================
def _support_thread(ticket: SupportTicket) -> list[dict]:
    """Merge user/admin messages and legacy admin comments into a single timeline."""
    items: list[dict] = []
    try:
        for msg in SupportTicketMessage.query.filter_by(ticket_id=ticket.id).all():
            items.append({
                "created_at": msg.created_at,
                "author": msg.author,
                "body": msg.body,
                "internal": False,
            })
    except Exception:
        pass
    try:
        for c in ticket.comments.all():
            items.append({
                "created_at": c.created_at,
                "author": c.admin,
                "body": c.body,
                "internal": True,
            })
    except Exception:
        pass
    items.sort(key=lambda i: i.get("created_at") or datetime.min)
    return items


@app.route("/support", endpoint="support_home")
@login_required
def support_home():
    tickets = SupportTicket.query.filter(SupportTicket.user_id == current_user.id).order_by(SupportTicket.created_at.desc()).all()
    return render_template("support_home.html", tickets=tickets, TicketStatus=TicketStatus, TicketType=TicketType)


@app.route("/support/new", methods=["GET", "POST"], endpoint="support_new")
@login_required
def support_new():
    if request.method == "POST":
        subject = sanitize_input((request.form.get("subject") or "").strip(), max_length=200)
        description = sanitize_input((request.form.get("description") or "").strip(), max_length=4000)
        type_raw = (request.form.get("type") or "").strip()

        if not subject:
            flash("Subject is required.", "error")
            return redirect(url_for("support_new"))
        if not description:
            flash("Description is required.", "error")
            return redirect(url_for("support_new"))

        try:
            ticket_type = TicketType(type_raw) if type_raw else TicketType.other
        except Exception:
            ticket_type = TicketType.other

        creator_admin_id = _system_audit_admin_id()
        if not creator_admin_id:
            # Fallback to current user if no admin exists (dev/test)
            creator_admin_id = int(current_user.id)

        ticket = SupportTicket(
            user_id=current_user.id,
            created_by_admin_id=creator_admin_id,
            type=ticket_type,
            status=TicketStatus.open,
            subject=subject,
            description=description,
        )
        db.session.add(ticket)
        db.session.flush()

        msg = SupportTicketMessage(
            ticket_id=ticket.id,
            author_user_id=current_user.id,
            body=description,
        )
        db.session.add(msg)
        db.session.commit()

        flash("Support ticket created.", "success")
        return redirect(url_for("support_ticket_detail", ticket_id=ticket.id))

    return render_template("support_search.html", TicketType=TicketType)


@app.route("/support/<int:ticket_id>", endpoint="support_ticket_detail")
@login_required
def support_ticket_detail(ticket_id: int):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    if (ticket.user_id != current_user.id) and (current_user.role != RoleEnum.admin):
        abort(403)

    thread = _support_thread(ticket)
    return render_template(
        "support_user_detail.html",
        ticket=ticket,
        thread=thread,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )


@app.route("/support/<int:ticket_id>/reply", methods=["POST"], endpoint="support_ticket_reply")
@login_required
def support_ticket_reply(ticket_id: int):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    if (ticket.user_id != current_user.id) and (current_user.role != RoleEnum.admin):
        abort(403)

    body = sanitize_input((request.form.get("body") or "").strip(), max_length=4000)
    if not body:
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("support_ticket_detail", ticket_id=ticket.id))

    msg = SupportTicketMessage(
        ticket_id=ticket.id,
        author_user_id=current_user.id,
        body=body,
    )
    db.session.add(msg)

    if current_user.role != RoleEnum.admin:
        # Move to in_review when user replies
        try:
            ticket.status = TicketStatus.in_review
        except Exception:
            pass

    db.session.commit()
    flash("Reply sent.", "success")
    return redirect(url_for("support_ticket_detail", ticket_id=ticket.id))


@app.route("/tickets", endpoint="my_tickets")
@login_required
def my_tickets():
    return redirect(url_for("support_home"))


@app.route("/tickets/<int:ticket_id>", endpoint="my_ticket_detail")
@login_required
def my_ticket_detail(ticket_id: int):
    return redirect(url_for("support_ticket_detail", ticket_id=ticket_id))


# =========================================================
# Admin Dashboard
# =========================================================
@app.route("/dashboard/admin", endpoint="admin_dashboard")
@role_required("admin")
def admin_dashboard():
    total_users = User.query.filter(User.role != RoleEnum.admin.value).count()
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


@app.route("/admin/payment-orders", endpoint="admin_payment_orders")
@app.route("/dashboard/admin/payment-orders", endpoint="admin_payment_orders_dashboard")
@role_required("admin")
def admin_payment_orders():
    order_type = (request.args.get("type") or "").strip().lower()
    status = (request.args.get("status") or "").strip().lower()

    query = PaymentOrder.query
    if order_type:
        try:
            query = query.filter(PaymentOrder.order_type == OrderType(order_type))
        except Exception:
            pass
    if status:
        try:
            query = query.filter(PaymentOrder.status == OrderStatus(status))
        except Exception:
            pass

    orders = query.order_by(PaymentOrder.created_at.desc()).limit(300).all()
    ledger_rows = PaymentLedger.query.order_by(PaymentLedger.created_at.desc()).limit(300).all()
    return render_template(
        "admin_payment_orders.html",
        orders=orders,
        ledger_rows=ledger_rows,
        filters={"type": order_type, "status": status},
    )


@app.route("/admin/affiliates", endpoint="admin_affiliates")
@app.route("/dashboard/admin/affiliates", endpoint="admin_affiliates_dashboard")
@role_required("admin")
def admin_affiliates():
    status = (request.args.get("status") or "").strip().lower()
    query = Affiliate.query
    if status:
        try:
            query = query.filter(Affiliate.status == AffiliateStatus(status))
        except Exception:
            pass
    affiliates = query.order_by(Affiliate.created_at.desc()).all()
    return render_template("admin_affiliates.html", affiliates=affiliates, status=status)


@app.route("/admin/affiliate-earnings", endpoint="admin_affiliate_earnings")
@app.route("/dashboard/admin/affiliate-earnings", endpoint="admin_affiliate_earnings_dashboard")
@role_required("admin")
def admin_affiliate_earnings():
    try:
        now = datetime.utcnow()
        (
            AffiliateEarning.query
            .filter(
                AffiliateEarning.status == AffiliateEarningStatus.pending,
                AffiliateEarning.available_at.isnot(None),
                AffiliateEarning.available_at <= now,
            )
            .update({"status": AffiliateEarningStatus.available}, synchronize_session=False)
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

    rows = AffiliateEarning.query.order_by(AffiliateEarning.created_at.desc()).limit(500).all()

    summary_rows = (
        db.session.query(
            AffiliateEarning.status,
            func.count(AffiliateEarning.id),
            func.coalesce(func.sum(AffiliateEarning.commission_cents), 0),
        )
        .group_by(AffiliateEarning.status)
        .all()
    )
    summary = {}
    for status, count, total_cents in summary_rows:
        summary[str(status)] = {"count": int(count or 0), "total_cents": int(total_cents or 0)}

    return render_template(
        "admin_affiliate_earnings.html",
        rows=rows,
        summary=summary,
    )


# =========================================================
# Admin Careers Routes
# =========================================================
@app.route("/dashboard/admin/jobs", endpoint="admin_jobs")
@role_required("admin")
def admin_jobs():
    """List all job posts"""
    jobs = JobPost.query.order_by(JobPost.is_active.desc(), JobPost.created_at.desc()).all()
    return render_template("admin/jobs/index.html", jobs=jobs)


@app.route("/dashboard/admin/jobs/new", methods=["GET", "POST"], endpoint="admin_jobs_new")
@role_required("admin")
def admin_jobs_new():
    """Create new job post"""
    if request.method == "POST":
        title = sanitize_input(request.form.get("title", "").strip(), max_length=200)
        department = sanitize_input(request.form.get("department", "").strip(), max_length=120) or None
        location = sanitize_input(request.form.get("location", "").strip(), max_length=120) or None
        employment_type = sanitize_input(request.form.get("employment_type", "").strip(), max_length=80) or None
        level = sanitize_input(request.form.get("level", "").strip(), max_length=80) or None
        description = sanitize_input(request.form.get("description", ""), max_length=50000)
        responsibilities = sanitize_input(request.form.get("responsibilities", ""), max_length=50000) or None
        requirements = sanitize_input(request.form.get("requirements", ""), max_length=50000) or None
        nice_to_have = sanitize_input(request.form.get("nice_to_have", ""), max_length=50000) or None
        how_to_apply = sanitize_input(request.form.get("how_to_apply", ""), max_length=50000) or None
        is_active = request.form.get("is_active") == "on"
        
        if not title or not description:
            flash("Title and description are required.", "error")
            return render_template("admin/jobs/form.html")
        
        job = JobPost(
            title=title,
            department=department,
            location=location,
            employment_type=employment_type,
            level=level,
            description=description,
            responsibilities=responsibilities,
            requirements=requirements,
            nice_to_have=nice_to_have,
            how_to_apply=how_to_apply,
            is_active=is_active
        )
        
        db.session.add(job)
        db.session.commit()

        try:
            log_admin_action(
                ActivityEventType.admin_job_post_created,
                actor_admin_id=current_user.id,
                target_type="job_post",
                target_id=job.id,
                summary=f"Created job post: {job.title}",
                payload_dict={"job_id": job.id, "title": job.title, "is_active": bool(job.is_active)},
                url=url_for("admin_jobs"),
                include_actor=True,
            )
        except Exception:
            pass
        
        flash("Job post created successfully!", "success")
        return redirect(url_for("admin_jobs"))
    
    return render_template("admin/jobs/form.html")


@app.route("/dashboard/admin/jobs/<int:job_id>/edit", methods=["GET", "POST"], endpoint="admin_jobs_edit")
@role_required("admin")
def admin_jobs_edit(job_id):
    """Edit job post"""
    job = JobPost.query.get_or_404(job_id)
    
    if request.method == "POST":
        before = {
            "title": job.title,
            "department": job.department,
            "location": job.location,
            "employment_type": job.employment_type,
            "level": job.level,
            "is_active": bool(job.is_active),
        }
        job.title = sanitize_input(request.form.get("title", "").strip(), max_length=200)
        job.department = sanitize_input(request.form.get("department", "").strip(), max_length=120) or None
        job.location = sanitize_input(request.form.get("location", "").strip(), max_length=120) or None
        job.employment_type = sanitize_input(request.form.get("employment_type", "").strip(), max_length=80) or None
        job.level = sanitize_input(request.form.get("level", "").strip(), max_length=80) or None
        job.description = sanitize_input(request.form.get("description", ""), max_length=50000)
        job.responsibilities = sanitize_input(request.form.get("responsibilities", ""), max_length=50000) or None
        job.requirements = sanitize_input(request.form.get("requirements", ""), max_length=50000) or None
        job.nice_to_have = sanitize_input(request.form.get("nice_to_have", ""), max_length=50000) or None
        job.how_to_apply = sanitize_input(request.form.get("how_to_apply", ""), max_length=50000) or None
        job.is_active = request.form.get("is_active") == "on"
        
        if not job.title or not job.description:
            flash("Title and description are required.", "error")
            return render_template("admin/jobs/form.html", job=job)
        
        db.session.commit()

        try:
            log_admin_action(
                ActivityEventType.admin_job_post_updated,
                actor_admin_id=current_user.id,
                target_type="job_post",
                target_id=job.id,
                summary=f"Updated job post: {job.title}",
                payload_dict={"before": before, "after": {"title": job.title, "department": job.department, "location": job.location, "employment_type": job.employment_type, "level": job.level, "is_active": bool(job.is_active)}},
                url=url_for("admin_jobs_edit", job_id=job.id),
                include_actor=True,
            )
        except Exception:
            pass

        flash("Job post updated successfully!", "success")
        return redirect(url_for("admin_jobs"))
    
    return render_template("admin/jobs/form.html", job=job)


@app.route("/dashboard/admin/jobs/<int:job_id>/toggle", methods=["POST"], endpoint="admin_jobs_toggle")
@role_required("admin")
def admin_jobs_toggle(job_id):
    """Toggle job active status"""
    job = JobPost.query.get_or_404(job_id)
    before_active = bool(job.is_active)
    job.is_active = not job.is_active
    db.session.commit()

    try:
        log_admin_action(
            ActivityEventType.admin_job_post_updated,
            actor_admin_id=current_user.id,
            target_type="job_post",
            target_id=job.id,
            summary=f"{'Activated' if job.is_active else 'Archived'} job post: {job.title}",
            payload_dict={"before": {"is_active": before_active}, "after": {"is_active": bool(job.is_active)}, "job_id": job.id, "title": job.title},
            url=url_for("admin_jobs"),
            include_actor=True,
        )
    except Exception:
        pass

    flash(f"Job post {'activated' if job.is_active else 'archived'} successfully!", "success")
    return redirect(url_for("admin_jobs"))


@app.route("/dashboard/admin/applications", endpoint="admin_job_applications")
@role_required("admin")
def admin_job_applications():
    """Global applications inbox with filters"""
    status_filter = request.args.get("status", "").strip()
    job_id_filter = request.args.get("job_id", "").strip()
    search_q = request.args.get("q", "").strip()
    
    query = JobApplication.query
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    if job_id_filter:
        try:
            query = query.filter_by(job_id=int(job_id_filter))
        except ValueError:
            pass
    if search_q:
        query = query.filter(
            db.or_(
                JobApplication.full_name.ilike(f"%{search_q}%"),
                JobApplication.email.ilike(f"%{search_q}%")
            )
        )
    
    applications = query.order_by(JobApplication.created_at.desc()).limit(200).all()
    jobs = JobPost.query.order_by(JobPost.title).all()
    
    return render_template("admin/applications/index.html", applications=applications, jobs=jobs, 
                         status_filter=status_filter, job_id_filter=job_id_filter, search_q=search_q)


@app.route("/dashboard/admin/jobs/<int:job_id>/applications", endpoint="admin_job_applications_for_job")
@role_required("admin")
def admin_job_applications_for_job(job_id):
    """Applications inbox for a specific job"""
    job = JobPost.query.get_or_404(job_id)
    applications = JobApplication.query.filter_by(job_id=job_id).order_by(JobApplication.created_at.desc()).all()
    return render_template("admin/jobs/applications.html", job=job, applications=applications)


@app.route("/dashboard/admin/waitlist", endpoint="admin_waitlist")
@role_required("admin")
def admin_waitlist():
    """View waitlist entries (last 200)"""
    entries = WaitlistEntry.query.order_by(WaitlistEntry.created_at.desc()).limit(200).all()
    total_count = WaitlistEntry.query.count()
    return render_template("admin/waitlist.html", entries=entries, total_count=total_count)


@app.route("/dashboard/admin/waitlist/export", endpoint="admin_waitlist_export")
@role_required("admin")
def admin_waitlist_export():
    """Export waitlist entries as CSV"""
    entries = WaitlistEntry.query.order_by(WaitlistEntry.created_at.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Email", "Full Name", "Role Interest", "Note", "IP", "User Agent", "Created At"])
    
    for entry in entries:
        writer.writerow([
            entry.id,
            entry.email,
            entry.full_name or "",
            entry.role_interest or "",
            entry.note or "",
            entry.ip or "",
            entry.user_agent or "",
            entry.created_at.isoformat() if entry.created_at else ""
        ])
    
    output.seek(0)
    response = Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=waitlist_export.csv"}
    )
    return response


@app.route("/dashboard/admin/applications/<int:app_id>/status", methods=["POST"], endpoint="admin_job_application_status")
@role_required("admin")
def admin_job_application_status(app_id):
    """Update application status"""
    application = JobApplication.query.get_or_404(app_id)
    new_status = request.form.get("status", "").strip()
    
    valid_statuses = {"new", "reviewed", "interviewing", "rejected", "hired"}
    if new_status not in valid_statuses:
        flash("Invalid status.", "error")
        return redirect(request.referrer or url_for("admin_job_applications"))
    
    application.status = new_status
    db.session.commit()
    
    flash(f"Application status updated to {new_status}.", "success")
    return redirect(request.referrer or url_for("admin_job_applications"))


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

        if not OWNER_PANEL_PASS_HASH_EFFECTIVE:
            flash(
                "Owner panel passcode is not configured yet. Set it first (superadmin only).",
                "error",
            )
            return redirect(url_for("superadmin_change_passcode"))

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

    is_initial_setup = not bool(OWNER_PANEL_PASS_HASH_EFFECTIVE)

    # Access control: require owner panel unlocked (unless initial setup in dev)
    if not is_initial_setup and not owner_panel_unlocked():
        flash("Owner panel must be unlocked to change the passcode.", "error")
        return redirect(url_for("superadmin_unlock"))

    # Env-managed block
    if OWNER_PASS_MANAGED_BY_ENV:
        flash(
            "Owner passcode is managed by environment secrets; update it in your .env/host settings.",
            "error",
        )
        return redirect(url_for("superadmin_dashboard"))

    if request.method == "POST":
        # Rate limiting
        if not check_rate_limit("owner_passcode_change", max_requests=5, window_seconds=600):
            log_security_event("owner_passcode_change_failed", "Rate limit exceeded for owner passcode change", "warning")
            flash("Too many attempts. Please wait 10 minutes and try again.", "error")
            return redirect(url_for("superadmin_change_passcode"))

        # Get inputs
        admin_password = (request.form.get("admin_password") or "").strip()
        current_code = (request.form.get("current_passcode") or "").strip()
        new_code = (request.form.get("new_passcode") or "").strip()
        confirm_code = (request.form.get("confirm_passcode") or "").strip()

        # Re-auth check: validate admin password
        if not admin_password or not current_user.check_password(admin_password):
            log_security_event("owner_passcode_change_failed", f"Admin password wrong for @{current_user.username}", "warning")
            flash("Admin password is incorrect.", "error")
            return redirect(url_for("superadmin_change_passcode"))

        # Current owner passcode check (skip if initial setup)
        if not is_initial_setup:
            if not current_code or not check_password_hash(OWNER_PANEL_PASS_HASH_EFFECTIVE, current_code):
                log_security_event(
                    "owner_passcode_change_failed",
                    f"Owner passcode wrong for @{current_user.username}",
                    "warning",
                )
                flash("Current owner passcode is incorrect.", "error")
                return redirect(url_for("superadmin_change_passcode"))

        # New passcode validation
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

        # Apply change
        new_hash = generate_password_hash(new_code)
        _save_owner_pass_hash_to_instance(new_hash)
        OWNER_PANEL_PASS_HASH_EFFECTIVE = new_hash

        # Session hardening: invalidate owner unlock session
        session.pop(OWNER_UNLOCK_SESSION_KEY, None)

        # Security logging
        log_security_event("owner_passcode_changed", f"superadmin @{current_user.username} changed owner passcode", "warning")

        flash("Owner passcode updated. Please unlock again with your new passcode.", "success")
        return redirect(url_for("superadmin_unlock"))

    return render_template("superadmin_change_passcode.html")


@app.route("/dashboard/admin/owner", endpoint="superadmin_dashboard")
@superadmin_required
def superadmin_dashboard():
    if not owner_panel_unlocked():
        return redirect(url_for("superadmin_unlock"))

    total_users = User.query.filter(User.role != RoleEnum.admin.value).count()
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
    role = current_user.role

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
    elif role == "photographer":
        endpoint = "photographer_dashboard"
    elif role == "dj":
        endpoint = "dj_dashboard"
    elif role == "emcee_host_hypeman":
        endpoint = "host_dashboard"
    elif role == "hair_stylist_barber":
        endpoint = "hair_dashboard"
    elif role == "wardrobe_stylist":
        endpoint = "wardrobe_dashboard"
    elif role == "makeup_artist":
        endpoint = "makeup_dashboard"
    elif role == "funder":
        endpoint = "funder_dashboard"
    elif role == "client":
        endpoint = "client_dashboard"
    elif role == "social_media_manager":
        endpoint = "social_dashboard"
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
    total_beats = (
        Beat.query
        .filter_by(owner_id=current_user.id, is_active=True)
        .filter(or_(Beat.preview_status == "ready", Beat.preview_status.is_(None)))
        .count()
    )
    
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
    
    # Booking requests (producers can be BookMe providers)
    incoming_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .order_by(BookingRequest.created_at.desc())
        .limit(5)
        .all()
    )
    incoming_requests_count = BookingRequest.query.filter_by(
        provider_id=current_user.id,
        status=BookingStatus.pending
    ).count()
    
    outgoing_requests = (
        BookingRequest.query
        .filter_by(client_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(5)
        .all()
    )
    
    return render_template(
        "dash_producer.html",
        total_beats=total_beats,
        sales_count=sales_count,
        revenue=revenue,
        wallet_balance=wallet_balance,
        followers_count=followers_count,
        following_count=following_count,
        incoming_requests=incoming_requests,
        incoming_requests_count=incoming_requests_count,
        outgoing_requests=outgoing_requests,
        BookingStatus=BookingStatus,
        HOLD_FEE_CENTS=HOLD_FEE_CENTS,
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
    accepted_requests = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.accepted
    ).count()
    outgoing_requests = BookingRequest.query.filter_by(client_id=current_user.id).count()
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
    ).count()
    provider_recent_bookings = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(10)
        .all()
    )
    provider_recent_accepted_requests = []
    try:
        provider_recent_accepted_requests = (
            BookingRequest.query
            .filter_by(provider_id=current_user.id, status=BookingStatus.accepted)
            .order_by(BookingRequest.created_at.desc())
            .limit(10)
            .all()
        )
    except Exception:
        provider_recent_accepted_requests = []
    
    # Bookings as client
    client_bookings_count = Booking.query.filter_by(client_id=current_user.id).count()
    client_pending_bookings = Booking.query.filter_by(
        client_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        accepted_requests=accepted_requests,
        outgoing_requests=outgoing_requests,
        provider_bookings_count=provider_bookings_count,
        provider_pending_bookings=provider_pending_bookings,
        client_bookings_count=client_bookings_count,
        client_pending_bookings=client_pending_bookings,
        provider_recent_bookings=provider_recent_bookings,
        provider_recent_accepted_requests=provider_recent_accepted_requests,
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
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        client_id=current_user.id, status=BOOKING_STATUS_PENDING
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
    
    was_visible = bool(getattr(prof, "is_visible", False))

    # Toggle is_visible status
    prof.is_visible = not prof.is_visible
    db.session.commit()

    # Broadcast only when it becomes public/active
    try:
        if (not was_visible) and getattr(prof, "is_visible", False):
            broadcast_event(
                ActivityEventType.listing_published,
                actor_user_id=current_user.id,
                payload_dict={
                    "listing_kind": "bookme_profile",
                    "listing_id": prof.id,
                    "listing_title": getattr(prof, "display_name", None) or "Service",
                    "listing_url": url_for("provider_portfolio_public", username=current_user.username),
                },
                audience="ALL",
                exclude_actor=True,
            )
    except Exception:
        pass
    
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
    
    was_visible = bool(getattr(prof, "is_visible", False))

    # Toggle is_visible status
    prof.is_visible = not prof.is_visible
    db.session.commit()

    # Broadcast only when it becomes public/active
    try:
        if (not was_visible) and getattr(prof, "is_visible", False):
            broadcast_event(
                ActivityEventType.listing_published,
                actor_user_id=current_user.id,
                payload_dict={
                    "listing_kind": "bookme_profile",
                    "listing_id": prof.id,
                    "listing_title": getattr(prof, "display_name", None) or "Service",
                    "listing_url": url_for("provider_portfolio_public", username=current_user.username),
                },
                audience="ALL",
                exclude_actor=True,
            )
    except Exception:
        pass
    
    status = "activated" if prof.is_visible else "deactivated"
    role_name = get_role_display(current_user.role)
    flash(f"Profile {status}. {'Your services are now visible on the marketplace.' if prof.is_visible else 'Your services are hidden from the marketplace, but your profile is still visible for following and portfolio viewing.'}", "success")
    
    # Redirect to appropriate dashboard based on role
    role = current_user.role
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
    confirmed_bookings = sum(1 for b in all_bookings if b.status == BOOKING_STATUS_CONFIRMED)
    upcoming_bookings = [
        b for b in all_bookings 
        if b.event_datetime and b.event_datetime > datetime.utcnow() and b.status in [BOOKING_STATUS_PENDING, BOOKING_STATUS_CONFIRMED]
    ]
    
    # Group bookings by status
    bookings_by_status = {
        BOOKING_STATUS_PENDING: [b for b in all_bookings if b.status == BOOKING_STATUS_PENDING],
        BOOKING_STATUS_CONFIRMED: [b for b in all_bookings if b.status == BOOKING_STATUS_CONFIRMED],
        BOOKING_STATUS_COMPLETED: [b for b in all_bookings if b.status == BOOKING_STATUS_COMPLETED],
        BOOKING_STATUS_CANCELLED: [b for b in all_bookings if b.status == BOOKING_STATUS_CANCELLED],
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
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_PENDING]))
        .order_by(Booking.event_datetime.asc())
        .limit(10)
        .all()
    )
    upcoming_bookings_count = len(upcoming_bookings)
    
    # Active projects (accepted bookings)
    active_projects = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .filter(Booking.event_datetime >= now)
        .count()
    )
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .order_by(Booking.event_datetime.asc())
        .limit(20)
        .all()
    )
    
    # Earnings this month
    start_of_month = datetime(now.year, now.month, 1)
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Total earnings
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
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
        client_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .count()
    )
    
    # Bookings as provider
    provider_bookings_count = Booking.query.filter_by(provider_id=current_user.id).count()
    provider_pending_bookings = Booking.query.filter_by(
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .order_by(Booking.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Earnings this month
    start_of_month = datetime(now.year, now.month, 1)
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Total earnings
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
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
        client_id=current_user.id, status=BOOKING_STATUS_PENDING
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


@app.route("/dashboard/photographer", endpoint="photographer_dashboard")
@role_required("photographer")
def photographer_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # BookMe profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Stats for dashboard overview
    new_requests_count = BookingRequest.query.filter_by(
        provider_id=current_user.id, status=BookingStatus.pending
    ).count()
    
    now = datetime.utcnow()
    upcoming_shoots_count = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .filter(Booking.event_datetime >= now)
        .count()
    )
    
    active_projects_count = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .count()
    )
    
    # Monthly earnings
    start_of_month = datetime(now.year, now.month, 1)
    monthly_earnings_total_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    monthly_earnings_total = monthly_earnings_total_cents / 100.0
    
    # Average rating (placeholder - no review system yet)
    average_rating = None
    rating_count = 0
    
    # Incoming booking requests
    incoming_requests_list = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .order_by(BookingRequest.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Active & upcoming shoots
    active_shoots = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .order_by(Booking.event_datetime.asc())
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
    
    # Specialties (from service_types)
    specialties = []
    if prof and prof.service_types:
        specialties = [s.strip() for s in prof.service_types.split(",") if s.strip()]
    
    # Wallet balance
    w = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(w) / 100.0
    
    # Earnings summary
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .scalar() or 0
    )
    total_earnings = total_earnings_cents / 100.0
    
    # Pending payouts (bookings with payment but not yet paid out)
    pending_payouts_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .filter(Booking.total_cents.isnot(None))
        .scalar() or 0
    )
    pending_payouts = pending_payouts_cents / 100.0
    
    # Completed payouts (completed bookings)
    completed_payouts_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status == BOOKING_STATUS_COMPLETED)
        .scalar() or 0
    )
    completed_payouts = completed_payouts_cents / 100.0
    
    # Transaction history
    recent_transactions = (
        LedgerEntry.query
        .filter_by(wallet_id=w.id)
        .order_by(LedgerEntry.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Placeholder data for galleries (to be implemented with actual Gallery model)
    galleries = []
    
    # Note: Licensing section removed - replaced with portfolio copyright protection
    
    # Availability data (placeholder - can be expanded with actual availability model)
    availability = {
        "accept_new_bookings": prof.is_visible if prof else False,
        "max_shoots_per_day": 3,  # Placeholder
        "weekly_hours": "Mon-Fri 9am-6pm",  # Placeholder
        "blocked_dates": []  # Placeholder
    }
    
    # Reviews (placeholder - no review system yet)
    reviews = []
    
    return render_template(
        "dash_photographer.html",
        role_label=get_role_display(current_user.role),
        photographer={
            "display_name": prof.display_name if prof else current_user.display_name or current_user.username,
            "studio_name": prof.display_name if prof else None,
            "profile_image_url": current_user.avatar_url,
            "specialties": specialties,
            "location": f"{prof.city}, {prof.state}" if prof and (prof.city or prof.state) else "Remote",
            "kyc_status": current_user.kyc_status
        },
        stats={
            "new_requests_count": new_requests_count,
            "upcoming_shoots_count": upcoming_shoots_count,
            "active_projects_count": active_projects_count,
            "monthly_earnings_total": monthly_earnings_total,
            "average_rating": average_rating
        },
        requests=incoming_requests_list,
        shoots=active_shoots,
        galleries=galleries,
        portfolio_items=portfolio_items,
        availability=availability,
        earnings={
            "total_earnings": total_earnings,
            "this_month_earnings": monthly_earnings_total,
            "pending_payouts": pending_payouts,
            "completed_payouts": completed_payouts
        },
        transactions=recent_transactions,
        reviews=reviews,
        prof=prof,
        artist_can_take_gigs=artist_can_take_gigs,
        followers_count=followers_count,
        following_count=following_count,
        wallet_balance=wallet_balance,
        rating_count=rating_count,
        BookingStatus=BookingStatus,
        EntryType=EntryType,
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
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
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
        client_id=current_user.id, status=BOOKING_STATUS_PENDING
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
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # Manager profile info
    manager_info = {
        'id': current_user.id,
        'display_name': current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url
    }
    
    # 1. Dashboard Overview Stats
    # Managed artists (providers with BookMe profiles - using all active providers as potential managed artists)
    # For now, we'll show all providers as potential artists to manage
    managed_artists_list = (
        db.session.query(User, BookMeProfile)
        .join(BookMeProfile, User.id == BookMeProfile.user_id)
        .filter(BookMeProfile.is_visible == True)
        .limit(50)
        .all()
    )
    managed_artists_count = len(managed_artists_list)
    
    # New inquiries (pending booking requests)
    new_inquiries_count = BookingRequest.query.filter_by(status=BookingStatus.pending).count()
    
    # Active projects (bookings in progress)
    active_projects_count = (
        Booking.query
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_PENDING]))
        .filter(Booking.event_datetime >= now)
        .count()
    )
    
    # Upcoming bookings
    upcoming_bookings_count = (
        Booking.query
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .filter(Booking.event_datetime >= now)
        .count()
    )
    
    # Total earnings this month (from all bookings)
    total_earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    total_earnings_this_month = total_earnings_this_month_cents / 100.0
    
    # 2. My Artists - List of managed artists (providers with profiles)
    artists_list = []
    for user, prof in managed_artists_list[:20]:
        # Get upcoming bookings count for this artist
        upcoming_count = Booking.query.filter(
            Booking.provider_id == user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]),
            Booking.event_datetime >= now
        ).count()
        
        # Get earnings snapshot
        earnings_cents = (
            db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
            .filter(
                Booking.provider_id == user.id,
                Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED])
            )
            .scalar() or 0
        )
        
        # Get genre/category from service_types
        genre = None
        if prof.service_types:
            genres = [s.strip() for s in prof.service_types.split(",") if s.strip()]
            genre = genres[0] if genres else None
        
        artists_list.append({
            'id': user.id,
            'name': prof.display_name or user.display_name or user.username,
            'avatar_url': user.avatar_url,
            'status': 'active' if prof.is_visible else 'inactive',
            'genre': genre or get_role_display(user.role),
            'upcoming_count': upcoming_count,
            'earnings_snapshot': earnings_cents / 100.0
        })
    
    # 3. Requests (BookingRequests - manager can view all requests)
    requests_list = []
    all_requests = (
        BookingRequest.query
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_requests[:20]:
        provider = req.provider
        client = req.client
        requests_list.append({
            'id': req.id,
            'artist_id': req.provider_id,
            'artist_name': provider.display_name if provider else f"User #{req.provider_id}",
            'lead_name': client.display_name if client else f"User #{req.client_id}",
            'service_type': req.message[:50] if req.message else "Service Request",
            'budget': None,  # Not in BookingRequest model
            'date_range': req.preferred_time,
            'status': req.status.value if req.status else 'pending'
        })
    
    # 4. Projects (Bookings)
    projects_list = []
    all_projects = (
        Booking.query
        .order_by(Booking.created_at.desc())
        .limit(50)
        .all()
    )
    
    for proj in all_projects[:20]:
        provider = proj.provider
        client = proj.client
        projects_list.append({
            'id': proj.id,
            'artist_id': proj.provider_id,
            'artist_name': provider.display_name if provider else f"User #{proj.provider_id}",
            'provider_id': proj.provider_id,
            'provider_name': provider.display_name if provider else f"User #{proj.provider_id}",
            'event_title': proj.event_title,
            'status': proj.status,
            'deliverables_status': 'pending',  # Placeholder
            'payment_status': 'paid' if proj.total_cents and proj.status in [BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED] else 'pending',
            'updated_at': proj.updated_at
        })
    
    # 5. Schedule items (from bookings)
    schedule_items = []
    upcoming_bookings = (
        Booking.query
        .filter(Booking.event_datetime >= now)
        .order_by(Booking.event_datetime.asc())
        .limit(30)
        .all()
    )
    
    for booking in upcoming_bookings:
        provider = booking.provider
        schedule_items.append({
            'id': booking.id,
            'artist_name': provider.display_name if provider else f"User #{booking.provider_id}",
            'type': 'booking',
            'start': booking.event_datetime,
            'end': booking.event_datetime + timedelta(minutes=booking.duration_minutes or 60) if booking.duration_minutes else booking.event_datetime + timedelta(hours=1),
            'label': booking.event_title
        })
    
    # 6. Payments
    # Total paid (completed bookings)
    total_paid_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.status == BOOKING_STATUS_COMPLETED)
        .scalar() or 0
    )
    total_paid = total_paid_cents / 100.0
    
    # Total pending (accepted/confirmed but not completed)
    total_pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]))
        .scalar() or 0
    )
    total_pending = total_pending_cents / 100.0
    
    payments_data = {
        'total_paid': total_paid,
        'total_pending': total_pending,
        'this_month_total': total_earnings_this_month
    }
    
    # Transactions (from bookings)
    transactions_list = []
    for booking in all_projects[:20]:
        provider = booking.provider
        transactions_list.append({
            'id': booking.id,
            'artist_name': provider.display_name if provider else f"User #{booking.provider_id}",
            'event_title': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.created_at,
            'status': booking.status
        })
    
    # 7. Reports
    # Conversion rate (requests -> booked)
    total_requests = BookingRequest.query.count()
    booked_requests = BookingRequest.query.filter(BookingRequest.booking_id.isnot(None)).count()
    conversion_rate = (booked_requests / total_requests * 100) if total_requests > 0 else 0
    
    # Revenue by artist
    revenue_by_artist = []
    for user, prof in managed_artists_list[:10]:
        artist_rev = (
            db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
            .filter(
                Booking.provider_id == user.id,
                Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED])
            )
            .scalar() or 0
        )
        if artist_rev > 0:
            revenue_by_artist.append({
                'artist_name': prof.display_name or user.display_name or user.username,
                'revenue': artist_rev / 100.0
            })
    revenue_by_artist.sort(key=lambda x: x['revenue'], reverse=True)
    
    # Top service categories (from provider roles)
    top_services = []
    service_counts = (
        db.session.query(Booking.provider_role, func.count(Booking.id).label('count'))
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .group_by(Booking.provider_role)
        .order_by(func.count(Booking.id).desc())
        .limit(10)
        .all()
    )
    for role, count in service_counts:
        top_services.append({
            'service': get_role_display(role),
            'count': count
        })
    
    reports_data = {
        'conversion_rate': conversion_rate,
        'revenue_by_artist': revenue_by_artist[:10],
        'top_services': top_services
    }
    
    # 8. Talent Discovery (unmanaged artists - all providers not currently in managed list)
    # For now, we'll show all providers as potential discovery targets
    discovery_artists = []
    all_providers = (
        db.session.query(User, BookMeProfile)
        .join(BookMeProfile, User.id == BookMeProfile.user_id)
        .filter(BookMeProfile.is_visible == True)
        .order_by(User.id.desc())  # Use id as proxy for creation time (newer users have higher IDs)
        .limit(50)
        .all()
    )
    
    managed_ids = {user.id for user, _ in managed_artists_list}
    for user, prof in all_providers[:20]:
        if user.id not in managed_ids:
            # Calculate engagement score (follower count)
            engagement = UserFollow.query.filter_by(followed_id=user.id).count()
            genre = None
            if prof.service_types:
                genres = [s.strip() for s in prof.service_types.split(",") if s.strip()]
                genre = genres[0] if genres else None
            
            discovery_artists.append({
                'id': user.id,
                'name': prof.display_name or user.display_name or user.username,
                'avatar_url': user.avatar_url,
                'genre': genre or get_role_display(user.role),
                'location': f"{prof.city or ''}, {prof.state or ''}".strip() if (prof.city or prof.state) else "Remote",
                'engagement_score': engagement,
                'is_managed': False
            })
    
    # 9. Invites (placeholder - no invite system yet)
    invites = []
    
    # Stats summary
    stats = {
        'managed_artists_count': managed_artists_count,
        'new_inquiries_count': new_inquiries_count,
        'active_projects_count': active_projects_count,
        'upcoming_bookings_count': upcoming_bookings_count,
        'total_earnings_this_month': total_earnings_this_month
    }
    
    return render_template(
        "dash_manager.html",
        role_label=get_role_display(current_user.role),
        manager=manager_info,
        stats=stats,
        artists=artists_list,
        requests=requests_list,
        projects=projects_list,
        schedule_items=schedule_items,
        payments=payments_data,
        transactions=transactions_list,
        reports=reports_data,
        discovery_artists=discovery_artists,
        invites=invites,
        BookingStatus=BookingStatus,
        EntryType=EntryType,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/dj", endpoint="dj_dashboard")
@role_required("dj")
def dj_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # DJ profile info
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    # Management status (placeholder - check if DJ is managed)
    # For now, we'll check if there are any bookings where the DJ is managed
    # Management relationship check (placeholder - implement when management model is added)
    is_managed = False  # No management relationships implemented yet
    manager_name = None
    
    dj_info = {
        'id': current_user.id,
        'display_name': prof.display_name if prof else current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url,
        'is_managed': is_managed,
        'manager_name': manager_name
    }
    
    # 1. Dashboard Overview Stats
    # Upcoming events (confirmed bookings in future)
    upcoming_events_count = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]),
            Booking.event_datetime >= now
        )
        .count()
    )
    
    # Booking requests (pending)
    booking_requests_count = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .count()
    )
    
    # Events this month
    events_this_month = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.event_datetime >= start_of_month,
            Booking.event_datetime < now + timedelta(days=31)
        )
        .count()
    )
    
    # Total earnings this month
    total_earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.created_at >= start_of_month
        )
        .scalar() or 0
    )
    total_earnings_this_month = total_earnings_this_month_cents / 100.0
    
    # Average rating (placeholder - no review system yet)
    average_rating = None
    
    stats = {
        'upcoming_events_count': upcoming_events_count,
        'booking_requests_count': booking_requests_count,
        'events_this_month': events_this_month,
        'total_earnings_this_month': total_earnings_this_month,
        'average_rating': average_rating
    }
    
    # 2. Bookings (Requests)
    bookings_list = []
    all_booking_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_booking_requests[:20]:
        client = req.client
        # Extract event type from message or use placeholder
        event_type = "private"  # Default
        if req.message:
            msg_lower = req.message.lower()
            if any(word in msg_lower for word in ["club", "nightclub"]):
                event_type = "club"
            elif any(word in msg_lower for word in ["wedding", "marriage"]):
                event_type = "wedding"
            elif any(word in msg_lower for word in ["festival", "concert"]):
                event_type = "festival"
            elif any(word in msg_lower for word in ["brand", "corporate", "business"]):
                event_type = "brand"
        
        bookings_list.append({
            'id': req.id,
            'client_name': client.display_name if client else f"User #{req.client_id}",
            'event_type': event_type,
            'date': req.preferred_time,  # This is a string field
            'location': None,  # Not in BookingRequest model
            'budget': None,  # Not in BookingRequest model
            'status': req.status.value if req.status else 'pending'
        })
    
    # 3. Events (Confirmed bookings)
    events_list = []
    confirmed_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .order_by(Booking.event_datetime.asc())
        .limit(50)
        .all()
    )
    
    for booking in confirmed_bookings[:20]:
        # Extract event type from title or use provider_role
        event_type = "private"
        if booking.event_title:
            title_lower = booking.event_title.lower()
            if any(word in title_lower for word in ["club", "nightclub"]):
                event_type = "club"
            elif any(word in title_lower for word in ["wedding", "marriage"]):
                event_type = "wedding"
            elif any(word in title_lower for word in ["festival", "concert"]):
                event_type = "festival"
            elif any(word in title_lower for word in ["brand", "corporate"]):
                event_type = "brand"
        
        events_list.append({
            'id': booking.id,
            'title': booking.event_title,
            'date': booking.event_datetime,
            'venue': booking.location_text or "TBA",
            'event_type': event_type,
            'payment_status': 'paid' if booking.total_cents and booking.status == BOOKING_STATUS_COMPLETED else 'pending'
        })
    
    # 4. Setlists (placeholder - no setlist model yet)
    setlists = []
    
    # 5. Media (Portfolio items)
    media_list = []
    if prof:
        portfolio_items = (
            PortfolioItem.query
            .filter_by(profile_id=prof.id)
            .order_by(PortfolioItem.created_at.desc())
            .limit(50)
            .all()
        )
        
        for item in portfolio_items:
            media_list.append({
                'id': item.id,
                'type': item.media_type.value if item.media_type else 'image',
                'url': item.media_url if hasattr(item, 'media_url') else None,
                'is_featured': False  # No featured field yet
            })
    
    # 6. Availability (placeholder - can use StudioAvailability logic later)
    availability = []
    
    # 7. Earnings
    # Total earned (all completed/accepted bookings)
    total_earned_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_(["accepted", "confirmed", "completed"])
        )
        .scalar() or 0
    )
    total_earned = total_earned_cents / 100.0
    
    # Pending payments (accepted/confirmed but not completed)
    pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    pending = pending_cents / 100.0
    
    earnings_data = {
        'total_earned': total_earned,
        'pending': pending,
        'this_month': total_earnings_this_month
    }
    
    # Transactions
    transactions_list = []
    for booking in confirmed_bookings[:20]:
        client = booking.client
        transactions_list.append({
            'event_name': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.event_datetime,
            'status': booking.status
        })
    
    # 8. Reviews (placeholder - no review system yet)
    reviews = []
    
    return render_template(
        "dash_dj.html",
        role_label=get_role_display(current_user.role),
        dj=dj_info,
        stats=stats,
        bookings=bookings_list,
        events=events_list,
        setlists=setlists,
        media=media_list,
        availability=availability,
        earnings=earnings_data,
        transactions=transactions_list,
        reviews=reviews,
        BookingStatus=BookingStatus,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/host", endpoint="host_dashboard")
@role_required("emcee_host_hypeman")
def host_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # Host profile info
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    # Management status (placeholder - implement when management model is added)
    is_managed = False  # No management relationships implemented yet
    manager_name = None
    
    host_info = {
        'id': current_user.id,
        'display_name': prof.display_name if prof else current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url,
        'is_managed': is_managed,
        'manager_name': manager_name,
        'hosting_style': None,  # Not implemented yet
        'genres': prof.service_types if prof else None,
        'languages': None,  # Not implemented yet
        'travel_radius': None,  # Not implemented yet
        'rates': prof.rate_notes if prof else None,
    }
    
    # 1. Dashboard Overview Stats
    # New requests (pending booking requests)
    new_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .count()
    )
    
    # Upcoming events (confirmed bookings in future)
    upcoming_events = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]),
            Booking.event_datetime >= now
        )
        .count()
    )
    
    # Active bookings (all confirmed/accepted)
    active_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .count()
    )
    
    # Earnings this month
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.created_at >= start_of_month
        )
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Average rating (placeholder)
    avg_rating = None
    
    stats = {
        'new_requests': new_requests,
        'upcoming_events': upcoming_events,
        'active_bookings': active_bookings,
        'earnings_this_month': earnings_this_month,
        'avg_rating': avg_rating
    }
    
    # 2. Requests
    requests_list = []
    all_booking_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_booking_requests[:20]:
        client = req.client
        # Extract event type from message
        event_type = "private"
        if req.message:
            msg_lower = req.message.lower()
            if any(word in msg_lower for word in ["wedding", "marriage"]):
                event_type = "wedding"
            elif any(word in msg_lower for word in ["corporate", "business", "brand"]):
                event_type = "corporate"
            elif any(word in msg_lower for word in ["festival", "concert"]):
                event_type = "festival"
            elif any(word in msg_lower for word in ["club", "nightclub"]):
                event_type = "club"
        
        requests_list.append({
            'id': req.id,
            'client_name': client.display_name if client else f"User #{req.client_id}",
            'event_type': event_type,
            'date_time': req.preferred_time,
            'location': None,
            'budget': None,
            'status': req.status.value if req.status else 'pending'
        })
    
    # 3. Bookings/Events
    bookings_list = []
    confirmed_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .order_by(Booking.event_datetime.asc())
        .limit(50)
        .all()
    )
    
    for booking in confirmed_bookings[:20]:
        bookings_list.append({
            'id': booking.id,
            'event_title': booking.event_title,
            'date_time': booking.event_datetime,
            'location': booking.location_text or "TBA",
            'client_requirements': booking.notes_from_client or "None",
            'run_of_show': booking.notes_from_provider or "None",
            'payment_status': 'paid' if booking.total_cents and booking.status == BOOKING_STATUS_COMPLETED else 'pending',
            'timing': f"{booking.duration_minutes} minutes" if booking.duration_minutes else "TBA"
        })
    
    # 4. Event Briefs (placeholder - no brief model yet)
    briefs_list = []
    
    # 5. Media Kit (Portfolio items)
    media_list = []
    if prof:
        portfolio_items = (
            PortfolioItem.query
            .filter_by(profile_id=prof.id)
            .order_by(PortfolioItem.created_at.desc())
            .limit(50)
            .all()
        )
        
        for item in portfolio_items:
            media_list.append({
                'id': item.id,
                'type': item.media_type.value if item.media_type else 'image',
                'url': item.media_url if hasattr(item, 'media_url') else None,
                'title': item.title,
                'is_one_sheet': False  # Placeholder
            })
    
    # 6. Availability (placeholder)
    availability = {
        'accept_new_requests': True,  # TODO: Add toggle to profile
        'blocked_dates': []
    }
    
    # 7. Earnings
    total_earned_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_(["accepted", "confirmed", "completed"])
        )
        .scalar() or 0
    )
    total_earned = total_earned_cents / 100.0
    
    pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    pending = pending_cents / 100.0
    
    earnings_data = {
        'total_earned': total_earned,
        'pending': pending,
        'this_month': earnings_this_month
    }
    
    # Transactions
    transactions_list = []
    for booking in confirmed_bookings[:20]:
        transactions_list.append({
            'event_name': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.event_datetime,
            'status': booking.status
        })
    
    # 8. Reviews (placeholder)
    reviews_list = []
    
    return render_template(
        "dash_host.html",
        role_label=get_role_display(current_user.role),
        host=host_info,
        stats=stats,
        requests=requests_list,
        bookings=bookings_list,
        briefs=briefs_list,
        media=media_list,
        availability=availability,
        earnings=earnings_data,
        transactions=transactions_list,
        reviews=reviews_list,
        BookingStatus=BookingStatus,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/hair", endpoint="hair_dashboard")
@role_required("hair_stylist_barber")
def hair_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # Stylist profile info
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    stylist_info = {
        'id': current_user.id,
        'display_name': prof.display_name if prof else current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url,
        'specialties': prof.service_types if prof else None,
        'location': f"{prof.city or ''}, {prof.state or ''}".strip() if (prof and (prof.city or prof.state)) else None,
        'travel_on_site': None,  # TODO: Add to profile
        'chair_booth_info': None,  # TODO: Add to profile
    }
    
    # 1. Dashboard Overview Stats
    # New requests (pending booking requests)
    new_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .count()
    )
    
    # Upcoming appointments (confirmed bookings in future)
    upcoming_appointments = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]),
            Booking.event_datetime >= now
        )
        .count()
    )
    
    # Repeat clients (simplified count)
    all_client_ids = [
        booking.client_id for booking in 
        Booking.query.filter_by(provider_id=current_user.id, status="completed").all()
    ]
    client_booking_counts = {}
    for client_id in all_client_ids:
        client_booking_counts[client_id] = client_booking_counts.get(client_id, 0) + 1
    repeat_clients = sum(1 for count in client_booking_counts.values() if count > 1)
    
    # Earnings this month
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.created_at >= start_of_month
        )
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Average rating (placeholder)
    avg_rating = None
    
    stats = {
        'new_requests': new_requests,
        'upcoming_appointments': upcoming_appointments,
        'repeat_clients': repeat_clients,
        'earnings_this_month': earnings_this_month,
        'avg_rating': avg_rating
    }
    
    # 2. Requests
    requests_list = []
    all_booking_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_booking_requests[:20]:
        client = req.client
        # Extract service type from message
        service = "Haircut"  # Default
        if req.message:
            msg_lower = req.message.lower()
            if any(word in msg_lower for word in ["braid", "braiding"]):
                service = "Braids"
            elif any(word in msg_lower for word in ["locs", "dread", "dreadlock"]):
                service = "Locs"
            elif any(word in msg_lower for word in ["color", "dye", "coloring"]):
                service = "Color"
            elif any(word in msg_lower for word in ["style", "styling"]):
                service = "Styling"
            elif any(word in msg_lower for word in ["beard", "trim"]):
                service = "Beard Trim"
        
        requests_list.append({
            'id': req.id,
            'service': service,
            'date_time': req.preferred_time,
            'location': None,
            'budget': None,
            'status': req.status.value if req.status else 'pending'
        })
    
    # 3. Appointments (Confirmed bookings)
    appointments_list = []
    confirmed_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .order_by(Booking.event_datetime.asc())
        .limit(50)
        .all()
    )
    
    for booking in confirmed_bookings[:20]:
        appointments_list.append({
            'id': booking.id,
            'client_name': booking.client.display_name if booking.client else f"User #{booking.client_id}",
            'service': booking.event_title,
            'date_time': booking.event_datetime,
            'duration': f"{booking.duration_minutes} minutes" if booking.duration_minutes else "TBA",
            'notes': booking.notes_from_client or "None",
            'payment_status': 'paid' if booking.total_cents and booking.status == BOOKING_STATUS_COMPLETED else 'pending',
            'location': booking.location_text or "TBA"
        })
    
    # 4. Services & Pricing (placeholder - no services model yet)
    services_list = [
        {'name': 'Haircut', 'duration': '30 min', 'base_price': 50.00, 'add_ons': ['Beard trim (+$10)', 'Wash (+$5)']},
        {'name': 'Braids', 'duration': '2-3 hours', 'base_price': 150.00, 'add_ons': ['Design (+$20)']},
        {'name': 'Color', 'duration': '2 hours', 'base_price': 120.00, 'add_ons': ['Highlight (+$30)']},
        {'name': 'Styling', 'duration': '45 min', 'base_price': 60.00, 'add_ons': []},
        {'name': 'Locs', 'duration': '3-4 hours', 'base_price': 200.00, 'add_ons': ['Maintenance (+$40)']},
    ]
    
    # 5. Portfolio (Portfolio items)
    portfolio_list = []
    if prof:
        portfolio_items = (
            PortfolioItem.query
            .filter_by(profile_id=prof.id)
            .order_by(PortfolioItem.created_at.desc())
            .limit(50)
            .all()
        )
        
        for item in portfolio_items:
            portfolio_list.append({
                'id': item.id,
                'title': item.title,
                'url': item.media_url if hasattr(item, 'media_url') else None,
                'category': "Before/After",  # Placeholder
                'is_featured': False,  # Placeholder
                'is_visible': True  # Placeholder
            })
    
    # 6. Availability (placeholder)
    availability = {
        'blocks': [],
        'capacity_per_day': 8  # Placeholder
    }
    
    # 7. Earnings
    total_earned_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_(["accepted", "confirmed", "completed"])
        )
        .scalar() or 0
    )
    total_earned = total_earned_cents / 100.0
    
    pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    pending = pending_cents / 100.0
    
    earnings_data = {
        'total_earned': total_earned,
        'pending': pending,
        'this_month': earnings_this_month
    }
    
    # Transactions
    transactions_list = []
    for booking in confirmed_bookings[:20]:
        transactions_list.append({
            'service': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.event_datetime,
            'status': booking.status
        })
    
    # 8. Reviews (placeholder)
    reviews_list = []
    
    return render_template(
        "dash_hair.html",
        role_label=get_role_display(current_user.role),
        stylist=stylist_info,
        stats=stats,
        requests=requests_list,
        appointments=appointments_list,
        services=services_list,
        portfolio=portfolio_list,
        availability=availability,
        earnings=earnings_data,
        transactions=transactions_list,
        reviews=reviews_list,
        BookingStatus=BookingStatus,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/wardrobe", endpoint="wardrobe_dashboard")
@role_required("wardrobe_stylist")
def wardrobe_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # Stylist profile info
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    stylist_info = {
        'id': current_user.id,
        'display_name': prof.display_name if prof else current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url,
        'specialties': prof.service_types if prof else None,
        'genres': None,  # TODO: Add to profile
        'sizes_served': None,  # TODO: Add to profile
        'travel': f"{prof.city or ''}, {prof.state or ''}".strip() if (prof and (prof.city or prof.state)) else None,
        'packages': prof.rate_notes if prof else None,
    }
    
    # 1. Dashboard Overview Stats
    new_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .count()
    )
    
    active_projects = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .count()
    )
    
    upcoming_fittings = 0  # Fittings not implemented yet
    pending_approvals = 0  # Approval system not implemented yet
    
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.created_at >= start_of_month
        )
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    stats = {
        'new_requests': new_requests,
        'active_projects': active_projects,
        'upcoming_fittings': upcoming_fittings,
        'pending_approvals': pending_approvals,
        'earnings_this_month': earnings_this_month
    }
    
    # 2. Requests
    requests_list = []
    all_booking_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_booking_requests[:20]:
        client = req.client
        project_type = "Photoshoot"
        if req.message:
            msg_lower = req.message.lower()
            if any(word in msg_lower for word in ["video", "music video"]):
                project_type = "Video"
            elif any(word in msg_lower for word in ["tour", "concert"]):
                project_type = "Tour"
            elif any(word in msg_lower for word in ["red carpet", "event", "awards"]):
                project_type = "Red Carpet"
            elif any(word in msg_lower for word in ["brand", "commercial"]):
                project_type = "Brand Styling"
            elif any(word in msg_lower for word in ["photo", "shoot"]):
                project_type = "Photoshoot"
        
        requests_list.append({
            'id': req.id,
            'client_name': client.display_name if client else f"User #{req.client_id}",
            'project_type': project_type,
            'date_range': req.preferred_time,
            'location': None,
            'budget': None,
            'status': req.status.value if req.status else 'pending'
        })
    
    # 3. Projects
    projects_list = []
    confirmed_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .order_by(Booking.event_datetime.asc())
        .limit(50)
        .all()
    )
    
    for booking in confirmed_bookings[:20]:
        projects_list.append({
            'id': booking.id,
            'client_name': booking.client.display_name if booking.client else f"User #{booking.client_id}",
            'project_title': booking.event_title,
            'timeline': booking.event_datetime.strftime("%b %d - %b %d, %Y") if booking.event_datetime else "TBA",
            'status': booking.status,
            'deliverables': "Looks: TBD",
            'payment_status': 'paid' if booking.total_cents and booking.status == BOOKING_STATUS_COMPLETED else 'pending'
        })
    
    # 4. Lookboards (placeholder)
    lookboards_list = []
    
    # 5. Fittings (placeholder)
    fittings_list = []
    
    # 6. Closet & Pull List (placeholder)
    pull_list_items = []
    
    # 7. Availability
    availability = {
        'blocks': [],
        'accept_new_requests': True
    }
    
    # 8. Earnings
    total_earned_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_(["accepted", "confirmed", "completed"])
        )
        .scalar() or 0
    )
    total_earned = total_earned_cents / 100.0
    
    pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    pending = pending_cents / 100.0
    
    earnings_data = {
        'total_earned': total_earned,
        'pending': pending,
        'this_month': earnings_this_month
    }
    
    # Transactions
    transactions_list = []
    for booking in confirmed_bookings[:20]:
        transactions_list.append({
            'project': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.event_datetime,
            'status': booking.status
        })
    
    # 9. Reviews (placeholder)
    reviews_list = []
    
    return render_template(
        "dash_wardrobe.html",
        role_label=get_role_display(current_user.role),
        stylist=stylist_info,
        stats=stats,
        requests=requests_list,
        projects=projects_list,
        lookboards=lookboards_list,
        fittings=fittings_list,
        pull_list_items=pull_list_items,
        availability=availability,
        earnings=earnings_data,
        transactions=transactions_list,
        reviews=reviews_list,
        BookingStatus=BookingStatus,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/makeup", endpoint="makeup_dashboard")
@role_required("makeup_artist")
def makeup_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    
    # Makeup artist profile info
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    
    makeup_artist_info = {
        'id': current_user.id,
        'display_name': prof.display_name if prof else current_user.display_name or current_user.username,
        'avatar_url': current_user.avatar_url,
        'specialties': prof.service_types if prof else None,
        'skin_tones_styles': None,  # TODO: Add to profile
        'travel_on_site': f"{prof.city or ''}, {prof.state or ''}".strip() if (prof and (prof.city or prof.state)) else None,
        'packages': prof.rate_notes if prof else None,
    }
    
    # 1. Dashboard Overview Stats
    # New requests (pending booking requests)
    new_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id, status=BookingStatus.pending)
        .count()
    )
    
    # Upcoming appointments (confirmed bookings in future)
    upcoming_appointments = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED]),
            Booking.event_datetime >= now
        )
        .count()
    )
    
    # Active clients (clients with active bookings)
    active_clients = (
        db.session.query(func.count(func.distinct(Booking.client_id)))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    
    # Earnings this month
    earnings_this_month_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]),
            Booking.created_at >= start_of_month
        )
        .scalar() or 0
    )
    earnings_this_month = earnings_this_month_cents / 100.0
    
    # Average rating (placeholder)
    avg_rating = None
    
    stats = {
        'new_requests': new_requests,
        'upcoming_appointments': upcoming_appointments,
        'active_clients': active_clients,
        'earnings_this_month': earnings_this_month,
        'avg_rating': avg_rating
    }
    
    # 2. Requests
    requests_list = []
    all_booking_requests = (
        BookingRequest.query
        .filter_by(provider_id=current_user.id)
        .order_by(BookingRequest.created_at.desc())
        .limit(50)
        .all()
    )
    
    for req in all_booking_requests[:20]:
        client = req.client
        # Extract service type from message
        service_type = "Glam"  # Default
        if req.message:
            msg_lower = req.message.lower()
            if any(word in msg_lower for word in ["bridal", "wedding", "bride"]):
                service_type = "Bridal"
            elif any(word in msg_lower for word in ["editorial", "fashion", "magazine"]):
                service_type = "Editorial"
            elif any(word in msg_lower for word in ["film", "movie", "tv", "production"]):
                service_type = "Film"
            elif any(word in msg_lower for word in ["event", "party", "gala"]):
                service_type = "Event"
            elif any(word in msg_lower for word in ["sfx", "special effects", "prosthetic"]):
                service_type = "SFX"
            elif any(word in msg_lower for word in ["glam", "glamour"]):
                service_type = "Glam"
        
        requests_list.append({
            'id': req.id,
            'client_name': client.display_name if client else f"User #{req.client_id}",
            'service_type': service_type,
            'date_time': req.preferred_time,
            'location': None,
            'party_size': None,  # Not in BookingRequest model
            'budget': None,
            'status': req.status.value if req.status else 'pending'
        })
    
    # 3. Appointments (Confirmed bookings)
    appointments_list = []
    confirmed_bookings = (
        Booking.query
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .order_by(Booking.event_datetime.asc())
        .limit(50)
        .all()
    )
    
    for booking in confirmed_bookings[:20]:
        appointments_list.append({
            'id': booking.id,
            'client_name': booking.client.display_name if booking.client else f"User #{booking.client_id}",
            'service': booking.event_title,
            'date_time': booking.event_datetime,
            'time_block': f"{booking.duration_minutes} minutes" if booking.duration_minutes else "TBA",
            'prep_notes': booking.notes_from_client or "None",
            'payment_status': 'paid' if booking.total_cents and booking.status == BOOKING_STATUS_COMPLETED else 'pending',
            'location': booking.location_text or "TBA"
        })
    
    # 4. Looks & Portfolio (Portfolio items)
    portfolio_items = []
    if prof:
        portfolio_list = (
            PortfolioItem.query
            .filter_by(profile_id=prof.id)
            .order_by(PortfolioItem.created_at.desc())
            .limit(50)
            .all()
        )
        
        for item in portfolio_list:
            portfolio_items.append({
                'id': item.id,
                'title': item.title,
                'url': item.media_url if hasattr(item, 'media_url') else None,
                'category': "Look",  # Placeholder
                'is_featured': False,  # Placeholder
                'is_visible': True  # Placeholder
            })
    
    # 5. Kit & Supplies (placeholder)
    kit_items = [
        {'name': 'Foundation Set', 'status': 'in_stock', 'low_stock': False, 'restock_notes': ''},
        {'name': 'Eyeshadow Palette', 'status': 'in_stock', 'low_stock': True, 'restock_notes': 'Running low on neutral shades'},
        {'name': 'Lipstick Collection', 'status': 'in_stock', 'low_stock': False, 'restock_notes': ''},
        {'name': 'Brushes Set', 'status': 'in_stock', 'low_stock': False, 'restock_notes': ''},
        {'name': 'Setting Spray', 'status': 'low_stock', 'low_stock': True, 'restock_notes': 'Order more before next event'},
    ]
    
    # 6. Availability (placeholder)
    availability = {
        'blocks': [],
        'accept_new_requests': True
    }
    
    # 7. Earnings
    total_earned_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_(["accepted", "confirmed", "completed"])
        )
        .scalar() or 0
    )
    total_earned = total_earned_cents / 100.0
    
    pending_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(
            Booking.provider_id == current_user.id,
            Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED])
        )
        .scalar() or 0
    )
    pending = pending_cents / 100.0
    
    earnings_data = {
        'total_earned': total_earned,
        'pending': pending,
        'this_month': earnings_this_month
    }
    
    # Transactions
    transactions_list = []
    for booking in confirmed_bookings[:20]:
        transactions_list.append({
            'service': booking.event_title,
            'amount': booking.total_cents / 100.0 if booking.total_cents else 0.0,
            'date': booking.event_datetime,
            'status': booking.status
        })
    
    # 8. Reviews (placeholder)
    reviews_list = []
    
    return render_template(
        "dash_makeup.html",
        role_label=get_role_display(current_user.role),
        makeup_artist=makeup_artist_info,
        stats=stats,
        requests=requests_list,
        appointments=appointments_list,
        portfolio_items=portfolio_items,
        kit_items=kit_items,
        availability=availability,
        earnings=earnings_data,
        transactions=transactions_list,
        reviews=reviews_list,
        BookingStatus=BookingStatus,
        get_role_display=get_role_display,
    )


@app.route("/dashboard/vendor", endpoint="vendor_dashboard")
@role_required("vendor")
def vendor_dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func, and_, or_
    
    # Vendor profile
    prof = BookMeProfile.query.filter_by(user_id=current_user.id).first()
    artist_can_take_gigs = prof is not None
    
    # Social counts
    followers_count = UserFollow.query.filter_by(followed_id=current_user.id).count()
    following_count = UserFollow.query.filter_by(follower_id=current_user.id).count()
    
    # Overview stats
    # Orders (bookings as provider)
    total_orders = Booking.query.filter_by(provider_id=current_user.id).count()
    pending_orders = Booking.query.filter_by(
        provider_id=current_user.id, status=BOOKING_STATUS_PENDING
    ).count()
    active_orders = Booking.query.filter(
        Booking.provider_id == current_user.id,
        Booking.status.in_(["accepted", "confirmed"])
    ).count()
    completed_orders = Booking.query.filter_by(
        provider_id=current_user.id, status="completed"
    ).count()
    
    # Listings (BookMe profile + portfolio items count as listings)
    listings_count = 0
    if prof:
        listings_count = prof.portfolio_items.count() or (1 if prof.is_visible else 0)
    else:
        listings_count = 0
    
    # Earnings
    now = datetime.utcnow()
    start_of_month = datetime(now.year, now.month, 1)
    monthly_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .filter(Booking.created_at >= start_of_month)
        .scalar() or 0
    )
    monthly_earnings = monthly_earnings_cents / 100.0
    
    total_earnings_cents = (
        db.session.query(func.coalesce(func.sum(Booking.total_cents), 0))
        .filter(Booking.provider_id == current_user.id)
        .filter(Booking.status.in_([BOOKING_STATUS_ACCEPTED, BOOKING_STATUS_CONFIRMED, BOOKING_STATUS_COMPLETED]))
        .scalar() or 0
    )
    total_earnings = total_earnings_cents / 100.0
    
    # Product/service listings (portfolio items)
    listings = []
    if prof:
        listings = (
            prof.portfolio_items
            .order_by(PortfolioItem.sort_order.asc(), PortfolioItem.created_at.desc())
            .limit(50)
            .all()
        )
    
    # Orders & fulfillment status
    recent_orders = (
        Booking.query
        .filter_by(provider_id=current_user.id)
        .order_by(Booking.created_at.desc())
        .limit(20)
        .all()
    )
    
    # Inventory management (placeholder - using portfolio items as inventory)
    inventory_items = listings[:20] if listings else []
    
    # Wallet and transactions
    wallet = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(wallet) / 100.0
    
    recent_transactions = (
        LedgerEntry.query
        .filter_by(wallet_id=wallet.id)
        .order_by(LedgerEntry.created_at.desc())
        .limit(10)
        .all()
    )
    
    # Reviews (placeholder - no review system yet)
    reviews = []
    average_rating = None
    rating_count = 0
    
    # Specialties (from service_types)
    specialties = []
    if prof and prof.service_types:
        specialties = [s.strip() for s in prof.service_types.split(",") if s.strip()]
    
    return render_template(
        "dash_vendor.html",
        role_label=get_role_display(current_user.role),
        prof=prof,
        artist_can_take_gigs=artist_can_take_gigs,
        followers_count=followers_count,
        following_count=following_count,
        total_orders=total_orders,
        pending_orders=pending_orders,
        active_orders=active_orders,
        completed_orders=completed_orders,
        listings_count=listings_count,
        monthly_earnings=monthly_earnings,
        total_earnings=total_earnings,
        listings=listings,
        recent_orders=recent_orders,
        inventory_items=inventory_items,
        wallet_balance=wallet_balance,
        recent_transactions=recent_transactions,
        reviews=reviews,
        average_rating=average_rating,
        rating_count=rating_count,
        specialties=specialties,
        BookingStatus=BookingStatus,
        EntryType=EntryType,
        PortfolioMediaType=PortfolioMediaType,
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
            return redirect(url_for("opportunities_interest"))

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
        f"role={current_user.role}, "
        f"kyc={current_user.kyc_status}, "
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
    sort = (request.args.get("sort") or "").strip().lower()
    order = (request.args.get("order") or "").strip().lower()
    group_by_role = (request.args.get("group") or "1").strip().lower() not in ("0", "false", "off", "no")

    query = User.query.filter(User.role != RoleEnum.admin.value)

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
            query = query.filter(User.role == RoleEnum(role).value)
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

    # Sorting
    sort_map = {
        "id": User.id,
        "username": func.lower(User.username),
        "role": User.role,
        "kyc": User.kyc_status,
        "status": User.is_active_col,
    }
    sort_expr = sort_map.get(sort or "role", User.role)
    if order in ("desc", "za"):
        sort_expr = sort_expr.desc()
    else:
        sort_expr = sort_expr.asc()

    if group_by_role:
        role_order = User.role.desc() if order in ("desc", "za") and (sort or "role") == "role" else User.role.asc()
        query = query.order_by(role_order, sort_expr, User.id.asc())
    else:
        query = query.order_by(sort_expr, User.id.asc())

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
        sort=sort or "role",
        order=order or "asc",
        group_by_role=group_by_role,
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
    before = str(getattr(user, "kyc_status", None))
    
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

    try:
        after = str(getattr(user, "kyc_status", None))
        log_admin_action(
            ActivityEventType.admin_user_role_changed,
            actor_admin_id=current_user.id,
            target_type="user",
            target_id=user.id,
            summary=f"KYC updated for @{user.username}: {after}",
            payload_dict={"before": {"kyc_status": before}, "after": {"kyc_status": after}, "action": action},
            url=url_for("admin_kyc"),
            include_actor=True,
        )
    except Exception:
        pass
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


@app.route("/dashboard/admin/refunds", methods=["GET", "POST"], endpoint="admin_refunds")
@role_required("admin")
def admin_refunds():
    """Admin refund tool for booking payments."""
    ok, err_msg = _stripe_env_guard()
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("admin_transactions"))

    if request.method == "POST":
        payment_id_raw = (request.form.get("payment_id") or "").strip()
        refund_base_raw = (request.form.get("refund_base_cents") or "").strip()
        provider_fault = (request.form.get("provider_fault") or "").strip().lower() in {"1", "true", "yes", "on"}
        reason = (request.form.get("reason") or "").strip()

        try:
            payment_id = int(payment_id_raw)
        except Exception:
            flash("Invalid payment ID.", "error")
            return redirect(url_for("admin_refunds"))

        try:
            refund_base_cents = int(refund_base_raw)
        except Exception:
            flash("Refund base cents must be a number.", "error")
            return redirect(url_for("admin_refunds"))

        payment = Payment.query.get(payment_id)
        if not payment:
            flash("Payment not found.", "error")
            return redirect(url_for("admin_refunds"))

        remaining_base = int(payment.base_amount_cents or 0) - int(payment.refunded_base_cents or 0)
        if refund_base_cents <= 0 or refund_base_cents > remaining_base:
            flash("Refund amount exceeds remaining refundable base.", "error")
            return redirect(url_for("admin_refunds"))

        refundable_bf = 0
        already_refunded_bf = int(payment.beatfund_fee_cents or 0) - int(payment.nonrefundable_beatfund_kept_cents or 0)
        if provider_fault and ALLOW_REFUND_BF_FEE_ON_PROVIDER_FAULT and already_refunded_bf <= 0:
            refundable_bf = int(payment.beatfund_fee_cents or 0)

        refundable_cents = refund_base_cents + refundable_bf
        if refundable_cents <= 0:
            flash("No refundable amount available for this payment.", "error")
            return redirect(url_for("admin_refunds"))

        try:
            refund_kwargs = {"amount": refundable_cents, "reason": "requested_by_customer"}
            if payment.stripe_payment_intent_id:
                refund_kwargs["payment_intent"] = payment.stripe_payment_intent_id
            elif payment.stripe_charge_id:
                refund_kwargs["charge"] = payment.stripe_charge_id
            else:
                flash("Stripe payment reference missing on this payment.", "error")
                return redirect(url_for("admin_refunds"))

            try:
                stripe.Refund.create(**refund_kwargs)
            except stripe.error.StripeError as e:
                _log_stripe_error(
                    "admin_refund",
                    e,
                    user_id=current_user.id,
                    payment_id=payment.id,
                    amount_cents=refundable_cents,
                    currency="usd",
                )
                flash("Stripe error issuing refund. Please try again.", "error")
                return redirect(url_for("admin_refunds"))

            payment.refunded_base_cents = int(payment.refunded_base_cents or 0) + refund_base_cents
            payment.nonrefundable_processing_kept_cents = int(payment.processing_fee_cents or 0)
            payment.nonrefundable_beatfund_kept_cents = int(payment.beatfund_fee_cents or 0) - refundable_bf

            if payment.refunded_base_cents >= int(payment.base_amount_cents or 0):
                payment.status = PaymentStatus.refunded
            else:
                payment.status = PaymentStatus.partially_refunded

            booking = Booking.query.get(payment.booking_id) if payment.booking_id else None
            if booking and refundable_bf > 0:
                booking.beatfund_fee_collected_cents = max(0, int(booking.beatfund_fee_collected_cents or 0) - refundable_bf)

            db.session.commit()
            try:
                log_admin_action(
                    ActivityEventType.admin_refund_issued,
                    actor_admin_id=current_user.id,
                    target_type="payment",
                    target_id=payment.id,
                    summary=f"Refund issued for payment #{payment.id} (${refundable_cents/100.0:.2f})",
                    payload_dict={
                        "payment_id": payment.id,
                        "booking_id": payment.booking_id,
                        "refund_cents": refundable_cents,
                        "refund_base_cents": refund_base_cents,
                        "provider_fault": provider_fault,
                    },
                    url=url_for("admin_refunds"),
                    include_actor=True,
                )
            except Exception:
                pass
            flash("Refund processed successfully.", "success")
            return redirect(url_for("admin_refunds"))
        except Exception as e:
            db.session.rollback()
            _log_stripe_error(
                "admin_refund",
                e,
                user_id=current_user.id,
                payment_id=payment.id,
                amount_cents=refundable_cents,
                currency="usd",
            )
            flash("Refund failed. Please try again.", "error")
            return redirect(url_for("admin_refunds"))

    payments = (
        Payment.query
        .filter(Payment.processor == PaymentProcessor.stripe)
        .order_by(Payment.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template("admin_refunds.html", payments=payments)


@app.route("/dashboard/admin/audit-access/<int:user_id>", methods=["GET", "POST"], endpoint="admin_audit_access")
@role_required("admin")
def admin_audit_access(user_id: int):
    """Admin audit access form - requires reason before viewing user wallet"""
    customer = User.query.get_or_404(user_id)
    
    # Don't allow admins to audit other admins
    if customer.role == RoleEnum.admin:
        flash("Cannot audit admin accounts.", "error")
        return redirect(url_for("admin_transactions"))
    
    if request.method == "POST":
        reason = (request.form.get("reason") or "").strip()
        if not reason:
            flash("Reason is required for audit access.", "error")
            return render_template("admin_audit_access.html", customer=customer)
        
        # Create audit log entry
        audit_log = AuditLog(
            admin_id=current_user.id,
            user_id=customer.id,
            action="wallet_access",
            reason=reason
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash(f"Audit log created. Viewing wallet for @{customer.username}.", "success")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))
    
    return render_template("admin_audit_access.html", customer=customer)


@app.route("/dashboard/admin/transactions/user/<int:user_id>", endpoint="admin_transactions_user")
@role_required("admin")
def admin_transactions_user(user_id: int):
    """Admin view of a specific user's wallet transactions"""
    customer = User.query.get_or_404(user_id)
    
    # Don't allow admins to view other admins' wallets
    if customer.role == RoleEnum.admin:
        flash("Cannot view admin wallet accounts.", "error")
        return redirect(url_for("admin_transactions"))
    
    # Get or create wallet
    wallet = get_or_create_wallet(customer.id)
    
    # Get all ledger entries for this wallet
    ledger = (
        LedgerEntry.query
        .filter_by(wallet_id=wallet.id)
        .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
        .all()
    )
    
    return render_template(
        "admin_transactions_user.html",
        customer=customer,
        ledger=ledger,
        EntryType=EntryType,
    )


@app.route("/dashboard/admin/transactions/user/<int:user_id>/adjust", methods=["POST"], endpoint="admin_wallet_adjust")
@role_required("admin")
def admin_wallet_adjust(user_id: int):
    """Admin-only manual wallet adjustment (requires reason + audit log)."""
    customer = User.query.get_or_404(user_id)

    # Don't allow admins to adjust admin wallets
    if customer.role == RoleEnum.admin:
        flash("Cannot adjust admin wallet accounts.", "error")
        return redirect(url_for("admin_transactions"))

    direction = (request.form.get("direction") or "").strip().lower()
    amount_raw = (request.form.get("amount_dollars") or "").strip()
    reason = (request.form.get("reason") or "").strip()
    note = (request.form.get("note") or "").strip()

    if not reason:
        flash("Reason is required for wallet adjustments.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    if direction not in ("credit", "debit"):
        flash("Invalid direction.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    try:
        amt = Decimal(amount_raw)
    except Exception:
        flash("Amount must be a valid number.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    if amt <= 0:
        flash("Amount must be greater than 0.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    if amt > Decimal(str(MAX_TXN_DOLLARS)):
        flash(f"Amount too large. Max is ${MAX_TXN_DOLLARS:,}.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    cents = int((amt * 100).to_integral_value())
    if cents <= 0:
        flash("Amount too small.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    w = get_or_create_wallet(customer.id, commit=False, lock=True)
    before_balance = wallet_balance_cents(w)
    after_balance = before_balance + (cents if direction == "credit" else -cents)

    if after_balance < 0:
        flash("This adjustment would make the wallet balance negative.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    meta = f"admin adjustment ({direction}) by @{current_user.username}: {note}".strip()
    meta = meta[:255]

    try:
        with db_txn():
            if direction == "credit":
                post_ledger(w, EntryType.adjustment, cents, meta=meta)
                delta_cents = cents
                ledger_entry_type = EntryType.adjustment.value
            else:
                # Use a debit-type entry for balance correctness (post_ledger requires positive cents)
                post_ledger(w, EntryType.transfer_out, cents, meta=meta)
                delta_cents = -cents
                ledger_entry_type = EntryType.transfer_out.value
            audit_log_event(
                action_type="WALLET_ADJUSTMENT",
                actor_user=current_user,
                target_type="Wallet",
                target_id=str(w.id),
                reason=reason,
                before={"wallet_id": w.id, "user_id": customer.id, "balance_cents": before_balance},
                after={"wallet_id": w.id, "user_id": customer.id, "balance_cents": after_balance},
                metadata={
                    "direction": direction,
                    "amount_cents": cents,
                    "delta_cents": delta_cents,
                    "ledger_entry_type": ledger_entry_type,
                    "note": note or None,
                    "customer_username": customer.username,
                },
                commit=False,
            )
    except Exception:
        flash("Failed to apply adjustment.", "error")
        return redirect(url_for("admin_transactions_user", user_id=customer.id))

    try:
        log_admin_action(
            ActivityEventType.admin_wallet_adjusted,
            actor_admin_id=current_user.id,
            target_type="wallet",
            target_id=w.id,
            summary=f"Wallet adjusted for @{customer.username}: {direction} ${cents/100.0:.2f}",
            payload_dict={"user_id": customer.id, "wallet_id": w.id, "direction": direction, "amount_cents": cents, "reason": reason},
            url=url_for("admin_transactions_user", user_id=customer.id),
            include_actor=True,
        )
    except Exception:
        pass

    flash("Wallet adjustment applied.", "success")
    return redirect(url_for("admin_transactions_user", user_id=customer.id))


@app.route("/dashboard/admin/transactions/user/<int:user_id>/export", endpoint="admin_export_wallet_csv")
@role_required("admin")
def admin_export_wallet_csv(user_id: int):
    """Admin export of a user's wallet transactions as CSV"""
    customer = User.query.get_or_404(user_id)
    
    # Don't allow admins to export other admins' wallets
    if customer.role == RoleEnum.admin:
        flash("Cannot export admin wallet accounts.", "error")
        return redirect(url_for("admin_transactions"))
    
    # Get or create wallet
    wallet = get_or_create_wallet(customer.id)
    
    # Get all ledger entries for this wallet
    entries = (
        LedgerEntry.query
        .filter_by(wallet_id=wallet.id)
        .order_by(LedgerEntry.created_at.asc())
        .all()
    )
    
    # Generate CSV
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
    filename = f"beatfund_wallet_{customer.username}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


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


@app.route("/dashboard/admin/tickets/<int:ticket_id>", methods=["GET", "POST"], endpoint="admin_ticket_detail")
@role_required("admin")
def admin_ticket_detail(ticket_id: int):
    """Admin view and update of a support ticket"""
    ticket = SupportTicket.query.get_or_404(ticket_id)
    
    if request.method == "POST":
        before = {"status": str(ticket.status), "priority": str(ticket.priority)}

        # Update ticket status
        new_status = request.form.get("status", "").strip()
        if new_status:
            try:
                ticket.status = TicketStatus(new_status)
            except ValueError:
                flash("Invalid status value.", "error")
        
        # Update priority
        new_priority = request.form.get("priority", "").strip()
        if new_priority in ["low", "normal", "high"]:
            ticket.priority = new_priority
        
        # Add reply to user (public)
        reply_body = sanitize_input((request.form.get("reply_body") or "").strip(), max_length=4000)
        if reply_body:
            msg = SupportTicketMessage(
                ticket_id=ticket.id,
                author_user_id=current_user.id,
                body=reply_body,
            )
            db.session.add(msg)

        # Add internal comment if provided
        comment_body = sanitize_input((request.form.get("comment_body") or "").strip(), max_length=2000)
        if comment_body:
            comment = SupportTicketComment(
                ticket_id=ticket.id,
                admin_id=current_user.id,
                body=comment_body
            )
            db.session.add(comment)
        
        db.session.commit()

        try:
            after = {"status": str(ticket.status), "priority": str(ticket.priority)}
            log_admin_action(
                ActivityEventType.admin_ticket_updated,
                actor_admin_id=current_user.id,
                target_type="ticket",
                target_id=ticket.id,
                summary=f"Updated ticket #{ticket.id}: {ticket.subject}",
                payload_dict={"before": before, "after": after, "comment_added": bool(comment_body), "reply_added": bool(reply_body)},
                url=url_for("admin_ticket_detail", ticket_id=ticket.id),
                include_actor=True,
            )
        except Exception:
            pass

        flash("Ticket updated successfully.", "success")
        return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))
    
    # Get thread + internal notes
    thread = _support_thread(ticket)
    comments = ticket.comments.order_by(SupportTicketComment.created_at.asc()).all()
    
    return render_template(
        "admin_ticket_detail.html",
        ticket=ticket,
        thread=thread,
        comments=comments,
        TicketStatus=TicketStatus,
        TicketType=TicketType,
    )


@app.route("/admin/tickets/<int:ticket_id>/reply", methods=["POST"], endpoint="admin_ticket_reply")
@role_required("admin")
def admin_ticket_reply(ticket_id: int):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    body = sanitize_input((request.form.get("body") or "").strip(), max_length=4000)
    if not body:
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))
    msg = SupportTicketMessage(
        ticket_id=ticket.id,
        author_user_id=current_user.id,
        body=body,
    )
    db.session.add(msg)
    db.session.commit()
    flash("Reply sent.", "success")
    return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))


@app.route("/admin/tickets/<int:ticket_id>/status", methods=["POST"], endpoint="admin_ticket_status")
@role_required("admin")
def admin_ticket_status(ticket_id: int):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    new_status = (request.form.get("status") or "").strip().lower()
    if new_status:
        try:
            ticket.status = TicketStatus(new_status)
            db.session.commit()
            flash("Status updated.", "success")
        except Exception:
            db.session.rollback()
    return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))


@app.route("/dashboard/admin/audit", endpoint="admin_audit_log")
@role_required("admin")
def admin_audit_log():
    """Admin audit log view - shows all audit entries"""
    # Get all audit logs, ordered by most recent first
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    
    return render_template("admin_audit.html", logs=logs)


def _parse_date_ymd(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except Exception:
        return None


@app.route("/admin/audit", endpoint="admin_audit")
@role_required("admin")
def admin_audit():
    """Admin audit log (filterable)."""
    q_action = (request.args.get("action_type") or "").strip()
    q_actor = (request.args.get("actor") or "").strip()
    q_target_type = (request.args.get("target_type") or "").strip()
    q_target_id = (request.args.get("target_id") or "").strip()
    q_start = _parse_date_ymd(request.args.get("start"))
    q_end = _parse_date_ymd(request.args.get("end"))

    query = AuditLog.query
    if q_start:
        query = query.filter(AuditLog.created_at >= q_start)
    if q_end:
        # inclusive end-of-day
        query = query.filter(AuditLog.created_at < (q_end + timedelta(days=1)))

    if q_action:
        query = query.filter(or_(AuditLog.action_type == q_action, AuditLog.action == q_action))

    if q_target_type:
        query = query.filter(AuditLog.target_type == q_target_type)
    if q_target_id:
        query = query.filter(AuditLog.target_id == q_target_id)

    if q_actor:
        # Support actor by id or username (admin_id legacy + actor_user_id new)
        if q_actor.isdigit():
            uid = int(q_actor)
            query = query.filter(or_(AuditLog.admin_id == uid, AuditLog.actor_user_id == uid))
        else:
            query = query.join(User, User.id == AuditLog.admin_id).filter(func.lower(User.username) == q_actor.lower())

    logs = query.order_by(AuditLog.created_at.desc()).limit(500).all()

    return render_template(
        "admin_audit_v2.html",
        logs=logs,
        filters={"action_type": q_action, "actor": q_actor, "target_type": q_target_type, "target_id": q_target_id, "start": request.args.get("start") or "", "end": request.args.get("end") or ""},
    )


@app.route("/admin/audit/<int:log_id>", endpoint="admin_audit_detail")
@role_required("admin")
def admin_audit_detail(log_id: int):
    log = AuditLog.query.get_or_404(log_id)
    before = _safe_json_loads(getattr(log, "before_json", None))
    after = _safe_json_loads(getattr(log, "after_json", None))
    meta = _safe_json_loads(getattr(log, "metadata_json", None))
    return render_template("admin_audit_detail.html", log=log, before=before, after=after, meta=meta)


@app.route("/admin/audit/export.csv", endpoint="admin_audit_export_csv")
@role_required("admin")
def admin_audit_export_csv():
    """CSV export for audit events with filters."""
    q_action = (request.args.get("action_type") or "").strip()
    q_target_type = (request.args.get("target_type") or "").strip()
    q_target_id = (request.args.get("target_id") or "").strip()
    q_start = _parse_date_ymd(request.args.get("start"))
    q_end = _parse_date_ymd(request.args.get("end"))

    query = AuditLog.query
    if q_start:
        query = query.filter(AuditLog.created_at >= q_start)
    if q_end:
        query = query.filter(AuditLog.created_at < (q_end + timedelta(days=1)))
    if q_action:
        query = query.filter(or_(AuditLog.action_type == q_action, AuditLog.action == q_action))
    if q_target_type:
        query = query.filter(AuditLog.target_type == q_target_type)
    if q_target_id:
        query = query.filter(AuditLog.target_id == q_target_id)

    logs = query.order_by(AuditLog.created_at.asc()).limit(50_000).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        "created_at",
        "action_type",
        "admin_id",
        "admin_username",
        "actor_user_id",
        "target_type",
        "target_id",
        "reason",
        "ip_address",
        "user_agent",
        "metadata_json",
    ])
    for log in logs:
        admin_username = log.admin.username if getattr(log, "admin", None) else ""
        action_type = getattr(log, "action_type", None) or log.action
        writer.writerow([
            log.created_at.isoformat(sep=" ") if log.created_at else "",
            action_type or "",
            log.admin_id,
            admin_username,
            getattr(log, "actor_user_id", "") or "",
            getattr(log, "target_type", "") or "",
            getattr(log, "target_id", "") or "",
            (log.reason or "").replace("\n", " ").strip(),
            getattr(log, "ip_address", "") or "",
            getattr(log, "user_agent", "") or "",
            (getattr(log, "metadata_json", "") or "")[:5000],
        ])

    output = si.getvalue()
    filename = f"beatfund_audit_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/admin/finance/events", endpoint="admin_finance_events")
@role_required("admin")
def admin_finance_events():
    """Finance-focused audit view."""
    finance_actions = [
        "WALLET_ADJUSTMENT",
        "TRANSFER",
        "WITHDRAWAL_REQUESTED",
        "HOLD_CREATED",
        "STRIPE_WEBHOOK_APPLIED",
    ]
    logs = (
        AuditLog.query
        .filter(or_(AuditLog.action_type.in_(finance_actions), AuditLog.action.in_(finance_actions)))
        .order_by(AuditLog.created_at.desc())
        .limit(500)
        .all()
    )
    return render_template("admin_finance_events.html", logs=logs, finance_actions=finance_actions)


@app.route("/admin/stripe/webhooks", endpoint="admin_stripe_webhooks")
@role_required("admin")
def admin_stripe_webhooks():
    status = (request.args.get("status") or "").strip().upper()
    type_q = (request.args.get("type") or "").strip()
    query = StripeWebhookEvent.query
    if status in ("RECEIVED", "PROCESSING", "PROCESSED", "FAILED"):
        query = query.filter(StripeWebhookEvent.status == status)
    if type_q:
        query = query.filter(StripeWebhookEvent.type == type_q)
    rows = query.order_by(StripeWebhookEvent.received_at.desc()).limit(300).all()
    return render_template("admin_stripe_webhooks.html", rows=rows, filters={"status": status, "type": type_q})


@app.route("/admin/stripe/webhooks/<int:row_id>/retry", methods=["POST"], endpoint="admin_stripe_webhook_retry")
@role_required("admin")
def admin_stripe_webhook_retry(row_id: int):
    row = StripeWebhookEvent.query.get_or_404(row_id)
    if row.status == StripeWebhookEventStatus.processed.value:
        flash("Webhook already processed.", "info")
        return redirect(url_for("admin_stripe_webhooks"))

    ok, err_msg = _stripe_env_guard(require_webhook=True)
    if not ok:
        flash(err_msg, "error")
        return redirect(url_for("admin_stripe_webhooks"))

    try:
        event = stripe.Event.retrieve(row.stripe_event_id)
    except stripe.error.StripeError as e:
        _log_stripe_error(
            "admin_stripe_webhook_retry",
            e,
            user_id=current_user.id,
            stripe_event_id=row.stripe_event_id,
        )
        row.status = StripeWebhookEventStatus.failed.value
        row.last_error = (f"retrieve_failed: {str(e)}" or "retrieve_failed")[:500]
        db.session.commit()
        try:
            _alert_create(AlertSeverity.high, "STRIPE_WEBHOOK_RETRY_FAILED", "Admin retry failed to retrieve Stripe event", {"stripe_event_id": row.stripe_event_id})
        except Exception:
            pass
        flash("Failed to retrieve event from Stripe.", "error")
        return redirect(url_for("admin_stripe_webhooks"))
    except Exception as e:
        _log_stripe_error(
            "admin_stripe_webhook_retry",
            e,
            user_id=current_user.id,
            stripe_event_id=row.stripe_event_id,
        )
        row.status = StripeWebhookEventStatus.failed.value
        row.last_error = (f"retrieve_failed: {str(e)}" or "retrieve_failed")[:500]
        db.session.commit()
        try:
            _alert_create(AlertSeverity.high, "STRIPE_WEBHOOK_RETRY_FAILED", "Admin retry failed to retrieve Stripe event", {"stripe_event_id": row.stripe_event_id})
        except Exception:
            pass
        flash("Failed to retrieve event from Stripe.", "error")
        return redirect(url_for("admin_stripe_webhooks"))

    # Best-effort: re-run processing by applying the same logic used by the webhook handler.
    try:
        # Reset status to allow processing
        row.status = StripeWebhookEventStatus.received.value
        row.last_error = None
        db.session.commit()

        # Create a minimal "event-like" dict compatible with our handler logic
        ev = event.to_dict_recursive() if hasattr(event, "to_dict_recursive") else dict(event)
        ev_type = ev.get("type")
        ev_id = ev.get("id")
        if ev_id and ev_id != row.stripe_event_id:
            row.last_error = "stripe_event_id_mismatch"
            row.status = StripeWebhookEventStatus.failed.value
            db.session.commit()
            flash("Stripe event id mismatch.", "error")
            return redirect(url_for("admin_stripe_webhooks"))

        if ev_type != "checkout.session.completed":
            row.status = StripeWebhookEventStatus.processed.value
            row.processed_at = datetime.utcnow()
            db.session.commit()
            flash("Event type does not require fulfillment; marked processed.", "success")
            return redirect(url_for("admin_stripe_webhooks"))

        session_obj = (((ev.get("data") or {}).get("object")) or {})
        session_id = session_obj.get("id")
        metadata = session_obj.get("metadata") or {}
        purpose = metadata.get("type") or metadata.get("purpose")
        if purpose == "wallet_topup":
            user_id = int(metadata.get("user_id") or 0)
            amount_total = int(session_obj.get("amount_total") or 0)
            if user_id and amount_total > 0:
                _finalize_wallet_topup(user_id=user_id, amount_cents=amount_total, session_id=session_id, source="admin_retry")
            row.status = StripeWebhookEventStatus.processed.value
            row.processed_at = datetime.utcnow()
            db.session.commit()
            audit_log_event(
                action_type="STRIPE_WEBHOOK_APPLIED",
                actor_user=current_user,
                target_type="StripeWebhookEvent",
                target_id=str(row.id),
                reason="Admin retried Stripe webhook event",
                metadata={"stripe_event_id": row.stripe_event_id, "session_id": session_id, "purpose": purpose},
            )
            flash("Retry processed (wallet_topup).", "success")
            return redirect(url_for("admin_stripe_webhooks"))

        # beat_purchase (order will enforce idempotency)
        if purpose == "beat_purchase":
            # Let the existing idempotent logic run by marking row as failed if anything throws
            # We reuse the same code path by calling into the webhook handler's beat_purchase logic:
            # easiest is to simulate by updating Order if present
            order_id = metadata.get("order_id")
            order = Order.query.get(int(order_id)) if order_id and str(order_id).isdigit() else None
            if not order and session_id:
                order = Order.query.filter_by(stripe_session_id=session_id).first()
            if order and order.status != OrderStatus.paid:
                # mirror the key updates; core idempotency is in ledger meta checks
                payment_intent = session_obj.get("payment_intent")
                amount_total = session_obj.get("amount_total")
                currency = (session_obj.get("currency") or "usd").lower()
                with db_txn():
                    if db.engine.dialect.name == "postgresql":
                        order = Order.query.filter_by(id=order.id).with_for_update().first()
                    else:
                        order = Order.query.filter_by(id=order.id).first()
                    if order and order.status != OrderStatus.paid:
                        beat = Beat.query.get(order.beat_id) if order.beat_id else None
                        seller = User.query.get(order.seller_id or (beat.owner_id if beat else None))
                        buyer = User.query.get(order.buyer_id)
                        if beat and seller and buyer:
                            if amount_total is not None:
                                order.total_cents = int(amount_total)
                            order.currency = currency
                            if session_id:
                                order.stripe_session_id = str(session_id)
                            if payment_intent:
                                order.stripe_payment_intent = str(payment_intent)
                            buyer_w = Wallet.query.filter_by(user_id=buyer.id).first() or Wallet(user_id=buyer.id)
                            seller_w = Wallet.query.filter_by(user_id=seller.id).first() or Wallet(user_id=seller.id)
                            db.session.add(buyer_w)
                            db.session.add(seller_w)
                            db.session.flush()
                            total_cents = int(order.total_cents or 0)
                            subtotal_cents = int(order.amount_cents or 0)
                            platform_fee_cents = int(order.platform_fee_cents or 0)
                            processing_fee_cents = int(order.processing_fee_cents or 0)
                            if total_cents <= 0:
                                total_cents = subtotal_cents + platform_fee_cents + processing_fee_cents
                            fund_meta = f"external payment (Stripe) order#{order.id} session {str(session_id)[:18] if session_id else ''}".strip()
                            spend_meta = f"buy beat #{beat.id} order#{order.id} via Stripe".strip()
                            if not LedgerEntry.query.filter_by(wallet_id=buyer_w.id, entry_type=EntryType.external_payment, meta=fund_meta).first():
                                post_ledger(buyer_w, EntryType.external_payment, total_cents, meta=fund_meta)
                            if not LedgerEntry.query.filter_by(wallet_id=buyer_w.id, entry_type=EntryType.purchase_spend, meta=spend_meta).first():
                                post_ledger(buyer_w, EntryType.purchase_spend, total_cents, meta=spend_meta)
                            if subtotal_cents > 0:
                                seller_meta = f"sale beat #{beat.id} order#{order.id} to @{buyer.username} (Stripe)"[:255]
                                if not LedgerEntry.query.filter_by(wallet_id=seller_w.id, entry_type=EntryType.sale_income, meta=seller_meta).first():
                                    post_ledger(seller_w, EntryType.sale_income, subtotal_cents, meta=seller_meta)
                            if beat.license == "exclusive":
                                beat.is_active = False
                                beat.updated_at = datetime.utcnow()
                            order.status = OrderStatus.paid
                            order.paid_at = datetime.utcnow()

            row.status = StripeWebhookEventStatus.processed.value
            row.processed_at = datetime.utcnow()
            db.session.commit()
            audit_log_event(
                action_type="STRIPE_WEBHOOK_APPLIED",
                actor_user=current_user,
                target_type="StripeWebhookEvent",
                target_id=str(row.id),
                reason="Admin retried Stripe webhook event",
                metadata={"stripe_event_id": row.stripe_event_id, "session_id": session_id, "purpose": purpose, "order_id": metadata.get("order_id")},
            )
            flash("Retry processed (beat_purchase).", "success")
            return redirect(url_for("admin_stripe_webhooks"))

        row.status = StripeWebhookEventStatus.processed.value
        row.processed_at = datetime.utcnow()
        db.session.commit()
        flash("Marked processed (no applicable fulfillment).", "success")
        return redirect(url_for("admin_stripe_webhooks"))

    except Exception as e:
        row.status = StripeWebhookEventStatus.failed.value
        row.last_error = (str(e) or "retry_failed")[:500]
        db.session.commit()
        try:
            _alert_create(AlertSeverity.high, "STRIPE_WEBHOOK_RETRY_FAILED", "Admin retry processing failed", {"stripe_event_id": row.stripe_event_id})
        except Exception:
            pass
        flash("Retry failed; see last_error.", "error")
        return redirect(url_for("admin_stripe_webhooks"))


@app.route("/admin/alerts", endpoint="admin_alerts")
@role_required("admin")
def admin_alerts():
    severity = (request.args.get("severity") or "").strip().upper()
    status = (request.args.get("status") or "").strip().lower()  # open|resolved
    query = Alert.query
    if severity in ("LOW", "MED", "HIGH"):
        try:
            query = query.filter(Alert.severity == AlertSeverity(severity))
        except Exception:
            pass
    if status == "open":
        query = query.filter(Alert.resolved_at.is_(None))
    elif status == "resolved":
        query = query.filter(Alert.resolved_at.isnot(None))
    rows = query.order_by(Alert.created_at.desc()).limit(300).all()
    return render_template("admin_alerts.html", rows=rows, filters={"severity": severity, "status": status})


@app.route("/admin/alerts/<int:alert_id>/resolve", methods=["POST"], endpoint="admin_alert_resolve")
@role_required("admin")
def admin_alert_resolve(alert_id: int):
    a = Alert.query.get_or_404(alert_id)
    if a.resolved_at is None:
        a.resolved_at = datetime.utcnow()
        db.session.commit()
    flash("Alert resolved.", "success")
    return redirect(url_for("admin_alerts"))


@app.route("/admin/uploads", endpoint="admin_uploads")
@role_required("admin")
def admin_uploads():
    scan = (request.args.get("scan_status") or "").strip().upper()
    provider = (request.args.get("provider") or "").strip().lower()
    q = UploadedFile.query
    if scan in ("PENDING", "CLEAN", "INFECTED", "FAILED"):
        try:
            q = q.filter(UploadedFile.scan_status == ScanStatus(scan))
        except Exception:
            pass
    if provider in ("local", "s3"):
        q = q.filter(UploadedFile.storage_provider == provider)
    rows = q.order_by(UploadedFile.created_at.desc()).limit(400).all()
    return render_template("admin_uploads.html", rows=rows, filters={"scan_status": scan, "provider": provider})


@app.route("/admin/uploads/<int:file_id>/delete", methods=["POST"], endpoint="admin_upload_delete")
@role_required("admin")
def admin_upload_delete(file_id: int):
    uf = UploadedFile.query.get_or_404(file_id)
    key = uf.key
    try:
        storage_backend.delete_file(key)
    except Exception:
        pass
    db.session.delete(uf)
    db.session.commit()
    flash("Upload deleted.", "success")
    try:
        audit_log_event(
            action_type="UPLOAD_DELETED",
            actor_user=current_user,
            target_type="UploadedFile",
            target_id=str(file_id),
            reason="Admin deleted uploaded file",
            metadata={"key": key, "storage_provider": uf.storage_provider, "scan_status": uf.scan_status.value if uf.scan_status else None},
        )
    except Exception:
        pass
    return redirect(url_for("admin_uploads"))


@app.route("/admin/fees", endpoint="admin_fees")
@role_required("admin")
def admin_fees():
    """Admin read-only view of fee configuration (transparency)."""
    return render_template(
        "admin_fees.html",
        cfg={
            "HOLD_FEE_CENTS": HOLD_FEE_CENTS,
            "BEAT_FEE_FLAT_CENTS": BEAT_FEE_FLAT_CENTS,
            "MAX_TXN_DOLLARS": MAX_TXN_DOLLARS,
        },
    )


@app.route("/dashboard/admin/schema/booking", endpoint="admin_booking_schema")
@app.route("/dashboard/admin/schema-check", endpoint="admin_schema_check")
@role_required("admin")
def admin_booking_schema():
    """Admin schema check for booking/payment fee columns (Postgres)."""
    booking_cols = []
    payment_cols = []
    error = None
    has_fee_columns = False
    has_payment_columns = False
    has_payment_kind = False
    booking_sample_ok = False
    payment_sample_ok = False

    try:
        if db.engine.dialect.name == "postgresql":
            with db.engine.begin() as conn:
                booking_rows = conn.execute(text("""
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'booking'
                    ORDER BY ordinal_position
                """)).fetchall()
                payment_rows = conn.execute(text("""
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'payment'
                    ORDER BY ordinal_position
                """)).fetchall()

                booking_cols = [{"name": r[0], "type": r[1]} for r in booking_rows]
                payment_cols = [{"name": r[0], "type": r[1]} for r in payment_rows]

                booking_names = {r[0] for r in booking_rows}
                payment_names = {r[0] for r in payment_rows}

                booking_required = {
                    "quoted_total_cents",
                    "quote_hourly_rate_cents",
                    "quote_billable_minutes",
                    "quote_calculation_text",
                    "quote_breakdown_text",
                    "deposit_base_cents",
                    "beatfund_fee_total_cents",
                    "beatfund_fee_collected_cents",
                }
                payment_required = {
                    "kind",
                    "base_amount_cents",
                    "beatfund_fee_cents",
                    "processing_fee_cents",
                    "total_paid_cents",
                    "refunded_base_cents",
                    "nonrefundable_processing_kept_cents",
                    "nonrefundable_beatfund_kept_cents",
                    "idempotency_key",
                    "external_id",
                    "booking_request_id",
                    "booking_id",
                    "stripe_payment_intent_id",
                    "stripe_charge_id",
                }

                has_fee_columns = booking_required.issubset(booking_names)
                has_payment_columns = payment_required.issubset(payment_names)
                has_payment_kind = "kind" in payment_names

                try:
                    conn.execute(text("SELECT quoted_total_cents FROM booking LIMIT 1"))
                    booking_sample_ok = True
                except Exception:
                    booking_sample_ok = False

                try:
                    conn.execute(text("SELECT kind FROM payment LIMIT 1"))
                    payment_sample_ok = True
                except Exception:
                    payment_sample_ok = False
        else:
            booking_names = set()
            payment_names = set()
            if _sqlite_has_table("booking"):
                booking_names = set(_sqlite_columns("booking"))
            if _sqlite_has_table("payment"):
                payment_names = set(_sqlite_columns("payment"))

            booking_cols = [{"name": c, "type": "unknown"} for c in sorted(booking_names)]
            payment_cols = [{"name": c, "type": "unknown"} for c in sorted(payment_names)]

            booking_required = {
                "quoted_total_cents",
                "quote_hourly_rate_cents",
                "quote_billable_minutes",
                "quote_calculation_text",
                "quote_breakdown_text",
                "deposit_base_cents",
                "beatfund_fee_total_cents",
                "beatfund_fee_collected_cents",
            }
            payment_required = {
                "kind",
                "base_amount_cents",
                "beatfund_fee_cents",
                "processing_fee_cents",
                "total_paid_cents",
                "refunded_base_cents",
                "nonrefundable_processing_kept_cents",
                "nonrefundable_beatfund_kept_cents",
                "idempotency_key",
                "external_id",
                "booking_request_id",
                "booking_id",
                "stripe_payment_intent_id",
                "stripe_charge_id",
            }

            has_fee_columns = booking_required.issubset(booking_names)
            has_payment_columns = payment_required.issubset(payment_names)
            has_payment_kind = "kind" in payment_names
            booking_sample_ok = bool(booking_names)
            payment_sample_ok = bool(payment_names)
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:200]}"

    return jsonify({
        "ok": error is None,
        "has_fee_columns": has_fee_columns,
        "sample_ok": booking_sample_ok,
        "columns": booking_cols,
        "booking": {
            "has_fee_columns": has_fee_columns,
            "sample_ok": booking_sample_ok,
            "columns": booking_cols,
        },
        "payment": {
            "has_payment_columns": has_payment_columns,
            "has_payment_kind": has_payment_kind,
            "sample_ok": payment_sample_ok,
            "columns": payment_cols,
        },
        "error": error,
    })


@app.route("/health")
def health():
    """Basic liveness probe (no DB)."""
    return jsonify({"ok": True, "env": "prod" if is_prod() else "dev"}), 200


@app.route("/healthz")
def healthz():
    """Liveness probe (no DB)."""
    return jsonify({"ok": True}), 200


@app.route("/readyz")
def readyz():
    """Readiness probe (DB + critical env vars in production)."""
    problems: list[str] = []
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        problems.append("db")

    if is_prod():
        for k in ("SECRET_KEY", "APP_BASE_URL", "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET"):
            if not (os.getenv(k) or "").strip():
                problems.append(f"missing_env:{k}")

    if problems:
        return jsonify({"ok": False, "problems": problems}), 503
    return jsonify({"ok": True}), 200


@app.route("/dashboard/admin/tickets/new", methods=["GET", "POST"], endpoint="admin_ticket_new")
@role_required("admin")
def admin_ticket_new():
    """Admin create new support ticket for a user"""
    user_id = request.args.get("user_id", type=int) or request.form.get("user_id", type=int)
    ledger_id = request.args.get("ledger_id", type=int) or request.form.get("ledger_id", type=int)
    
    if not user_id:
        flash("User ID is required.", "error")
        return redirect(url_for("admin_tickets"))
    
    customer = User.query.get_or_404(user_id)
    
    # Don't allow creating tickets for other admins
    if customer.role == RoleEnum.admin:
        flash("Cannot create tickets for admin accounts.", "error")
        return redirect(url_for("admin_tickets"))
    
    # Get ledger entry if provided
    ledger = None
    if ledger_id:
        ledger = LedgerEntry.query.get(ledger_id)
        # Verify ledger belongs to the user
        if ledger:
            wallet = Wallet.query.get(ledger.wallet_id)
            if wallet and wallet.user_id != customer.id:
                ledger = None  # Don't link if it doesn't belong to the user
    
    if request.method == "POST":
        # Get form data
        ticket_type = request.form.get("type", "").strip()
        subject = (request.form.get("subject") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority = (request.form.get("priority") or "normal").strip()
        
        # Validate
        if not subject:
            flash("Subject is required.", "error")
            return render_template(
                "admin_ticket_new.html",
                customer=customer,
                ledger=ledger,
                TicketType=TicketType,
                type_value=ticket_type,
                subject=subject,
                description=description,
                priority=priority,
            )
        
        if not description:
            flash("Description is required.", "error")
            return render_template(
                "admin_ticket_new.html",
                customer=customer,
                ledger=ledger,
                TicketType=TicketType,
                type_value=ticket_type,
                subject=subject,
                description=description,
                priority=priority,
            )
        
        # Validate ticket type
        try:
            ticket_type_enum = TicketType(ticket_type) if ticket_type else TicketType.other
        except ValueError:
            ticket_type_enum = TicketType.other
        
        # Validate priority
        if priority not in ["low", "normal", "high"]:
            priority = "normal"
        
        # Create ticket
        ticket = SupportTicket(
            user_id=customer.id,
            created_by_admin_id=current_user.id,
            related_ledger_id=ledger.id if ledger else None,
            type=ticket_type_enum,
            status=TicketStatus.open,
            priority=priority,
            subject=subject[:200],  # Enforce max length
            description=description,
        )
        
        db.session.add(ticket)
        db.session.commit()

        try:
            log_admin_action(
                ActivityEventType.admin_ticket_updated,
                actor_admin_id=current_user.id,
                target_type="ticket",
                target_id=ticket.id,
                summary=f"Created ticket #{ticket.id}: {ticket.subject}",
                payload_dict={
                    "user_id": customer.id,
                    "username": customer.username,
                    "priority": ticket.priority,
                    "status": str(ticket.status),
                    "type": str(ticket.type),
                },
                url=url_for("admin_ticket_detail", ticket_id=ticket.id),
                include_actor=True,
            )
        except Exception:
            pass
        
        flash(f"Ticket #{ticket.id} created successfully for @{customer.username}.", "success")
        return redirect(url_for("admin_ticket_detail", ticket_id=ticket.id))
    
    # GET request - show form
    # Pre-fill type if linked to ledger
    type_value = None
    if ledger:
        # Suggest ticket type based on ledger entry type
        if ledger.entry_type in [EntryType.withdrawal, EntryType.transfer_out]:
            type_value = TicketType.refund_request.value
        elif ledger.entry_type in [EntryType.deposit, EntryType.transfer_in]:
            type_value = TicketType.charge_dispute.value
        else:
            type_value = TicketType.other.value
    
    return render_template(
        "admin_ticket_new.html",
        customer=customer,
        ledger=ledger,
        TicketType=TicketType,
        type_value=type_value,
        subject="",
        description="",
        priority="normal",
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
        .filter(User.role != RoleEnum.admin.value)
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


@app.route("/dashboard/admin/analytics", endpoint="admin_analytics")
@role_required("admin")
def admin_analytics():
    """Admin analytics dashboard (high-signal operational metrics)."""
    now = datetime.utcnow()
    last_30 = now - timedelta(days=30)

    # Users (exclude admins)
    role_counts = (
        db.session.query(User.role, func.count(User.id))
        .filter(User.role != RoleEnum.admin.value)
        .group_by(User.role)
        .order_by(User.role)
        .all()
    )
    total_users = sum(row[1] for row in role_counts) if role_counts else 0
    active_users = (
        db.session.query(func.count(User.id))
        .filter(User.role != RoleEnum.admin.value, User.is_active_col.is_(True))
        .scalar() or 0
    )

    kyc_counts = (
        db.session.query(User.kyc_status, func.count(User.id))
        .filter(User.role != RoleEnum.admin.value)
        .group_by(User.kyc_status)
        .order_by(User.kyc_status)
        .all()
    )

    # Orders / revenue
    total_orders = db.session.query(func.count(Order.id)).scalar() or 0
    paid_orders = db.session.query(func.count(Order.id)).filter(Order.status == OrderStatus.paid).scalar() or 0
    total_sales_cents = (
        db.session.query(func.coalesce(func.sum(Order.amount_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )
    total_gross_cents = (
        db.session.query(func.coalesce(func.sum(Order.total_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )
    platform_fee_cents = (
        db.session.query(func.coalesce(func.sum(Order.platform_fee_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )
    processing_fee_cents = (
        db.session.query(func.coalesce(func.sum(Order.processing_fee_cents), 0))
        .filter(Order.status == OrderStatus.paid)
        .scalar() or 0
    )

    orders_series = (
        db.session.query(
            func.date(Order.created_at).label("day"),
            func.count(Order.id).label("count"),
            func.coalesce(func.sum(Order.amount_cents), 0).label("sum_cents"),
        )
        .filter(Order.created_at >= last_30)
        .group_by("day")
        .order_by("day")
        .all()
    )

    # Wallet / ledger
    wallet_volume_cents = (
        db.session.query(func.coalesce(func.sum(func.abs(LedgerEntry.amount_cents)), 0))
        .scalar() or 0
    )
    ledger_by_type = (
        db.session.query(
            LedgerEntry.entry_type,
            func.count(LedgerEntry.id).label("count"),
            func.coalesce(func.sum(LedgerEntry.amount_cents), 0).label("sum_cents"),
        )
        .group_by(LedgerEntry.entry_type)
        .order_by(LedgerEntry.entry_type)
        .all()
    )

    # Bookings & tickets
    booking_counts = (
        db.session.query(Booking.status, func.count(Booking.id))
        .group_by(Booking.status)
        .order_by(Booking.status)
        .all()
    )
    ticket_counts = (
        db.session.query(SupportTicket.status, func.count(SupportTicket.id))
        .group_by(SupportTicket.status)
        .order_by(SupportTicket.status)
        .all()
    )

    # Uploads
    upload_counts = (
        db.session.query(UploadedFile.scan_status, func.count(UploadedFile.id))
        .group_by(UploadedFile.scan_status)
        .order_by(UploadedFile.scan_status)
        .all()
    )

    # Top sellers + beats
    top_sellers = (
        db.session.query(
            User.username,
            func.count(Order.id).label("count"),
            func.coalesce(func.sum(Order.amount_cents), 0).label("sum_cents"),
        )
        .join(User, User.id == Order.seller_id)
        .filter(Order.status == OrderStatus.paid)
        .group_by(User.username)
        .order_by(func.sum(Order.amount_cents).desc())
        .limit(5)
        .all()
    )
    top_beats = (
        db.session.query(
            Beat.title,
            func.count(Order.id).label("count"),
            func.coalesce(func.sum(Order.amount_cents), 0).label("sum_cents"),
        )
        .join(Order, Order.beat_id == Beat.id)
        .filter(Order.status == OrderStatus.paid)
        .group_by(Beat.title)
        .order_by(func.count(Order.id).desc())
        .limit(5)
        .all()
    )

    def _dstr(v):
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d")
        try:
            return v.strftime("%Y-%m-%d")  # date
        except Exception:
            return str(v)

    order_labels = [_dstr(row.day) for row in orders_series]
    order_counts_series = [int(row.count) for row in orders_series]
    order_sales_series = [round((row.sum_cents or 0) / 100.0, 2) for row in orders_series]

    role_labels = [get_role_display(r) for r, _ in role_counts]
    role_values = [int(c) for _, c in role_counts]

    kyc_labels = [str(k).replace("_", " ").title() for k, _ in kyc_counts]
    kyc_values = [int(c) for _, c in kyc_counts]

    ledger_labels = [row.entry_type.value if hasattr(row.entry_type, "value") else str(row.entry_type) for row in ledger_by_type]
    ledger_counts = [int(row.count) for row in ledger_by_type]
    ledger_amounts = [round((row.sum_cents or 0) / 100.0, 2) for row in ledger_by_type]

    booking_labels = [str(s).replace("_", " ").title() for s, _ in booking_counts]
    booking_values = [int(c) for _, c in booking_counts]

    ticket_labels = [str(s).replace("_", " ").title() for s, _ in ticket_counts]
    ticket_values = [int(c) for _, c in ticket_counts]

    upload_labels = [str(s).replace("_", " ").title() for s, _ in upload_counts]
    upload_values = [int(c) for _, c in upload_counts]

    return render_template(
        "admin_analytics.html",
        total_users=total_users,
        active_users=active_users,
        total_orders=total_orders,
        paid_orders=paid_orders,
        total_sales=round(total_sales_cents / 100.0, 2),
        total_gross=round(total_gross_cents / 100.0, 2),
        platform_fees=round(platform_fee_cents / 100.0, 2),
        processing_fees=round(processing_fee_cents / 100.0, 2),
        wallet_volume=round(wallet_volume_cents / 100.0, 2),
        order_labels=order_labels,
        order_counts_series=order_counts_series,
        order_sales_series=order_sales_series,
        role_labels=role_labels,
        role_values=role_values,
        kyc_labels=kyc_labels,
        kyc_values=kyc_values,
        ledger_labels=ledger_labels,
        ledger_counts=ledger_counts,
        ledger_amounts=ledger_amounts,
        booking_labels=booking_labels,
        booking_values=booking_values,
        ticket_labels=ticket_labels,
        ticket_values=ticket_values,
        upload_labels=upload_labels,
        upload_values=upload_values,
        top_sellers=top_sellers,
        top_beats=top_beats,
    )


@app.route("/dashboard/admin/reports/export/ledger", endpoint="admin_export_system_ledger_csv")
@role_required("admin")
def admin_export_system_ledger_csv():
    """Admin export of all system wallet ledger entries as CSV"""
    # Get all ledger entries across all wallets
    entries = (
        LedgerEntry.query
        .join(Wallet, LedgerEntry.wallet_id == Wallet.id)
        .join(User, Wallet.user_id == User.id)
        .order_by(LedgerEntry.created_at.asc())
        .all()
    )
    
    # Generate CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        "created_at",
        "wallet_id",
        "user_id",
        "username",
        "entry_type",
        "direction",
        "amount_dollars",
        "meta"
    ])
    
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
        
        # Get wallet and user info
        wallet = Wallet.query.get(row.wallet_id)
        user = User.query.get(wallet.user_id) if wallet else None
        username = user.username if user else "unknown"
        
        writer.writerow([
            created_str,
            row.wallet_id,
            wallet.user_id if wallet else "",
            username,
            row.entry_type.value,
            direction,
            amount_dollars,
            row.meta or ""
        ])
    
    output = si.getvalue()
    filename = f"beatfund_system_ledger_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/dashboard/admin/reports/export/audit", endpoint="admin_export_audit_log_csv")
@role_required("admin")
def admin_export_audit_log_csv():
    """Admin export of all audit log entries as CSV"""
    # Get all audit log entries
    logs = AuditLog.query.order_by(AuditLog.created_at.asc()).all()
    
    # Generate CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow([
        "created_at",
        "admin_id",
        "admin_username",
        "user_id",
        "user_username",
        "action",
        "reason"
    ])
    
    for log in logs:
        created_str = log.created_at.isoformat(sep=" ") if log.created_at else ""
        admin_username = log.admin.username if log.admin else "unknown"
        user_username = log.user.username if log.user else ""
        
        writer.writerow([
            created_str,
            log.admin_id,
            admin_username,
            log.user_id or "",
            user_username,
            log.action,
            log.reason
        ])
    
    output = si.getvalue()
    filename = f"beatfund_audit_log_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


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

        try:
            log_admin_action(
                ActivityEventType.admin_user_role_changed,
                actor_admin_id=current_user.id,
                target_type="user",
                target_id=new_admin.id,
                summary=f"Created admin account @{new_admin.username}",
                payload_dict={"before": None, "after": {"role": "admin"}, "username": new_admin.username},
                url=url_for("admin_team"),
                include_actor=True,
            )
        except Exception:
            pass
        
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
    before_active = bool(user.is_active_col)
    user.is_active_col = not user.is_active_col
    db.session.commit()

    try:
        log_admin_action(
            ActivityEventType.admin_user_disabled,
            actor_admin_id=current_user.id,
            target_type="user",
            target_id=user.id,
            summary=f"{'Activated' if user.is_active_col else 'Deactivated'} admin @{user.username}",
            payload_dict={"before": {"is_active": before_active}, "after": {"is_active": bool(user.is_active_col)}, "username": user.username},
            url=url_for("admin_team"),
            include_actor=True,
        )
    except Exception:
        pass
    
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
# Social Media Manager Routes
# =========================================================
@app.route("/social/dashboard", endpoint="social_dashboard")
@role_required("social_media_manager")
def social_dashboard():
    smm = current_user
    
    # Overview stats
    active_clients = SMMClient.query.filter_by(smm_id=smm.id, is_active=True).count()
    scheduled_posts = SMMPost.query.filter_by(
        smm_id=smm.id,
        status=SMMPostStatus.scheduled
    ).count()
    pending_approvals = SMMApproval.query.join(SMMPost).filter(
        SMMPost.smm_id == smm.id,
        SMMApproval.status == "pending"
    ).count()
    
    # Top channel (most posts)
    top_channel_query = db.session.query(
        SMMPost.platform,
        func.count(SMMPost.id).label('count')
    ).filter_by(smm_id=smm.id).group_by(SMMPost.platform).order_by(func.count(SMMPost.id).desc()).first()
    top_channel = top_channel_query[0] if top_channel_query else "None"
    
    # Earnings this month
    this_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    earnings_this_month = 0  # Placeholder - would need transaction model integration
    
    stats = {
        "active_clients": active_clients,
        "scheduled_posts": scheduled_posts,
        "pending_approvals": pending_approvals,
        "top_channel": top_channel,
        "earnings_this_month": earnings_this_month
    }
    
    return render_template("social/dashboard.html", smm=smm, stats=stats)


@app.route("/social/clients", endpoint="social_clients")
@role_required("social_media_manager")
def social_clients():
    smm = current_user
    clients = SMMClient.query.filter_by(smm_id=smm.id).order_by(SMMClient.created_at.desc()).all()
    
    # Add platform info for each client
    clients_data = []
    for client in clients:
        platforms = []
        if client.platforms:
            try:
                platforms = json.loads(client.platforms)
            except:
                platforms = []
        clients_data.append({
            "client": client,
            "platforms": platforms
        })
    
    return render_template("social/clients.html", smm=smm, clients=clients_data)


@app.route("/social/calendar", endpoint="social_calendar")
@role_required("social_media_manager")
def social_calendar():
    smm = current_user
    view = request.args.get("view", "week")  # week or month
    
    today = datetime.utcnow().date()
    if view == "month":
        start_date = today.replace(day=1)
        end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    else:
        # Week view
        days_since_monday = today.weekday()
        start_date = today - timedelta(days=days_since_monday)
        end_date = start_date + timedelta(days=6)
    
    calendar_items = SMMCalendarItem.query.filter(
        SMMCalendarItem.smm_id == smm.id,
        SMMCalendarItem.scheduled_date >= start_date,
        SMMCalendarItem.scheduled_date <= end_date
    ).order_by(SMMCalendarItem.scheduled_date, SMMCalendarItem.scheduled_time).all()
    
    return render_template("social/calendar.html", smm=smm, calendar_items=calendar_items, view=view, start_date=start_date, end_date=end_date)


@app.route("/social/posts", endpoint="social_posts")
@role_required("social_media_manager")
def social_posts():
    smm = current_user
    status_filter = request.args.get("status", "all")
    
    query = SMMPost.query.filter_by(smm_id=smm.id)
    if status_filter != "all":
        query = query.filter_by(status=SMMPostStatus(status_filter))
    
    posts = query.order_by(SMMPost.created_at.desc()).all()
    
    # Get assets for posts
    posts_data = []
    for post in posts:
        assets = SMMAsset.query.filter_by(post_id=post.id).all()
        posts_data.append({
            "post": post,
            "assets": assets
        })
    
    # Get all assets (not linked to posts)
    all_assets = SMMAsset.query.filter_by(smm_id=smm.id, post_id=None).order_by(SMMAsset.created_at.desc()).all()
    
    return render_template("social/posts.html", smm=smm, posts=posts_data, assets=all_assets, status_filter=status_filter)


@app.route("/social/approvals", endpoint="social_approvals")
@role_required("social_media_manager")
def social_approvals():
    smm = current_user
    status_filter = request.args.get("status", "pending")
    
    query = SMMApproval.query.join(SMMPost).filter(SMMPost.smm_id == smm.id)
    if status_filter == "pending":
        query = query.filter(SMMApproval.status == "pending")
    elif status_filter == "approved":
        query = query.filter(SMMApproval.status == "approved")
    elif status_filter == "changes":
        query = query.filter(SMMApproval.status == "changes_requested")
    
    approvals = query.order_by(SMMApproval.submitted_at.desc()).all()
    
    return render_template("social/approvals.html", smm=smm, approvals=approvals, status_filter=status_filter)


@app.route("/social/analytics", endpoint="social_analytics")
@role_required("social_media_manager")
def social_analytics():
    smm = current_user
    client_id = request.args.get("client_id", type=int)
    platform_filter = request.args.get("platform", "all")
    
    query = SMMAnalytics.query.filter_by(smm_id=smm.id)
    if client_id:
        query = query.filter_by(client_id=client_id)
    if platform_filter != "all":
        query = query.filter_by(platform=platform_filter)
    
    analytics_rows = query.order_by(SMMAnalytics.period_start.desc()).all()
    
    # Get clients for filter
    clients = SMMClient.query.filter_by(smm_id=smm.id, is_active=True).all()
    
    return render_template("social/analytics.html", smm=smm, analytics_rows=analytics_rows, clients=clients, client_id=client_id, platform_filter=platform_filter)


@app.route("/social/availability", endpoint="social_availability")
@role_required("social_media_manager")
def social_availability():
    smm = current_user
    availability = SMMAvailability.query.filter_by(smm_id=smm.id).all()
    
    # Create a dict by day of week
    availability_dict = {day: None for day in range(7)}
    for av in availability:
        availability_dict[av.day_of_week] = av
    
    return render_template("social/availability.html", smm=smm, availability=availability_dict)


@app.route("/social/earnings", endpoint="social_earnings")
@role_required("social_media_manager")
def social_earnings():
    smm = current_user
    
    # Get wallet balance
    wallet = Wallet.query.filter_by(user_id=smm.id).first()
    if wallet:
        balance_cents = wallet_balance_cents(wallet)
        balance = balance_cents / 100.0
    else:
        balance = 0.0
    
    # Get transactions from ledger
    transactions = []
    if wallet:
        ledger_entries = LedgerEntry.query.filter_by(wallet_id=wallet.id).order_by(LedgerEntry.created_at.desc()).limit(50).all()
        for entry in ledger_entries:
            transactions.append({
                "date": entry.created_at.strftime('%b %d, %Y'),
                "description": entry.meta or entry.entry_type.value,
                "amount": entry.amount_cents / 100.0,
                "status": "completed"
            })
    
    # Calculate earnings this month
    this_month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    earnings_this_month = 0.0
    if wallet:
        month_entries = LedgerEntry.query.filter(
            LedgerEntry.wallet_id == wallet.id,
            LedgerEntry.created_at >= this_month_start,
            LedgerEntry.entry_type.in_([
                EntryType.deposit,
                EntryType.transfer_in,
                EntryType.sale_income,
                EntryType.adjustment
            ])
        ).all()
        earnings_this_month = sum(entry.amount_cents for entry in month_entries) / 100.0
    
    earnings = {
        "balance": balance,
        "earnings_this_month": earnings_this_month,
        "transactions": transactions
    }
    
    return render_template("social/earnings.html", smm=smm, earnings=earnings)


@app.route("/social/reviews", endpoint="social_reviews")
@role_required("social_media_manager")
def social_reviews():
    smm = current_user
    reviews = SMMReview.query.filter_by(smm_id=smm.id).order_by(SMMReview.created_at.desc()).all()
    
    # Calculate average rating
    avg_rating = db.session.query(func.avg(SMMReview.rating)).filter_by(smm_id=smm.id).scalar() or 0
    
    return render_template("social/reviews.html", smm=smm, reviews=reviews, avg_rating=round(avg_rating, 1) if avg_rating else 0)


@app.route("/social/settings", endpoint="social_settings")
@role_required("social_media_manager")
def social_settings():
    smm = current_user
    return render_template("social/settings.html", smm=smm)


# =========================================================
# Project Vault Routes
# =========================================================
@app.route("/vaults", endpoint="vaults_index")
@login_required
def vaults_index():
    """Project vaults dashboard"""
    if not is_vault_eligible(current_user):
        flash("Project vaults are not available for your role.", "error")
        return redirect(url_for("route_to_dashboard"))
    
    vaults = ProjectVault.query.filter_by(user_id=current_user.id).order_by(
        ProjectVault.is_completed.asc(),
        ProjectVault.created_at.desc()
    ).all()
    
    # Get wallet balance
    wallet = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(wallet) / 100.0
    
    return render_template(
        "vaults/index.html",
        vaults=vaults,
        wallet_balance=wallet_balance,
    )


@app.route("/vaults/create", methods=["GET", "POST"], endpoint="vaults_create")
@login_required
def vaults_create():
    """Create a new project vault"""
    if not is_vault_eligible(current_user):
        flash("Project vaults are not available for your role.", "error")
        return redirect(url_for("route_to_dashboard"))
    
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        target_dollars = request.form.get("target", "").strip()
        
        errors = []
        if not name:
            errors.append("Vault name is required.")
        if not target_dollars:
            errors.append("Target amount is required.")
        else:
            try:
                target = float(target_dollars)
                if target <= 0:
                    errors.append("Target must be greater than zero.")
                target_cents = int(target * 100)
            except ValueError:
                errors.append("Target must be a valid number.")
                target_cents = None
        
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("vaults/create.html")
        
        vault = ProjectVault(
            user_id=current_user.id,
            name=name,
            description=description or None,
            target_cents=target_cents,
            current_balance_cents=0,
        )
        db.session.add(vault)
        db.session.commit()
        
        flash(f"Vault '{name}' created successfully!", "success")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    return render_template("vaults/create.html")


@app.route("/vaults/<int:vault_id>", endpoint="vaults_detail")
@login_required
def vaults_detail(vault_id):
    """View and manage a specific vault"""
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    # Get transactions
    transactions = VaultTransaction.query.filter_by(vault_id=vault.id).order_by(
        VaultTransaction.created_at.desc()
    ).limit(50).all()
    
    # Get wallet balance
    wallet = get_or_create_wallet(current_user.id)
    wallet_balance = wallet_balance_cents(wallet) / 100.0
    
    return render_template(
        "vaults/detail.html",
        vault=vault,
        transactions=transactions,
        wallet_balance=wallet_balance,
    )


@app.route("/vaults/<int:vault_id>/fund", methods=["POST"], endpoint="vaults_fund")
@login_required
def vaults_fund(vault_id):
    """Fund a vault manually"""
    # Allow vault_id from form if provided (for quick fund from index)
    form_vault_id = request.form.get("vault_id", "").strip()
    if form_vault_id:
        try:
            vault_id = int(form_vault_id)
        except ValueError:
            pass
    
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    if vault.is_completed:
        flash("This vault has reached its target and is completed.", "info")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    # Check if vault is locked
    if vault.is_locked_now():
        lock_reason = []
        if vault.lock_until_date:
            lock_reason.append(f"until {vault.lock_until_date.strftime('%B %d, %Y')}")
        if vault.lock_until_goal:
            lock_reason.append("until goal reached")
        reason_text = " " + " and ".join(lock_reason) if lock_reason else ""
        flash(f"This vault is locked{reason_text} and cannot be funded.", "error")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    amount_dollars = request.form.get("amount", "").strip()
    notes = (request.form.get("notes") or "").strip()
    
    if not amount_dollars:
        flash("Please enter an amount to fund.", "error")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    try:
        amount = float(amount_dollars)
        if amount <= 0:
            flash("Amount must be greater than zero.", "error")
            return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        amount_cents = int(amount * 100)
        
        # Check if would exceed target
        if vault.current_balance_cents + amount_cents > vault.target_cents:
            max_amount = vault.remaining_dollars
            flash(f"Amount exceeds target. Maximum: ${max_amount:.2f}", "error")
            return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        success = fund_vault(vault, amount_cents, transaction_type="manual", notes=notes)
        
        if success:
            flash(f"Successfully funded ${amount:.2f} to '{vault.name}'", "success")
        else:
            flash("Insufficient wallet balance.", "error")
        
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "error")
    
    return redirect(url_for("vaults_detail", vault_id=vault.id))


@app.route("/vaults/<int:vault_id>/settings", methods=["GET", "POST"], endpoint="vaults_settings")
@login_required
def vaults_settings(vault_id):
    """Configure vault settings including auto-funding"""
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    if request.method == "POST":
        # Update basic info
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        target_dollars = request.form.get("target", "").strip()
        
        if name:
            vault.name = name
        vault.description = description or None
        
        if target_dollars:
            try:
                target = float(target_dollars)
                if target > 0:
                    vault.target_cents = int(target * 100)
            except ValueError:
                flash("Invalid target amount.", "error")
        
        # Auto-funding settings
        auto_fund_enabled = request.form.get("auto_fund_enabled") == "on"
        vault.auto_fund_enabled = auto_fund_enabled
        
        if auto_fund_enabled:
            auto_fund_percent = request.form.get("auto_fund_percent", "").strip()
            auto_fund_min = request.form.get("auto_fund_min", "").strip()
            auto_fund_frequency = request.form.get("auto_fund_frequency", "").strip()
            
            if auto_fund_percent:
                try:
                    percent = int(auto_fund_percent)
                    if 0 <= percent <= 100:
                        vault.auto_fund_percent = percent
                except ValueError:
                    pass
            
            if auto_fund_min:
                try:
                    min_dollars = float(auto_fund_min)
                    if min_dollars >= 0:
                        vault.auto_fund_min_cents = int(min_dollars * 100)
                except ValueError:
                    pass
            
            if auto_fund_frequency in ["daily", "weekly", "monthly", "on_income"]:
                vault.auto_fund_frequency = auto_fund_frequency
        
        vault.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash("Vault settings updated successfully!", "success")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    return render_template("vaults/settings.html", vault=vault)


@app.route("/vaults/<int:vault_id>/withdraw", methods=["POST"], endpoint="vaults_withdraw")
@login_required
def vaults_withdraw(vault_id):
    """Withdraw funds from vault back to wallet"""
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    amount_dollars = request.form.get("amount", "").strip()
    
    if not amount_dollars:
        flash("Please enter an amount to withdraw.", "error")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    try:
        amount = float(amount_dollars)
        if amount <= 0:
            flash("Amount must be greater than zero.", "error")
            return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        amount_cents = int(amount * 100)
        
        if amount_cents > vault.current_balance_cents:
            flash("Insufficient vault balance.", "error")
            return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        # Check if vault is locked
        if vault.is_locked_now():
            flash("This vault is locked and cannot be withdrawn from.", "error")
            return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        # Withdraw to wallet
        with db_txn():
            vault.current_balance_cents -= amount_cents
            vault.is_completed = False  # Reset completion if withdrawing
            vault.completed_at = None
            vault.updated_at = datetime.utcnow()
            
            # Add to wallet
            wallet = get_or_create_wallet(current_user.id, commit=False)
            post_ledger(wallet, EntryType.deposit, amount_cents, meta=f"withdraw from vault '{vault.name[:80]}'")
            
            # Create transaction record
            txn = VaultTransaction(
                vault_id=vault.id,
                amount_cents=-amount_cents,
                transaction_type="withdrawal",
                source="wallet",
                notes=f"Withdrawn ${amount:.2f}"
            )
            db.session.add(txn)
        
        flash(f"Successfully withdrew ${amount:.2f} from '{vault.name}' to wallet", "success")
        
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "error")
    
    return redirect(url_for("vaults_detail", vault_id=vault.id))


@app.route("/vaults/<int:vault_id>/lock", methods=["POST"], endpoint="vaults_lock")
@login_required
def vaults_lock(vault_id):
    """Lock or unlock a vault"""
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    action = request.form.get("action", "").strip()
    lock_until_date_str = request.form.get("lock_until_date", "").strip()
    lock_until_goal = request.form.get("lock_until_goal") == "on"
    
    if action == "lock":
        vault.is_locked = True
        
        if lock_until_date_str:
            try:
                lock_date = datetime.strptime(lock_until_date_str, "%Y-%m-%d")
                vault.lock_until_date = lock_date
            except ValueError:
                flash("Invalid date format.", "error")
                return redirect(url_for("vaults_detail", vault_id=vault.id))
        
        vault.lock_until_goal = lock_until_goal
        
        lock_reason = []
        if vault.lock_until_date:
            lock_reason.append(f"until {vault.lock_until_date.strftime('%B %d, %Y')}")
        if vault.lock_until_goal:
            lock_reason.append("until goal reached")
        
        reason_text = " " + " and ".join(lock_reason) if lock_reason else ""
        flash(f"Vault '{vault.name}' has been locked{reason_text}.", "success")
    elif action == "unlock":
        vault.is_locked = False
        vault.lock_until_date = None
        vault.lock_until_goal = False
        flash(f"Vault '{vault.name}' has been unlocked.", "success")
    else:
        flash("Invalid action.", "error")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    vault.updated_at = datetime.utcnow()
    db.session.commit()
    
    return redirect(url_for("vaults_detail", vault_id=vault.id))


@app.route("/vaults/<int:vault_id>/delete", methods=["POST"], endpoint="vaults_delete")
@login_required
def vaults_delete(vault_id):
    """Delete a vault (only if empty)"""
    vault = ProjectVault.query.get_or_404(vault_id)
    
    if vault.user_id != current_user.id:
        flash("You don't have access to this vault.", "error")
        return redirect(url_for("vaults_index"))
    
    if vault.current_balance_cents > 0:
        flash("Cannot delete vault with funds. Please withdraw all funds first.", "error")
        return redirect(url_for("vaults_detail", vault_id=vault.id))
    
    db.session.delete(vault)
    db.session.commit()
    
    flash(f"Vault '{vault.name}' deleted successfully.", "success")
    return redirect(url_for("vaults_index"))


# =========================================================
# Run
# =========================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=IS_DEV)
