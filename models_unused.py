# models.py (or inside app.py)
import enum
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class KYCStatus(str, enum.Enum):
    not_started = "not_started"
    pending = "pending"
    approved = "approved"
    rejected = "rejected"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False)

    # Minimal KYC footprint
    kyc_status = db.Column(db.Enum(KYCStatus), nullable=False, default=KYCStatus.not_started)
    kyc_provider_ref = db.Column(db.String(128), nullable=True, index=True)   # e.g., session/verification id from provider
    kyc_country = db.Column(db.String(2), nullable=True)                      # optional: ISO 3166-1 alpha-2
    is_over_18 = db.Column(db.Boolean, nullable=True)

    kyc_created_at = db.Column(db.DateTime, default=datetime.utcnow)
    kyc_updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
