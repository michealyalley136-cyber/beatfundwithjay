from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

User = None
FundingRequest = None
Transaction = None
Loan = None
LoanPayment = None
VirtualCard = None

def create_models(db):
    global User, FundingRequest, Transaction, Loan, LoanPayment, VirtualCard

       class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(150), unique=True, nullable=False)
        email = db.Column(db.String(150), unique=True, nullable=False)
        password = db.Column(db.String(150), nullable=False)
        role = db.Column(db.String(50), nullable=False)
        wallet_balance = db.Column(db.Float, default=0.0)
        last_interest_date = db.Column(db.DateTime, default=datetime.utcnow)

        # KYC FIELDS
        full_name = db.Column(db.String(150), nullable=False)
        address = db.Column(db.String(200), nullable=False)
        ssn_last4 = db.Column(db.String(4))  # Only last 4 digits
        is_verified = db.Column(db.Boolean, default=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

    class FundingRequest(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        artist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        description = db.Column(db.Text, nullable=False)
        amount = db.Column(db.Float, nullable=False)
        status = db.Column(db.String(50), default='pending')
        approver_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    class Transaction(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        amount = db.Column(db.Float, nullable=False)
        type = db.Column(db.String(50), nullable=False)
        description = db.Column(db.String(200))
        date = db.Column(db.DateTime, default=datetime.utcnow)

    class Loan(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        amount = db.Column(db.Float, nullable=False)
        status = db.Column(db.String(50), default='pending')
        installments = db.Column(db.Integer, default=6)
        monthly_payment = db.Column(db.Float)
        project_type = db.Column(db.String(100))
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        interest_rate = db.Column(db.Float, default=0.10)

    class LoanPayment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=False)
        amount = db.Column(db.Float, nullable=False)
        due_date = db.Column(db.DateTime, nullable=False)
        paid = db.Column(db.Boolean, default=False)
        paid_at = db.Column(db.DateTime)

    class VirtualCard(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        card_number = db.Column(db.String(16), unique=True, nullable=False)
        cvv = db.Column(db.String(3), nullable=False)
        expiry = db.Column(db.String(5), nullable=False)  # MM/YY
        is_active = db.Column(db.Boolean, default=True)
        spending_limit = db.Column(db.Float, default=1000.0)
        spent = db.Column(db.Float, default=0.0)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

        def generate_card(self):
            import random
            self.card_number = '4' + ''.join([str(random.randint(0,9)) for _ in range(15)])
            self.cvv = ''.join([str(random.randint(0,9)) for _ in range(3)])
            month = f"{random.randint(1,12):02d}"
            year = str(random.randint(26, 30))
            self.expiry = f"{month}/{year}"

    return User, FundingRequest, Transaction, Loan, LoanPayment, VirtualCard