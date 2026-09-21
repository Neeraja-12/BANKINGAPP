from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from flask_socketio import SocketIO, emit, join_room, leave_room
from wtforms import StringField, PasswordField, BooleanField, FloatField, SelectField, DateField, TextAreaField, SubmitField, FileField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange, Email, Regexp, ValidationError, EqualTo
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import func, extract
from dotenv import load_dotenv
import os
import random
import uuid
import logging
import sys

# Load environment variables
load_dotenv()
# Fix for Vercel's postgres:// URL format
_db_url = os.environ.get('DATABASE_URL', '')
if _db_url.startswith('postgres://'):
    os.environ['DATABASE_URL'] = _db_url.replace('postgres://', 'postgresql://', 1)

# Fix recursion limit
sys.setrecursionlimit(2000)

# Initialize the Flask application
app = Flask(__name__)


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///bank_complete.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        'static', 'images', 'profile_pics'
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@flaskbank.com')

    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', SECRET_KEY)


app.config.from_object(Config)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
def setup_logging(app):
    app.logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)
    app.logger.addHandler(console)

    try:
        os.makedirs('logs', exist_ok=True)
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            'logs/bank.log', maxBytes=1_000_000, backupCount=5, delay=True
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
    except Exception as e:
        app.logger.warning(f'File logging disabled: {e}')


setup_logging(app)
app.logger.info('Bank application startup')


# ------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------
db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ------------------------------------------------------------------
# Custom Validators
# ------------------------------------------------------------------
def validate_password_strength(form, field):
    password = field.data or ''
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not any(c.isupper() for c in password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not any(c.islower() for c in password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not any(c.isdigit() for c in password):
        raise ValidationError('Password must contain at least one number.')


# ------------------------------------------------------------------
# Forms
# ------------------------------------------------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', [
        DataRequired(), Length(min=3, max=20),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = StringField('Email', [DataRequired(), Email(), Length(max=120)])
    account_number = StringField('Account Number', [
        DataRequired(), Length(min=8, max=20),
        Regexp('^[0-9]+$', message='Account number must contain only digits')
    ])
    password = PasswordField('Password', [DataRequired(), Length(min=8), validate_password_strength])
    confirm_password = PasswordField('Confirm Password', [
        DataRequired(), EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')


class CreditCardForm(FlaskForm):
    card_type = SelectField('Preferred Card Type', choices=[
        ('Visa Platinum', 'Visa Platinum'),
        ('Mastercard Gold', 'Mastercard Gold'),
        ('American Express', 'American Express'),
        ('RuPay', 'RuPay')
    ], validators=[DataRequired()])
    pan_number = StringField('PAN Number', [
        DataRequired(), Length(min=10, max=10),
        Regexp('^[A-Z]{5}[0-9]{4}[A-Z]{1}$', message='Invalid PAN number format')
    ])
    income = FloatField('Annual Income (₹)', validators=[DataRequired(), NumberRange(min=50000)])
    submit = SubmitField('Apply for Credit Card')


class LoanApplicationForm(FlaskForm):
    loan_amount = FloatField('Loan Amount (₹)', validators=[DataRequired(), NumberRange(min=1000, max=1000000)])
    tenure = SelectField('Tenure (Months)', choices=[
        (6, '6 Months'), (12, '1 Year'), (24, '2 Years'),
        (36, '3 Years'), (48, '4 Years'), (60, '5 Years')
    ], coerce=int, validators=[DataRequired()])
    loan_type = SelectField('Loan Type', choices=[
        ('Personal Loan', 'Personal Loan'),
        ('Home Loan', 'Home Loan'),
        ('Car Loan', 'Car Loan'),
        ('Education Loan', 'Education Loan'),
        ('Business Loan', 'Business Loan')
    ], validators=[DataRequired()])
    purpose = TextAreaField('Purpose', validators=[Length(max=500)])
    submit = SubmitField('Apply for Loan')


class BudgetForm(FlaskForm):
    category = SelectField('Category', choices=[
        ('Food & Dining', 'Food & Dining'), ('Shopping', 'Shopping'),
        ('Transportation', 'Transportation'), ('Entertainment', 'Entertainment'),
        ('Utilities', 'Utilities'), ('Healthcare', 'Healthcare'),
        ('Education', 'Education'), ('Other', 'Other')
    ], validators=[DataRequired()])
    amount = FloatField('Budget Amount (₹)', validators=[DataRequired(), NumberRange(min=1)])
    month = StringField('Month (YYYY-MM)', validators=[DataRequired(), Regexp(r'^\d{4}-\d{2}$')])
    submit = SubmitField('Set Budget')


class ProfilePictureForm(FlaskForm):
    photo = FileField('Upload New Photo', validators=[DataRequired()])
    submit = SubmitField('Upload Photo')


class SettingsForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Update Settings')


# ------------------------------------------------------------------
# Database Models
# ------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    profile_pic = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    transactions = db.relationship('Transaction', backref='user', lazy=True, cascade='all, delete-orphan')
    loan_applications = db.relationship('LoanApplication', backref='user', lazy=True, cascade='all, delete-orphan')
    credit_card_applications = db.relationship('CreditCardApplication', backref='user', lazy=True, cascade='all, delete-orphan')
    budgets = db.relationship('Budget', backref='user', lazy=True, cascade='all, delete-orphan')
    bills = db.relationship('Bill', backref='user', lazy=True, cascade='all, delete-orphan')
    investments = db.relationship('Investment', backref='user', lazy=True, cascade='all, delete-orphan')


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    reference_id = db.Column(db.String(50), unique=True)


class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    loan_amount = db.Column(db.Float, nullable=False)
    tenure = db.Column(db.Integer, nullable=False)
    loan_type = db.Column(db.String(200), nullable=False)
    purpose = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')
    applied_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    interest_rate = db.Column(db.Float, default=8.5)


class CreditCardApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    card_type = db.Column(db.String(100), nullable=False)
    pan_number = db.Column(db.String(20), nullable=False)
    income = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    applied_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    credit_limit = db.Column(db.Float)


class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    spent = db.Column(db.Float, default=0.0)
    month = db.Column(db.String(7), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def get_remaining(self):
        return max(0, self.amount - self.spent)

    def get_percentage_used(self):
        if self.amount > 0:
            return min(100, (self.spent / self.amount) * 100)
        return 0


class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    paid_date = db.Column(db.DateTime)


class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    amount_invested = db.Column(db.Float, nullable=False)
    current_value = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    quantity = db.Column(db.Float, default=1.0)
    symbol = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def get_profit_loss(self):
        return self.current_value - self.amount_invested

    def get_profit_loss_percentage(self):
        if self.amount_invested > 0:
            return ((self.current_value - self.amount_invested) / self.amount_invested) * 100
        return 0


# ------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def get_exchange_rates():
    try:
        import requests
        url = "https://api.exchangerate-api.com/v4/latest/USD"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.json().get('rates', {})
    except Exception:
        pass
    return {'INR': 83.0, 'EUR': 0.92, 'GBP': 0.81, 'JPY': 150.0, 'USD': 1.0}


def generate_reference_id():
    return f"REF{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"


def categorize_transaction(description):
    if not description:
        return 'Other'
    d = description.lower()
    categories = {
        'Food & Dining': ['food', 'restaurant', 'grocery', 'dining', 'cafe', 'coffee'],
        'Shopping': ['shopping', 'store', 'market', 'mall', 'amazon', 'flipkart'],
        'Transportation': ['transport', 'uber', 'taxi', 'fuel', 'petrol', 'bus'],
        'Utilities': ['bill', 'electricity', 'water', 'internet', 'mobile', 'phone'],
        'Entertainment': ['entertainment', 'movie', 'game', 'netflix', 'spotify'],
        'Healthcare': ['hospital', 'medical', 'doctor', 'pharmacy', 'medicine'],
        'Education': ['education', 'school', 'college', 'tuition', 'book'],
        'Income': ['salary', 'deposit', 'income', 'paycheck'],
    }
    for category, keywords in categories.items():
        if any(k in d for k in keywords):
            return category
    return 'Other'


def send_email(subject, recipient, body):
    """Send an email, or log it if mail isn't configured."""
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        app.logger.warning(
            f"Mail not configured. Would have sent to {recipient}:\n"
            f"Subject: {subject}\n{body}"
        )
        return True
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
    msg.body = body
    mail.send(msg)
    return True


def compute_balance_from_transactions(user_id):
    """
    Recompute the balance by summing all transactions.
    Used to verify the User.balance column hasn't drifted.
    """
    inflow = db.session.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.user_id == user_id,
        Transaction.type.in_(['Deposit', 'Transfer In', 'Income', 'Loan Disbursement'])
    ).scalar() or 0.0

    outflow = db.session.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
        Transaction.user_id == user_id,
        Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
    ).scalar() or 0.0

    return inflow - outflow


# ------------------------------------------------------------------
# Context Processor
# ------------------------------------------------------------------
@app.context_processor
def utility_processor():
    def format_currency(amount, currency='₹'):
        if amount is None:
            return f"{currency}0.00"
        return f"{currency}{amount:,.2f}"
    return {'format_currency': format_currency, 'now': datetime.now}


# ------------------------------------------------------------------
# Error Handlers
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    try:
        return render_template('404.html'), 404
    except Exception:
        return "404 Not Found", 404


@app.errorhandler(500)
def internal_error(error):
    try:
        db.session.rollback()
    except Exception:
        pass
    app.logger.error(f'Internal Server Error: {error}')
    try:
        return render_template('500.html'), 500
    except Exception:
        return "500 Internal Server Error", 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.exception('Unhandled exception')
    try:
        db.session.rollback()
    except Exception:
        pass
    try:
        return render_template('500.html'), 500
    except Exception:
        return "500 Internal Server Error", 500


# ------------------------------------------------------------------
# Security Headers
# ------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# ------------------------------------------------------------------
# SocketIO
# ------------------------------------------------------------------
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists!', 'danger')
                return render_template('register.html', form=form)
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered!', 'danger')
                return render_template('register.html', form=form)
            if User.query.filter_by(account_number=form.account_number.data).first():
                flash('Account number already exists!', 'danger')
                return render_template('register.html', form=form)

            otp = str(random.randint(100000, 999999))
            expiry = datetime.now() + timedelta(minutes=5)

            session['otp'] = otp
            session['otp_expiry'] = expiry.strftime('%Y-%m-%d %H:%M:%S')
            session['reg_username'] = form.username.data
            session['reg_email'] = form.email.data
            session['reg_account_number'] = form.account_number.data
            session['reg_password'] = generate_password_hash(form.password.data)

            body = f"Hello {form.username.data},\n\nYour OTP is: {otp}\n\nThis code will expire in 5 minutes."
            try:
                send_email('Your OTP Code', form.email.data, body)
                flash('OTP sent to your email. Please verify.', 'info')
                return redirect(url_for('verify_otp'))
            except Exception as e:
                app.logger.error(f'Failed to send OTP email: {e}')
                flash('Failed to send verification email. Please try again.', 'danger')

        except IntegrityError:
            db.session.rollback()
            flash('Registration failed. Please try different values.', 'danger')
        except Exception as e:
            app.logger.error(f'Registration error: {e}')
            flash('An unexpected error occurred. Please try again.', 'danger')
    return render_template('register.html', form=form)


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        stored_otp = session.get('otp')
        expiry_str = session.get('otp_expiry')

        if not stored_otp or not expiry_str:
            flash('OTP session expired. Please register again.', 'danger')
            return redirect(url_for('register'))

        try:
            expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            flash('Invalid session. Please register again.', 'danger')
            return redirect(url_for('register'))

        if datetime.now() > expiry:
            flash('OTP expired. Please register again.', 'danger')
            return redirect(url_for('register'))

        if entered_otp == stored_otp:
            new_user = User(
                username=session['reg_username'],
                email=session['reg_email'],
                account_number=session['reg_account_number'],
                password=session['reg_password'],
                balance=10000.00
            )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f'New user registered: {session["reg_username"]}')
            flash('Account created successfully! Please login.', 'success')
            session.clear()
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP, please try again.', 'danger')

    return render_template('verify_otp.html')


@app.route('/resend_otp')
def resend_otp():
    if 'reg_email' not in session:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('register'))

    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=5)
    session['otp'] = otp
    session['otp_expiry'] = expiry.strftime('%Y-%m-%d %H:%M:%S')

    body = f"Hello {session['reg_username']},\n\nYour new OTP is: {otp}\n\nThis code will expire in 5 minutes."
    try:
        send_email('Your New OTP Code', session['reg_email'], body)
        flash('A new OTP has been sent to your email.', 'info')
    except Exception as e:
        app.logger.error(f'Failed to resend OTP email: {e}')
        flash('Failed to send OTP email. Please try again.', 'danger')

    return redirect(url_for('verify_otp'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.is_active and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            app.logger.info(f'User {user.username} logged in successfully')
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            app.logger.warning(f'Failed login attempt for username: {form.username.data}')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    app.logger.info(f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    try:
        transactions = Transaction.query.filter_by(
            user_id=current_user.id
        ).order_by(Transaction.date.desc()).limit(5).all()

        current_month = datetime.now().strftime('%Y-%m')
        now = datetime.now()
        exchange_rates = get_exchange_rates()

        # Gross totals
        total_deposits = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id,
            Transaction.type.in_(['Deposit', 'Transfer In', 'Income', 'Loan Disbursement'])
        ).scalar() or 0.0

        total_withdrawals = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id,
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
        ).scalar() or 0.0

        # NET FLOW — this is what you asked for
        # Every withdrawal reduces this number automatically.
        net_flow = total_deposits - total_withdrawals

        spending_by_category = db.session.query(
            Transaction.category,
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == current_user.id,
            extract('year', Transaction.date) == now.year,
            extract('month', Transaction.date) == now.month,
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
        ).group_by(Transaction.category).all()

        upcoming_bills = Bill.query.filter(
            Bill.user_id == current_user.id,
            Bill.is_paid == False,
            Bill.due_date >= now.date(),
            Bill.due_date <= now.date() + timedelta(days=30)
        ).order_by(Bill.due_date).limit(5).all()

        # Reconciliation: warn if User.balance has drifted from transactions
        computed = compute_balance_from_transactions(current_user.id)
        if abs(computed - current_user.balance) > 0.01:
            app.logger.warning(
                f'Balance drift for {current_user.username}: '
                f'stored={current_user.balance:.2f}, computed={computed:.2f}'
            )

        return render_template(
            'dashboard.html',
            balance=current_user.balance,
            exchange_rates=exchange_rates,
            transactions=transactions,
            total_deposits=total_deposits,
            total_withdrawals=total_withdrawals,
            net_flow=net_flow,
            spending_by_category=spending_by_category,
            upcoming_bills=upcoming_bills,
            current_month=current_month
        )
    except Exception as e:
        app.logger.exception(f'Dashboard error for user {current_user.username}')
        flash('Error loading dashboard data', 'danger')
        return render_template(
            'dashboard.html',
            balance=current_user.balance,
            exchange_rates={'INR': 83.0, 'EUR': 0.92, 'GBP': 0.81, 'JPY': 150.0, 'USD': 1.0},
            transactions=[], total_deposits=0.0, total_withdrawals=0.0, net_flow=0.0,
            spending_by_category=[], upcoming_bills=[],
            current_month=datetime.now().strftime('%Y-%m')
        )


@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    try:
        amount = float(request.form.get('amount', 0))
        description = request.form.get('description', 'Deposit')
        if amount <= 0:
            flash('Amount must be greater than zero.', 'danger')
        else:
            current_user.balance += amount
            db.session.add(Transaction(
                user_id=current_user.id, type='Deposit', amount=amount,
                description=description, category='Income',
                reference_id=generate_reference_id()
            ))
            db.session.commit()
            socketio.emit('balance_update',
                          {'user_id': current_user.id, 'balance': current_user.balance},
                          room=f'user_{current_user.id}')
            flash(f'Successfully deposited ₹{amount:,.2f}', 'success')
    except ValueError:
        db.session.rollback()
        flash('Invalid amount entered.', 'danger')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Deposit error')
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        amount = float(request.form.get('amount', 0))
        description = request.form.get('description', 'Withdrawal')
        category = categorize_transaction(description)
        if amount <= 0:
            flash('Amount must be greater than zero.', 'danger')
        elif amount > current_user.balance:
            flash('Insufficient funds.', 'danger')
        else:
            current_user.balance -= amount
            db.session.add(Transaction(
                user_id=current_user.id, type='Withdraw', amount=amount,
                description=description, category=category,
                reference_id=generate_reference_id()
            ))
            current_month = datetime.now().strftime('%Y-%m')
            budget = Budget.query.filter_by(
                user_id=current_user.id, category=category, month=current_month
            ).first()
            if budget:
                budget.spent += amount
                if budget.spent > budget.amount:
                    flash(f'Warning: You have exceeded your {category} budget!', 'warning')
            db.session.commit()
            socketio.emit('balance_update',
                          {'user_id': current_user.id, 'balance': current_user.balance},
                          room=f'user_{current_user.id}')
            flash(f'Successfully withdrew ₹{amount:,.2f}', 'success')
    except ValueError:
        db.session.rollback()
        flash('Invalid amount entered.', 'danger')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Withdrawal error')
        flash('An error occurred. Please try again.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    try:
        amount = float(request.form.get('amount', 0))
        recipient_account = request.form.get('recipient_account')
        description = request.form.get('description', 'Fund Transfer')
        if amount <= 0:
            flash('Amount must be greater than zero.', 'danger')
        elif amount > current_user.balance:
            flash('Insufficient funds for transfer.', 'danger')
        elif recipient_account == current_user.account_number:
            flash('Cannot transfer funds to your own account.', 'danger')
        else:
            recipient = User.query.filter_by(account_number=recipient_account).first()
            if not recipient:
                flash(f'Recipient account {recipient_account} not found.', 'danger')
            else:
                current_user.balance -= amount
                recipient.balance += amount
                ref_id = generate_reference_id()
                db.session.add(Transaction(
                    user_id=current_user.id, type='Transfer Out', amount=amount,
                    description=f'Transfer to A/C {recipient_account} - {description}',
                    category='Transfer', reference_id=ref_id
                ))
                db.session.add(Transaction(
                    user_id=recipient.id, type='Transfer In', amount=amount,
                    description=f'Transfer from A/C {current_user.account_number} - {description}',
                    category='Income', reference_id=ref_id
                ))
                db.session.commit()
                socketio.emit('balance_update',
                              {'user_id': current_user.id, 'balance': current_user.balance},
                              room=f'user_{current_user.id}')
                socketio.emit('balance_update',
                              {'user_id': recipient.id, 'balance': recipient.balance},
                              room=f'user_{recipient.id}')
                flash(f'Successfully transferred ₹{amount:,.2f} to account {recipient_account}', 'success')
    except ValueError:
        db.session.rollback()
        flash('Invalid amount entered.', 'danger')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Transfer error')
        flash('An error occurred during transfer. Please try again.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/transactions')
@login_required
def transactions_history():
    page = request.args.get('page', 1, type=int)
    transactions = Transaction.query.filter_by(
        user_id=current_user.id
    ).order_by(Transaction.date.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template('transactions.html', transactions=transactions)


app.add_url_rule('/transactions-history', endpoint='transactions', view_func=transactions_history)


@app.route('/apply/loan', methods=['GET', 'POST'])
@login_required
def apply_loan():
    form = LoanApplicationForm()
    if form.validate_on_submit():
        try:
            if form.loan_amount.data <= current_user.balance * 2:
                status = 'Approved'
                flash_msg = 'Congratulations! Your loan application has been approved!'
                current_user.balance += form.loan_amount.data
                db.session.add(Transaction(
                    user_id=current_user.id, type='Loan Disbursement',
                    amount=form.loan_amount.data,
                    description=f'{form.loan_type.data} Approved',
                    category='Income', reference_id=generate_reference_id()
                ))
            else:
                status = 'Pending'
                flash_msg = 'Your loan application is under review.'
            db.session.add(LoanApplication(
                user_id=current_user.id, loan_amount=form.loan_amount.data,
                tenure=form.tenure.data, loan_type=form.loan_type.data,
                purpose=form.purpose.data, status=status
            ))
            db.session.commit()
            flash(flash_msg, 'success' if status == 'Approved' else 'info')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Loan application error')
            flash('An error occurred during application.', 'danger')
    applications = LoanApplication.query.filter_by(user_id=current_user.id).all()
    return render_template('apply_loan.html', form=form, applications=applications)


@app.route('/apply/credit_card', methods=['GET', 'POST'])
@login_required
def apply_credit_card():
    form = CreditCardForm()
    if form.validate_on_submit():
        try:
            if form.income.data >= 300000:
                status = 'Approved'
                credit_limit = form.income.data * 0.5
                flash_msg = 'Congratulations! Your credit card application has been approved!'
            else:
                status = 'Pending'
                credit_limit = form.income.data * 0.2
                flash_msg = 'Your credit card application is under review.'
            db.session.add(CreditCardApplication(
                user_id=current_user.id, card_type=form.card_type.data,
                pan_number=form.pan_number.data, income=form.income.data,
                status=status, credit_limit=credit_limit
            ))
            db.session.commit()
            flash(flash_msg, 'success' if status == 'Approved' else 'info')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Credit card application error')
            flash('An error occurred during application.', 'danger')
    applications = CreditCardApplication.query.filter_by(user_id=current_user.id).all()
    return render_template('credit_card.html', form=form, applications=applications)


@app.route('/budgets', methods=['GET', 'POST'])
@login_required
def budgets():
    form = BudgetForm()
    current_month = datetime.now().strftime('%Y-%m')
    if form.validate_on_submit():
        try:
            existing = Budget.query.filter_by(
                user_id=current_user.id, category=form.category.data, month=form.month.data
            ).first()
            if existing:
                existing.amount = form.amount.data
                flash(f'Budget for {form.category.data} updated.', 'success')
            else:
                db.session.add(Budget(
                    user_id=current_user.id, category=form.category.data,
                    amount=form.amount.data, month=form.month.data
                ))
                flash(f'New budget for {form.category.data} created.', 'success')
            db.session.commit()
            return redirect(url_for('budgets'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Budget error')
            flash('An error occurred.', 'danger')
    budgets = Budget.query.filter_by(user_id=current_user.id).order_by(Budget.month.desc()).all()
    return render_template('budgets.html', form=form, budgets=budgets, current_month=current_month)


@app.route('/profile')
@login_required
def profile():
    form = ProfilePictureForm()
    return render_template('profile.html', form=form)


app.add_url_rule('/profile-view', endpoint='profile_view', view_func=profile)


@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'photo' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    file = request.files['photo']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    if file and allowed_file(file.filename):
        try:
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{current_user.id}_{uuid.uuid4().hex}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            if current_user.profile_pic and current_user.profile_pic != 'default.jpg':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic)
                if os.path.exists(old_path):
                    os.remove(old_path)
            current_user.profile_pic = filename
            db.session.commit()
            flash('Profile picture updated successfully!', 'success')
        except Exception as e:
            app.logger.exception('Profile picture upload error')
            flash('Error uploading file. Please try again.', 'danger')
    else:
        flash('Invalid file type. Allowed: png, jpg, jpeg, gif', 'danger')
    return redirect(url_for('profile'))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    if request.method == 'GET':
        form.email.data = current_user.email
        form.username.data = current_user.username
    if form.validate_on_submit():
        try:
            if form.email.data != current_user.email:
                if User.query.filter_by(email=form.email.data).first():
                    flash('Email already registered by another user.', 'danger')
                    return render_template('settings.html', form=form)
                current_user.email = form.email.data
            if form.username.data != current_user.username:
                if User.query.filter_by(username=form.username.data).first():
                    flash('Username already taken by another user.', 'danger')
                    return render_template('settings.html', form=form)
                current_user.username = form.username.data
            if form.new_password.data:
                if not form.current_password.data:
                    flash('Current password is required to change password.', 'danger')
                    return render_template('settings.html', form=form)
                if not check_password_hash(current_user.password, form.current_password.data):
                    flash('Current password is incorrect.', 'danger')
                    return render_template('settings.html', form=form)
                current_user.password = generate_password_hash(form.new_password.data)
                flash('Password updated successfully.', 'success')
            db.session.commit()
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Settings update error')
            flash('An error occurred while updating settings.', 'danger')
    return render_template('settings.html', form=form)


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        user = db.session.get(User, current_user.id)
        logout_user()
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been successfully deleted.', 'info')
    except Exception as e:
        app.logger.exception('Account deletion error')
        flash('An error occurred while deleting your account.', 'danger')
    return redirect(url_for('register'))


@app.route('/bills', methods=['GET', 'POST'])
@login_required
def bills():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            amount = float(request.form.get('amount'))
            due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%d').date()
            category = request.form.get('category')
            db.session.add(Bill(
                user_id=current_user.id, name=name, amount=amount,
                due_date=due_date, category=category
            ))
            db.session.commit()
            flash(f'Bill "{name}" added successfully.', 'success')
            return redirect(url_for('bills'))
        except Exception as e:
            db.session.rollback()
            app.logger.exception('Bill creation error')
            flash('An error occurred while adding the bill.', 'danger')
    upcoming_bills = Bill.query.filter_by(user_id=current_user.id, is_paid=False).order_by(Bill.due_date).all()
    paid_bills = Bill.query.filter_by(user_id=current_user.id, is_paid=True).order_by(Bill.due_date.desc()).limit(5).all()
    return render_template('bills.html', upcoming_bills=upcoming_bills, paid_bills=paid_bills)


@app.route('/pay_bill/<int:bill_id>', methods=['POST'])
@login_required
def pay_bill(bill_id):
    try:
        bill = Bill.query.filter_by(id=bill_id, user_id=current_user.id, is_paid=False).first()
        if not bill:
            flash('Bill not found or already paid.', 'danger')
            return redirect(url_for('bills'))
        if current_user.balance < bill.amount:
            flash('Insufficient balance to pay this bill.', 'danger')
            return redirect(url_for('bills'))
        current_user.balance -= bill.amount
        bill.is_paid = True
        bill.paid_date = datetime.now(timezone.utc)
        db.session.add(Transaction(
            user_id=current_user.id, type='Bill Payment', amount=bill.amount,
            description=f'Payment for {bill.name}', category=bill.category,
            reference_id=generate_reference_id()
        ))
        db.session.commit()
        socketio.emit('balance_update',
                      {'user_id': current_user.id, 'balance': current_user.balance},
                      room=f'user_{current_user.id}')
        flash(f'Successfully paid bill "{bill.name}" for ₹{bill.amount:,.2f}.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Bill payment error')
        flash('An error occurred during bill payment.', 'danger')
    return redirect(url_for('bills'))


@app.route('/spending')
@login_required
def spending():
    now = datetime.now()
    current_month = now.strftime('%Y-%m')
    try:
        spending_by_category = db.session.query(
            Transaction.category,
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == current_user.id,
            extract('year', Transaction.date) == now.year,
            extract('month', Transaction.date) == now.month,
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
        ).group_by(Transaction.category).all()

        total_spent = sum((t or 0) for _, t in spending_by_category)

        # Month-over-month: last 6 months
        monthly_totals = []
        for i in range(5, -1, -1):
            m = now - timedelta(days=30 * i)
            total = db.session.query(func.coalesce(func.sum(Transaction.amount), 0.0)).filter(
                Transaction.user_id == current_user.id,
                extract('year', Transaction.date) == m.year,
                extract('month', Transaction.date) == m.month,
                Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
            ).scalar() or 0.0
            monthly_totals.append((m.strftime('%b'), total))

        return render_template(
            'spending.html',
            spending_by_category=spending_by_category,
            total_spent=total_spent,
            current_month=current_month,
            monthly_totals=monthly_totals,
        )
    except Exception as e:
        app.logger.exception('Spending page error')
        flash('Error loading spending data', 'danger')
        return render_template(
            'spending.html',
            spending_by_category=[], total_spent=0,
            current_month=current_month, monthly_totals=[]
        )


@app.route('/exchange-rates')
@login_required
def exchange_rates():
    rates = get_exchange_rates()
    return render_template('exchange_rates.html', rates=rates, current_month=datetime.now().strftime('%B %Y'))


# ------------------------------------------------------------------
# Database initialization
# ------------------------------------------------------------------
with app.app_context():
    try:
        db.create_all()
        if not User.query.first():
            db.session.add(User(
                username='admin',
                email='admin@bank.com',
                account_number='1234567890',
                password=generate_password_hash('Admin@123'),
                balance=1000000.00,
                profile_pic='default.jpg'
            ))
            db.session.commit()
            app.logger.info('Default admin user created')
    except Exception as e:
        app.logger.exception('DB init failed')


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Flask Banking Application Starting...")
    print("=" * 60)
    print("📊 Access your application at: http://localhost:5000")
    print("🔑 Default admin login - Username: admin, Password: Admin@123")
    print("=" * 60)
    socketio.run(app, debug=True, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)