<<<<<<< HEAD
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import uuid
import re
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import requests
import json
from flask_wtf import FlaskForm, CSRFProtect
from flask_socketio import SocketIO, emit, join_room, leave_room
from wtforms import StringField, PasswordField, BooleanField, FloatField, SelectField, DateField, TextAreaField, SubmitField, FileField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange, Email, Regexp, ValidationError, EqualTo
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from dotenv import load_dotenv
import secrets
import sys
from functools import wraps
from sqlalchemy import func

# Load environment variables
load_dotenv()

# Fix recursion limit
sys.setrecursionlimit(2000)

# Initialize the Flask application
app = Flask(__name__)

# Configuration - HTTP only, no SSL
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-' + secrets.token_hex(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///bank_complete.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'images', 'profile_pics')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@flaskbank.com')
    
    # Security settings - HTTP for development
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # CSRF settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'csrf-secret-key-' + secrets.token_hex(32))

app.config.from_object(Config)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)
csrf = CSRFProtect(app)

# Flask-Login Setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = "strong"
=======
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm, CreditCardForm # Assuming forms.py exists with these classes
import os
import random, datetime
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import requests

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'images', 'profile_pics')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- WARNING: Use environment variables for sensitive info in production ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'neerajan340@gmail.com' # Your email
app.config['MAIL_PASSWORD'] = 'xodd chmo bnkp fbku' # Your App password

mail = Mail(app)

# --- Database and Flask-Login Setup ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

<<<<<<< HEAD
# Setup logging
file_handler = RotatingFileHandler('logs/bank.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Bank application startup')

# Custom Validators
def validate_password_strength(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not any(c.isupper() for c in password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not any(c.islower() for c in password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not any(c.isdigit() for c in password):
        raise ValidationError('Password must contain at least one number.')

def validate_account_number(form, field):
    account_number = field.data
    if not account_number.isdigit():
        raise ValidationError('Account number must contain only digits.')
    if len(account_number) < 8 or len(account_number) > 20:
        raise ValidationError('Account number must be between 8 and 20 digits.')

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        DataRequired(),
        Length(min=3, max=20),
        Regexp('^[A-Za-z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    email = StringField('Email', [
        DataRequired(),
        Email(),
        Length(max=120)
    ])
    account_number = StringField('Account Number', [
        DataRequired(),
        Length(min=8, max=20),
        Regexp('^[0-9]+$', message='Account number must contain only digits')
    ])
    password = PasswordField('Password', [
        DataRequired(),
        Length(min=8),
        validate_password_strength
    ])
    confirm_password = PasswordField('Confirm Password', [
        DataRequired(),
        Length(min=8),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class CreditCardForm(FlaskForm):
    card_type = SelectField('Preferred Card Type', choices=[
        ('Visa Platinum', 'Visa Platinum (High Limit)'), 
        ('Mastercard Gold', 'Mastercard Gold (Moderate Limit)'), 
        ('American Express Green', 'American Express Green (Travel Focus)'),
        ('RuPay Classic', 'RuPay Classic (Entry Level)')
    ], validators=[DataRequired()])
    pan_number = StringField('PAN Number', [
        DataRequired(), 
        Length(min=10, max=10),
        Regexp('^[A-Z]{5}[0-9]{4}[A-Z]{1}$', message='Invalid PAN number format (e.g., ABCDE1234F)')
    ])
    income = FloatField('Annual Income (₹)', validators=[DataRequired(), NumberRange(min=50000, message="Minimum annual income is ₹50,000")])
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
        ('Food & Dining', 'Food & Dining'),
        ('Shopping', 'Shopping'),
        ('Transportation', 'Transportation'),
        ('Entertainment', 'Entertainment'),
        ('Utilities', 'Utilities'),
        ('Healthcare', 'Healthcare'),
        ('Education', 'Education'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    amount = FloatField('Budget Amount (₹)', validators=[DataRequired(), NumberRange(min=1)])
    month = StringField('Month (YYYY-MM)', validators=[DataRequired(), Regexp('^\\d{4}-\\d{2}$', message='Format: YYYY-MM')])
    submit = SubmitField('Set Budget')

class CardManagementForm(FlaskForm):
    card_holder = StringField('Card Holder Name', validators=[DataRequired(), Length(max=100)])
    card_number = StringField('Card Number', validators=[DataRequired(), Length(min=16, max=16), Regexp('^[0-9]+$', message='Only digits allowed')])
    expiry_date = StringField('Expiry (MM/YY)', validators=[DataRequired(), Regexp(r'^(0[1-9]|1[0-2])\/(\d{2})$', message='Format: MM/YY')])
    cvv = StringField('CVV', validators=[DataRequired(), Length(min=3, max=4), Regexp('^[0-9]+$', message='Only digits allowed')])
    bank_name = StringField('Issuing Bank', validators=[DataRequired(), Length(max=100)])
    credit_limit = FloatField('Credit Limit (₹) (Optional)', default=0.0)
    submit = SubmitField('Add Card for Tracking')

class BillForm(FlaskForm):
    name = StringField('Bill Name', validators=[DataRequired(), Length(max=100)])
    amount = FloatField('Amount (₹)', validators=[DataRequired(), NumberRange(min=1)])
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('Rent', 'Rent/Mortgage'),
        ('Electricity', 'Electricity'),
        ('Internet', 'Internet'),
        ('Water', 'Water'),
        ('Phone', 'Phone Bill'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    submit = SubmitField('Add Bill')

class InvestmentForm(FlaskForm):
    name = StringField('Investment Name', validators=[DataRequired(), Length(max=100)])
    type = SelectField('Type', choices=[
        ('Stock', 'Stock'),
        ('Mutual Fund', 'Mutual Fund'),
        ('Fixed Deposit', 'Fixed Deposit'),
        ('Real Estate', 'Real Estate'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    amount_invested = FloatField('Amount Invested (₹)', validators=[DataRequired(), NumberRange(min=1)])
    quantity = FloatField('Quantity (e.g., number of shares)', default=1.0)
    purchase_date = DateField('Purchase Date', format='%Y-%m-%d', validators=[DataRequired()])
    symbol = StringField('Symbol (e.g., GOOGL, Optional)', default='')
    submit = SubmitField('Add Investment')

class ProfilePictureForm(FlaskForm):
    photo = FileField('Upload New Photo', validators=[DataRequired()])
    submit = SubmitField('Upload Photo')

class SettingsForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Update Settings')

# Database Models
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

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    reference_id = db.Column(db.String(50), unique=True)

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    loan_amount = db.Column(db.Float, nullable=False)
    tenure = db.Column(db.Integer, nullable=False)
    loan_type = db.Column(db.String(200), nullable=False)
    purpose = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pending')
    applied_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    interest_rate = db.Column(db.Float, default=8.5)

class CreditCardApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
=======
# --- Database Models (no changes needed) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    profile_pic = db.Column(db.String(200), nullable=True, default='default.jpg')
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    loan_applications = db.relationship('LoanApplication', backref='user', lazy=True)
    credit_card_applications = db.relationship('CreditCardApplication', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    tenure = db.Column(db.Integer, nullable=False)
    loan_type = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    applied_date = db.Column(db.DateTime, default=datetime.utcnow)

class CreditCardApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
    card_type = db.Column(db.String(100), nullable=False)
    pan_number = db.Column(db.String(20), nullable=False)
    income = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Pending')
<<<<<<< HEAD
    applied_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    credit_limit = db.Column(db.Float)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
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
    
    def is_over_budget(self):
        return self.spent > self.amount

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    bank_name = db.Column(db.String(100), nullable=False)
    card_holder = db.Column(db.String(100), nullable=False)
    card_number = db.Column(db.String(20), nullable=False)
    expiry_date = db.Column(db.String(7), nullable=False)
    cvv = db.Column(db.String(3), nullable=False)
    card_type = db.Column(db.String(20), nullable=False)
    network = db.Column(db.String(20), nullable=False)
    credit_limit = db.Column(db.Float, default=0.0)
    used_amount = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    paid_date = db.Column(db.DateTime)

class Investment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
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

# Service Classes & Helpers
class CardService:
    @staticmethod
    def mask_card_number(card_number):
        if len(card_number) >= 4:
            return f"**** **** **** {card_number[-4:]}"
        return card_number
    
    @staticmethod
    def get_card_network(card_number):
        if card_number.startswith('4'):
            return 'Visa'
        elif card_number.startswith(('51', '52', '53', '54', '55')):
            return 'Mastercard'
        elif card_number.startswith(('34', '37')):
            return 'American Express'
        elif card_number.startswith(('60', '65', '81', '82')):
            return 'RuPay'
        else:
            return 'Unknown'
            
    @staticmethod
    def generate_simulated_card_details(card_type):
        if 'Visa' in card_type:
            prefix = '4'
            limit = 150000.0 if 'Platinum' in card_type else 50000.0
        elif 'Mastercard' in card_type:
            prefix = '54'
            limit = 100000.0 if 'Gold' in card_type else 40000.0
        elif 'American Express' in card_type:
            prefix = '37'
            limit = 200000.0
        elif 'RuPay' in card_type:
            prefix = '60'
            limit = 30000.0
        else:
            prefix = '9'
            limit = 20000.0

        card_number = prefix + ''.join([str(random.randint(0, 9)) for _ in range(16 - len(prefix))])
        current_year = datetime.now().year % 100
        expiry_month = random.randint(1, 12)
        expiry_year = current_year + random.randint(3, 5)
        expiry_date = f"{expiry_month:02d}/{expiry_year}"
        cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])
        
        return card_number, expiry_date, cvv, limit

class InvestmentService:
    @staticmethod
    def calculate_current_value(investment):
        days_since_purchase = (datetime.now(timezone.utc).date() - investment.purchase_date).days
        if days_since_purchase <= 0:
            return investment.amount_invested
        
        volatility = 0.0005 * days_since_purchase
        change = random.uniform(-volatility, volatility)
        change = max(change, -0.1)
        
        return investment.amount_invested * (1 + change)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_exchange_rates():
    try:
        url = "https://api.exchangerate-api.com/v4/latest/USD"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get('rates', {})
    except:
        pass
    return {'INR': 83.0, 'EUR': 0.92, 'GBP': 0.81, 'JPY': 150.0, 'USD': 1.0}

def categorize_transaction(description):
    if not description:
        return 'Other'
    
    description_lower = description.lower()
    
    categories = {
        'Food & Dining': ['food', 'restaurant', 'grocery', 'dining', 'cafe', 'coffee', 'mcdonalds'],
        'Shopping': ['shopping', 'store', 'market', 'mall', 'amazon', 'flipkart', 'retail'],
        'Transportation': ['transport', 'uber', 'taxi', 'fuel', 'petrol', 'bus', 'train', 'metro'],
        'Utilities': ['bill', 'electricity', 'water', 'internet', 'mobile', 'phone', 'utility'],
        'Entertainment': ['entertainment', 'movie', 'game', 'netflix', 'spotify', 'cinema'],
        'Healthcare': ['hospital', 'medical', 'doctor', 'pharmacy', 'medicine', 'clinic'],
        'Education': ['education', 'school', 'college', 'tuition', 'book', 'course'],
        'Transfer': ['transfer', 'p2p', 'from', 'to'],
        'Income': ['salary', 'deposit', 'income', 'paycheck'],
    }
    
    for category, keywords in categories.items():
        if any(keyword in description_lower for keyword in keywords):
            return category
    
    return 'Other'

def generate_reference_id():
    return f"REF{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"

# Context Processor
@app.context_processor
def utility_processor():
    def format_currency(amount, currency='₹'):
        if amount is None:
            return f"{currency}0.00"
        return f"{currency}{amount:,.2f}"
    
    return {
        'format_currency': format_currency,
        'now': datetime.now,
        'CardService': CardService
    }

# Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #e74c3c; }
            a { color: #3498db; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>404 - Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    </body>
    </html>
    """, 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Internal Server Error: {error}')
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>500 - Internal Server Error</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #e74c3c; }
            a { color: #3498db; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>500 - Internal Server Error</h1>
        <p>Something went wrong on our end. Please try again later.</p>
        <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    </body>
    </html>
    """, 500

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 16MB.', 'danger')
    return redirect(request.url)

@app.errorhandler(400)
def bad_request(error):
    if 'CSRF token' in str(error):
        flash('Session expired (CSRF token missing/invalid). Please log in again.', 'danger')
        return redirect(url_for('login'))
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>400 - Bad Request</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #e74c3c; }
            a { color: #3498db; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>400 - Bad Request</h1>
        <p>Invalid request. Please check your input and try again.</p>
        <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    </body>
    </html>
    """, 400

@app.errorhandler(405)
def method_not_allowed(error):
    flash('Invalid request method. Please try again.', 'warning')
    return redirect(url_for('dashboard'))

@app.errorhandler(RecursionError)
def handle_recursion_error(error):
    app.logger.error(f'Recursion error: {error}')
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>500 - Server Error</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            h1 { color: #e74c3c; }
            a { color: #3498db; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>500 - Server Configuration Error</h1>
        <p>Server configuration error. Please try again later.</p>
        <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    </body>
    </html>
    """, 500

# Security Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# WebSocket Handlers
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        emit('balance_update', {
            'user_id': current_user.id,
            'balance': current_user.balance,
            'message': 'Connected successfully'
        }, room=f'user_{current_user.id}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')

# Routes
=======
    applied_date = db.Column(db.DateTime, default=datetime.utcnow)

class CreditCardTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey('credit_card_application.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))
    merchant = db.Column(db.String(100))

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_exchange_rates():
    """Fetches exchange rates from a public API."""
    url = "https://open.er-api.com/v6/latest/USD"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get('rates', {})
    except requests.exceptions.RequestException as e:
        print(f"Error fetching exchange rates: {e}")
        return None

# --- Application Context Processor ---
@app.context_processor
def utility_processor():
    def static_file_exists(filepath):
        return os.path.exists(os.path.join(app.root_path, 'static', filepath))
    return dict(static_file_exists=static_file_exists)

# --- Routes ---
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
@app.route('/')
def home():
    return render_template('home.html')

<<<<<<< HEAD
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
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
            
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                account_number=form.account_number.data,
                password=generate_password_hash(form.password.data),
                balance=10000.00
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            app.logger.info(f'New user registered: {form.username.data}')
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
        except IntegrityError:
            db.session.rollback()
            flash('A unique constraint violation occurred during registration. Try different values.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {e}')
            flash('An unexpected error occurred. Please try again.', 'danger')
    
    return render_template('register.html', form=form)
=======
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        account_number = form.account_number.data
        password = generate_password_hash(form.password.data)

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(account_number=account_number).first():
            flash('Account number already used!', 'danger')
            return redirect(url_for('register'))

        otp = str(random.randint(100000, 999999))
        expiry = datetime.now() + timedelta(minutes=5)

        session['otp'] = otp
        session['otp_expiry'] = expiry.strftime('%Y-%m-%d %H:%M:%S')
        session['username'] = username
        session['email'] = email
        session['account_number'] = account_number
        session['password'] = password

        msg = Message('Your OTP Code',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Hello {username},\n\nYour OTP is: {otp}\n\nThis code will expire in 5 minutes."
        try:
            mail.send(msg)
            flash('OTP sent to your email. Please verify.', 'info')
        except Exception as e:
            flash(f'Failed to send OTP email: {e}. Please check your mail settings.', 'danger')
            print(f"Mail error: {e}")
        
        return redirect(url_for('verify_otp'))

    return render_template('register.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        stored_otp = session.get('otp')
        expiry_str = session.get('otp_expiry')

        if not stored_otp or not expiry_str:
            flash('OTP not found. Please register again.', 'danger')
            return redirect(url_for('register'))

        expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')

        if datetime.now() > expiry:
            flash('OTP expired. Please resend.', 'danger')
            return redirect(url_for('verify_otp'))

        if entered_otp == stored_otp:
            new_user = User(
                username=session['username'],
                account_number=session['account_number'],
                password=session['password']
            )
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! Please login.', 'success')
            session.clear()
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP, please try again.', 'danger')

    return render_template('verify_otp.html')

@app.route('/resend_otp')
def resend_otp():
    if 'email' not in session:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('register'))

    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=5)

    session['otp'] = otp
    session['otp_expiry'] = expiry.strftime('%Y-%m-%d %H:%M:%S')

    msg = Message('Your New OTP Code',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[session['email']])
    msg.body = f"Hello {session['username']},\n\nYour new OTP is: {otp}\n\nThis code will expire in 5 minutes."
    try:
        mail.send(msg)
        flash('A new OTP has been sent to your email.', 'info')
    except Exception as e:
        flash(f'Failed to send OTP email: {e}. Please check your mail settings.', 'danger')
        print(f"Mail error: {e}")

    return redirect(url_for('verify_otp'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        account_number = form.account_number.data
        password = form.password.data
        user = User.query.filter_by(account_number=account_number).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        user_to_delete = User.query.get(current_user.id)
        if user_to_delete:
            logout_user()
            db.session.delete(user_to_delete)
            db.session.commit()
            flash("Your account has been successfully deleted.", "info")
            return redirect(url_for('register'))
        flash("An error occurred while trying to delete your account.", "danger")
    return redirect(url_for('settings'))
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0

@app.route('/logout')
@login_required
def logout():
<<<<<<< HEAD
    app.logger.info(f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out successfully.', 'info')
=======
    logout_user()
    flash('Logged out successfully!', 'info')
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
<<<<<<< HEAD
    try:
        # Get recent transactions
        transactions = Transaction.query.filter_by(
            user_id=current_user.id
        ).order_by(Transaction.date.desc()).limit(5).all()
        
        current_month = datetime.now().strftime('%Y-%m')
        
        # Get current month budgets with accurate spending
        budgets = Budget.query.filter_by(user_id=current_user.id, month=current_month).all()
        
        # Calculate total budget usage for the month
        total_budget = sum(budget.amount for budget in budgets)
        total_spent = sum(budget.spent for budget in budgets)
        budget_usage_percentage = (total_spent / total_budget * 100) if total_budget > 0 else 0
        
        # Get upcoming bills
        upcoming_bills = Bill.query.filter(
            Bill.user_id == current_user.id,
            Bill.is_paid == False,
            Bill.due_date >= datetime.now().date(),
            Bill.due_date <= datetime.now().date() + timedelta(days=30)
        ).order_by(Bill.due_date).limit(5).all()
        
        # Get exchange rates
        exchange_rates = get_exchange_rates()
        
        # Calculate REAL total deposits (all time)
        total_deposits = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id, 
            Transaction.type.in_(['Deposit', 'Transfer In', 'Income', 'Loan Disbursement'])
        ).scalar() or 0.0
        
        # Calculate REAL total withdrawals (all time)
        total_withdrawals = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id, 
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment', 'Investment'])
        ).scalar() or 0.0
        
        # Calculate THIS MONTH'S deposits and withdrawals
        current_month_deposits = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id,
            Transaction.date.like(f'{current_month}%'),
            Transaction.type.in_(['Deposit', 'Transfer In', 'Income', 'Loan Disbursement'])
        ).scalar() or 0.0
        
        current_month_withdrawals = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.user_id == current_user.id,
            Transaction.date.like(f'{current_month}%'),
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment', 'Investment'])
        ).scalar() or 0.0
        
        # Get spending by category for current month
        spending_by_category = db.session.query(
            Transaction.category,
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == current_user.id,
            Transaction.date.like(f'{current_month}%'),
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
        ).group_by(Transaction.category).all()
        
        # Get budget alerts (categories over budget)
        budget_alerts = []
        for budget in budgets:
            if budget.is_over_budget():
                budget_alerts.append({
                    'category': budget.category,
                    'budgeted': budget.amount,
                    'spent': budget.spent,
                    'over_by': budget.spent - budget.amount
                })
        
        return render_template(
            'dashboard.html',
            balance=current_user.balance,
            exchange_rates=exchange_rates,
            transactions=transactions,
            budgets=budgets,
            upcoming_bills=upcoming_bills,
            total_deposits=total_deposits,
            total_withdrawals=total_withdrawals,
            current_month_deposits=current_month_deposits,
            current_month_withdrawals=current_month_withdrawals,
            budget_usage_percentage=budget_usage_percentage,
            budget_alerts=budget_alerts,
            spending_by_category=spending_by_category,
            current_month=current_month,
            current_user=current_user
        )
        
    except Exception as e:
        app.logger.error(f'Dashboard error for user {current_user.username}: {e}')
        flash('Error loading dashboard data', 'danger')
        return render_template('dashboard.html', 
                             balance=current_user.balance,
                             error=True)

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    if request.method == 'POST':
        try:
            # CSRF protection
            csrf.protect()
            
            amount = float(request.form.get('amount', 0))
            source = request.form.get('source', 'External Deposit')
            description = request.form.get('description', f'Deposit from {source}')
            
            if amount <= 0:
                flash('Amount must be greater than zero.', 'danger')
                return render_template('deposit.html')
            
=======
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    total_deposits = sum(t.amount for t in transactions if t.type == 'Deposit')
    total_withdrawals = sum(t.amount for t in transactions if t.type == 'Withdraw')
    
    now = datetime.now()
    monthly_deposits = sum(
        t.amount for t in transactions 
        if t.type == 'Deposit' and t.date.month == now.month
    )
    monthly_withdrawals = sum(
        t.amount for t in transactions 
        if t.type == 'Withdraw' and t.date.month == now.month
    )
    exchange_rates = get_exchange_rates()
    
    if exchange_rates is None:
        exchange_rates = {}
        flash("Could not fetch latest exchange rates. Displaying limited data.", "warning")
    
    return render_template(
        'dashboard.html',
        total_deposits=total_deposits,
        total_withdrawals=total_withdrawals,
        monthly_deposits=monthly_deposits,
        monthly_withdrawals=monthly_withdrawals,
        balance=current_user.balance,
        exchange_rates=exchange_rates,
        transactions=transactions[:5] # Pass only the first 5 for the quick view
    )

@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    try:
        amount = float(request.form['amount'])
        source = request.form.get('source', 'Deposit')
        
        if amount <= 0:
            flash('Amount must be positive', 'danger')
        else:
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
            current_user.balance += amount
            transaction = Transaction(
                user_id=current_user.id,
                type='Deposit',
                amount=amount,
<<<<<<< HEAD
                description=description,
                category='Income',
                reference_id=generate_reference_id()
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            socketio.emit('balance_update', {
                'user_id': current_user.id,
                'balance': current_user.balance
            }, room=f'user_{current_user.id}')
            
            app.logger.info(f'User {current_user.username} deposited {amount}')
            flash(f'Successfully deposited ₹{amount:,.2f}', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid amount entered.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Deposit error: {e}')
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if request.method == 'POST':
        try:
            # CSRF protection
            csrf.protect()

            amount = float(request.form.get('amount', 0))
            description = request.form.get('description', 'Withdrawal')
            category = categorize_transaction(description)
            
            if amount <= 0:
                flash('Amount must be greater than zero.', 'danger')
                return render_template('withdraw.html')
            
            if amount > current_user.balance:
                flash('Insufficient funds.', 'danger')
                return render_template('withdraw.html')
            
=======
                description=f'Deposit from {source}'
            )
            db.session.add(transaction)
            db.session.commit()
            flash(f'Successfully deposited ₹{amount:,.2f}', 'success')
    except (ValueError, KeyError):
        flash('Invalid amount entered', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        amount = float(request.form['amount'])
        destination = request.form.get('destination', 'Withdrawal')
        
        if amount <= 0:
            flash('Amount must be positive', 'danger')
        elif amount > current_user.balance:
            flash('Insufficient funds', 'danger')
        else:
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
            current_user.balance -= amount
            transaction = Transaction(
                user_id=current_user.id,
                type='Withdraw',
                amount=amount,
<<<<<<< HEAD
                description=description,
                category=category,
                reference_id=generate_reference_id()
            )
            
            db.session.add(transaction)
            
            current_month = datetime.now().strftime('%Y-%m')
            budget = Budget.query.filter_by(
                user_id=current_user.id,
                category=category,
                month=current_month
            ).first()
            
            if budget:
                budget.spent += amount
                if budget.is_over_budget():
                    flash(f'Warning: You have exceeded your {category} budget for {current_month}!', 'warning')
            
            db.session.commit()
            
            socketio.emit('balance_update', {
                'user_id': current_user.id,
                'balance': current_user.balance
            }, room=f'user_{current_user.id}')
            
            app.logger.info(f'User {current_user.username} withdrew {amount} for {category}')
            flash(f'Successfully withdrew ₹{amount:,.2f}', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid amount entered.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Withdrawal error: {e}')
            flash('An error occurred. Please try again.', 'danger')
    
    return render_template('withdraw.html')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        try:
            # CSRF protection
            csrf.protect()

            amount = float(request.form.get('amount', 0))
            recipient_account = request.form.get('recipient_account')
            description = request.form.get('description', 'Fund Transfer')
            
            if amount <= 0:
                flash('Amount must be greater than zero.', 'danger')
                return render_template('transfer.html')
            
            if amount > current_user.balance:
                flash('Insufficient funds for transfer.', 'danger')
                return render_template('transfer.html')

            if recipient_account == current_user.account_number:
                flash('Cannot transfer funds to your own account using this method.', 'danger')
                return render_template('transfer.html')

            recipient = User.query.filter_by(account_number=recipient_account).first()

            if not recipient:
                flash(f'Recipient account {recipient_account} not found.', 'danger')
                return render_template('transfer.html')

            current_user.balance -= amount
            ref_id = generate_reference_id()
            
            sender_tx = Transaction(
                user_id=current_user.id,
                type='Transfer Out',
                amount=amount,
                description=f'Transfer to A/C {recipient_account} - {description}',
                category='Transfer',
                reference_id=ref_id
            )
            
            recipient.balance += amount
            recipient_tx = Transaction(
                user_id=recipient.id,
                type='Transfer In',
                amount=amount,
                description=f'Transfer from A/C {current_user.account_number} - {description}',
                category='Income',
                reference_id=ref_id
            )
            
            db.session.add(sender_tx)
            db.session.add(recipient_tx)
            db.session.commit()
            
            socketio.emit('balance_update', {
                'user_id': current_user.id,
                'balance': current_user.balance
            }, room=f'user_{current_user.id}')
            
            socketio.emit('balance_update', {
                'user_id': recipient.id,
                'balance': recipient.balance
            }, room=f'user_{recipient.id}')
            
            app.logger.info(f'User {current_user.username} transferred {amount} to {recipient.username}')
            flash(f'Successfully transferred ₹{amount:,.2f} to account {recipient_account}', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError:
            flash('Invalid amount entered.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Transfer error: {e}')
            flash('An error occurred during transfer. Please try again.', 'danger')
    
    return render_template('transfer.html')
=======
                description=f'Withdrawal to {destination}'
            )
            db.session.add(transaction)
            db.session.commit()
            flash(f'Successfully withdrew ₹{amount:,.2f}', 'success')
    except (ValueError, KeyError):
        flash('Invalid amount entered', 'danger')
        
    return redirect(url_for('dashboard'))
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0

@app.route('/transactions')
@login_required
def transactions_history():
<<<<<<< HEAD
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    transactions_query = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc())
    transactions = transactions_query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('transactions.html', transactions=transactions)

@app.route('/analytics')
@login_required
def analytics():
    try:
        # Get spending by category for current month
        current_month = datetime.now().strftime('%Y-%m')
        spending_by_category = db.session.query(
            Transaction.category,
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == current_user.id,
            Transaction.date.like(f'{current_month}%'),
            Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
        ).group_by(Transaction.category).all()
        
        # Get monthly spending for the last 6 months
        monthly_spending = []
        for i in range(6):
            month = (datetime.now() - timedelta(days=30*i)).strftime('%Y-%m')
            monthly_total = db.session.query(func.sum(Transaction.amount)).filter(
                Transaction.user_id == current_user.id,
                Transaction.date.like(f'{month}%'),
                Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
            ).scalar() or 0.0
            monthly_spending.append({
                'month': month,
                'amount': monthly_total
            })
        
        monthly_spending.reverse()
        
        # Get budget vs actual
        budgets = Budget.query.filter_by(user_id=current_user.id, month=current_month).all()
        budget_data = []
        for budget in budgets:
            budget_data.append({
                'category': budget.category,
                'budgeted': budget.amount,
                'spent': budget.spent,
                'remaining': budget.get_remaining()
            })
        
        return render_template(
            'analytics.html',
            spending_by_category=spending_by_category,
            monthly_spending=monthly_spending,
            budget_data=budget_data,
            current_month=current_month
        )
        
    except Exception as e:
        app.logger.error(f'Analytics error for user {current_user.username}: {e}')
        flash('Error loading analytics data', 'danger')
        return render_template('analytics.html', error=True)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    
    # Pre-populate form with current user data
    if request.method == 'GET':
        form.email.data = current_user.email
        form.username.data = current_user.username
    
    if form.validate_on_submit():
        try:
            # Check if email is already taken by another user
            if form.email.data != current_user.email:
                existing_user = User.query.filter_by(email=form.email.data).first()
                if existing_user and existing_user.id != current_user.id:
                    flash('Email already registered by another user.', 'danger')
                    return render_template('settings.html', form=form)
                current_user.email = form.email.data
            
            # Check if username is already taken by another user
            if form.username.data != current_user.username:
                existing_user = User.query.filter_by(username=form.username.data).first()
                if existing_user and existing_user.id != current_user.id:
                    flash('Username already taken by another user.', 'danger')
                    return render_template('settings.html', form=form)
                current_user.username = form.username.data
            
            # Update password if provided
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
            app.logger.error(f'Settings update error for user {current_user.username}: {e}')
            flash('An error occurred while updating settings.', 'danger')
    
    return render_template('settings.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfilePictureForm()
    if form.validate_on_submit():
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                try:
                    filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    
                    current_user.profile_pic = filename
                    db.session.commit()
                    
                    flash('Profile picture updated successfully!', 'success')
                except Exception as e:
                    app.logger.error(f'Profile picture upload error: {e}')
                    flash('Error uploading file. Please try again.', 'danger')
            else:
                flash('Invalid file type or no file selected.', 'danger')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)

@app.route('/apply/credit_card', methods=['GET', 'POST'])
=======
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    return render_template('transactions.html', transactions=transactions)

@app.route('/apply_loan', methods=['GET', 'POST'])
@login_required
def apply_loan():
    if request.method == 'POST':
        amount = request.form.get('amount')
        term = request.form.get('term')
        purpose = request.form.get('purpose')

        if not all([amount, term, purpose]):
            flash("Please fill all loan fields.", "danger")
            return redirect(url_for('apply_loan'))

        try:
            loan = LoanApplication(
                user_id=current_user.id,
                loan_amount=float(amount),
                tenure=int(term),
                loan_type=purpose
            )
            db.session.add(loan)
            db.session.commit()
            flash("Loan application submitted successfully!", "success")
            return redirect(url_for('dashboard'))
        except ValueError:
            flash("Invalid input values", "danger")

    return render_template('loan.html')

@app.route('/credit_card', methods=['GET', 'POST'])
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
@login_required
def apply_credit_card():
    form = CreditCardForm()
    if form.validate_on_submit():
<<<<<<< HEAD
        try:
            if form.income.data >= 150000:
                status = 'Approved'
                credit_limit = form.income.data * 0.5
                flash_msg = 'Congratulations! Your Credit Card application has been provisionally Approved!'
            else:
                status = 'Pending'
                credit_limit = form.income.data * 0.2
                flash_msg = 'Your application is under review.'

            application = CreditCardApplication(
                user_id=current_user.id,
                card_type=form.card_type.data,
                pan_number=form.pan_number.data,
                income=form.income.data,
                status=status,
                credit_limit=credit_limit
            )
            db.session.add(application)
            db.session.commit()
            
            flash(flash_msg, 'success' if status == 'Approved' else 'info')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Credit card application error: {e}')
            flash('An unexpected error occurred during application.', 'danger')

    applications = CreditCardApplication.query.filter_by(user_id=current_user.id).all()
    return render_template('credit_card.html', form=form, applications=applications)

@app.route('/apply/loan', methods=['GET', 'POST'])
@login_required
def apply_loan():
    form = LoanApplicationForm()
    if form.validate_on_submit():
        try:
            if form.loan_amount.data <= current_user.balance * 2:
                status = 'Approved'
                flash_msg = 'Congratulations! Your Loan application has been provisionally Approved!'
            else:
                status = 'Pending'
                flash_msg = 'Your application is under review.'

            application = LoanApplication(
                user_id=current_user.id,
                loan_amount=form.loan_amount.data,
                tenure=form.tenure.data,
                loan_type=form.loan_type.data,
                purpose=form.purpose.data,
                status=status
            )
            db.session.add(application)
            db.session.commit()

            if status == 'Approved':
                current_user.balance += application.loan_amount
                tx = Transaction(
                    user_id=current_user.id,
                    type='Loan Disbursement',
                    amount=application.loan_amount,
                    description=f'{application.loan_type} Approved and Disbursed',
                    category='Income',
                    reference_id=generate_reference_id()
                )
                db.session.add(tx)
                db.session.commit()
                socketio.emit('balance_update', {
                    'user_id': current_user.id,
                    'balance': current_user.balance
                }, room=f'user_{current_user.id}')
            
            flash(flash_msg, 'success' if status == 'Approved' else 'info')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Loan application error: {e}')
            flash('An unexpected error occurred during application.', 'danger')

    applications = LoanApplication.query.filter_by(user_id=current_user.id).all()
    return render_template('apply_loan.html', form=form, applications=applications)

@app.route('/budgets', methods=['GET', 'POST'])
@login_required
def budgets():
    form = BudgetForm()
    
    current_month = datetime.now().strftime('%Y-%m')
    
    spending_data = db.session.query(
        Transaction.category,
        func.sum(Transaction.amount).label('total_spent')
    ).filter(
        Transaction.user_id == current_user.id,
        Transaction.date.like(f'{current_month}%'),
        Transaction.type.in_(['Withdraw', 'Transfer Out', 'Bill Payment'])
    ).group_by(Transaction.category).all()
    
    spending_map = {item.category: item.total_spent for item in spending_data}
    
    budgets_list = Budget.query.filter_by(user_id=current_user.id, month=current_month).all()
    
    for budget in budgets_list:
        actual_spent = spending_map.get(budget.category, 0.0)
        if budget.spent != actual_spent:
            budget.spent = actual_spent
    db.session.commit()

    if form.validate_on_submit():
        try:
            existing_budget = Budget.query.filter_by(
                user_id=current_user.id,
                category=form.category.data,
                month=form.month.data
            ).first()
            
            if existing_budget:
                existing_budget.amount = form.amount.data
                flash(f'Budget for {form.category.data} in {form.month.data} updated.', 'success')
            else:
                initial_spent = spending_map.get(form.category.data, 0.0) if form.month.data == current_month else 0.0
                new_budget = Budget(
                    user_id=current_user.id,
                    category=form.category.data,
                    amount=form.amount.data,
                    month=form.month.data,
                    spent=initial_spent
                )
                db.session.add(new_budget)
                flash(f'New budget for {form.category.data} in {form.month.data} set.', 'success')

            db.session.commit()
            return redirect(url_for('budgets'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Budget setting error: {e}')
            flash('An unexpected error occurred while setting the budget.', 'danger')
            
    all_budgets = Budget.query.filter_by(user_id=current_user.id).order_by(Budget.month.desc(), Budget.category).all()
    
    return render_template('budgets.html', form=form, budgets=all_budgets, current_month=current_month)

@app.route('/cards', methods=['GET', 'POST'])
@login_required
def cards():
    form = CardManagementForm()
    
    if form.validate_on_submit():
        try:
            network = CardService.get_card_network(form.card_number.data)
            
            new_card = Card(
                user_id=current_user.id,
                bank_name=form.bank_name.data,
                card_holder=form.card_holder.data,
                card_number=form.card_number.data,
                expiry_date=form.expiry_date.data,
                cvv=form.cvv.data,
                card_type='Credit' if form.credit_limit.data > 0 else 'Debit',
                network=network,
                credit_limit=form.credit_limit.data,
                used_amount=0.0
            )
            db.session.add(new_card)
            db.session.commit()
            
            flash(f'Successfully started tracking {network} card ending in {form.card_number.data[-4:]}.', 'success')
            return redirect(url_for('cards'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Card management error: {e}')
            flash('An error occurred while adding the card.', 'danger')

    tracked_cards = Card.query.filter_by(user_id=current_user.id).all()
    return render_template('cards.html', form=form, cards=tracked_cards)

@app.route('/bills', methods=['GET', 'POST'])
@login_required
def bills():
    form = BillForm()
    
    if form.validate_on_submit():
        try:
            new_bill = Bill(
                user_id=current_user.id,
                name=form.name.data,
                amount=form.amount.data,
                due_date=form.due_date.data,
                category=form.category.data
            )
            db.session.add(new_bill)
            db.session.commit()
            
            flash(f'Bill "{form.name.data}" added successfully.', 'success')
            return redirect(url_for('bills'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Bill creation error: {e}')
            flash('An error occurred while adding the bill.', 'danger')

    upcoming_bills = Bill.query.filter_by(user_id=current_user.id, is_paid=False).order_by(Bill.due_date).all()
    paid_bills = Bill.query.filter_by(user_id=current_user.id, is_paid=True).order_by(Bill.due_date.desc()).limit(5).all()
    
    return render_template('bills.html', form=form, upcoming_bills=upcoming_bills, paid_bills=paid_bills)

@app.route('/pay_bill/<int:bill_id>', methods=['POST'])
@login_required
def pay_bill(bill_id):
    try:
        # CSRF protection
        csrf.protect()

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
        
        transaction = Transaction(
            user_id=current_user.id,
            type='Bill Payment',
            amount=bill.amount,
            description=f'Payment for {bill.name} ({bill.category})',
            category='Utilities',
            reference_id=generate_reference_id()
        )
        db.session.add(transaction)
        db.session.commit()
        
        socketio.emit('balance_update', {
            'user_id': current_user.id,
            'balance': current_user.balance
        }, room=f'user_{current_user.id}')
        
        flash(f'Successfully paid bill "{bill.name}" for ₹{bill.amount:,.2f}.', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Bill payment error for user {current_user.username}: {e}')
        flash('An error occurred during bill payment. Please try again.', 'danger')
        
    return redirect(url_for('bills'))

@app.route('/investments', methods=['GET', 'POST'])
@login_required
def investments():
    form = InvestmentForm()
    
    if form.validate_on_submit():
        try:
            new_investment = Investment(
                user_id=current_user.id,
                name=form.name.data,
                type=form.type.data,
                amount_invested=form.amount_invested.data,
                current_value=form.amount_invested.data,
                purchase_date=form.purchase_date.data,
                quantity=form.quantity.data,
                symbol=form.symbol.data
            )
            db.session.add(new_investment)
            
            if current_user.balance < form.amount_invested.data:
                 flash('Insufficient balance to make this investment.', 'danger')
                 db.session.rollback()
                 return render_template('investments.html', form=form, investments=Investment.query.filter_by(user_id=current_user.id).all())
                 
            current_user.balance -= form.amount_invested.data
            
            tx = Transaction(
                user_id=current_user.id,
                type='Investment',
                amount=form.amount_invested.data,
                description=f'Investment in {form.name.data} ({form.type.data})',
                category='Other',
                reference_id=generate_reference_id()
            )
            db.session.add(tx)
            
            db.session.commit()
            
            socketio.emit('balance_update', {
                'user_id': current_user.id,
                'balance': current_user.balance
            }, room=f'user_{current_user.id}')
            
            flash(f'Investment "{form.name.data}" added successfully.', 'success')
            return redirect(url_for('investments'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Investment creation error: {e}')
            flash('An error occurred while adding the investment.', 'danger')

    investments_list = Investment.query.filter_by(user_id=current_user.id).all()
    total_invested = 0.0
    total_current_value = 0.0
    
    for investment in investments_list:
        new_value = InvestmentService.calculate_current_value(investment)
        if investment.current_value != new_value:
             investment.current_value = new_value
        total_invested += investment.amount_invested
        total_current_value += investment.current_value
        
    db.session.commit()
        
    overall_profit_loss = total_current_value - total_invested
    
    return render_template(
        'investments.html', 
        form=form, 
        investments=investments_list,
        total_invested=total_invested,
        total_current_value=total_current_value,
        overall_profit_loss=overall_profit_loss
    )

# DB Initialization
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Flask Banking Application Starting...")
    print("=" * 60)
    print("📊 Access your application at: http://localhost:5000")
    print("🔒 Running on HTTP (no SSL certificate issues)")
    print("💡 Features: Banking, Investments, Loans, Budgets, Analytics, Settings & More!")
    print("=" * 60)
    
    # Run with HTTP only - no SSL
    socketio.run(
        app, 
        debug=True, 
        host='127.0.0.1', 
        port=5000,
        allow_unsafe_werkzeug=True
    )
=======
        credit_card = CreditCardApplication(
            user_id=current_user.id,
            card_type=form.card_type.data,
            pan_number=form.pan_number.data,
            income=form.income.data
        )
        db.session.add(credit_card)
        db.session.commit()
        flash('Credit Card application submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('credit_card.html', form=form)

@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            transaction_type = request.form.get('type')
            description = request.form.get('description')

            if amount <= 0:
                flash("Amount must be a positive number.", "warning")
                return redirect(url_for('add_transaction'))

            if transaction_type not in ['Deposit', 'Withdraw']:
                flash("Invalid transaction type.", "warning")
                return redirect(url_for('add_transaction'))

            new_transaction = Transaction(
                amount=amount,
                type=transaction_type,
                description=description,
                user_id=current_user.id
            )

            if transaction_type == 'Deposit':
                current_user.balance += amount
            else:
                current_user.balance -= amount

            db.session.add(new_transaction)
            db.session.commit()
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except (ValueError, TypeError):
            flash("Invalid amount entered. Please enter a valid number.", "warning")
            return redirect(url_for('add_transaction'))
    
    return render_template('add_transaction.html')

@app.route('/profile', endpoint='profile_view')
@login_required
def profile():
    return render_template('profile.html')

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        name = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        current_user.username = name if name else current_user.username
        # Uncomment below if your User model has an email field
        # current_user.email = email if email else current_user.email
        if password.strip():
            current_user.password = generate_password_hash(password)

        db.session.commit()
        flash("Settings updated successfully!", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html")

@app.route('/update_profile_details', methods=['POST'])
@login_required
def update_profile_details():
    try:
        username = request.form.get('username')
        if username:
            current_user.username = username
        
        db.session.commit()
        flash('Profile details updated successfully!', 'success')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    
    return redirect(url_for('profile_view'))

@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('profile_view'))

    file = request.files['profile_pic']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('profile_view'))

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{current_user.id}_{uuid.uuid4().hex}.{ext}"
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if current_user.profile_pic and current_user.profile_pic != 'default.jpg':
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic)
            if os.path.exists(old_path):
                os.remove(old_path)

        current_user.profile_pic = filename
        db.session.commit()
        flash('Profile picture updated successfully!', 'success')
    else:
        flash('Invalid file type. Allowed: png, jpg, jpeg, gif', 'danger')
    return redirect(url_for('profile_view'))

# --- Main Entry Point ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create a test user if the database is empty
        if not User.query.first():
            test_user = User(
                username='testuser',
                account_number='1234567890',
                password=generate_password_hash('password123'),
                balance=50000.00,
                profile_pic='default.jpg'
            )
            db.session.add(test_user)
            db.session.commit()
    app.run(debug=True)
>>>>>>> fcec41f6627daa58d3280163b7117936610d30a0
