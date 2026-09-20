from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField
from wtforms.validators import (
    InputRequired, Length, DataRequired, Email, EqualTo, ValidationError, NumberRange
)
import re


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    account_number = StringField('Account Number', validators=[InputRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_account_number(self, field):
        """Validate that account number contains only digits."""
        if not field.data.isdigit():
            raise ValidationError('Account number must contain only numbers.')
        if len(field.data) < 10:
            raise ValidationError('Account number must be at least 10 digits long.')

    def validate_username(self, field):
        """Validate username format."""
        if not re.match(r'^[A-Za-z0-9_]+$', field.data):
            raise ValidationError('Username can only contain letters, numbers, and underscores.')


class LoginForm(FlaskForm):
    # NOTE: app.py currently defines its OWN LoginForm that logs in with
    # `username` instead of `account_number`. Pick ONE source of truth --
    # either import these classes from forms.py everywhere, or delete this
    # file's copies and keep only the ones in app.py. Having both is what
    # let the mismatch (and the merge conflict) happen in the first place.
    account_number = StringField('Account Number', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class CreditCardForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    card_type = SelectField("Card Type", choices=[
        ('silver', 'Silver - Credit Limit: \u20b950,000'),
        ('gold', 'Gold - Credit Limit: \u20b92,00,000'),
        ('platinum', 'Platinum - Credit Limit: \u20b95,00,000')
    ], validators=[DataRequired()])
    pan_number = StringField("PAN Number", validators=[
        DataRequired(),
        Length(min=10, max=10, message='PAN number must be exactly 10 characters')
    ])
    income = FloatField("Annual Income (\u20b9)", validators=[
        DataRequired(),
        NumberRange(min=100000, message='Minimum annual income must be \u20b91,00,000')
    ])
    submit = SubmitField("Submit Application")

    def validate_pan_number(self, field):
        """Validate PAN number format (e.g. ABCDE1234F)."""
        pan_pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$'
        if not re.match(pan_pattern, field.data.upper()):
            raise ValidationError('Please enter a valid PAN number (e.g., ABCDE1234F)')

    def validate_name(self, field):
        """Validate name contains only letters and spaces."""
        if not re.match(r'^[A-Za-z\s]+$', field.data):
            raise ValidationError('Name can only contain letters and spaces.')
