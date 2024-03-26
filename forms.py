from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, validators

class RegisterForm(FlaskForm):
    username=StringField('Username', [validators.Length(min=4, max=20)])
    password=PasswordField('Password', [validators.DataRequired()])
    email=StringField('Email', [validators.Email()])
    first_name=StringField('First Name', [validators.Length(min=2, max=30)])
    last_name=StringField('Last Name', [validators.Length(min=2, max=30)])

class LoginForm(FlaskForm):
    username=StringField('Username', [validators.DataRequired()])
    password=StringField('Password', [validators.DataRequired()])

class FeedbackForm(FlaskForm):
    title=StringField('Title', [validators.Length(max=100)])
    content=TextAreaField('Content', [validators.DataRequired()])