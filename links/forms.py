from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField


class LoginForm(FlaskForm):
    name = StringField("name", validators=[validators.DataRequired()])
    password = PasswordField("password", validators=[validators.DataRequired()])


class RegisterForm(FlaskForm):
    name = StringField("name", validators=[validators.DataRequired()])
    password = PasswordField("password", validators=[validators.DataRequired()])


class LinkForm(FlaskForm):
    new_name = StringField("New Name")
    link = StringField("link", validators=[validators.DataRequired()])
