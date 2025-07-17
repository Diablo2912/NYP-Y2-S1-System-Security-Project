from wtforms import *
import re
from wtforms import FileField
from flask_wtf.file import FileAllowed
from flask_wtf import FlaskForm
class SignUpForm(FlaskForm):
    def no_numbers(form, field):
        if re.search(r'\d', field.data):
            raise validators.ValidationError('Name cannot contain numbers')

    def no_letters(form, field):
        if re.search(r'[a-zA-Z]', field.data):
            raise validators.ValidationError('Name cannot contain letters')

    first_name = StringField('First Name*', [validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    last_name = StringField('Last Name*', [validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    gender = SelectField('Gender*', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    number = StringField('Phone Number*', [validators.DataRequired(), no_letters])
    email = EmailField('Email*', [validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])
    cfm_pswd = PasswordField('Confirm Password*', [validators.EqualTo('pswd', message='Passwords must match'), validators.DataRequired()])

class CreateAdminForm(Form):
    def no_numbers(form, field):
        if re.search(r'\d', field.data):
            raise validators.ValidationError('Name cannot contain numbers')

    def no_letters(form, field):
        if re.search(r'[a-zA-Z]', field.data):
            raise validators.ValidationError('Name cannot contain letters')

    first_name = StringField('First Name*', [validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    last_name = StringField('Last Name*', [validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    gender = SelectField('Gender*', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    number = StringField('Phone Number*', [validators.DataRequired(), no_letters])
    status = SelectField('Role*', [validators.DataRequired()],choices=[('', 'Select'), ('manager','Manager'), ('admin','Admin')], default='')
    email = EmailField('Email*', [validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])
    cfm_pswd = PasswordField('Confirm Password*', [validators.EqualTo('pswd', message='Passwords must match'), validators.DataRequired()])


class ChangeDetForm(Form):
    def no_numbers(form, field):
        if re.search(r'\d', field.data):
            raise validators.ValidationError('Name cannot contain numbers')

    def no_letters(form, field):
        if re.search(r'[a-zA-Z]', field.data):
            raise validators.ValidationError('Name cannot contain letters')

    first_name = StringField('First Name*',[validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    last_name = StringField('Last Name*',[validators.Length(min=1, max=150), validators.DataRequired(), no_numbers])
    gender = SelectField('Gender*', [validators.DataRequired()],choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    number = StringField('Phone Number*', [validators.DataRequired(), no_letters])
    email = EmailField('Email*', [validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Enter Password to Confirm:', [validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])

class ChangePswdForm(FlaskForm):
    current_pswd = PasswordField('Current Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])
    new_pswd = PasswordField('New Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])
    confirm_pswd = PasswordField('Confirm New Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])

class LoginForm(FlaskForm):
    email = EmailField('Email*',[validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])

class CreateProductForm(FlaskForm):
    product_name = StringField('Product Name', [validators.Length(min=1, max=150), validators.DataRequired()],
                               render_kw={"placeholder": "e.g. Wheat Seeds"})
    quantity = IntegerField('Quantity', [validators.DataRequired()], render_kw={"placeholder": "e.g. 10"})

    # ensure category field has correct choices
    category = SelectField('Category', [validators.DataRequired()], choices=[])

    price = DecimalField('Price', [validators.DataRequired()], render_kw={"placeholder": "e.g. 10.00"})
    co2 = DecimalField('CO₂ Emissions (kg)', [validators.Optional()], render_kw={"placeholder": "e.g. 2.5"})
    product_description = TextAreaField('Product Description', [validators.Optional()])
    product_image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Only images allowed!')])

    submit = SubmitField('Create Product')