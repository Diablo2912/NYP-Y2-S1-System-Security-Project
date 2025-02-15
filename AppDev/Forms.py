from wtforms import *
import re
from wtforms import FileField
from flask_wtf.file import FileAllowed
class SignUpForm(Form):
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
    email = EmailField('Email*',[validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])
    cfm_pswd = PasswordField('Confirm Password*', [validators.EqualTo('pswd', message='Passwords must match'), validators.DataRequired()])

    def validate_number(form, field):
        if len(field.data) != 8:
            raise ValidationError('Invalid phone number.')
        elif not field.data.isdigit():
            raise ValidationError('Invalid phone number.')

class LoginForm(Form):
    email = EmailField('Email*',[validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])

class CreateProductForm(Form):
    product_name = StringField('Product Name',[validators.Length(min=1, max=150), validators.DataRequired()],
                             render_kw={"placeholder": "e.g. Wheat Seeds"})
    quantity = StringField('Quantity',[validators.Length(min=1, max=150), validators.DataRequired()],
                            render_kw={"placeholder": "e.g. 10"})
    category = SelectField('Category', [validators.DataRequired()], choices=[('', 'Select'), ('Fruits', 'Fruits'), ('Cereal Crops', 'Cereal Crops')], default='')
    price = StringField('Price',[validators.Length(min=1, max=150), validators.DataRequired()],
                            render_kw={"placeholder": "e.g. 10.00"})
    product_description = TextAreaField('Product Description', [validators.Optional()])
    product_image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Only images allowed!')])