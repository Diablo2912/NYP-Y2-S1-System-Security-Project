from wtforms import *
import re
from wtforms import FileField
from flask_wtf.file import FileAllowed
from flask_wtf import FlaskForm
from decimal import Decimal
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

class CreateAdminForm(FlaskForm):
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


from wtforms import StringField, PasswordField, SelectField, EmailField, validators, ValidationError
from flask_wtf import FlaskForm
import re

_name_re = re.compile(r"^[A-Za-z][A-Za-z '\-]{1,149}$")  # 2–150 chars, letters/space/'/-
_sg_phone_re = re.compile(r"^(?:\+65\s*)?(?:[3689]\d{7})$")  # SG phones, optional +65

def _strip(x):
    return x.strip() if isinstance(x, str) else x

class ChangeDetForm(FlaskForm):
    # Basic “no digits” & “no letters” helpers (kept for compatibility)
    def no_numbers(form, field):
        if field.data and re.search(r'\d', field.data):
            raise validators.ValidationError('Name cannot contain numbers')

    def no_letters(form, field):
        if field.data and re.search(r'[a-zA-Z]', field.data):
            raise validators.ValidationError('Phone cannot contain letters')

    first_name = StringField(
        'First Name*',
        [
            validators.DataRequired(),
            validators.Length(min=2, max=150, message='First name must be 2–150 characters.'),
        ],
        filters=[_strip],
    )

    last_name = StringField(
        'Last Name*',
        [
            validators.DataRequired(),
            validators.Length(min=2, max=150, message='Last name must be 2–150 characters.'),
        ],
        filters=[_strip],
    )

    gender = SelectField(
        'Gender*',
        [validators.DataRequired(message='Please select your gender.')],
        choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')],
        default='',
    )

    number = StringField(
        'Phone Number*',
        [
            validators.DataRequired(),
            validators.Length(min=8, max=16, message='Enter a valid Singapore phone number.'),
        ],
        filters=[_strip],
    )

    email = EmailField(
        'Email*',
        [
            validators.DataRequired(),
            validators.Email(message='Please enter a valid email address.'),
            validators.Length(max=254),
        ],
        filters=[_strip],
    )

    pswd = PasswordField(
        'Enter Password to Confirm:',
        [
            validators.DataRequired(),
            validators.Length(min=8, message='Password must be at least 8 characters.'),
        ],
    )

    # --- Field-level specific validations ---

    def validate_first_name(self, field):
        if not _name_re.match(field.data):
            raise ValidationError("Only letters, spaces, apostrophes (’) and hyphens (-) allowed.")

    def validate_last_name(self, field):
        if not _name_re.match(field.data):
            raise ValidationError("Only letters, spaces, apostrophes (’) and hyphens (-) allowed.")

    def validate_number(self, field):
        if not _sg_phone_re.match(field.data):
            raise ValidationError("Use a valid SG number (8 digits starting 3/6/8/9, optional +65).")

    def validate_gender(self, field):
        if field.data not in ('F', 'M'):
            raise ValidationError("Please select a valid option.")


class ChangePswdForm(FlaskForm):
    current_pswd = PasswordField('Current Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])
    new_pswd = PasswordField('New Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])
    confirm_pswd = PasswordField('Confirm New Password:',[validators.Length(min=8, message='Password must be at least 8 characters.'),validators.DataRequired()])

class LoginForm(FlaskForm):
    email = EmailField('Email*',[validators.Email(), validators.DataRequired()])
    pswd = PasswordField('Password*', [validators.Length(min=8, message='Password must be at least 8 characters.'), validators.DataRequired()])

class CreateProductForm(FlaskForm):
    product_name = StringField(
        'Product Name',
        [
            validators.DataRequired(),
            validators.Length(min=1, max=150, message="1–150 characters."),
        ],
        render_kw={"placeholder": "e.g. Wheat Seeds"},
        filters=[_strip]
    )

    quantity = IntegerField(
        'Quantity',
        [
            validators.DataRequired(message="Please enter a quantity."),
            validators.NumberRange(min=0, max=1_000_000, message="Quantity must be 0 or more."),
        ],
        render_kw={"placeholder": "e.g. 10"}
    )

    # Populate choices in your route; we’ll validate below that the posted value is in the list.
    category = SelectField(
        'Category',
        [validators.DataRequired(message="Please pick a category.")],
        choices=[],  # set in route
    )

    price = DecimalField(
        'Price',
        [
            validators.DataRequired(message="Enter a price."),
            validators.NumberRange(min=0, max=1_000_000, message="Price must be 0 or more."),
        ],
        render_kw={"placeholder": "e.g. 10.00"}
    )

    co2 = DecimalField(
        'CO₂ Emissions (kg)',
        [
            validators.Optional(),
            validators.NumberRange(min=0, max=1_000_000, message="CO₂ must be 0 or more."),
        ],
        render_kw={"placeholder": "e.g. 2.5"}
    )

    product_description = TextAreaField(
        'Product Description',
        [validators.Optional(), validators.Length(max=1000, message="Max 1000 characters.")],
    )

    product_image = FileField(
        'Product Image',
        validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Only JPG/PNG images allowed!')]
    )

    submit = SubmitField('Create Product')

    # ---- Field-specific validations ----

    def validate_product_name(self, field):
        if not _name_re.match(field.data or ""):
            raise ValidationError("Letters/numbers/spaces and - _ ’ ( ) , . & / allowed.")

    def validate_category(self, field):
        # Ensure posted value is one of the rendered choices
        valid_values = {val for val, _ in self.category.choices}
        if field.data not in valid_values:
            raise ValidationError("Invalid category selected.")

    def validate_price(self, field):
        """
        Ensure two decimal places max (for UI consistency),
        while still allowing integers (e.g., 10 -> 10.00).
        """
        val = field.data
        if isinstance(val, Decimal):
            # Normalize exponent; allow up to 2 dp
            if (-val.as_tuple().exponent) > 2:
                raise ValidationError("Use at most 2 decimal places.")

    def validate_co2(self, field):
        val = field.data
        if val is None:
            return
        if isinstance(val, Decimal) and (-val.as_tuple().exponent) > 2:
            raise ValidationError("Use at most 2 decimal places.")

    def validate_product_image(self, field):
        """
        Optional: cap file size at ~2MB.
        """
        f = field.data
        if not f:
            return
        try:
            pos = f.stream.tell()
            f.stream.seek(0, 2)          # end
            size = f.stream.tell()
            f.stream.seek(pos)            # restore
            if size > 2 * 1024 * 1024:
                raise ValidationError("Image must be ≤ 2 MB.")
        except Exception:
            # If stream does not support tell/seek, skip size check
            pass

class ResetPassRequest(Form):
    email = EmailField('Email*',[validators.Email(), validators.DataRequired()])

class ResetPass(Form):
    new_pswd = PasswordField('New Password:',
                             [validators.Length(min=8, message='Password must be at least 8 characters.'),
                              validators.DataRequired()])
    confirm_pswd = PasswordField('Confirm New Password:',
                                 [validators.Length(min=8, message='Password must be at least 8 characters.'),
                                  validators.DataRequired()])