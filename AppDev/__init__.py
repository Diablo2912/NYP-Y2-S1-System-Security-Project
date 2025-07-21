import tempfile
from markupsafe import Markup
from flask import Flask, g, Response, render_template, request, redirect, url_for, session, jsonify, flash, \
    make_response, send_file
from functools import wraps
from Forms import SignUpForm, CreateAdminForm, CreateProductForm, LoginForm, ChangeDetForm, ChangePswdForm, ResetPassRequest, ResetPass
import shelve, User
from FeaturedArticles import get_featured_articles
from Filter import main_blueprint
from seasonalUpdateForm import SeasonalUpdateForm
from flask_mail import Mail, Message
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from chatbot import generate_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import configure_uploads, IMAGES, UploadSet
from modelsProduct import db, Product
import stripe
import uuid  # For unique transaction IDs
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import requests
import bleach
import MySQLdb.cursors
from MySQLdb.cursors import DictCursor
from flask_mysqldb import MySQL
import base64
import hashlib
import secrets
import pyotp
import random
import time
from datetime import datetime, timedelta, date
import jwt
import socket
import requests
from twilio.rest import Client
import json
import numpy as np
from deepface import DeepFace
from PIL import Image
import io
from scipy.spatial.distance import cosine
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch
from reportlab.lib import colors
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from transformers import pipeline
from collections import defaultdict, Counter
from cryptography.fernet import Fernet
import pathlib
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask_wtf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791262abcdefg'
UPLOAD_FOLDER = 'static/uploads/'  # Define where images are stored
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
stripe.api_key = "sk_test_51Qrle9CddzoT6fzjpqNPd1g3UV8ScbnxiiPK5uYT0clGPV82Gn7QPwcakuijNv4diGpcbDadJjzunwRcWo0eOXvb00uDZ2Gnw6"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=90)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

load_dotenv()
print("Loaded ENV value for TEST_VAR =", os.getenv("TEST_VAR"))
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

images = UploadSet('images', IMAGES)

#csrf (activate global CSRF protection)
csrf = CSRFProtect()


app.register_blueprint(main_blueprint)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cropzyssp@gmail.com'
app.config['MAIL_PASSWORD'] = 'wivz gtou ftjo dokp'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
app.permanent_session_lifetime = timedelta(minutes=90)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure Uploads Directory Exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
MAIL_USE_TLS = True
EMAIL_SENDER = "cropzyssp@gmail.com"
EMAIL_PASSWORD = "wivz gtou ftjo dokp"


# SETUP UR DB CONFIG ACCORDINGLY
# DON'T DELETE OTHER CONFIGS JUST COMMENT AWAY IF NOT USING

# GLEN SQL DB CONFIG
app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'glen'
app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
app.config['MYSQL_DB'] = 'ssp_db'
app.config['MYSQL_PORT'] = 3306


#BRANDON SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'brandon'
# app.config['MYSQL_PASSWORD'] = 'Pa$$w0rd'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306
#
# #SACHIN SQL DB CONFIG

# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'glen'
# app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306
#
# #SACHIN SQL DB CONFIG
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'              # or your MySQL username
# app.config['MYSQL_PASSWORD'] = 'mysql'       # match what you set in Workbench
# app.config['MYSQL_DB'] = 'sspCropzy'
#
# #SADEV SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'Pa$$w0rd'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306

mysql = MySQL(app)

with app.app_context():
    db.create_all()

ALGORITHM = 'pbkdf2_sha256'

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "500 per hour"])

# CFT on SQL#
# SQL LOGGING
# Info
# Warning
# Error
# Critical

#ssl

def generate_self_signed_cert(cert_file='certs/cert.pem', key_file='certs/key.pem'):
    cert_path = pathlib.Path(cert_file)
    key_path = pathlib.Path(key_file)

    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if cert_path.exists() and key_path.exists():
        print("✅ SSL certs already exist. Skipping generation.")
        return

    print("🔐 Generating self-signed SSL certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FlaskApp"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ Certificate saved to", cert_file)
    print("✅ Private key saved to", key_file)

# input sanitisation
def sanitize_input(user_input):
    allowed_tags = ['a', 'b', 'i', 'em', 'strong']
    allowed_attributes = {'a': ['href']}

    return bleach.clean(user_input, tags=allowed_tags, attributes=allowed_attributes)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("errors/429.html", error=str(e)), 429

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:  # Check if user is logged in
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt_token')

        if not token:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))

        user_data = verify_jwt_token(token)
        if not user_data:
            flash("Invalid or expired token. Please log in again.", "danger")
            return redirect(url_for('login'))

        session_id = session.get('current_session_id')
        if session_id:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""
                SELECT logout_time FROM user_session_activity
                WHERE id = %s AND user_id = %s
            """, (session_id, user_data['user_id']))
            result = cursor.fetchone()
            cursor.close()

            if result and result['logout_time']:
                flash("Your session has been revoked. Please log in again.", "danger")
                response = make_response(redirect(url_for('login')))
                response.delete_cookie('jwt_token')
                return response

        g.user = user_data
        return f(*args, **kwargs)

    return decorated_function


@app.route('/add_sample_products/')
def add_sample_products():
    sample_products = [
        # Organic Seeds
        Product(name="Organic Wheat Seeds", quantity=50, category="Organic Seeds", price=5.99, co2=2.5),
        Product(name="Organic Corn Seeds", quantity=60, category="Organic Seeds", price=4.99, co2=3.0),
        Product(name="Organic Tomato Seeds", quantity=40, category="Organic Seeds", price=6.49, co2=1.8),

        # Natural Fertilizers
        Product(name="Organic Compost", quantity=100, category="Natural Fertilizers", price=12.99, co2=0.8),
        Product(name="Vermicompost", quantity=80, category="Natural Fertilizers", price=15.99, co2=0.6),
        Product(name="Seaweed Fertilizer", quantity=50, category="Natural Fertilizers", price=18.49, co2=1.2),

        # Biodegradable Pest Control
        Product(name="Neem Oil Spray", quantity=70, category="Biodegradable Pest Control", price=9.99, co2=0.4),
        Product(name="Diatomaceous Earth", quantity=90, category="Biodegradable Pest Control", price=7.99, co2=0.5),

        # Eco-Friendly Farming Tools
        Product(name="Bamboo Hand Trowel", quantity=30, category="Eco-Friendly Farming Tools", price=8.99, co2=1.0),
        Product(name="Solar-Powered Irrigation Timer", quantity=20, category="Eco-Friendly Farming Tools", price=34.99,
                co2=2.2),

        # Regenerative Agriculture Products
        Product(name="Cover Crop Mix", quantity=25, category="Regenerative Agriculture", price=14.99, co2=2.8),
        Product(name="Biochar Soil Amendment", quantity=35, category="Regenerative Agriculture", price=19.99, co2=1.5)
    ]

    db.session.add_all(sample_products)
    db.session.commit()
    return "Sample sustainable agricultural products added!"


@app.route('/404_NOT_FOUND')
def notfound():
    return render_template('404.html')


@app.route('/')
def home():
    # Retrieve JWT token from cookies
    token = request.cookies.get('jwt_token')
    user_info = None

    if token:
        # Decode and verify the token
        user_info = verify_jwt_token(token)

    # Fetch featured articles and updates
    articles = get_featured_articles()
    updates = []

    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])

    # Retrieve all products
    products = Product.query.all()

    if not products:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None, user_info=user_info)

    # Convert product data to Pandas DataFrame
    data = [{'name': product.name, 'category': product.category, 'co2': product.co2} for product in products]
    df = pd.DataFrame(data)

    # Ensure there is data before plotting
    if df.empty:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None, user_info=user_info)

    # Chart 1 - CO₂ Emissions by Product
    plt.figure(figsize=(10, 5))
    plt.bar(df['name'], df['co2'], color='skyblue')
    plt.xlabel('Product Name')
    plt.ylabel('CO₂ Emissions (kg)')
    plt.title('CO₂ Emissions by Product')
    plt.xticks(rotation=45)
    plt.tight_layout()

    buffer1 = BytesIO()
    plt.savefig(buffer1, format='png')
    buffer1.seek(0)
    chart1_data = base64.b64encode(buffer1.getvalue()).decode('utf-8')
    buffer1.close()

    # Chart 2 - CO₂ Emissions by Product Category
    category_totals = df.groupby('category')['co2'].sum()
    plt.figure(figsize=(8, 5))
    plt.pie(category_totals, labels=category_totals.index, autopct='%1.1f%%', startangle=140)
    plt.title('CO₂ Emissions by Product Category')

    buffer2 = BytesIO()
    plt.savefig(buffer2, format='png')
    buffer2.seek(0)
    chart2_data = base64.b64encode(buffer2.getvalue()).decode('utf-8')
    buffer2.close()

    # Chart 3 - Highest vs. Lowest CO₂ Emission Products
    highest = df.nlargest(3, 'co2')
    lowest = df.nsmallest(3, 'co2')

    plt.figure(figsize=(10, 5))
    plt.bar(highest['name'], highest['co2'], color='red', label="Highest CO₂")
    plt.bar(lowest['name'], lowest['co2'], color='green', label="Lowest CO₂")
    plt.xlabel('Product Name')
    plt.ylabel('CO₂ Emissions (kg)')
    plt.title('Highest vs. Lowest CO₂ Emission Products')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()

    buffer3 = BytesIO()
    plt.savefig(buffer3, format='png')
    buffer3.seek(0)
    chart3_data = base64.b64encode(buffer3.getvalue()).decode('utf-8')
    buffer3.close()

    # Dynamic welcome message
    welcome_message = f"Welcome, {user_info['first_name']}!" if user_info else "Welcome to our site!"

    return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=chart1_data,
                           chart2_data=chart2_data, chart3_data=chart3_data, welcome_message=welcome_message,
                           user_info=user_info)


@app.route('/buyProduct', methods=['GET'])
def buy_product():
    # Get selected categories (list of selected checkboxes)
    selected_categories = request.args.getlist('category')  # for multiple sections

    # Base query
    query = Product.query

    # Apply category filter (if any category is selected)
    if selected_categories:
        query = query.filter(Product.category.in_(selected_categories))

    # Get filtered products
    products = query.all()

    # Get all unique categories
    all_categories = {product.category for product in Product.query.all()}
    cart = session.get("cart", {})  # Retrieve cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())

    return render_template('/productPage/buyProduct.html',
                           products=products,
                           all_categories=all_categories,
                           selected_categories=selected_categories,
                           total_price=total_price)


@app.route('/createProduct', methods=['GET', 'POST'])
@jwt_required
def create_product():
    form = CreateProductForm()

    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin', 'manager']:
        return render_template('404.html')

    # fetch categories from database
    categories = db.session.query(Product.category).distinct().all()
    category_choices = [(category[0], category[0]) for category in categories]

    form.category.choices = [('', 'Select Category')] + category_choices

    if request.method == 'POST' and form.validate_on_submit():
        name = form.product_name.data
        quantity = int(form.quantity.data)
        category = form.category.data
        price = float(form.price.data)
        co2 = float(form.co2.data)
        description = form.product_description.data

        # image upload
        image_file = form.product_image.data
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            filename = "default.jpg"

        new_product = Product(name=name, quantity=quantity, category=category, price=price, co2=co2,
                              description=description, image_filename=filename)

        db.session.add(new_product)
        db.session.commit()
        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"Created new product: {name} (Category: {category})"
        )

        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"Created new product: {name} (Category: {category})"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Created New Product",
            item_name=name
        )

        return redirect(url_for('buy_product'))

    return render_template('/productPage/createProduct.html', form=form)


@app.route('/manageProduct')
@jwt_required
def manageProduct():
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin', 'manager']:
        return render_template('404.html')

    products = Product.query.all()  # Fetch all products from the database

    if not products:
        print("❌ No products found in the database.")  # Debugging message
        if request.args.get("export") == "csv":
            return "No products found.", 404
        return render_template('/productPage/manageProduct.html', products=[])

    # Handle CSV Export
    if request.args.get("export") == "csv":
        def generate():
            data = ["Product Name,Quantity,Category,Price,CO2,Description,Image Filename\n"]
            for product in products:
                data.append(
                    f"{product.name},{product.quantity},{product.category},{product.price},{product.co2},{product.description},{product.image_filename}\n")
            return "".join(data)

        response = Response(generate(), mimetype='text/csv')
        response.headers["Content-Disposition"] = "attachment; filename=products.csv"
        return response

    print(f"✅ Loaded {len(products)} products for management.")  # Debugging message
    return render_template('/productPage/manageProduct.html', products=products)


@app.route('/updateProduct/<int:id>/', methods=['GET', 'POST'])
@jwt_required
def update_product(id):
    product = Product.query.get_or_404(id)
    form = CreateProductForm(obj=product)  # Prepopulate form fields

    # Ensure category dropdown is populated
    categories = db.session.query(Product.category).distinct().all()
    category_choices = [(cat[0], cat[0]) for cat in categories]
    form.category.choices = category_choices

    if request.method == 'GET':
        form.product_name.data = product.name
        form.product_description.data = product.description

    if request.method == 'POST' and form.validate_on_submit():
        product.name = form.product_name.data
        product.quantity = int(form.quantity.data)
        product.category = form.category.data
        product.price = float(form.price.data)
        product.co2 = float(form.co2.data)
        product.description = form.product_description.data  # Ensure this is updated

        # Handle Image Upload
        image_file = form.product_image.data
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            product.image_filename = filename if filename else "default.png"

        db.session.commit()
        log_user_action(
            user_id=g.user['user_id'],
            session_id=g.user['session_id'],
            action=f"Updated product: {product.name} (ID: {product.id})"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Updated Product",
            item_name=product.name
        )

        return redirect(url_for('manageProduct'))

    return render_template('/productPage/updateProduct.html', form=form, product=product)


@app.route('/deleteProduct/<int:id>', methods=['POST'])
@jwt_required
def delete_product(id):
    product = Product.query.get_or_404(id)

    # delete image if its not default
    if product.image_filename != "default.jpg":
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(product)
    db.session.commit()
    log_user_action(
        user_id=g.user['user_id'],
        session_id=g.user['session_id'],
        action=f"Deleted product: {product.name} (ID: {product.id})"
    )
    notify_user_action(
        to_email=g.user['email'],
        action_type="Deleted Product",
        item_name=product.name
    )

    return redirect(url_for('manageProduct'))


@app.route('/view_products')
def view_products():
    products = Product.query.all()  # Fetch all products from the database

    if not products:
        return "<p style='color: red; font-size: 20px; text-align: center;'>No products found in the database!</p>"

    product_list = """
    <div style="text-align: center; font-family: Arial;">
        <h1 style="color: green;">Product List</h1>
        <table border="1" style="margin: auto; width: 80%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th>ID</th>
                <th>Name</th>
                <th>Quantity</th>
                <th>Category</th>
                <th>Price</th>
                <th>CO₂ Emissions (kg)</th>
                <th>Description</th>
            </tr>
    """

    for product in products:
        product_list += f"""
            <tr>
                <td>{product.id}</td>
                <td>{product.name}</td>
                <td>{product.quantity}</td>
                <td>{product.category}</td>
                <td>${"{:.2f}".format(product.price)}</td>
                <td>{product.co2} kg</td>
                <td>{product.description}</td>
            </tr>
        """

    product_list += "</table></div>"

    return product_list


@app.route('/clearProducts', methods=['POST', 'GET'])
def clear_products():
    try:
        num_deleted = db.session.query(Product).delete()  # Deletes all products
        db.session.commit()
        return f"Successfully deleted {num_deleted} products!"
    except Exception as e:
        db.session.rollback()
        return f"Error: {str(e)}"

    return product_list


@app.route('/carbonFootprintTracker', methods=['GET', 'POST'])
def carbonFootprintTracker():
    if 'selected_products' not in session:
        session['selected_products'] = []  # Initialize session storage

    products = Product.query.all()

    if request.method == 'POST':
        product_name = request.form.get('product')

        # Find the product from the database
        product = Product.query.filter_by(name=product_name).first()

        if product:
            # store product details
            session['selected_products'].append({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'co2': product.co2
            })
            session.modified = True  # save session changes

    # calculate co2 emission
    selected_products = session['selected_products']
    total_co2 = sum(product['co2'] for product in selected_products)

    co2_equivalent = ""
    goal_status = ""

    # co2 impact comparison
    if total_co2 > 0:
        if total_co2 < 10:
            co2_equivalent = "Equivalent to charging a smartphone 1,200 times."
        elif total_co2 < 30:
            co2_equivalent = "Equivalent to driving a car for 10 miles."
        elif total_co2 < 50:
            co2_equivalent = "Equivalent to running an AC for 3 hours."
        else:
            co2_equivalent = "Equivalent to 100kg of CO₂ emitted!"

    # co2 alternative suggestions
    suggested_alternatives = []
    for product in selected_products:
        if 'category' in product:
            low_co2_alternative = Product.query.filter(
                Product.category == product['category'], Product.co2 < product['co2']
            ).order_by(Product.co2).first()

            if low_co2_alternative:
                suggested_alternatives.append((product, low_co2_alternative))

    # co2 goal tracker
    target_co2_limit = 30  # Set a sustainable benchmark
    if total_co2 < target_co2_limit:
        goal_status = f"✅ You are within the sustainable limit! ({total_co2}kg CO₂)"
    else:
        goal_status = f"⚠️ Reduce emissions! Try staying under {target_co2_limit}kg CO₂."

    return render_template('carbonFootprintTracker.html',
                           products=products,
                           selected_products=selected_products,
                           total_co2=total_co2,
                           co2_equivalent=co2_equivalent,
                           suggested_alternatives=suggested_alternatives,
                           goal_status=goal_status)


@app.route('/deleteSelectedProduct/<int:product_id>', methods=['POST'])
def deleteSelectedProduct(product_id):
    if 'selected_products' in session:
        session['selected_products'] = [p for p in session['selected_products'] if p['id'] != product_id]
        session.modified = True  # Save session changes

    return redirect(url_for('carbonFootprintTracker'))  # Redirect back


@app.route('/educationalGuide')
def educationalGuide():
    return render_template('/resourcesPage/educational_guide.html')


@app.route('/farmTools')
def farmTools():
    return render_template('/resourcesPage/farmTools.html')


@app.route('/initiatives')
def initiatives():
    return render_template('/resourcesPage/initiatives.html')


@app.route('/aboutUs')
def aboutUs():
    return render_template('aboutUs.html')


@app.route('/contactUs', methods=['GET', 'POST'])
def contactUs():
    if request.method == 'POST':
        # first_name = request.form.get('inputFirstname')
        # last_name = request.form.get('inputLastname')
        # email = request.form.get('inputEmail')
        # phone = request.form.get('inputNumber')
        # purpose = request.form.get('flexRadioDefault')
        # additional_info = request.form.get('addInfo')

        flash('Your form has been submitted successfully!', 'success')
        return redirect(url_for('home'))  # Redirect to clear form

    return render_template('contactUs.html')


@app.route('/accountInfo')
@jwt_required
def accountInfo():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    # 🛠 Fix: MySQL stores BLOBs or bytes — decode to string first
    if user and user.get('recovery_code'):
        try:
            encrypted = user['recovery_code']
            if isinstance(encrypted, bytearray):  # MySQL may return bytearray
                encrypted = bytes(encrypted)
            decrypted_code = fernet.decrypt(encrypted).decode()
            user['recovery_code'] = decrypted_code
        except Exception as e:
            print(f"[Decryption Error] {e}")
            user['recovery_code'] = "[Decryption Failed]"

    return render_template('/accountPage/accountInfo.html', user=user)


@app.route('/accountSecurity', methods=['GET', 'POST'])
@jwt_required
def accountSecurity():
    user_id = g.user['user_id']
    session_id = g.user['session_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        selected_countries = request.form.getlist('allowed_countries')

        # Validation: Ensure at least one country is selected
        if not selected_countries:
            flash("You must select at least one country.", "danger")
            # Reload user to show current settings
            cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            cursor.close()
            return render_template('/accountPage/accountSecurity.html', user=user)

        country_str = ','.join(selected_countries)

        try:
            cursor.execute("UPDATE accounts SET countries = %s WHERE id = %s", (country_str, user_id))
            mysql.connection.commit()
            log_user_action(
                user_id=user_id,
                session_id=session_id,
                action=f"Updated allowed countries to: {country_str}"
            )
            flash("Allowed countries updated successfully.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Update failed: {str(e)}", "danger")

    # Always load user after possible update
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        return render_template('/accountPage/accountSecurity.html', user=user)

    flash("User data not found.", "danger")
    return redirect(url_for('login'))


@app.route('/accountHist')
@jwt_required
def accountHist():
    user_id = g.user['email']  # Get logged-in user ID

    # Get all transactions from session (if not found, return empty list)
    all_transactions = session.get("transactions", [])

    # DEBUGGING: Print transactions for testing
    print(f"All Transactions: {all_transactions}")
    print(f"Logged-in User ID: {user_id}")

    # Ensure transactions are correctly structured and filter them
    user_transactions = [t for t in all_transactions if t.get("email") == user_id]

    # DEBUGGING: Check filtered transactions
    print(f"User Transactions: {user_transactions}")

    # Apply Search Filter (if applicable)
    search_query = request.args.get("search", "").strip().lower()
    if search_query:
        user_transactions = [t for t in user_transactions if
                             search_query in t["id"].lower() or search_query in t["name"].lower()]

    return render_template('/accountPage/accountHist.html', transactions=user_transactions, search_query=search_query)


@app.route('/dashboard')
@jwt_required
def dashboard():
    jwt_user = g.user
    if jwt_user['status'] not in ['admin']:
        return render_template('404glen.html')

    user_id = jwt_user['user_id']
    session_id = jwt_user['session_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get current user info
    cursor.execute("SELECT id, first_name, last_name, email, gender, status FROM accounts WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()

    if not user_info:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    # Get search and role filters
    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")  # multi-select

    # Build dynamic query
    query = "SELECT id, first_name, last_name, email, status FROM accounts WHERE 1=1"
    params = []

    if search_query:
        query += " AND (LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s OR LOWER(email) LIKE %s)"
        like_value = f"%{search_query}%"
        params += [like_value, like_value, like_value]

    if selected_roles:
        role_placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND status IN ({role_placeholders})"
        params += selected_roles

    cursor.execute(query, params)
    users = cursor.fetchall()
    cursor.close()
    log_user_action(
        user_id=user_id,
        session_id=session_id,
        action="Accessed admin dashboard"
    )

    notify_user_action(
        to_email=jwt_user['email'],
        action_type="Accessed Admin Dashboard",
        item_name="Dashboard View"
    )

    return render_template(
        'dashboard.html',
        user=user_info,
        users=users,
        search_query=search_query,
        selected_roles=selected_roles
    )


@app.route('/updateUserStatus/<int:id>', methods=['POST'])
@jwt_required
def update_user_status(id):
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin']:
        return render_template('404.html')

    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only staff can change user statuses.", "danger")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor()
    # Fetch previous status before update (for user_action_log in session activity tracking)
    cursor.execute("SELECT email, status FROM accounts WHERE id = %s", (id,))
    user_record = cursor.fetchone()
    user_email = user_record[0]
    old_status = user_record[1]

    cursor.execute("UPDATE accounts SET status = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Updated user ID {id}'s status from '{old_status}' to '{new_status}'"
    )

    notify_user_action(
        to_email=user_email,
        action_type="Status Change",
        item_name=f"Your account status has been changed from '{old_status}' to '{new_status}'."
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Status Change",
        item_name=f"You changed user ID {id}'s status from '{old_status}' to '{new_status}'."
    )

    cursor.close()

    flash("User status updated successfully.", "success")
    return redirect(url_for('roleManagement'))


@app.route('/createAdmin', methods=['GET', 'POST'])
@jwt_required
def createAdmin():
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin']:
        return render_template('404.html')

    create_admin_form = CreateAdminForm(request.form)

    if request.method == 'POST' and create_admin_form.validate():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Step 1: Check for duplicate email or phone number (unsanitized for accurate lookup)
        cursor.execute("SELECT * FROM accounts WHERE email = %s OR phone_number = %s",
                       (create_admin_form.email.data.lower(), create_admin_form.number.data))
        existing_user = cursor.fetchone()

        if existing_user:
            if existing_user['email'] == create_admin_form.email.data:
                flash('Email is already registered. Please use a different email.', 'danger')
            elif existing_user['phone_number'] == create_admin_form.number.data:
                flash('Phone number is already registered. Please use a different number.', 'danger')
            cursor.close()
            return redirect(url_for('createAdmin'))

        # Step 2: Sanitize all inputs after duplicate check
        first_name = sanitize_input(create_admin_form.first_name.data)
        last_name = sanitize_input(create_admin_form.last_name.data)
        gender = sanitize_input(create_admin_form.gender.data)
        status = sanitize_input(create_admin_form.status.data)
        phone_number = sanitize_input(create_admin_form.number.data)
        email = sanitize_input(create_admin_form.email.data.lower())

        # Step 4: Hash password and insert user
        hashed_password = hash_password(create_admin_form.pswd.data)

        cursor.execute('''
            INSERT INTO accounts (first_name, last_name, gender, phone_number, email, password, status, two_factor_status) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            first_name,
            last_name,
            gender,
            phone_number,
            email,
            hashed_password,
            status,
            'disabled'
        ))

        mysql.connection.commit()
        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"Created admin account for {email}"
        )

        notify_user_action(
            to_email=current_user['email'],
            action_type="Created Admin Account",
            item_name=f"You created an admin account for {email}."
        )

        cursor.close()

        flash('Admin account created successfully.', 'success')
        return redirect(url_for('createAdmin'))

    return render_template('createAdmin.html', form=create_admin_form)


@app.route('/updateLogStatus/<int:id>', methods=['POST'])
@jwt_required
def update_log_status(id):
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only admins can change log statuses.", "danger")
        return redirect(url_for('logging'))

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE logs SET status = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Updated log status (Log ID: {id}) to '{new_status}'"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Log Status Update",
        item_name=f"You changed the status of Log ID {id} to '{new_status}'."
    )

    cursor.close()

    flash("Log status updated successfully.", "success")
    return redirect(url_for('logging'))


@app.route('/delete_log/<int:id>', methods=['POST'])
@jwt_required
def delete_log(id):
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only admins can delete logs.", "danger")
        return redirect(url_for('logging'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM logs WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Deleted log entry with ID: {id}"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Deleted Log Entry",
        item_name=f"You deleted the log entry with ID: {id}."
    )

    flash("Log deleted successfully.", "success")
    return redirect(url_for('logging'))


@app.route('/logging', methods=['GET'])
@jwt_required
def logging():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")
    selected_statuses = request.args.getlist("statuses")
    sort_by = request.args.get("sort_by", "date")
    sort_order = request.args.get("sort_order", "desc")
    start_date = request.args.get("start_date")

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (current_user['user_id'],))
    user_info = cursor.fetchone()

    query = "SELECT id, user_id, date, time, category, activity, status, ip_address FROM logs WHERE 1=1"
    params = []

    if selected_roles:
        placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND category IN ({placeholders})"
        params.extend(selected_roles)

    if selected_statuses:
        placeholders = ','.join(['%s'] * len(selected_statuses))
        query += f" AND status IN ({placeholders})"
        params.extend(selected_statuses)

    if search_query:
        query += " AND (LOWER(category) LIKE %s OR LOWER(activity) LIKE %s OR ip_address LIKE %s)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term])

    if start_date:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")  # validate format
            query += " AND date >= %s"
            params.append(start_date)
        except ValueError:
            flash("Invalid date format provided.", "warning")

    sortable_columns = {
        "date": "date",
        "category": "FIELD(category, 'Critical', 'Error', 'Warning', 'Info')"
    }

    if sort_by in sortable_columns:
        order_clause = sortable_columns[sort_by]
        query += f" ORDER BY {order_clause} {'ASC' if sort_order == 'asc' else 'DESC'}"

    cursor.execute(query, params)
    logs = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) AS logs_count FROM logs")
    logs_result = cursor.fetchone()
    logs_count = logs_result['logs_count']

    cursor.close()

    current_date = date.today().isoformat()

    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action="Viewed log dashboard"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Viewed Logs",
        item_name="You accessed the log dashboard and viewed recent activities."
    )


    return render_template(
        'logging.html',
        user=user_info,
        users=logs,
        selected_roles=selected_roles,
        selected_statuses=selected_statuses,
        current_date=current_date,
        search_query=search_query,
        sort_by=sort_by,
        sort_order=sort_order,
        start_date=start_date,
        logs_count=logs_count
    )


@app.route('/logging_analytics', methods=['GET'])
@jwt_required
def logging_analytics():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    today = datetime.now().date()

    summary = summarize_recent_logs(mysql)

    today_str = datetime.today().strftime("%Y-%m-%d")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    num_days = request.args.get('days')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if start_date and end_date:
        # Custom date range logic
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
            GROUP BY DATE(date), category
            ORDER BY date
        """, (start_date, end_date))

        date_range = pd.date_range(start=start_date, end=end_date)
        dates_iso = [d.date().isoformat() for d in date_range]
        dates_display = [d.strftime('%d - %m - %Y') for d in date_range]
        display_start_date = start_date  # For display in template
        num_days = len(date_range)

    else:
        # Default to last N days
        num_days = int(num_days or 10)
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(date), category
            ORDER BY date
        """, (num_days - 1,))

        today = datetime.today().date()
        dates_iso = [(today - timedelta(days=i)).isoformat() for i in range(num_days - 1, -1, -1)]
        dates_display = [(today - timedelta(days=i)).strftime('%d - %m - %Y') for i in range(num_days - 1, -1, -1)]
        start_date_obj = datetime.now().date() - timedelta(days=num_days - 1)
        display_start_date = start_date_obj.strftime("%d/%m/%Y")

    log_data = cursor.fetchall()

    categories = ['Info', 'Warning', 'Error', 'Critical']
    chart_data = {date: {cat: 0 for cat in categories} for date in dates_iso}
    category_summary = {cat: 0 for cat in categories}

    for row in log_data:
        db_date = str(row['date'])
        cat = row['category']
        count = row['count']
        if db_date in chart_data and cat in chart_data[db_date]:
            chart_data[db_date][cat] = count
            category_summary[cat] += count

    current_time = datetime.now().strftime("%d-%m-%Y , %I:%M %p")
    current_day = datetime.now().strftime("%d-%m-%Y")

    cursor.execute("SELECT COUNT(*) AS closed_count FROM logs WHERE status = 'Closed'")
    closed_result = cursor.fetchone()
    closed_count = closed_result['closed_count']

    cursor.execute("SELECT COUNT(*) AS logs_count FROM logs")
    logs_result = cursor.fetchone()
    logs_count = logs_result['logs_count']

    # Determine which date to show login activity for
    login_date = request.args.get('login_date') or request.args.get('start_date') or today_str

    # Query login counts by hour and status
    cursor.execute("""
        SELECT HOUR(login_time) AS login_hour, status, COUNT(*) AS count
        FROM user_session_activity
        WHERE DATE(login_time) = %s
        GROUP BY login_hour, status
        ORDER BY login_hour, status
    """, (login_date,))
    login_activity_rows = cursor.fetchall()

    # Initialize hourly login dictionary
    login_activity = {hour: {'admin': 0, 'manager': 0, 'user': 0} for hour in range(24)}

    # Populate it
    for row in login_activity_rows:
        hour = int(row['login_hour'])
        status = row['status'].lower()
        count = row['count']
        if status in login_activity[hour]:
            login_activity[hour][status] = count

    cursor.close()

    return render_template(
        'logging_analytics.html',
        login_activity=login_activity,
        chart_data=chart_data,
        dates_iso=dates_iso,
        dates_display=dates_display,
        categories=categories,
        current_time=current_time,
        current_day=current_day,
        today_str=today_str,
        start_date=display_start_date,
        category_summary=category_summary,
        closed_count=closed_count,
        logs_count=logs_count,
        num_days=num_days,
        logs_summary=summary,
        summary_date=today,
    )

# SUMMARIZER V1
# SHOWS DATES
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
#
# def summarize_recent_logs(mysql):
#     cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#
#     today = datetime.now().date()
#     five_days_ago = today - timedelta(days=5)
#
#     cursor.execute('''
#         SELECT date, activity
#         FROM logs
#         WHERE DATE(date) BETWEEN %s AND %s
#         ORDER BY date DESC
#     ''', (five_days_ago, today))
#     logs = cursor.fetchall()
#
#     daily_activities = defaultdict(Counter)
#     for log in logs:
#         date_obj = log['date']
#         if isinstance(date_obj, str):
#             date_obj = datetime.strptime(date_obj.strip(), '%Y-%m-%d').date()
#         date_str = date_obj.strftime('%Y-%m-%d')
#         daily_activities[date_str][log['activity']] += 1
#
#     summary_lines = []
#     for date, activities in sorted(daily_activities.items(), key=lambda x: x[0], reverse=True):
#         summary_lines.append(f"{date}:")
#         for activity, count in activities.items():
#             summary_lines.append(f"- {activity} (x{count})" if count > 1 else f"- {activity}")
#         summary_lines.append("")  # blank line between dates
#
#     return "\n".join(summary_lines) if summary_lines else "No significant activities in the past 5 days."

# SUMMARIZER V2
# SHOWS NO DATES
#
def summarize_recent_logs(mysql):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    today = datetime.now().date()
    five_days_ago = today - timedelta(days=5)

    # Strict date filtering
    cursor.execute('''
        SELECT date, activity
        FROM logs
        WHERE DATE(date) BETWEEN %s AND %s
        ORDER BY date DESC
    ''', (five_days_ago, today))
    logs = cursor.fetchall()

    # Group logs by date (clean formatting)
    daily_activities = defaultdict(Counter)
    for log in logs:
        try:
            date_obj = log['date']
            if isinstance(date_obj, str):
                date_obj = datetime.strptime(date_obj.strip(), '%Y-%m-%d').date()
            date_str = date_obj.strftime('%Y-%m-%d')
            daily_activities[date_str][log['activity']] += 1
        except Exception as e:
            print(f"Skipping log due to date parsing error: {e}, log: {log}")
            continue

    # Prepare summary input string
    summary_lines = []
    for date, activities in sorted(daily_activities.items(), key=lambda x: datetime.strptime(x[0], '%Y-%m-%d'), reverse=True):
        summary_lines.append(f"{date}:")
        for activity, count in activities.items():
            summary_lines.append(f"- {activity} (x{count})" if count > 1 else f"- {activity}")
        summary_lines.append("")

    summary_input = "\n".join(summary_lines)

    if summary_input.strip():
        # Just get all activities into one string (no dates)
        activities_text = ". ".join([
            f"{act} (x{cnt})"
            for day in daily_activities.values()
            for act, cnt in day.items()
        ]) + "."

        summary = summarizer(activities_text, max_length=150, min_length=30, do_sample=False)[0]['summary_text']
    else:
        summary = "No significant activities in the past 5 days."

    return summary

def generate_log_report_pdf(filename, login_activity, category_summary, trend_data, trend_dates):
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    def draw_chart(fig, x, y, scale=0.4):
        img_io = io.BytesIO()
        fig.savefig(img_io, format='PNG', bbox_inches='tight')
        img_io.seek(0)
        image = ImageReader(img_io)
        c.drawImage(image, x, y, width=fig.get_figwidth() * 72 * scale, preserveAspectRatio=True, mask='auto')
        plt.close(fig)

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "System Logging Analytics Report")
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Chart positions
    login_x, login_y = 40, height - 300
    pie_x, pie_y = width / 2 + 20, height - 300
    bar_x, bar_y = 40, height - 540
    trend_x, trend_y = 40, height - 760

    # --- Log Category card counter  ---
    c.drawString(50, 780, "Info:")

    # --- Login Activity Line Chart ---
    fig, ax = plt.subplots(figsize=(5, 3))
    hours = [f"{i:02d}:00" for i in range(24)]
    for role in ['user', 'manager', 'admin']:
        role_data = [login_activity.get(h, {}).get(role, 0) for h in hours]
        ax.plot(hours, role_data, label=role.capitalize())
    ax.set_title('Login Activity')
    ax.set_xlabel('Hour')
    ax.set_ylabel('Logins')
    ax.legend()
    ax.grid(True)
    draw_chart(fig, x=login_x, y=login_y)

    # --- Pie Chart ---
    fig, ax = plt.subplots(figsize=(4, 3))
    labels = list(category_summary.keys())
    values = [category_summary[k] for k in labels]
    ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=140)
    ax.set_title("Log Category Distribution")
    draw_chart(fig, x=pie_x, y=pie_y)

    # --- Bar Chart ---
    fig, ax = plt.subplots(figsize=(5, 2.5))
    ax.bar(labels, values, color=['green', 'orange', 'orangered', 'red'])
    ax.set_title("Log Category Distribution (Bar)")
    ax.set_ylabel("Count")
    draw_chart(fig, x=bar_x, y=bar_y)

    # --- Trend Line Chart ---
    fig, ax = plt.subplots(figsize=(7, 2.5))
    for category, counts in trend_data.items():
        ax.plot(trend_dates, counts, label=category)
    ax.set_title("Log Trend Over Time")
    ax.set_xlabel("Date")
    ax.set_ylabel("Logs")
    ax.legend()
    ax.grid(True)
    draw_chart(fig, x=trend_x, y=trend_y)

    c.save()
    return filename

@app.route("/generate_pdf_report")
@jwt_required
def download_pdf_report():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    today_str = datetime.today().strftime("%Y-%m-%d")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    num_days = request.args.get('days')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Determine date range
    if start_date and end_date:
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
            GROUP BY DATE(date), category
            ORDER BY date
        """, (start_date, end_date))

        date_range = pd.date_range(start=start_date, end=end_date)
        dates_iso = [d.date().isoformat() for d in date_range]
    else:
        num_days = int(num_days or 10)
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(date), category
            ORDER BY date
        """, (num_days - 1,))
        today = datetime.today().date()
        dates_iso = [(today - timedelta(days=i)).isoformat() for i in range(num_days - 1, -1, -1)]

    log_data = cursor.fetchall()
    categories = ['Info', 'Warning', 'Error', 'Critical']

    # Prepare trend data and category summary
    chart_data = {date: {cat: 0 for cat in categories} for date in dates_iso}
    category_summary = {cat: 0 for cat in categories}

    for row in log_data:
        db_date = str(row['date'])
        cat = row['category']
        count = row['count']
        if db_date in chart_data and cat in chart_data[db_date]:
            chart_data[db_date][cat] = count
            category_summary[cat] += count

    trend_dates = dates_iso
    trend_data = {cat: [chart_data[date][cat] for date in trend_dates] for cat in categories}

    # Determine login activity date
    login_date = request.args.get('login_date') or request.args.get('start_date') or today_str
    cursor.execute("""
        SELECT HOUR(login_time) AS login_hour, status, COUNT(*) AS count
        FROM user_session_activity
        WHERE DATE(login_time) = %s
        GROUP BY login_hour, status
        ORDER BY login_hour, status
    """, (login_date,))
    login_activity_rows = cursor.fetchall()

    # Build login activity per hour
    login_activity = {f"{h:02d}:00": {'admin': 0, 'manager': 0, 'user': 0} for h in range(24)}
    for row in login_activity_rows:
        hour = int(row['login_hour'])
        status = row['status'].lower()
        count = row['count']
        if status in login_activity[f"{hour:02d}:00"]:
            login_activity[f"{hour:02d}:00"][status] = count

    cursor.close()

    # Generate PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    filepath = temp_file.name
    generate_log_report_pdf(filepath, login_activity, category_summary, trend_data, trend_dates)

    return send_file(filepath, as_attachment=True, download_name="Log_Report.pdf", mimetype='application/pdf')


ALGORITHM = "pbkdf2_sha256"


def admin_log_activity(mysql, activity, category="Info", user_id=None, status=None):
    """
    Logs an activity to the logs table.
    If the category is 'Critical', it will send email alerts to all admin users.

    Args:
        mysql: The MySQL connection object.
        activity (str): Description of the activity to log.
        category (str): Log category (e.g., 'Info', 'Warning', 'Error', 'Critical')
    """
    if not mysql:
        raise ValueError("MySQL connection object is required.")

    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    date = datetime.now().strftime('%Y-%m-%d')
    time = datetime.now().strftime('%I:%M %p')

    # Insert log into DB
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('''
                    INSERT INTO logs (user_id, date, time, category, activity, status, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (user_id, date, time, category, activity,status, ip_addr))
        mysql.connection.commit()
    finally:
        cursor.close()

    # If critical, notify all admins
    if category.lower() == "critical":
        notify_all_admins(mysql, activity)


def notify_all_admins(mysql, message):
    """
    Sends an email notification to all admin users about a critical log event.
    """
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT email, first_name FROM accounts WHERE status = 'admin'")
        admins = cursor.fetchall()
        cursor.close()

        subject = "[Cropzy Alert] ⚠️ Critical System Event"
        for admin in admins:
            alert_message = f"""
            Dear {admin['first_name']},

            A critical event has occurred:

            {message}

            Please investigate this issue as soon as possible.

            Regards,
            Cropzy Security System
            """
            send_email(admin['email'], subject, alert_message)
    except Exception as e:
        print(f"Failed to send admin alerts: {e}")


@app.route('/roleManagement', methods=['GET', 'POST'])
@jwt_required
def roleManagement():
    new_status = request.form.get('status')
    current_user = g.user

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, first_name, last_name, email, status FROM accounts")
    users = cursor.fetchall()
    user_info = cursor.fetchone()

    if current_user['status'] not in ['admin', 'staff']:
        return render_template('404.html')

    # Get search and role filters
    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")  # multi-select

    # Build dynamic query
    query = "SELECT id, first_name, last_name, email, status FROM accounts WHERE 1=1"
    params = []

    if search_query:
        query += " AND (LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s OR LOWER(email) LIKE %s)"
        like_value = f"%{search_query}%"
        params += [like_value, like_value, like_value]

    if selected_roles:
        role_placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND status IN ({role_placeholders})"
        params += selected_roles

    cursor.execute(query, params)
    users = cursor.fetchall()
    cursor.close()

    return render_template(
        'roleManagement.html',
        user=user_info,
        users=users,
        search_query=search_query,
        selected_roles=selected_roles
    )


ALGORITHM = "pbkdf2_sha256"


def hash_password(password, salt=None, iterations=260000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


@app.route('/signUp', methods=['GET', 'POST'])
@limiter.limit("500 per 1 minutes")
def sign_up():
    sign_up_form = SignUpForm(request.form)

    if request.method == 'POST' and sign_up_form.validate():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Check if email or phone number already exists
        cursor.execute("SELECT * FROM accounts WHERE email = %s OR phone_number = %s",
                       (sign_up_form.email.data, sign_up_form.number.data))
        existing_user = cursor.fetchone()

        first_name = sanitize_input(sign_up_form.first_name.data)
        last_name = sanitize_input(sign_up_form.last_name.data)
        gender = sanitize_input(sign_up_form.gender.data)
        phone_number = sanitize_input(sign_up_form.number.data)
        email = sanitize_input(sign_up_form.email.data.lower())

        if existing_user:
            if existing_user['email'] == sign_up_form.email.data:
                flash('Email is already registered. Please use a different email.', 'danger')
            elif existing_user['phone_number'] == sign_up_form.number.data:
                flash('Phone number is already registered. Please use a different number.', 'danger')
            cursor.close()
            return redirect(url_for('sign_up'))

        # Determine status based on email domain
        email = sign_up_form.email.data
        status = 'admin' if email.endswith('@cropzy.com') else 'user'

        # Hash the password before storing
        hashed_password = hash_password(sign_up_form.pswd.data)

        # Get user IP (use real IP for deployment)
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        # If testing locally, uncomment this line:
        # ip_address = requests.get("https://api.ipify.org").text

        # Get country code from IP

        if ip_address.startswith("127.") or ip_address.startswith("192.") or ip_address.startswith(
                "10.") or ip_address.startswith("172."):
            ip_address = get_public_ip()

        current_country = get_user_country(ip_address)
        print(f"User IP: {ip_address}, Country: {current_country}")

        # Insert new user with hashed password
        cursor.execute('''
            INSERT INTO accounts (first_name, last_name, gender, phone_number, email, password, status, two_factor_status, countries) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            first_name,
            last_name,
            gender,
            '+65' + str(phone_number),
            email,
            hashed_password,
            status,
            'disabled',
            current_country
        ))

        user_id = cursor.lastrowid

        # Log registration
        admin_log_activity(mysql, "User signed up successfully", category="Critical", user_id=user_id, status=status)

        notify_user_action(
            to_email=email,
            action_type="Sign Up Successful",
            item_name=f"Welcome to Cropzy, {first_name}! Your account has been successfully created."
        )

        mysql.connection.commit()
        cursor.close()

        flash('Sign up successful! Please log in.', 'info')
        return redirect(url_for('complete_signUp'))
    return render_template('/accountPage/signUp.html', form=sign_up_form)


SECRET_KEY = 'asdsa8f7as8d67a8du289p1eu89hsad7y2189eha8'  # You can change this to a more secure value


@app.context_processor
def inject_user():
    token = request.cookies.get('jwt_token')
    user = verify_jwt_token(token) if token else None
    return dict(current_user=user)


def get_user_country(ip_address):
    try:
        res = requests.get(f"https://ipwho.is/{ip_address}")
        data = res.json()
        if data.get('success', False):
            return data.get('country_code', 'Unknown')
        return "Unknown"
    except Exception as e:
        print("GeoIP Error:", e)
        return "Unknown"


def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except Exception as e:
        print("IP fetch error:", e)
        return "127.0.0.1"


SECRET_KEY = 'asdsa8f7as8d67a8du289p1eu89hsad7y2189eha8'  # You can change this to a more secure value


@app.context_processor
def inject_user():
    token = request.cookies.get('jwt_token')
    user = verify_jwt_token(token) if token else None
    return dict(current_user=user)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("500 per 1 minutes")
def login():
    login_form = LoginForm(request.form)
    #redirect
    if 'jwt_token' in request.cookies:
        return redirect(url_for('home'))

    if request.method == 'POST' and login_form.validate():
        email = sanitize_input(login_form.email.data.lower())
        password = login_form.pswd.data

        # for user action log purposes
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        user_agent = request.headers.get('User-Agent')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Hardcoded IP (Singapore - SG) for testing purposes
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

            # If running locally (private IP), use real public IP
            if ip_address.startswith("127.") or ip_address.startswith("192.") or ip_address.startswith(
                    "10.") or ip_address.startswith("172."):
                ip_address = get_public_ip()

            current_country = get_user_country(ip_address)
            print(f"User IP: {ip_address}, Country: {current_country}")

            # Ensure 'countries' is not None
            allowed_countries = user.get('countries') or ''
            allowed_list = [c.strip() for c in allowed_countries.split(',')] if allowed_countries else []

            if current_country not in allowed_list:
                flash("Login from your region is not allowed.", "danger")
                log_user_action(
                    user_id=user['id'],
                    session_id=None,
                    action=f"Login blocked - Disallowed region ({current_country}) | IP: {ip_address} | Agent: {user_agent}"
                )
                return redirect(url_for('login'))

            if is_account_frozen(user['id']):
                unfreeze_link = url_for('ajax_send_unfreeze_email', user_id=user['id'])
                message = Markup(
                    f"Account has been frozen. Send unfreeze email <a href='#' class='alert-link' onclick=\"sendUnfreezeRequest('{unfreeze_link}')\">here</a>.")
                flash(message, "danger")
                return redirect(url_for('login'))

            # Password validation
            stored_password_hash = user['password']
            if verify_password(password, stored_password_hash):
                if user.get('two_factor_status') == 'enabled':
                    send_otp_email(user['email'], user['id'], user['first_name'], user['last_name'])
                    session['pending_2fa_user_id'] = user['id']
                    log_user_action(
                        user_id=user['id'],
                        session_id=None,
                        action=f"Login passed password check, pending OTP | IP: {ip_address} | Agent: {user_agent}"
                    )
                    return redirect(url_for('verify_otp', id=user['id']))
                else:
                    session_id = log_session_activity(user['id'], user['status'], 'login')
                    payload = {
                        'user_id': user['id'],
                        'first_name': user['first_name'],
                        'last_name': user['last_name'],
                        'email': user['email'],
                        'gender': user['gender'],
                        'phone': user['phone_number'],
                        'status': user['status'],
                        'session_id': session_id,
                        'exp': datetime.utcnow() + timedelta(hours=1)
                    }

                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                    response = make_response(redirect(url_for('home')))
                    response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')
                    flash('Login successful!', 'success')
                    log_user_action(
                        user_id=user['id'],
                        session_id=session_id,
                        action=f"Login successful (no 2FA) | IP: {ip_addr} | Agent: {user_agent}"
                    )
                    notify_user_action(
                        to_email=user['email'],
                        action_type="Login Notification",
                        item_name=f"Your Cropzy account was just logged in from IP: {ip_addr}\n\nDevice: {user_agent}"
                    )

                    return response

            flash('Incorrect password.', 'danger')
        else:
            flash('Email not found. Please sign up.', 'danger')
      #no cache
    response = make_response(render_template('/accountPage/login.html', form=login_form))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


# A helper function to verify JWT token
def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


otp_store = {}


def send_otp_email(email, user_id, first_name, last_name):
    """
    Generate a 6-digit OTP, store it with an expiration time,
    and send it to the specified email address.

    Args:
        email (str): Recipient email address.
        user_id (int): ID of the user to associate with the OTP.

    Returns:
        None
    """
    otp = f"{random.randint(0, 999999):06d}"
    expires = time.time() + 60  # OTP valid for 60 seconds

    # Store OTP and expiry time
    otp_store[user_id] = {"otp": otp, "expires": expires}

    # Prepare email content
    subject = "[Cropzy] Cropzy Login 2FA OTP Code"
    message = (f"Hello {first_name} {last_name},\n\nPlease enter the generated code below to authenticate yourself \n\n"
               f"Your OTP code is: {otp} It expires in 1 minute. "
               f"If you did not attempt to sign in to your account, your password may be compromised.\n\nVisit http://127.0.0.1:5000/accountSecurity to create a new, strong password for your Cropzy account.\n\n"
               f"Thanks,\nCropzy Support Team")

    # Call existing email sending function
    send_email(email, subject, message)


# Twilio credentials (use environment variables in production!)
account_sid = 'AC69fe3693aeb2b86b276600293ab078d5'
auth_token = 'e475d20188609c83fc90575507d297b1'
twilio_phone = '+13072882468'

# Twilio client setup
client = Client(account_sid, auth_token)


def send_otp_sms(phone_number, user_id, first_name, last_name):
    otp = f"{random.randint(0, 999999):06d}"
    expires = time.time() + 60  # OTP valid for 60 seconds

    # Store OTP and expiry time
    otp_store[user_id] = {"otp": otp, "expires": expires}

    try:
        message = client.messages.create(
            from_=twilio_phone,
            body=f'\n Use verification code {otp} for Cropzy authentication.',
            to=phone_number
        )
        print(f" SMS sent: {message.sid}")  # Debugger msg
    except Exception as e:
        print(f" Failed to send SMS: {e}")  # Debugger msg


@app.route('/sms-verify-otp/<int:id>', methods=['GET', 'POST'])
def sms_verify_otp(id):
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    # Send OTP on GET request
    if request.method == 'GET':
        # Generate and send OTP
        otp = f"{random.randint(0, 999999):06d}"
        expires = time.time() + 60  # 60 seconds expiry
        otp_store[id] = {"otp": otp, "expires": expires}

        # Fetch user phone
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            send_otp_sms(user['phone_number'], id, user['first_name'], user['last_name'])

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        record = otp_store.get(id)

        if not record:
            flash("No OTP found. Please login again.", "error")
            return redirect(url_for('login'))

        if time.time() > record['expires']:
            flash("OTP expired. Please login again.", "error")
            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('login'))

        if entered_otp == record['otp']:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
            user = cursor.fetchone()
            cursor.close()

            if not user:
                flash("User not found. Please login again.", "error")
                return redirect(url_for('login'))

            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)

            session_id = log_session_activity(user['id'], user['status'], 'login')

            payload = {
                'user_id': user['id'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'gender': user['gender'],
                'phone': user['phone_number'],
                'status': user['status'],
                'session_id': session_id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            response = make_response(redirect(url_for('home')))
            response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

            log_user_action(
                user_id=user['id'],
                session_id=session_id,
                action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
            )

            notify_user_action(
                to_email=user['email'],
                action_type="Login Notification (2FA)",
                item_name=f"Your Cropzy account was just logged in via 2FA from IP: {ip_addr}\n\nDevice: {user_agent}"
            )

            flash("Login successful!", "success")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('/accountPage/sms_auth.html', id=id)


def generate_recovery_code(id):
    code = f"{random.randint(0, 999999):6d}"  # Generate 12-digit code

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if user exists
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return False  # User not found

    # Update recovery code
    encrypted_code = fernet.encrypt(code.encode())
    cursor.execute("UPDATE accounts SET recovery_code = %s WHERE id = %s", (encrypted_code, id))

    mysql.connection.commit()
    cursor.close()

    return code

@app.route('/setup_face_id/<int:id>', methods=['GET', 'POST'])
@jwt_required
def setup_face_id(id):
    current_email = g.user['email']

    if request.method == 'POST':
        base64_img = request.form.get('face_image')

        if not base64_img or "," not in base64_img:
            flash("Face capture failed. Please try again.", "danger")
            return redirect(request.url)

        image_data = base64_img.split(",")[1]
        img_bytes = base64.b64decode(image_data)

        # Save image bytes to database directly
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE accounts SET face = %s WHERE id = %s", (img_bytes, id))
        mysql.connection.commit()
        cursor.close()

        notify_user_action(
            to_email=g.user['email'],
            action_type="Face ID Setup",
            item_name="You have successfully registered a Face ID for your Cropzy account."
        )

        flash("Face ID registered successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template("accountPage/setup_face_id.html", id=id)


@app.route('/delete_face_id/<int:id>', methods=['POST'])
def delete_face_id(id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE accounts SET face = NULL WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()

        flash("Face ID deleted successfully!", "success")
    except Exception as e:
        print(f"Failed to delete Face ID: {e}")
        flash("Failed to delete Face ID. Please try again.", "danger")

    return redirect(url_for('accountInfo'))


@app.route('/face_id/<int:id>', methods=['GET', 'POST'])
def face_id(id):
    if request.method == 'POST':
        base64_img = request.form.get('face_image')
        if not base64_img or "," not in base64_img:
            flash("Face not captured. Please click 'Capture Face' before submitting.", "danger")
            return redirect(request.url)

        # Save the newly captured face as a temporary file
        image_data = base64_img.split(",")[1]
        temp_filename = f"temp_face_scan_user_{id}.png"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        with open(temp_path, 'wb') as f:
            f.write(base64.b64decode(image_data))

        # Retrieve the stored face blob from the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT face FROM accounts WHERE id = %s", (id,))
        user_face_data = cursor.fetchone()
        cursor.close()

        if not user_face_data or not user_face_data['face']:
            flash("No registered face found. Please set up Face ID first.", "danger")
            return redirect(url_for('setup_face_id', id=id))

        # Save the registered face blob as an image
        registered_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{id}_face.png")
        with open(registered_path, 'wb') as f:
            f.write(user_face_data['face'])

        try:
            result = DeepFace.verify(
                img1_path=temp_path,
                img2_path=registered_path,
                model_name='VGG-Face',
                enforce_detection=False
            )

            if result["verified"]:
                # Fetch full user info
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
                user = cursor.fetchone()
                cursor.close()

                if not user:
                    flash("User not found. Please try again.", "danger")
                    return redirect(url_for('login'))

                session_id = log_session_activity(user['id'], user['status'], 'login')

                payload = {
                    'user_id': user['id'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'email': user['email'],
                    'gender': user['gender'],
                    'phone': user['phone_number'],
                    'status': user['status'],
                    'session_id': session_id,
                    'exp': datetime.utcnow() + timedelta(hours=1)
                }

                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                response = make_response(redirect(url_for('home')))
                response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

                # Optionally delete temp files
                if os.path.exists(temp_path): os.remove(temp_path)
                if os.path.exists(registered_path): os.remove(registered_path)

                log_user_action(
                    user_id=user['id'],
                    session_id=session_id,
                    action="Login successful (via Face ID)"
                )

                notify_user_action(
                    to_email=user['email'],
                    action_type="Face ID Login",
                    item_name="You have successfully logged in using Face ID."
                )

                flash("Face matched. Logged in successfully!", "success")
                return response
            else:
                flash("Face does not match. Access denied.", "danger")

        except Exception as e:
            flash(f"Error during face verification: {str(e)}", "danger")

    return render_template("accountPage/face_id.html", id=id)


@app.route('/more_auth/<int:id>')
def more_auth(id):
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    return render_template('/accountPage/more_auth.html', id=id, user=user)




@app.route('/2FA/<int:id>', methods=['POST'])
@jwt_required
def enable_two_factor(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if the user exists
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('accountInfo'))

    # If already enabled, don't update again
    if user['two_factor_status'] == 'enabled':
        flash("2FA is already enabled for this account.", "info")
    else:
        # Enable 2FA
        cursor.execute("UPDATE accounts SET two_factor_status = %s WHERE id = %s", ('enabled', id))
        mysql.connection.commit()
        flash('You have successfully enabled 2FA for this account', 'success')

        log_user_action(
            user_id=id,
            session_id=g.user['session_id'] if hasattr(g, 'user') and g.user.get('session_id') else None,
            action=f"Enabled 2FA"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Enabled 2FA",
            item_name="You have successfully enabled 2FA for your account."
        )

    generate_recovery_code(id)

    cursor.close()
    return redirect(url_for('accountInfo'))


@app.route('/disable2FA/<int:id>/', methods=['POST'])
@jwt_required
def disable_two_factor(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('accountInfo'))

    if user['two_factor_status'] == 'disabled':
        flash("2FA is already disabled for this account.", "info")
    else:
        cursor.execute("UPDATE accounts SET two_factor_status = %s, recovery_code = NULL WHERE id = %s",
                       ('disabled', id))
        mysql.connection.commit()
        flash("2FA has been disabled for this account.", "success")

        log_user_action(
            user_id=id,
            session_id=g.user['session_id'] if hasattr(g, 'user') and g.user.get('session_id') else None,
            action=f"Disabled 2FA"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Disabled 2FA",
            item_name="You have successfully disabled 2FA for your account."
        )

    cursor.close()
    return redirect(url_for('accountInfo'))


def log_session_activity(user_id, status, action):
    print(f"[DEBUG] Creating session log for user {user_id} at {datetime.now()}")
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)

    try:
        cursor = mysql.connection.cursor()
        session_id = None  # default

        if action == 'login':
            cursor.execute('''
                INSERT INTO user_session_activity (user_id, status, login_time, ip_address, user_agent)
                VALUES (%s, %s, NOW(), %s, %s)
            ''', (
                user_id,
                status,
                ip_addr,
                request.headers.get('User-Agent')
            ))

            session_id = cursor.lastrowid
            session['current_session_id'] = session_id
            session['user_id'] = user_id

        elif action == 'logout':
            cursor.execute('''
                UPDATE user_session_activity
                SET logout_time = NOW()
                WHERE user_id = %s AND logout_time IS NULL
                ORDER BY login_time DESC
                LIMIT 1
            ''', (user_id,))

        # Diagnostic
        cursor.execute('SELECT DATABASE()')
        current_db = cursor.fetchone()
        print("[DEBUG] Connected to DB:", current_db)

        mysql.connection.commit()
        cursor.close()
        print("[DEBUG] Log saved to DB")
        return session_id

    except Exception as e:
        print("[ERROR] Session log failed:", e)
        return None



def log_user_action(user_id, session_id, action):
    if not user_id or not session_id:
        print("[WARN] Missing user_id or session_id, skipping action log")
        return
    try:
        timestamp = datetime.utcnow()
        cursor = mysql.connection.cursor()
        cursor.execute('''
            INSERT INTO user_actions_log (user_id, session_id, action, timestamp)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, session_id, action, timestamp))
        mysql.connection.commit()
        cursor.close()
        print(f"[DEBUG] Action logged: {action} at {timestamp}")
    except Exception as e:
        print("[ERROR] Action log failed:", e)

@app.route('/export_activity_pdf')
@jwt_required
def export_activity_pdf():
    user_id = g.user['user_id']
    filter_type = request.args.get("filter", "all")

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    query = "SELECT * FROM user_session_activity WHERE user_id = %s"
    params = [user_id]

    if filter_type == "active":
        query += " AND logout_time IS NULL"
    elif filter_type == "revoked":
        query += " AND logout_time IS NOT NULL"
    elif filter_type.startswith("last_"):
        try:
            limit = int(filter_type.split("_")[1])
            query += " ORDER BY login_time DESC LIMIT %s"
            params.append(limit)
        except:
            pass
    else:
        query += " ORDER BY login_time DESC"

    cursor.execute(query, tuple(params))
    sessions = cursor.fetchall()

    # Fetch all related actions
    session_ids = [s['id'] for s in sessions]
    actions_by_session = {sid: [] for sid in session_ids}

    if session_ids:
        format_strings = ','.join(['%s'] * len(session_ids))
        cursor.execute(f"SELECT * FROM user_actions_log WHERE session_id IN ({format_strings}) ORDER BY timestamp", tuple(session_ids))
        actions = cursor.fetchall()
        for action in actions:
            actions_by_session[action['session_id']].append(action)

    cursor.close()

    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"<b>Session Activity History</b>", styles['Title']))
    elements.append(Spacer(1, 0.3 * inch))

    for session in sessions:
        login = session['login_time']
        logout = session['logout_time'] or "Active Now"
        ip = session['ip_address']
        agent = session['user_agent']
        revoked_by = session.get('revoked_by', 'N/A')
        revoked_at = session.get('revoked_at', 'N/A')

        session_info = f"""
        <b>Session ID:</b> {session['id']}<br/>
        <b>Login Time:</b> {login} <br/>
        <b>Logout Time:</b> {logout} <br/>
        <b>IP Address:</b> {ip} <br/>
        <b>Device Info:</b> {agent} <br/>
        <b>Revoked By:</b> {revoked_by} <br/>
        <b>Revoked At:</b> {revoked_at} <br/>
        """
        elements.append(Paragraph(session_info, styles['Normal']))
        elements.append(Spacer(1, 0.1 * inch))

        # Actions for this session
        actions = actions_by_session.get(session['id'], [])
        if actions:
            elements.append(Paragraph("<b>Actions:</b>", styles['Heading4']))
            for a in actions:
                action_line = f"{a['timestamp']} — {a['action']}"
                elements.append(Paragraph(action_line, styles['Code']))
        else:
            elements.append(Paragraph("<i>No actions recorded for this session.</i>", styles['Italic']))

        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("<hr/>", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name='session_activity.pdf', mimetype='application/pdf')

@app.route('/send_activity_email_token/<int:id>')
@jwt_required
def send_activity_email_token(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    token = serializer.dumps({'id': id}, salt='activity-verification')
    link = url_for('confirm_activity_access', token=token, _external=True)

    msg = Message(
        "[Cropzy] Session Activity Verification",
        sender=EMAIL_SENDER,
        recipients=[user['email']]
    )
    msg.body = f"Click to confirm access to session activity (valid for 5 minutes):\n\n{link}"
    mail.send(msg)

    flash("Verification email sent. Please check your inbox.", "info")
    return redirect(url_for('home'))


@app.route('/confirm_activity_access/<token>')
def confirm_activity_access(token):
    try:
        data = serializer.loads(token, salt='activity-verification', max_age=300)
        user_id = data['id']

        # Update user's verification timestamp in DB
        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE accounts SET activity_verified_at = %s WHERE id = %s
        """, (datetime.utcnow(), user_id))
        mysql.connection.commit()
        cursor.close()

        return render_template("accountPage/verification_success.html")

    except Exception:
        flash("Verification link expired or invalid.", "danger")
        return redirect(url_for('verify_before_activity'))

@app.route('/verification_success_message/<token>')
def verification_success_message(token):
    return render_template("accountPage/verification_success.html", token=token)

@app.route('/face_verify_activity/<int:id>', methods=['GET', 'POST'])
@jwt_required
def face_verify_activity(id):
    if request.method == 'POST':
        base64_img = request.form.get('face_image')
        if not base64_img or "," not in base64_img:
            flash("Face not captured.", "danger")
            return redirect(request.url)

        image_data = base64_img.split(",")[1]
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_verify_user_{id}.png")
        with open(temp_path, 'wb') as f:
            f.write(base64.b64decode(image_data))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT face FROM accounts WHERE id = %s", (id,))
        user_face_data = cursor.fetchone()
        cursor.close()

        if not user_face_data or not user_face_data['face']:
            flash("No registered face found.", "danger")
            return redirect(url_for('setup_face_id', id=id))

        registered_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{id}_face.png")
        with open(registered_path, 'wb') as f:
            f.write(user_face_data['face'])

        try:
            result = DeepFace.verify(
                img1_path=temp_path,
                img2_path=registered_path,
                model_name='VGG-Face',
                enforce_detection=False
            )
            os.remove(temp_path)
            os.remove(registered_path)

            if result["verified"]:
                cursor = mysql.connection.cursor()
                cursor.execute("""
                    UPDATE accounts SET activity_verified_at = %s WHERE id = %s
                """, (datetime.utcnow(), id))
                mysql.connection.commit()
                cursor.close()

                flash("Face verified. Access granted.", "success")
                return redirect(url_for('activity_history'))
            else:
                flash("Face does not match.", "danger")

        except Exception as e:
            flash(f"Face verification error: {str(e)}", "danger")

    return render_template("accountPage/face_id_activity.html", id=id)



@app.route('/verify_before_activity')
@jwt_required
def verify_before_activity():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('accountPage/verify_activity_choice.html', id=g.user['user_id'], user=user)



@app.route('/activity_history')
@jwt_required
def activity_history():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT activity_verified_at FROM accounts WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()

    if not result or not result['activity_verified_at']:
        return redirect(url_for('verify_before_activity'))

    last_verified = result['activity_verified_at']
    if (datetime.utcnow() - last_verified).total_seconds() > 300:
        # Clear it from DB
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE accounts SET activity_verified_at = NULL WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cursor.close()
        flash("Access expired. Please re-verify to view session activity.", "warning")
        return redirect(url_for('verify_before_activity'))

    time_left = 300 - int((datetime.utcnow() - last_verified).total_seconds())

    # --- Fetch session activity logic here ---
    filter_type = request.args.get("filter", "all")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    query = "SELECT * FROM user_session_activity WHERE user_id = %s"
    params = [user_id]

    if filter_type == "active":
        query += " AND logout_time IS NULL"
    elif filter_type == "revoked":
        query += " AND logout_time IS NOT NULL"
    elif filter_type.startswith("last_"):
        try:
            limit = int(filter_type.split("_")[1])
            query += " ORDER BY login_time DESC LIMIT %s"
            params.append(limit)
        except:
            pass
    else:
        query += " ORDER BY login_time DESC"

    cursor.execute(query, tuple(params))
    sessions = cursor.fetchall()
    cursor.close()

    for s in sessions:
        session_id = s['id']
        action_cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        action_cursor.execute("""
            SELECT * FROM user_actions_log
            WHERE session_id = %s
            ORDER BY timestamp ASC
        """, (session_id,))
        s['actions'] = action_cursor.fetchall()
        action_cursor.close()

    return render_template("accountPage/activity.html",
                           sessions=sessions,
                           selected_filter=filter_type,
                           time_left=time_left)




@app.route('/revoke_session/<session_id>', methods=['POST'])
@jwt_required
def revoke_session(session_id):
    current_user_id = g.user['user_id']
    current_user_status = g.user['status']  # 'admin' or 'user'

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get original session owner
    cursor.execute("SELECT user_id FROM user_session_activity WHERE id = %s", (session_id,))
    session_row = cursor.fetchone()

    if not session_row:
        flash("Session not found.", "danger")
        return redirect(url_for('activity_history'))

    session_owner_id = session_row['user_id']

    # Determine who revoked it
    revoked_by = 'self' if session_owner_id == current_user_id else current_user_status
    revoked_by_id = current_user_id
    revoked_at = datetime.utcnow()

    # Update the session row
    cursor.execute("""
        UPDATE user_session_activity
        SET logout_time = %s,
            revoked_by = %s,
            revoked_by_id = %s,
            revoked_at = %s
        WHERE id = %s
    """, (revoked_at, revoked_by, revoked_by_id, revoked_at, session_id))

    mysql.connection.commit()
    cursor.close()

    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')

    log_user_action(
        user_id=current_user_id,
        session_id=g.user.get('session_id'),
        action=f"Revoked an active session | Revoked by: {revoked_by} | IP: {ip_addr} | Agent: {user_agent}"
    )

    notify_user_action(
        to_email=g.user['email'],
        action_type="Revoked Session",
        item_name=f"You revoked a session from IP {ip_addr}"
    )

    flash("Session has been revoked successfully.", "success")
    return redirect(url_for('activity_history'))



@app.route('/check_session_validity')
def check_session_validity():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({"valid": False})

    user_data = verify_jwt_token(token)
    if not user_data:
        return jsonify({"valid": False})

    session_id = user_data.get('session_id')
    user_id = user_data.get('user_id')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT logout_time FROM user_session_activity
        WHERE id = %s AND user_id = %s
    """, (session_id, user_id))
    result = cursor.fetchone()
    cursor.close()

    if result and result['logout_time']:
        return jsonify({"valid": False})

    return jsonify({"valid": True})

@app.route('/verify-otp/<int:id>', methods=['GET', 'POST'])
def verify_otp(id):
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')

    print(f"[DEBUG] OTP form submitted for user_id={id} at {datetime.now()}")
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        record = otp_store.get(id)

        if not record:
            flash("No OTP found. Please login again.", "error")
            return redirect(url_for('login'))

        if time.time() > record['expires']:
            flash("OTP expired. Please login again.", "error")
            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('login'))

        if entered_otp == record['otp']:
            # Fetch the user BEFORE using it
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
            user = cursor.fetchone()
            cursor.close()

            if not user:
                flash("User not found. Please login again.", "error")
                return redirect(url_for('login'))

            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)

            # ✅ Only ONE call here
            session_id = log_session_activity(user['id'], user['status'], 'login')

            payload = {
                'user_id': user['id'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'gender': user['gender'],
                'phone': user['phone_number'],
                'status': user['status'],
                'session_id': session_id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }

            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            response = make_response(redirect(url_for('home')))
            response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

            log_user_action(
                user_id=user['id'],
                session_id=session_id,
                action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
            )

            notify_user_action(
                to_email=user['email'],
                action_type="Login Success (2FA)",
                item_name=f"You logged in via OTP from IP {ip_addr} using {user_agent}."
            )

            flash("Login successful!", "success")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('/accountPage/two_factor.html', id=id)

@app.route('/resend-otp/<int:id>', methods=['GET'])
def resend_otp(id):
    # Ensure only users in 2FA process can request resend
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    # Fetch user info for email
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, email, first_name, last_name FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found. Please login again.", "error")
        return redirect(url_for('login'))

    # Send new OTP
    send_otp_email(user['email'], user['id'], user['first_name'], user['last_name'])
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp', id=id))


@app.route('/recovery_auth/<int:id>', methods=['GET', 'POST'])
def recovery_auth(id):
    if request.method == 'POST':
        input_code = request.form.get('recovery_code')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            stored_code = result['recovery_code']

            if input_code == stored_code:
                generate_recovery_code(id)

                # ✅ Only one log here
                session_id = log_session_activity(result['id'],result['status'], 'login')

                payload = {
                    'user_id': result['id'],
                    'first_name': result['first_name'],
                    'last_name': result['last_name'],
                    'email': result['email'],
                    'gender': result['gender'],
                    'phone': result['phone_number'],
                    'status': result['status'],
                    'session_id': session_id,
                    'exp': datetime.utcnow() + timedelta(hours=1)
                }

                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                response = make_response(redirect(url_for('home')))
                response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

                hostname = socket.gethostname()
                ip_addr = socket.gethostbyname(hostname)
                user_agent = request.headers.get('User-Agent')
                # ✅ Use user action log instead of logging a new session
                log_user_action(
                    user_id=result['id'],
                    session_id=session_id,
                    action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
                )

                notify_user_action(
                    to_email=result['email'],
                    action_type="Login Success (Recovery Code)",
                    item_name=f"You logged in using a recovery code from IP {ip_addr} using {user_agent}."
                )

                flash('Recovery successful. You are now logged in.', 'success')
                return response

    return render_template('/accountPage/recovery_code.html', id=id)


@app.route('/logout')
def logout():
    token = request.cookies.get('jwt_token')
    session_id = None
    user_id = None

    if token:
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            session_id = data.get('session_id')
            user_id = data.get('user_id')
        except:
            pass

    if session_id and user_id:
        cursor = mysql.connection.cursor()
        cursor.execute('''
            UPDATE user_session_activity
            SET logout_time = NOW()
            WHERE id = %s AND user_id = %s
        ''', (session_id, user_id))
        mysql.connection.commit()
        cursor.close()

    log_user_action(
        user_id=user_id,
        session_id=session_id,
        action="User logged out"
    )

    response = make_response(redirect(url_for('login')))
    response.delete_cookie('jwt_token')
    flash('You have been logged out.', 'success')
    return response


@app.route('/complete_signUp')
def complete_signUp():
    return render_template('/accountPage/complete_signUp.html')


@app.route('/changeDets/<int:id>/', methods=['GET', 'POST'])
def change_dets(id):
    change_dets_form = ChangeDetForm(request.form)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        cursor.close()
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_dets_form.validate():
        entered_password = change_dets_form.pswd.data
        stored_password_hash = user['password']  # assuming this is hashed

        # Check current password before updating
        if user:
            stored_password = user['password']

            # Update database with new user details
            cursor.execute('''
                UPDATE accounts
                SET first_name = %s,
                    last_name = %s,
                    gender = %s,
                    phone_number = %s,
                    email = %s
                WHERE id = %s
            ''', (
                change_dets_form.first_name.data,
                change_dets_form.last_name.data,
                change_dets_form.gender.data,
                change_dets_form.number.data,
                change_dets_form.email.data,
                id
            ))

            mysql.connection.commit()

            if 'user_id' in session:
                log_user_action(session['user_id'], session.get('current_session_id'), "Changed account details")

            notify_user_action(
                to_email=change_dets_form.email.data,
                action_type="Account Update",
                item_name="Your account details were updated successfully."
            )

            cursor.close()

            # Update session
            session['first_name'] = change_dets_form.first_name.data
            session['last_name'] = change_dets_form.last_name.data
            session['gender'] = change_dets_form.gender.data
            session['phone'] = change_dets_form.number.data
            session['email'] = change_dets_form.email.data

        flash("Details updated successfully!", "success")
        return redirect(url_for('accountInfo'))

    # Pre-fill form fields from the DB
    change_dets_form.first_name.data = user['first_name']
    change_dets_form.last_name.data = user['last_name']
    change_dets_form.gender.data = user['gender']
    change_dets_form.number.data = user['phone_number']
    change_dets_form.email.data = user['email']

    cursor.close()
    return render_template('/accountPage/changeDets.html', form=change_dets_form)


@app.route('/changePswd/<int:id>/', methods=['GET', 'POST'])
@jwt_required
def change_pswd(id):
    change_pswd_form = ChangePswdForm(request.form)
    user_id = g.user['user_id']  # ✅ Get from JWT

    user_id = session.get('user_id')
    if not user_id or user_id != id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        cursor.close()
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_pswd_form.validate():
        current_pswd = change_pswd_form.current_pswd.data
        new_pswd = change_pswd_form.new_pswd.data
        confirm_pswd = change_pswd_form.confirm_pswd.data

        # Using plaintext comparison (insecure; follow your current code pattern)
        if user['password'] != current_pswd:
            flash("Incorrect current password.", "danger")
            cursor.close()
            return redirect(url_for('change_pswd', id=id))

        if new_pswd != confirm_pswd:
            flash("New passwords do not match.", "danger")
            cursor.close()
            return redirect(url_for('change_pswd', id=id))

        # Update new password in the DB (still plaintext)

        mysql.connection.commit()
        cursor.close()

        # ✅ Log user action
        log_user_action(user_id, session.get('current_session_id'), "Changed password")

        notify_user_action(
            to_email=user['email'],
            action_type="Password Change",
            item_name="Your password has been successfully changed. If this wasn't you, reset your password immediately."
        )
        # Update session value too
        session['password'] = confirm_pswd

        flash("Password changed successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template('/accountPage/changePswd.html', form=change_pswd_form)


@app.route('/deleteUser/<int:id>', methods=['POST'])
@jwt_required
def delete_user(id):
    current_user = g.user  # Extract from JWT

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user_to_delete = cursor.fetchone()

    if not user_to_delete:
        cursor.close()
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))

    # Case 1: Deleting own account
    if current_user['user_id'] == id:
        cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()
        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"User deleted own account (ID: {id})"
        )
        flash("Your account has been deleted successfully!", "success")
        return redirect(url_for('logout'))  # Or home, depending on your flow

    # Case 2: Admin deleting another account
    if current_user['status'] == 'admin':
        cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()
        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"Admin deleted user account (ID: {id})"
        )
        flash("User account deleted successfully.", "success")
        return redirect(url_for('dashboard'))

    # Unauthorized access
    cursor.close()
    flash("You are not authorized to delete this account.", "danger")
    return redirect(url_for('accountInfo'))


@app.route("/create_update", methods=['GET', 'POST'])
@jwt_required
def create_update():
    form = SeasonalUpdateForm()
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if form.validate_on_submit():
        # reCAPTCHA validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })
        if not r.json().get('success'):
            flash("reCAPTCHA failed.", "danger")
            return render_template('/home/update.html', form=form, site_key=site_key)

        # Decode JWT
        token = request.cookies.get('jwt_token')
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id, user_email = decoded['user_id'], decoded['email']
            session_id = decoded.get('session_id')
        except:
            flash("Invalid session token.", "danger")
            return redirect(url_for('login'))

        # Save pending update
        update_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data
        }

        pending_id = str(uuid.uuid4())
        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending = db.get('pending_updates', {})
            pending[pending_id] = {
                'user_id': user_id,
                'session_id': session_id,
                'email': user_email,  # ✅ ensure this is stored
                'update_data': update_data
            }
            db['pending_updates'] = pending

        # Send verification email
        send_create_verification_email(user_email, pending_id)

        flash("A verification email has been sent. Please confirm to complete your update.", "info")
        return redirect(url_for('home'))

    return render_template('/home/update.html', title='Create Update', form=form, site_key=site_key, is_edit=False)

def send_create_verification_email(email, pending_id):
    token = serializer.dumps({'pending_id': pending_id}, salt='create-update-verification')
    confirm_url = url_for('finalize_create', token=token, _external=True)

    msg = Message("[Cropzy] Confirm Your Seasonal Update", sender=EMAIL_SENDER, recipients=[email])
    msg.body = f"""Hello,

You recently attempted to create a seasonal update on Cropzy.

Please confirm your identity by clicking the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this, you can ignore this email.
"""
    mail.send(msg)

@app.route('/finalize_create/<token>')
def finalize_create(token):
    try:
        data = serializer.loads(token, salt='create-update-verification', max_age=300)
        pending_id = data.get('pending_id')

        if not pending_id:
            flash("Invalid or expired token.", "danger")
            return redirect(url_for('home'))

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending = db.get('pending_updates', {})
            entry = pending.pop(pending_id, None)
            db['pending_updates'] = pending

            if not entry:
                flash("This update has already been confirmed or expired.", "warning")
                return redirect(url_for('home'))

            updates = db.get('updates', [])
            updates.append(entry['update_data'])
            db['updates'] = updates

        log_user_action(
            user_id=entry['user_id'],
            session_id=entry['session_id'],
            action=f"Confirmed and created seasonal update: {entry['update_data']['title']}"
        )

        notify_user_action(
            to_email=entry['email'],
            action_type="Created Seasonal Update",
            item_name=entry['update_data']['title']
        )

        return redirect(url_for('home'))

    except Exception as e:
        flash("Something went wrong or the link has expired.", "danger")
        return redirect(url_for('home'))


@app.route('/delete_update/<int:index>', methods=['POST'])
@jwt_required
def delete_update(index):
    # Save index in session and send email
    session['delete_pending_index'] = index

    token = serializer.dumps({
        'user_id': g.user['user_id'],
        'email': g.user['email']
    }, salt='delete-update-verification')

    confirm_url = url_for('finalize_delete', token=token, _external=True)

    msg = Message("[Cropzy] Confirm Deletion of Update", sender=EMAIL_SENDER, recipients=[g.user['email']])
    msg.body = f"""Hello,

You requested to delete one of your seasonal updates on Cropzy.

To confirm this deletion, please click the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this action, you can safely ignore this message.
"""
    mail.send(msg)

    flash("Verification email sent. Please confirm to delete the update.", "info")
    return redirect(url_for('home'))

@app.route('/finalize_delete/<token>')
def finalize_delete(token):
    try:
        data = serializer.loads(token, salt='delete-update-verification', max_age=300)
        user_id = data['user_id']
        user_email = data['email']
        index = session.pop('delete_pending_index', None)

        if index is None:
            flash("No pending deletion found or session expired.", "warning")
            return redirect(url_for('home'))

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            updates = db.get('updates', [])
            if 0 <= index < len(updates):
                removed = updates.pop(index)
                db['updates'] = updates

                log_user_action(user_id, session.get('current_session_id'), f"Deleted seasonal update: {removed['title']}")

                # ✅ Send email notification
                notify_user_action(
                    to_email=user_email,
                    action_type="Deleted Seasonal Update",
                    item_name=removed['title']
                )

                flash(f"Update \"{removed['title']}\" deleted successfully!", "success")
            else:
                flash("Invalid update index.", "danger")

    except Exception:
        flash("Verification link expired or invalid.", "danger")

    return redirect(url_for('home'))

@app.route('/edit_update/<int:index>', methods=['GET', 'POST'])
@jwt_required
def edit_update(index):
    form = SeasonalUpdateForm()
    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])
        if 0 <= index < len(updates):
            update = updates[index]
        else:
            flash('Invalid update index.', 'danger')
            return redirect(url_for('home'))

    if form.validate_on_submit():
        # Save the edit temporarily
        edited_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data
        }

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            db['pending_edits'] = db.get('pending_edits', {})
            db['pending_edits'][str(index)] = {
                'user_id': g.user['user_id'],
                'session_id': g.user.get('session_id'),
                'data': edited_data
            }

        # Send verification email
        token = serializer.dumps({
            'user_id': g.user['user_id'],
            'index': index,
            'email': g.user['email']
        }, salt='edit-update-verification')

        confirm_url = url_for('finalize_edit', token=token, _external=True)

        msg = Message(
            "[Cropzy] Confirm Edit of Seasonal Update",
            sender=EMAIL_SENDER,
            recipients=[g.user['email']]
        )
        msg.body = f"""Hello,

You attempted to edit a seasonal update on Cropzy.

To confirm and apply your edit, click the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this, you may ignore this message.
"""
        mail.send(msg)

        flash("Edit submitted. Please confirm via the email sent to you.", "info")
        return redirect(url_for('home'))

    # Pre-fill the form with current update data
    form.update.data = update.get('title', '')
    form.content.data = update.get('content', '')
    form.date.data = datetime.strptime(update.get('date', '01-01-2025'), '%d-%m-%Y')
    form.season.data = update.get('season', '')

    return render_template('/home/update.html', title='Edit Update', form=form, is_edit=True, index=index)

@app.route('/finalize_edit/<token>')
def finalize_edit(token):
    try:
        data = serializer.loads(token, salt='edit-update-verification', max_age=300)
        user_id = data['user_id']
        user_email = data['email']
        index = str(data['index'])

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending_edits = db.get('pending_edits', {})
            updates = db.get('updates', [])

            if index not in pending_edits:
                flash("No pending edit found or already confirmed.", "warning")
                return redirect(url_for('home'))

            edit_entry = pending_edits.pop(index)
            db['pending_edits'] = pending_edits

            if 0 <= int(index) < len(updates):
                updates[int(index)] = edit_entry['data']
                db['updates'] = updates

                log_user_action(
                    user_id,
                    edit_entry['session_id'],
                    f"Edited seasonal update: {edit_entry['data']['title']}"
                )

                # ✅ Send confirmation notification
                notify_user_action(
                    to_email=user_email,
                    action_type="Edited Seasonal Update",
                    item_name=edit_entry['data']['title']
                )

                flash("Update successfully edited.", "success")
            else:
                flash("Invalid update index.", "danger")

    except Exception:
        flash("Verification link is invalid or expired.", "danger")

    return redirect(url_for('home'))



@app.route('/request_delete/<int:index>', methods=['GET'])
@jwt_required
def request_delete(index):
    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])
        if 0 <= index < len(updates):
            update = updates[index]

            if 'user_id' in session:
                log_user_action(
                    session['user_id'],
                    session.get('current_session_id'),
                    f'Requested delete confirmation for seasonal update: {update["title"]}'
                )

            return render_template('/home/confirm_delete.html', update=update, index=index)
        else:
            flash('Invalid update index.', 'danger')
            return redirect(url_for('home'))

@app.route('/update_cart', methods=['POST'])
def update_cart():
    product_id = request.form.get("product_id")
    action = request.form.get("action")
    cart = session.get("cart", {})

    if product_id in cart:
        if action == "increase":
            cart[product_id]['quantity'] += 1
        elif action == "decrease":
            cart[product_id]['quantity'] -= 1
            if cart[product_id]['quantity'] <= 0:
                del cart[product_id]

    session["cart"] = cart  # update session cart
    session.modified = True  # save changes

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action=f"Updated cart: Product ID {product_id}, Action {action}"
        )

    return redirect(url_for('buy_product'))


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    cart = session.get("cart", {})

    product = Product.query.get(product_id)
    if not product:
        flash("❌ Product not found!", "danger")
        return redirect(url_for('buy_product'))

    if str(product_id) in cart:
        cart[str(product_id)]['quantity'] += 1
    else:
        cart[str(product_id)] = {
            "name": product.name,
            "price": float(product.price),
            "image": url_for('static', filename='uploads/' + (product.image_filename or 'default.jpg')),
            # ✅ Include Image
            "quantity": 1
        }

    session["cart"] = cart
    session["show_cart"] = True
    session.modified = True

    flash(f"✅ {product.name} added to cart!", "success")

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action=f"Added to cart: {product.name} (ID {product.id})"
        )

    return redirect(url_for('buy_product'))


@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("🛒 Cart cleared!", "info")

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action="Cleared shopping cart"
        )

    return redirect(url_for('buy_product'))


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    cart = session.get("cart", {})

    if not cart:
        return redirect(url_for('buy_product'))

    session["customer"] = {
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "phone": request.form.get("phone"),
        "address_line1": request.form.get("address_line1"),
        "address_line2": request.form.get("address_line2"),
        "province": request.form.get("province"),
        "postal_code": request.form.get("postal_code"),
    }
    session.modified = True

    line_items = [
        {
            "price_data": {
                "currency": "usd",
                "product_data": {"name": item["name"]},
                "unit_amount": int(item["price"] * 100),
            },
            "quantity": item["quantity"],
        }
        for item in cart.values()
    ]

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="payment",
            customer_email=request.form.get("email"),
            success_url=url_for('thank_you', _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for('checkout', _external=True),
        )
        return redirect(checkout_session.url)
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route('/checkout', methods=['GET'])
@login_required
def checkout():
    cart = session.get("cart", {})  # Get cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())  # Calculate total price

    return render_template('/checkout/checkout.html', cart=cart, total_price=total_price)


def notify_user_action(to_email, action_type, item_name=None, details=None):
    """
    Send a general-purpose email notification to the user.

    Parameters:
    - to_email: Recipient's email address.
    - action_type: What action occurred (e.g., "Deleted Product", "Edited Update").
    - item_name: Optional name/title of the item involved.
    - details: Optional extra details to include in the email.
    """
    try:
        subject = f"[Cropzy] {action_type}"
        message = f"The following action was performed on your Cropzy account:\n\n"
        message += f"Action: {action_type}\n"

        if item_name:
            message += f"Item: {item_name}\n"

        if details:
            message += f"Details: {details}\n"

        message += f"\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += "\nIf you did not authorize this action, please contact support immediately.\n\n- Cropzy Team"

        # Construct and send email
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(app.config['MAIL_USERNAME'], to_email, msg.as_string())
        server.quit()

        print(f"[DEBUG] Notification sent to {to_email}")

    except Exception as e:
        print(f"[ERROR] Failed to send notification: {e}")

def send_email(to_email, subject, message):
    """Send an email using SMTP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        server.quit()
        print(f"Email sent successfully to {to_email}")

    except Exception as e:
        print(f"❌ Email failed to send: {e}")


@app.route('/thank_you')
def thank_you():
    session_id = request.args.get('session_id')
    if not session_id:
        return "Invalid request", 400

    try:
        stripe_session = stripe.checkout.Session.retrieve(session_id)

        if stripe_session.payment_status == "paid":
            order = session.get("cart", {})
            customer = session.get("customer", {})
            total_price = sum(item['price'] * item['quantity'] for item in order.values())
            order_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            transaction_id = str(uuid.uuid4())[:6]  # Generate a random transaction ID

            if "transactions" not in session:
                session["transactions"] = []

            session["transactions"].append({
                "id": transaction_id,
                "user_id": session.get("user_id"),  # Store the logged-in user ID
                "name": customer.get("name", "N/A"),
                "email": customer.get("email", "N/A"),
                "total": total_price,
                "date": order_date,
                "products": [
                    {
                        "product_name": item["name"],
                        "price": item["price"],
                        "quantity": item["quantity"]
                    }
                    for item in order.values()
                ]
            })
            session.modified = True

            if 'user_id' in session:
                log_user_action(
                    user_id=session['user_id'],
                    session_id=session.get('current_session_id'),
                    action=f"Completed purchase - Transaction ID: {transaction_id}, Total: ${total_price}"
                )

            # send confirmation email
            if customer.get("email"):
                email_subject = "Order Confirmation"
                email_message = f"""
                Thank you for your purchase, {customer.get('name', 'Customer')}!\n
                Transaction ID: {transaction_id}
                Total Price: ${total_price}
                Date: {order_date}
                """
                send_email(customer.get("email"), email_subject, email_message)

            # clear cart after payment
            session.pop("cart", None)
            session.pop("customer", None)

            return render_template('checkout/thanks.html', order=order, customer=customer,
                                   total_price=total_price, order_date=order_date,
                                   transaction_id=transaction_id)
        else:
            return "Payment not confirmed", 400
    except Exception as e:
        return f"Error retrieving session: {str(e)}", 500


@app.route('/transactions', methods=['GET'])
def transactions():
    transactions = session.get("transactions", [])  # Get transaction history from session

    # Search Filter (If user enters a search term)
    search_query = request.args.get("search", "").strip().lower()
    if search_query:
        transactions = [t for t in transactions if search_query in t["id"].lower() or search_query in t["name"].lower()]

    return render_template('checkout/transaction.html', transactions=transactions, search_query=search_query)


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    cart = session.get("cart", {})  # Retrieve cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())  # Calculate total price

    return render_template('/checkout/cart.html', cart=cart, total_price=total_price)


@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')

    if not user_message:
        return jsonify({'response': "Please provide a message!"})

    bot_response = generate_response(user_message)
    return jsonify({'response': bot_response})

def send_reset_pass(email, user_id):
    try:
        token = secrets.token_urlsafe(32)
        sg_time = datetime.utcnow() + timedelta(hours=8)
        expires_at = sg_time + timedelta(minutes=1)

        # Store token in DB
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO password_resets (email, token, expires_at) VALUES (%s, %s, %s)",
            (email, token, expires_at))
        mysql.connection.commit()
        cursor.close()

        # Construct URL
        reset_url = url_for('reset_password', token=token, _external=True)
        subject = "[Cropzy] Reset Your Password"
        message = (
            f"Hi,\n\n"
            f"We received a request to reset your password. You can reset it by clicking the link below:\n\n"
            f"{reset_url}\n\n"
            f"This link will expire in 10 minutes.\n\n"
            f"Thanks,\nCropzy Support")
        send_email(email, subject, message)

    except Exception as e:
        print(f"[ERROR] Failed to send reset password email: {e}")

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPassRequest(request.form)

    if request.method == 'POST' and form.validate():
        email = form.email.data  # Define this helper to fetch user_id
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            send_reset_pass(email, user[0])

        # Always show same message regardless
        flash("If an account with that email exists, a reset link has been sent.", "info")


    return render_template("accountPage/reset_pass_request.html", form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPass(request.form)
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT email, expires_at FROM password_resets WHERE token = %s", (token,))
    row = cursor.fetchone()

    if not row:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('reset_password_request'))

    email, expires_at = row
    if datetime.now() > expires_at:
        flash("Reset link has expired.", "danger")
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST' and form.validate():
        new_password = form.new_pswd.data
        confirm_password = form.confirm_pswd.data

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token,_external=True))
        else:
            hashed_pw = hash_password(new_password)
            cursor.execute("UPDATE accounts SET password = %s WHERE email = %s", (hashed_pw, email))
            cursor.execute("DELETE FROM password_resets WHERE token = %s", (token,))
            mysql.connection.commit()
            cursor.close()

        flash("Password reset successfully.", "success")
        return redirect(url_for('login'))

    cursor.close()
    return render_template("accountPage/reset_pass.html", form=form)

@app.after_request
def set_clickjacking_protection(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none';"
    return response

@app.route('/freeze_account/<int:user_id>', methods=['POST'])
def freeze_account(user_id):
    cursor = mysql.connection.cursor()

    cursor.execute(
        "INSERT INTO frozen_account (user_id, reason, frozen_at, is_frozen) VALUES (%s, %s, NOW(), TRUE)",
        (user_id, 'Manual freeze by user'))

    mysql.connection.commit()
    cursor.close()
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('jwt_token')
    flash("Account has been frozen.", "danger")

    return response  # Or wherever you're managing users


def is_account_frozen(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT is_frozen FROM frozen_account WHERE user_id = %s ORDER BY frozen_at DESC LIMIT 1", (user_id,))
    freeze_entry = cursor.fetchone()
    cursor.close()

    # Return True if most recent freeze entry exists and is active
    return freeze_entry and freeze_entry['is_frozen'] == True

# Helper: Send Unfreeze Email
def send_unfreeze_email(user_id, email):
    try:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=1)

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO unfreeze_requests (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, token, expires_at))
        mysql.connection.commit()

        unfreeze_url = url_for('unfreeze_account', token=token, _external=True)
        subject = "[Cropzy] Unfreeze Your Account"
        message = (
            f"Hi,\n\n"
            f"Your account was frozen. To unfreeze it, please click the link below:\n\n"
            f"{unfreeze_url}\n\n"
            f"This link will expire in 10 minutes.\n\n"
            f"Best,\nCropzy Support"
        )
        send_email(email, subject, message)

    except Exception as e:
        print(f"[ERROR] Failed to send unfreeze email: {e}")


@app.route('/unfreeze/<token>')
def unfreeze_account(token):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM unfreeze_requests WHERE token = %s", (token,))
    request_row = cursor.fetchone()

    if not request_row:
        flash("Invalid or expired unfreeze link.", "danger")
        return redirect(url_for('login'))

    if datetime.utcnow() > request_row['expires_at']:
        flash("This unfreeze link has expired.", "danger")
        return redirect(url_for('login'))

    user_id = request_row['user_id']
    cursor.execute("UPDATE frozen_account SET is_frozen = FALSE WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM unfreeze_requests WHERE token = %s", (token,))
    mysql.connection.commit()
    cursor.close()

    flash("Your account has been unfrozen. You can now log in.", "success")
    return redirect(url_for('login'))


@app.route('/send_unfreeze_email', methods=['POST'])
def ajax_send_unfreeze_email():
    user_id = request.args.get('user_id')  # or from request.json

    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not logged in.'}), 403

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    send_unfreeze_email(user_id, user['email'])
    return jsonify({'status': 'success', 'message': 'Unfreeze email sent.'})



if __name__ == "__main__":
    generate_self_signed_cert()

    app.run(ssl_context=("certs/cert.pem", "certs/key.pem"), host="127.0.0.1", port=443, debug=True)
