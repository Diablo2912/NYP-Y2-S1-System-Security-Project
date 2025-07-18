from flask import Flask, g, Response, render_template, request, redirect, url_for, session, jsonify, flash, \
    make_response
from functools import wraps
from Forms import SignUpForm, CreateAdminForm, CreateProductForm, LoginForm, ChangeDetForm, ChangePswdForm
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

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791262abcdefg'
UPLOAD_FOLDER = 'static/uploads/'  # Define where images are stored
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
stripe.api_key = "sk_test_51Qrle9CddzoT6fzjpqNPd1g3UV8ScbnxiiPK5uYT0clGPV82Gn7QPwcakuijNv4diGpcbDadJjzunwRcWo0eOXvb00uDZ2Gnw6"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=90)

load_dotenv()
print("Loaded ENV value for TEST_VAR =", os.getenv("TEST_VAR"))

images = UploadSet('images', IMAGES)

app.register_blueprint(main_blueprint)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'ngiam.brandon@gmail.com'
app.config['MAIL_PASSWORD'] = 'isgw cesr jdbs oytx'
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
EMAIL_SENDER = "sadevdulneth6@gmail.com"
EMAIL_PASSWORD = "isgw cesr jdbs oytx"

# SETUP UR DB CONFIG ACCORDINGLY
# DON'T DELETE OTHER CONFIGS JUST COMMENT AWAY IF NOT USING

# GLEN SQL DB CONFIG
app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'glen'
app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
app.config['MYSQL_DB'] = 'ssp_db'
app.config['MYSQL_PORT'] = 3306

# BRANDON SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'glen'
# app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
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
# #SADEV SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'glen'
# app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306

mysql = MySQL(app)

with app.app_context():
    db.create_all()

ALGORITHM = 'pbkdf2_sha256'


# CFT on SQL#
# SQL LOGGING
# Info
# Warning
# Error
# Critical

# input sanitisation
def sanitize_input(user_input):
    allowed_tags = ['a', 'b', 'i', 'em', 'strong']
    allowed_attributes = {'a': ['href']}

    return bleach.clean(user_input, tags=allowed_tags, attributes=allowed_attributes)


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
        return redirect(url_for('manageProduct'))

    return render_template('/productPage/updateProduct.html', form=form, product=product)


@app.route('/deleteProduct/<int:id>', methods=['POST'])
def delete_product(id):
    product = Product.query.get_or_404(id)

    # delete image if its not default
    if product.image_filename != "default.jpg":
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(product)
    db.session.commit()
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
    return render_template('/accountPage/accountInfo.html', user=user)  # ❗️Passing as `user`, not updating current_user



@app.route('/accountSecurity', methods=['GET', 'POST'])
@jwt_required
def accountSecurity():
    user_id = g.user['user_id']
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
    cursor.execute("UPDATE accounts SET status = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
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

    cursor.close()

    return render_template(
        'logging_analytics.html',
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
        num_days=num_days
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


def admin_log_activity(mysql, activity, category="Info"):
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

    user_id = g.user['user_id']

    user_id = user_id
    date = datetime.now().strftime('%Y-%m-%d')
    time = datetime.now().strftime('%I:%M %p')
    status = 'Open'
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)

    # Insert log into DB
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('''
            INSERT INTO logs (user_id, date, time, category, activity, status, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        ''', (user_id, date, time, category, activity, status, ip_addr))
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
        user_country = get_user_country(ip_address)

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
            user_country
        ))

        # Log registration
        # admin_log_activity(mysql, "User signed up successfully", category="Critical")

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
def login():
    login_form = LoginForm(request.form)

    if request.method == 'POST' and login_form.validate():
        email = sanitize_input(login_form.email.data.lower())
        password = login_form.pswd.data

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Hardcoded IP (Singapore - SG) for testing purposes
            ip_address = '183.90.84.148'
            # Hardcoded IP (Malaysia - MYS) for testing purposes
            # Hardcoded IP (Japan - JPN) for testing purposes
            # #Uncomment if not run on code editor, but on Proxy or Load Balancer
            # Eg: Nginx, Heroku, Apache, Cloudflare
            # ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            current_country = get_user_country(ip_address)
            print(f"User IP: {ip_address}, Country: {current_country}")

            # Ensure 'countries' is not None
            allowed_countries = user.get('countries') or ''
            allowed_list = [c.strip() for c in allowed_countries.split(',')] if allowed_countries else []

            if current_country not in allowed_list:
                flash("Login from your region is not allowed.", "danger")
                return redirect(url_for('login'))

            # Password validation
            stored_password_hash = user['password']
            if verify_password(password, stored_password_hash):
                if user.get('two_factor_status') == 'enabled':
                    send_otp_email(user['email'], user['id'], user['first_name'], user['last_name'])
                    session['pending_2fa_user_id'] = user['id']
                    return redirect(url_for('verify_otp', id=user['id']))
                else:
                    session_id = log_session_activity(user['id'], 'login')
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
                    return response

            flash('Incorrect password.', 'danger')
        else:
            flash('Email not found. Please sign up.', 'danger')

    return render_template('/accountPage/login.html', form=login_form)


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
auth_token = '53bd48449584c66310867cf380f2efb6'
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

            session_id = log_session_activity(user['id'], 'login')

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

            flash("Login successful!", "success")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('/accountPage/sms_auth.html', id=id)


def generate_recovery_code(id):
    code = f"{random.randint(0, 999999):012d}"  # Generate 12-digit code

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if user exists
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return False  # User not found

    # Update recovery code
    cursor.execute("UPDATE accounts SET recovery_code = %s WHERE id = %s", (code, id))
    mysql.connection.commit()
    cursor.close()

    return code


@app.route('/setup_face_id/<int:id>', methods=['GET', 'POST'])
def setup_face_id(id):
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

        flash("Face ID registered successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template("accountPage/setup_face_id.html", id=id)


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

                session_id = log_session_activity(user['id'], 'login')

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

                flash("Face matched. Logged in successfully!", "success")
                return response
            else:
                flash("Face does not match. Access denied.", "danger")

        except Exception as e:
            flash(f"Error during face verification: {str(e)}", "danger")

    return render_template("accountPage/face_id.html", id=id)

@app.route('/more_auth/<int:id>', methods=['GET'])
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

    generate_recovery_code(id)

    cursor.close()
    return redirect(url_for('accountInfo'))


@app.route('/disable2FA/<int:id>/', methods=['POST'])
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
        cursor.execute("UPDATE accounts SET two_factor_status = %s, recovery_code = NULL , face = NULL WHERE id = %s",
                       ('disabled', id))
        mysql.connection.commit()
        flash("2FA has been disabled for this account.", "success")

    cursor.close()
    return redirect(url_for('accountInfo'))


def log_session_activity(user_id, action):
    print(f"[DEBUG] Creating session log for user {user_id} at {datetime.now()}")
    try:
        cursor = mysql.connection.cursor()

        session_id = None  # default

        if action == 'login':
            cursor.execute('''
                INSERT INTO user_session_activity (user_id, login_time, ip_address, user_agent)
                VALUES (%s, NOW(), %s, %s)
            ''', (
                user_id,
                request.remote_addr,
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

        return session_id  # ✅ return this always (None for logout)

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


@app.route('/test-log')
def test_log():
    log_session_activity(3, 'login')
    return 'Test log done'


@app.route('/activity_history')
@jwt_required
def activity_history():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch session activity logs
    cursor.execute("""
        SELECT id, login_time, logout_time, ip_address, user_agent
        FROM user_session_activity
        WHERE user_id = %s
        ORDER BY login_time DESC
        LIMIT 50
    """, (user_id,))
    sessions = cursor.fetchall()

    # For each session, fetch related actions
    for s in sessions:
        cursor.execute("""
            SELECT action, timestamp
            FROM user_actions_log
            WHERE session_id = %s
            ORDER BY timestamp ASC
        """, (s['id'],))
        s['actions'] = cursor.fetchall()

    cursor.close()

    return render_template('/accountPage/activity.html', sessions=sessions)


@app.route('/revoke_session/<session_id>', methods=['POST'])
@jwt_required
def revoke_session(session_id):
    user_id = g.user['user_id']
    if not user_id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE user_session_activity
        SET logout_time = %s
        WHERE id = %s AND user_id = %s AND logout_time IS NULL
    """, (datetime.utcnow(), session_id, user_id))
    mysql.connection.commit()
    cursor.close()

    # ✅ Log under the correct session
    log_user_action(user_id, g.user['session_id'], f"Manually revoked session {session_id}")

    flash("Session revoked successfully.", "success")
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

    # Call your existing email sending function
    send_email(email, subject, message)


# def send_otp_sms():

@app.route('/verify-otp/<int:id>', methods=['GET', 'POST'])
def verify_otp(id):
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
            session_id = log_session_activity(user['id'], 'login')

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

            flash("Login successful!", "success")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('/accountPage/two_factor.html', id=id)


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
                session_id = log_session_activity(result['id'], 'login')

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

                # ✅ Use user action log instead of logging a new session
                log_user_action(result['id'], session_id, "Logged in via recovery code")

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
        flash("Your account has been deleted successfully!", "success")
        return redirect(url_for('logout'))  # Or home, depending on your flow

    # Case 2: Admin deleting another account
    if current_user['status'] == 'admin':
        cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()
        flash("User account deleted successfully.", "success")
        return redirect(url_for('dashboard'))

    # Unauthorized access
    cursor.close()
    flash("You are not authorized to delete this account.", "danger")
    return redirect(url_for('accountInfo'))


@app.route("/create_update", methods=['GET', 'POST'])
def create_update():
    form = SeasonalUpdateForm()
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if form.validate_on_submit():
        # reCAPTCHA validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {'secret': secret_key, 'response': recaptcha_response}
        r = requests.post(verify_url, data=payload)
        result = r.json()

        if not result.get('success'):
            flash("reCAPTCHA verification failed. Please try again.", 'danger')
            return render_template('/home/update.html', title='Update', form=form, site_key=site_key)

        # ✅ Decode JWT token from cookie
        token = request.cookies.get('jwt_token')
        if not token:
            flash("User not authenticated. No token found.", "danger")
            return redirect(url_for('login'))

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_email = decoded['email']
            user_id = decoded['user_id']
            print("[DEBUG] Decoded user:", decoded)
        except jwt.ExpiredSignatureError:
            flash("Session expired. Please log in again.", "danger")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Invalid session token. Please log in again.", "danger")
            print(f"[ERROR] JWT decoding failed: {e}")
            return redirect(url_for('login'))

        # Prepare update data
        update_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data,
        }

        # ✅ Send confirmation email
        send_update_confirmation_email(
            email=user_email,
            user_id=user_id,
            update_data=update_data
        )
        flash("A confirmation email has been sent. Please verify to complete the update.", "info")
        return redirect(url_for('home'))

    return render_template('/home/update.html', title='Update', form=form, site_key=site_key)


def send_update_confirmation_email(email, user_id, update_data):
    token_data = {
        'user_id': user_id,
        'update_id': str(uuid.uuid4()),
        'update_data': update_data,
        'exp': datetime.utcnow() + timedelta(minutes=15)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm='HS256')

    confirm_url = url_for('confirm_update', token=token, _external=True)
    reject_url = url_for('reject_update', token=token, _external=True)

    html = f"""
    <html>
    <body>
    <p>Hello,</p>
    <p>You attempted to create the following seasonal update:</p>
    <ul>
        <li><strong>Title:</strong> {update_data['title']}</li>
        <li><strong>Content:</strong> {update_data['content']}</li>
        <li><strong>Date:</strong> {update_data['date']}</li>
        <li><strong>Season:</strong> {update_data['season']}</li>
    </ul>
    <p>Please confirm your identity:</p>
    <p>
        <a href="{confirm_url}" style="padding:10px 15px;background-color:green;color:white;text-decoration:none;">Yes, this is me</a>
        &nbsp;
        <a href="{reject_url}" style="padding:10px 15px;background-color:red;color:white;text-decoration:none;">This is not me</a>
    </p>
    </body>
    </html>
    """

    sender_email = "sadevdulneth6@gmail.com"
    receiver_email = email
    sender_password = "isgw cesr jdbs oytx"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Confirm Your Seasonal Update"
    message["From"] = sender_email
    message["To"] = receiver_email

    # ✅ Attach HTML with proper UTF-8 encoding
    message.attach(MIMEText(html, "html", _charset="utf-8"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        print("[DEBUG] Email confirmation sent.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


@app.route('/confirm_update/<token>')
def confirm_update(token):
    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        update_data = decoded['update_data']
        user_id = decoded['user_id']

        # ✅ Fetch user from DB to restore session
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # ✅ Restore session
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['first_name'] = user['first_name']
            session['last_name'] = user['last_name']
            session['gender'] = user['gender']
            session['phone'] = user['phone_number']
            session['status'] = user['status']

            # ✅ Save the update
            with shelve.open('seasonal_updates.db') as db:
                updates = db.get('updates', [])
                updates.append(update_data)
                db['updates'] = updates

            log_user_action(user['id'], session.get('current_session_id'),
                            f"Confirmed and created seasonal update: {update_data['title']}")
            flash("Seasonal update created successfully!", "success")
        else:
            flash("User not found. Cannot restore session.", "danger")

    except jwt.ExpiredSignatureError:
        flash("Confirmation link expired.", "danger")
    except Exception as e:
        flash(f"Failed to confirm update: {e}", "danger")

    return redirect(url_for('home'))


@app.route('/reject_update/<token>')
def reject_update(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        update_data = decoded['update_data']
        user_id = decoded['user_id']

        log_user_action(user_id, session.get('current_session_id'), f"Rejected seasonal update: {update_data['title']}")

        flash("Update rejected and not saved.", "info")
    except Exception as e:
        flash(f"Error processing rejection: {e}", "danger")
    return redirect(url_for('home'))


@app.route('/delete_update/<int:index>', methods=['POST'])
def delete_update(index):
    try:
        with shelve.open('seasonal_updates.db', writeback=True) as db:
            updates = db.get('updates', [])
            if 0 <= index < len(updates):
                removed_update = updates.pop(index)
                db['updates'] = updates  # Save the updated list
                if 'user_id' in session:
                    log_user_action(session['user_id'], session.get('current_session_id'),
                                    f'Deleted seasonal update: {removed_update["title"]}')

                flash(f'Update "{removed_update["title"]}" deleted successfully!', 'success')
            else:
                flash('Invalid update index.', 'danger')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')

    return redirect(url_for('home'))


@app.route('/edit_update/<int:index>', methods=['GET', 'POST'])
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
        # Update the selected update with form data
        updates[index] = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data,
        }
        with shelve.open('seasonal_updates.db') as db:
            db['updates'] = updates  # Save the updated list back to the database

            if 'user_id' in session:
                log_user_action(session['user_id'], session.get('current_session_id'),
                                f'Edited seasonal update: {form.update.data}')

        flash(f'Update "{form.update.data}" updated successfully!', 'success')
        return redirect(url_for('home'))

    # Pre-fill the form with current update data
    form.update.data = update['title']
    form.content.data = update['content']
    form.date.data = datetime.strptime(update['date'], '%d-%m-%Y')  # Convert string to date
    form.season.data = update['season']

    return render_template('/home/update.html', title='Edit Update', form=form)


@app.route('/request_delete/<int:index>', methods=['GET'])
def request_delete(index):
    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])
        if 0 <= index < len(updates):
            update = updates[index]
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
    return redirect(url_for('buy_product'))


@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("🛒 Cart cleared!", "info")
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


if __name__ == '__main__':
    app.run(debug=True)