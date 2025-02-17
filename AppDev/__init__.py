from flask import Flask, Response, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
import os
from Forms import SignUpForm, CreateProductForm, LoginForm, ChangeDetForm, ChangePswdForm
import shelve, User
from FeaturedArticles import get_featured_articles
from Filter import main_blueprint
from seasonalUpdateForm import SeasonalUpdateForm
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import base64
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

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791262abcdefg'
UPLOAD_FOLDER = 'static/uploads/'  # Define where images are stored
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
stripe.api_key = "sk_test_51Qrle9CddzoT6fzjpqNPd1g3UV8ScbnxiiPK5uYT0clGPV82Gn7QPwcakuijNv4diGpcbDadJjzunwRcWo0eOXvb00uDZ2Gnw6"

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


with app.app_context():
    db.create_all()

#CFT on SQL#

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:  # Check if user is logged in
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for("login"))
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
        Product(name="Solar-Powered Irrigation Timer", quantity=20, category="Eco-Friendly Farming Tools", price=34.99, co2=2.2),

        # Regenerative Agriculture Products
        Product(name="Cover Crop Mix", quantity=25, category="Regenerative Agriculture", price=14.99, co2=2.8),
        Product(name="Biochar Soil Amendment", quantity=35, category="Regenerative Agriculture", price=19.99, co2=1.5)
    ]

    db.session.add_all(sample_products)
    db.session.commit()
    return "Sample sustainable agricultural products added!"

@app.route('/')
def home():
    articles = get_featured_articles()
    updates = []

    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])

    # Retrieve all products
    products = Product.query.all()

    if not products:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None)

    # Convert product data to Pandas DataFrame
    data = [{'name': product.name, 'category': product.category, 'co2': product.co2} for product in products]
    df = pd.DataFrame(data)

    # Ensure there is data before plotting
    if df.empty:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None)

    # chart 1
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

    # chart 2
    category_totals = df.groupby('category')['co2'].sum()
    plt.figure(figsize=(8, 5))
    plt.pie(category_totals, labels=category_totals.index, autopct='%1.1f%%', startangle=140)
    plt.title('CO₂ Emissions by Product Category')

    buffer2 = BytesIO()
    plt.savefig(buffer2, format='png')
    buffer2.seek(0)
    chart2_data = base64.b64encode(buffer2.getvalue()).decode('utf-8')
    buffer2.close()

    # chart 3
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

    welcome_message = f"Welcome, {session['first_name']}!" if 'first_name' in session else "Welcome!"

    return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=chart1_data,
                           chart2_data=chart2_data, chart3_data=chart3_data, welcome_message=welcome_message)

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

    return render_template('/productPage/buyProduct.html',
                           products=products,
                           all_categories=all_categories,
                           selected_categories=selected_categories)

@app.route('/createProduct', methods=['GET', 'POST'])
def create_product():
    form = CreateProductForm()

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
def manageProduct():
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
                data.append(f"{product.name},{product.quantity},{product.category},{product.price},{product.co2},{product.description},{product.image_filename}\n")
            return "".join(data)

        response = Response(generate(), mimetype='text/csv')
        response.headers["Content-Disposition"] = "attachment; filename=products.csv"
        return response

    print(f"✅ Loaded {len(products)} products for management.")  # Debugging message
    return render_template('/productPage/manageProduct.html', products=products)

@app.route('/updateProduct/<int:id>/', methods=['GET', 'POST'])
def update_product(id):
    product = Product.query.get_or_404(id)
    form = CreateProductForm(obj=product)

    categories = db.session.query(Product.category).distinct().all()
    category_choices = [(cat[0], cat[0]) for cat in categories]
    form.category.choices = category_choices

    if request.method == 'POST' and form.validate_on_submit():
        product.name = form.product_name.data
        product.quantity = int(form.quantity.data)
        product.category = form.category.data
        product.price = float(form.price.data)
        product.co2 = float(form.co2.data)
        product.description = form.product_description.data

        # Handle Image Upload
        image_file = form.product_image.data
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

            # Ensure `product.image_filename` is never None
            product.image_filename = filename if filename else "default.png"

        db.session.commit()
        return redirect(url_for('manageProduct'))  # ✅ Redirect after update

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
    return redirect(url_for('manageProduct'))  #

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

# Route to delete a selected product from the tracker
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

@app.route('/contactUs')
def contactUs():
   return render_template('contactUs.html')

@app.route('/accountInfo')
@login_required
def accountInfo():
    users_dict = {}
    db = shelve.open('user.db', 'r')
    users_dict = db['Users']
    db.close()

    users_list = []

    for key in users_dict:
        user = users_dict.get(key)
        users_list.append(user)
    return render_template('/accountPage/accountInfo.html', count=len(users_list), users_list=users_list)


@app.route('/accountSecurity')
@login_required
def accountSecurity():
    # Fetch the logged-in user’s ID from the session
    user_id = session.get('user_id')

    # Open the database and fetch user information
    with shelve.open('user.db', 'r') as db:
        users_dict = db.get('Users', {})
        user = users_dict.get(user_id)

    # Check if the user exists in the database
    if user:
        return render_template('/accountPage/accountSecurity.html', user=user)

    # If the user is not found in the db (just in case)
    flash("User data not found.", "danger")
    return redirect(url_for('login'))

@app.route('/accountHist')
@login_required
def accountHist():
   return render_template('/accountPage/accountHist.html')

@app.route('/signUp', methods=['GET', 'POST'])
def sign_up():
    sign_up_form = SignUpForm(request.form)
    if request.method == 'POST' and sign_up_form.validate():
        db = shelve.open('user.db','c')

        users_dict = db.get('Users', {})

        existing_users = list(users_dict.values())

        # Check if email or phone number already exists
        for user in existing_users:
            if user.get_email() == sign_up_form.email.data:  # Use get_email()
                flash('Email is already registered. Please use a different email.', 'danger')
                db.close()
                return redirect(url_for('sign_up'))

            if user.get_number() == sign_up_form.number.data:  # Use get_number()
                flash('Phone number is already registered. Please use a different number.', 'danger')
                db.close()
                return redirect(url_for('sign_up'))

        hashed_password = generate_password_hash(sign_up_form.cfm_pswd.data, method='pbkdf2:sha256')

        user = User.User(sign_up_form.first_name.data,
                         sign_up_form.last_name.data,
                         sign_up_form.gender.data,
                         sign_up_form.number.data,
                         sign_up_form.email.data,
                         sign_up_form.pswd.data,
                         hashed_password)

        users_dict[user.get_user_id()] = user
        db['Users'] = users_dict
        db.close()

        flash('Sign up successful! Please log in.', 'info')
        return redirect(url_for('complete_signUp'))
    return render_template('/accountPage/signUp.html', form=sign_up_form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)

    if request.method == 'POST' and login_form.validate():
        email = login_form.email.data
        password = login_form.pswd.data

        with shelve.open('user.db', 'c') as db:  # Ensures the DB is closed properly
            users_dict = db.get('Users', {})

            # Find the user by email
            user = next((u for u in users_dict.values() if u.get_email() == email), None)

            if user:
                print(f"User found: {user.get_email()}, checking password...")

                if check_password_hash(user.get_cfm_pswd(), password):  # Correct password field
                    session['logged_in'] = True
                    session['user_id'] = user.get_user_id()
                    session['first_name'] = user.get_first_name()
                    session['last_name'] = user.get_last_name()
                    session['gender'] = user.get_gender()
                    session['phone'] = user.get_number()
                    session['email'] = user.get_email()
                    session['pswd'] = password
                    session['is_staff'] = user.get_is_staff()

                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))  # Redirect after login

                flash('Incorrect password.', 'danger')
                return redirect(url_for('login'))

        flash('Email not found. Please sign up.', 'danger')

    return render_template('/accountPage/login.html', form=login_form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/complete_signUp')
def complete_signUp():
   return render_template('/accountPage/complete_signUp.html')

@app.route('/changeDets/<int:id>/', methods=['GET', 'POST'])
def change_dets(id):
    change_dets_form = ChangeDetForm(request.form)

    with shelve.open('user.db', 'r') as db:
        users_dict = db.get('Users', {})

    user = users_dict.get(id)

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_dets_form.validate():
        entered_password = change_dets_form.pswd.data
        stored_password_hash = user.get_cfm_pswd()  # Ensure this method returns the hashed password

        # Check if the entered password matches the stored hashed password
        if not check_password_hash(stored_password_hash, entered_password):
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for('change_dets', id=id))

        with shelve.open('user.db', 'w') as db:
            users_dict = db['Users']

            # Update user details
            user = users_dict.get(id)
            user.set_first_name(change_dets_form.first_name.data)
            user.set_last_name(change_dets_form.last_name.data)
            user.set_gender(change_dets_form.gender.data)
            user.set_number(change_dets_form.number.data)
            user.set_email(change_dets_form.email.data)

            db['Users'] = users_dict

            # Update session details
            session['user_id'] = user.get_user_id()
            session['first_name'] = user.get_first_name()
            session['last_name'] = user.get_last_name()
            session['gender'] = user.get_gender()
            session['phone'] = user.get_number()
            session['email'] = user.get_email()

        flash("Details updated successfully!", "success")
        return redirect(url_for('accountInfo'))

    # Prepopulate form fields
    change_dets_form.first_name.data = user.get_first_name()
    change_dets_form.last_name.data = user.get_last_name()
    change_dets_form.gender.data = user.get_gender()
    change_dets_form.number.data = user.get_number()
    change_dets_form.email.data = user.get_email()

    return render_template('/accountPage/changeDets.html', form=change_dets_form)

@app.route('/changePswd/<int:id>/', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def change_pswd(id):
    change_pswd_form = ChangePswdForm(request.form)

    # Get the currently logged-in user
    user_id = session['user_id']
    with shelve.open('user.db', 'r') as db:
        users_dict = db.get('Users', {})

    user = users_dict.get(user_id)

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_pswd_form.validate():
        current_pswd = change_pswd_form.current_pswd.data
        stored_pswd_hash = user.get_cfm_pswd()  # Ensure this method returns the hashed password

        # Check if the entered current password matches the stored hashed password
        if not check_password_hash(stored_pswd_hash, current_pswd):
            flash("Incorrect current password. Please try again.", "danger")
            return redirect(url_for('change_pswd', id=id))

        # Get the new password and confirm it
        new_pswd = change_pswd_form.new_pswd.data
        confirm_pswd = change_pswd_form.confirm_pswd.data

        if new_pswd != confirm_pswd:
            flash("New passwords do not match. Please try again.", "danger")
            return redirect(url_for('change_pswd', id=id))

        # Update password in the database
        with shelve.open('user.db', 'w') as db:
            users_dict = db['Users']

            # Hash the new password before saving
            new_pswd_hash = generate_password_hash(new_pswd)
            user.set_cfm_pswd(new_pswd_hash)  # Update password hash

            db['Users'] = users_dict

            session['pswd'] = confirm_pswd

        flash("Password changed successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template('/accountPage/changePswd.html', form=change_pswd_form)

@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    db = shelve.open('user.db', 'w')
    users_dict = db.get('Users', {})

    if id in users_dict:
        del users_dict[id]  # Remove the user from the database
        db['Users'] = users_dict
        db.close()

        # Clear the session after deletion
        session.clear()

        flash("Account deleted successfully!", "success")
        return redirect(url_for('home'))  # Redirect to home page after logout

    db.close()
    flash("User not found.", "danger")
    return redirect(url_for('account_info'))

@app.route("/create_update", methods=['GET', 'POST'])
def create_update():
    form = SeasonalUpdateForm()
    if form.validate_on_submit():
        update_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data,
        }

        # Save the update_data to the shelve database
        with shelve.open('seasonal_updates.db') as db:
            if 'updates' not in db:
                db['updates'] = []  # Initialize a list if it doesn't exist
            updates = db['updates']  # Get the existing list
            updates.append(update_data)  # Append the new update
            db['updates'] = updates  # Save the updated list back to the database


        flash(f'Update "{form.update.data}" created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('/home/update.html', title='Update', form=form)

@app.route('/delete_update/<int:index>', methods=['POST'])
def delete_update(index):
    try:
        with shelve.open('seasonal_updates.db', writeback=True) as db:
            updates = db.get('updates', [])
            if 0 <= index < len(updates):
                removed_update = updates.pop(index)
                db['updates'] = updates  # Save the updated list
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
            "image": url_for('static', filename='uploads/' + (product.image_filename or 'default.jpg')),  # ✅ Include Image
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
        print(f"✅ Email sent successfully to {to_email}")

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
                "name": customer.get("name", "N/A"),
                "email": customer.get("email", "N/A"),
                "total": total_price,
                "date": order_date
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