from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash

from Forms import SignUpForm, CreateProductForm, LoginForm
import shelve, User, Product
from FeaturedArticles import get_featured_articles
from Filter import main_blueprint
from seasonalUpdateForm import SeasonalUpdateForm
from ProductsList import load_products
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import random
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from chatbot import generate_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791262abcdefg'

app.register_blueprint(main_blueprint)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'ngiam.brandon3@gmail.com'
app.config['MAIL_PASSWORD'] = 'isgw cesr jdbs oytx'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
sql_db = SQLAlchemy(app)
app.permanent_session_lifetime = timedelta(minutes=90)
#CFT on SQL#
class ProductCFT(sql_db.Model):
    id = sql_db.Column(sql_db.Integer, primary_key=True)
    name = sql_db.Column(sql_db.String(100), nullable=False)
    quantity = sql_db.Column(sql_db.Integer, nullable=False)
    category = sql_db.Column(sql_db.String(50), nullable=False)
    price = sql_db.Column(sql_db.Float, nullable=False)
    co2 = sql_db.Column(sql_db.Float, nullable=False)

    def __repr__(self):
        return f'<Product {self.name}>'


with app.app_context():
    sql_db.create_all()

#testing for sql
@app.route('/add_sample_products/')
def add_sample_products():
    sample_products = [
        ProductCFT(name="Corn", quantity=100, category="Crops", price=2.50, co2=10),
        ProductCFT(name="Apple", quantity=100, category="Fruits", price=1.50, co2=5),
        ProductCFT(name="Rice", quantity=100, category="Crops", price=3.50, co2=8),
        ProductCFT(name="Potato", quantity=100, category="Roots", price=2.00, co2=6),
        ProductCFT(name="Banana", quantity=100, category="Fruits", price=1.75, co2=4),
        ProductCFT(name="Tomato", quantity=80, category="Vegetables", price=2.25, co2=7),
        ProductCFT(name="Carrot", quantity=120, category="Vegetables", price=1.95, co2=5),
        ProductCFT(name="Strawberry", quantity=60, category="Berries", price=3.00, co2=9)
    ]

    sql_db.session.add_all(sample_products)
    sql_db.session.commit()

    return "Sample products added!"


@app.route('/')
def home():
    # if 'logged_in' not in session:
    #     flash('Please log in to access this page.', 'warning')
    #     return redirect(url_for('login'))

    articles = get_featured_articles()

    updates = []
    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])

    products = ProductCFT.query.all()

    # pandas code
    data = [{'name': product.name, 'co2': product.co2} for product in products]
    df = pd.DataFrame(data)

    plt.figure(figsize=(10, 5))
    plt.bar(df['name'], df['co2'], color='skyblue')
    plt.xlabel('Product Name')
    plt.ylabel('CO2 Emissions (kg)')
    plt.title('CO2 Emissions by Product')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save plot to a buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    chart_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    buffer.close()  # Always close the buffer after using it

    welcome_message = f"Welcome, {session['first_name']}!" if 'first_name' in session else "Welcome!"

    return render_template('/home/homePage.html', articles=articles, updates=updates, product=load_products(), chart_data=chart_data, welcome_message=welcome_message)

@app.route('/buyProduct')
def product():
    products = load_products()  # Call the function and store the list
    categories = {product.category for product in products}
    return render_template('/productPage/buyProduct.html', load_products=products, all_categories=categories)

@app.route('/createProduct', methods=['GET', 'POST'])
def create_product():
    create_product_form = CreateProductForm(request.form)
    if request.method == 'POST' and create_product_form.validate():
        product_dict = {}
        db = shelve.open('product.db', 'c')

        try:
            product_dict = db['Product']
        except:
            print("Error in retrieving Products from product.db.")

        product = Product.Product(create_product_form.product_name.data, create_product_form.quantity.data, create_product_form.category.data, create_product_form.price.data, create_product_form.product_description.data)
        product_dict[product.get_product_id()] = product
        db['Product'] = product_dict

        db.close()

        return redirect(url_for('manageProduct'))
    return render_template('/productPage/createProduct.html', form=create_product_form)

@app.route('/manageProduct')
def manageProduct():
    product_dict = {}
    db = shelve.open('product.db', 'r')
    product_dict = db['Product']
    db.close()

    product_list = []
    for key in product_dict:
        product = product_dict.get(key)
        product_list.append(product)

    return render_template('/productPage/manageProduct.html', count=len(product_list), product_list=product_list)

@app.route('/updateProduct/<int:id>/', methods=['GET', 'POST'])
def update_product(id):
    update_product_form = CreateProductForm(request.form)
    if request.method == 'POST' and update_product_form.validate():
        product_dict = {}
        db = shelve.open('product.db', 'w')
        product_dict = db['Product']

        product = product_dict.get(id)
        product.set_product_name(update_product_form.product_name.data)
        product.set_quantity(update_product_form.quantity.data)
        product.set_category(update_product_form.category.data)
        product.set_price(update_product_form.price.data)
        product.set_product_description(update_product_form.product_description.data)

        db['Product'] = product_dict
        db.close()

        return redirect(url_for('manageProduct'))
    else:
        product_dict = {}
        db = shelve.open('product.db', 'r')
        product_dict = db['Product']
        db.close()

        product = product_dict.get(id)
        update_product_form.product_name.data = product.get_product_name()
        update_product_form.quantity.data = product.get_quantity()
        update_product_form.category.data = product.get_category()
        update_product_form.price.data = product.get_price()
        update_product_form.product_description.data = product.get_product_description()

        return render_template('/productPage/updateProduct.html', form=update_product_form)

@app.route('/deleteProduct/<int:id>', methods=['POST'])
def delete_product(id):
    product_dict = {}
    db = shelve.open('product.db', 'w')
    product_dict = db['Product']

    product_dict.pop(id)

    db['Product'] = product_dict
    db.close()

    return redirect(url_for('manageProduct'))

@app.route('/view_products')
def view_products():
    productsCFT = ProductCFT.query.all()
    if not productsCFT:
        return "<p>No products found in the database!</p>"

    # Display each product's details in HTML
    product_list = "<h1>Product List</h1><ul>"
    for product in productsCFT:
        product_list += f"<li>{product.name}: Quantity={product.quantity}, CO2={product.co2} kg</li>"
    product_list += "</ul>"

    return product_list

@app.route('/carbonFootprintTracker', methods=['GET', 'POST'])
def carbonFootprintTracker():
    selected_products = []
    total_co2 = 0

    productsCFT = ProductCFT.query.all()

    if request.method == 'POST':
        product_names = request.form.getlist('product[]')

        # Query selected products from the database
        for name in product_names:
            product = ProductCFT.query.filter_by(name=name).first()
            if product:
                selected_products.append(product)
                total_co2 += product.co2

        return render_template('carbonFootprintTracker.html',
                               productsCFT=productsCFT,
                               selected_products=selected_products,
                               total_co2=total_co2)

    return render_template('carbonFootprintTracker.html',
                           productsCFT=productsCFT,
                           selected_products=[],
                           total_co2=0)

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
def accountSecurity():
    users_dict = {}
    db = shelve.open('user.db', 'r')
    users_dict = db['Users']
    db.close()

    users_list = []
    show_password = request.args.get('show', 'false') == 'true'

    for key in users_dict:
        user = users_dict.get(key)
        users_list.append(user)
    return render_template('/accountPage/accountSecurity.html', count=len(users_list), users_list=users_list, len=len, show_password=show_password)

@app.route('/accountHist')
def accountHist():
   return render_template('/accountPage/accountHist.html')

@app.route('/signUp', methods=['GET', 'POST'])
def sign_up():
    sign_up_form = SignUpForm(request.form)
    if request.method == 'POST' and sign_up_form.validate():
        db = shelve.open('user.db','c')

        users_dict = db.get('Users', {})

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

        flash('Sign up successful! Please log in.', 'success')
        return redirect(url_for('complete_signUp'))
    return render_template('/accountPage/signUp.html', form=sign_up_form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        db = shelve.open('user.db', 'c')

        users_dict = db.get('Users', {})
        db.close()

        email = login_form.email.data
        password = login_form.pswd.data

        # Check if user exists
        for user in users_dict.values():
            print("Checking user:", user.get_email())
            if user.get_email() == email:
                print("User found, checking password...")
                if check_password_hash(user.get_cfm_pswd(), password):
                    session['logged_in'] = True
                    session['user_id'] = user.get_user_id()
                    session['email'] = user.get_email()
                    session['first_name'] = user.get_first_name()
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))  # Redirect to a protected page

                flash('Incorrect password.', 'danger')
                return redirect(url_for('login'))

        flash('Email not found. Please sign up.', 'danger')
    return render_template('/accountPage/login.html', form=login_form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/cart')
def cart():
   return render_template('/checkout/cart.html')

@app.route('/complete_signUp')
def complete_signUp():
   return render_template('/accountPage/complete_signUp.html')

@app.route('/changeDets/<int:id>/', methods=['GET', 'POST'])
def change_dets(id):
    change_dets_form = SignUpForm(request.form)
    users_dict = {}
    db = shelve.open('user.db', 'r')
    users_dict = db['Users']
    db.close()

    # Get the user object and the list of all users
    user = users_dict.get(id)
    users_list = list(users_dict.values())

    if request.method == 'POST' and change_dets_form.validate():
        db = shelve.open('user.db', 'w')
        users_dict = db['Users']

        # Update the user's details
        user = users_dict.get(id)
        user.set_first_name(change_dets_form.first_name.data)
        user.set_last_name(change_dets_form.last_name.data)
        user.set_gender(change_dets_form.gender.data)
        user.set_number(change_dets_form.number.data)
        user.set_email(change_dets_form.email.data)

        db['Users'] = users_dict
        db.close()

        return redirect(url_for('accountInfo'))
    else:
        # Prepopulate form fields
        change_dets_form.first_name.data = user.get_first_name()
        change_dets_form.last_name.data = user.get_last_name()
        change_dets_form.gender.data = user.get_gender()
        change_dets_form.number.data = user.get_number()
        change_dets_form.email.data = user.get_email()

        # Pass both form and users_list to the template
        return render_template('/accountPage/changeDets.html', form=change_dets_form, users_list=users_list)

@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    users_dict = {}
    db = shelve.open('user.db', 'w')
    users_dict = db['Users']

    users_dict.pop(id)
    db['Users'] = users_dict
    db.close()

    return redirect(url_for('accountInfo'))

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

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    cart = get_cart()
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())

    if request.method == "POST":
        customer_name = request.form['customer_name']
        phone_number = request.form['phone_number']
        email_address = request.form['email_address']
        customer_address = request.form['customer_address']
        postal_code = request.form['postal_code']
        customer_city = request.form['customer_city']
        order_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        transaction_id = str(random.randint(10000, 99999))

        order = {
            'id': transaction_id,
            'customer_name': customer_name,
            'phone_number': phone_number,
            'email_address': email_address,
            'customer_address': customer_address,
            'postal_code': postal_code,
            'customer_city': customer_city,
            'cart': cart,
            'total_price': total_price,
            'order_date': order_date  # Added order_date field here
        }

        if "transactions" not in session:
            session["transactions"] = []
        session["transactions"].append(order)
        session.modified = True

        # Send the confirmation email
        msg = Message("Order Confirmation",
                      sender="ngiam.brandon@gmail.com",
                      recipients=[email_address])
        msg.body = f"""
        Dear {customer_name},

        Thank you for your order!

        Order Details:
        ---------------------------
        Transaction ID: {transaction_id}
        Name: {customer_name}
        Phone: {phone_number}
        Email: {email_address}
        Address: {customer_address}
        Postal Code: {postal_code}
        City: {customer_city}
        Date: {order_date}
        Total: ${total_price}

        Ordered Items:
        """
        for item in cart.values():
            msg.body += f"\n- {item['name']} (x{item['quantity']}) - ${item['price'] * item['quantity']}"
        msg.body += "\n\nThank you for shopping with us!"

        try:
            mail.send(msg)
            print("Order confirmation email sent successfully.")
        except Exception as e:
            print(f"Error sending email: {e}")

        session.pop("cart", None)

        # Pass the order data to the order_success page
        return render_template("/checkout/order_success.html", order=order)

    return render_template("/checkout/cart.html", cart=cart, total_price=total_price)

def get_cart():
    return session.get("cart", {})

def save_cart(cart):
    session["cart"] = cart
    session.modified = True
    print("Cart saved:", session["cart"])

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')

    if not user_message:
        return jsonify({'response': "Please provide a message!"})

    bot_response = generate_response(user_message)
    return jsonify({'response': bot_response})

if __name__ == '__main__':
    app.run(debug=True)