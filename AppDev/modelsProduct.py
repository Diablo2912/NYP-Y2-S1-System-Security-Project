from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    co2 = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(255), nullable=False, default="default.jpg")  # ✅ New column

    def __repr__(self):
        return f"<Product {self.name}>"


    # def __init__(self, name, quantity, category, price, co2, description, image_filename="default.jpg"):
    #     self.name = name
    #     self.quantity = quantity
    #     self.category = category
    #     self.price = price
    #     self.co2 = co2
    #     self.description = description
    #     self.image_filename = image_filename  # ✅ Store uploaded image filename

