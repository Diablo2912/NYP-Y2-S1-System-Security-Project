from flask import Flask
import shelve

class Product:
    def __init__(self, name, quantity, category, price, co2):
        self.name = name
        self.quantity = int(quantity)
        self.category = category
        self.price = float(price)
        self.co2 = float(co2)

    def __repr__(self):
        return f'{self.name} - {self.co2} kg'

# Updated products list with new entries
products = [
    Product("Corn", 100, "Crops", 2.50, 10),
    Product("Apple", 100, "Fruits", 1.50, 5),
    Product("Rice", 100, "Crops", 3.50, 8),
    Product("Potato", 100, "Roots", 2.00, 6),
    Product("Banana", 100, "Fruits", 1.75, 4),
    # New products:
    Product("Tomato", 80, "Vegetables", 2.25, 7),
    Product("Carrot", 120, "Vegetables", 1.95, 5),
    Product("Strawberry", 60, "Berries", 3.00, 9)
]

def save_products():
    with shelve.open('products.db') as db:
        db['products'] = products  # Use the key 'products'

def load_products_cft():
    with shelve.open('products.db') as db:
        # Return stored products, or the updated default list if not present
        return db.get('products', products)