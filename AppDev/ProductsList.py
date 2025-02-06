

# ProductsList.py

class Product:
    def __init__(self, name, quantity, category, price):
        self.name = name
        self.quantity = int(quantity)
        self.category = category
        self.price = float(price)

# Original products plus new entries
def load_products():

    return [
        Product("Corn", 100, "Crops", 2.50),
        Product("Apple", 95, "Fruits", 1.50),
        Product("Rice", 100, "Crops", 3.50),
        Product("Potato", 100, "Roots", 2.00),
        Product("Banana", 100, "Fruits", 1.75),
        Product("Tomato", 80, "Vegetables", 2.25),
        Product("Carrot", 120, "Vegetables", 1.95),
        Product("Strawberry", 60, "Berries", 3.00)
    ]
