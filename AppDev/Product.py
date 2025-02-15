# User class
class Product:
    count_id = 0

    # initializer method
    def __init__(self, product_name, quantity, category, price, product_description, product_image):
        Product.count_id += 1
        self.__product_id = Product.count_id
        self.__product_name = product_name
        self.__quantity = quantity
        self.__category = category
        self.__price = price
        self.__product_description = product_description
        self.__product_image = product_image

    # accessor methods
    def get_product_id(self):
        return self.__product_id

    def get_product_name(self):
        return self.__product_name

    def get_quantity(self):
        return self.__quantity

    def get_category(self):
        return self.__category

    def get_price(self):
        return self.__price

    def get_product_description(self):
        return self.__product_description

    def get_product_image(self):
        return self.__product_image

    # mutator methods
    def set_product_id(self, product_id):
        self.__product_id = product_id

    def set_product_name(self, product_name):
        self.__product_name = product_name

    def set_quantity(self, quantity):
        self.__quantity = quantity

    def set_category(self, category):
        self.__category = category

    def set_price(self, price):
        self.__price = price

    def set_product_description(self, product_description):
        self.__product_description = product_description

    def set_product_image(self, product_image):
        self.__product_image = product_image