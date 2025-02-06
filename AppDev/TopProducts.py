from ProductsList import products

def get_lowest_quantity_product():
    product = min(products, key=lambda product: product.quantity)
    product.image = f"static/pics/cart.jpg{product.name.lower()}.jpg"
    return product