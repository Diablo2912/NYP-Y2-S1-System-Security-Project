from flask import Blueprint, render_template, request
from modelsProduct import Product


main_blueprint = Blueprint('main', __name__, url_prefix='/buyProduct')

def filter_products(selected_categories=None):
    all_products = load_products()  # Load all products

    if selected_categories:
        print("Filtering by categories:", selected_categories)  # Debugging log
        filtered = [p for p in all_products if p.category in selected_categories]
    else:
        filtered = all_products  # No filters, show all

    print("Filtered products:", [p.name for p in filtered])  # Debugging log
    return filtered


@main_blueprint.route("/", methods=["GET"])
def index():
    categories = request.args.getlist("category")  # Get selected categories from URL
    print("Selected Categories:", categories)  # Debugging log

    filtered_products = filter_products(categories)  # Filter products
    all_categories = set(p.category for p in load_products())  # Get all unique categories

    return render_template("/productPage/buyProduct.html",
                           products=filtered_products,
                           all_categories=all_categories,
                           selected_categories=categories)  # Pass selected categories
