from flask import Blueprint, render_template, request
from ProductsList import load_products


main_blueprint = Blueprint('main', __name__, url_prefix='/buyProduct')

def filter_products(selected_categories=None):
    filtered = load_products()

    if selected_categories:
        filtered = [p for p in filtered if p.category in selected_categories]

    return filtered

@main_blueprint.route("/", methods=["GET"])
def index():
    categories = request.args.getlist("category")
    filtered_products = filter_products(categories)
    all_categories = set(p.category for p in load_products())  # 'products' from ProductsList.py
    return render_template("buyProduct.html", products=filtered_products, all_categories=all_categories)
