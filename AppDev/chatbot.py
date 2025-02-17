import google.generativeai as ai
from flask import url_for, current_app

# Your Google Gemini API key
API_KEY = 'AIzaSyCTx6rJdEAbA0nd-3jnb8ri_0AsLK2VEx4'

# Configure the Google Gemini API
ai.configure(api_key=API_KEY)
model = ai.GenerativeModel("gemini-2.0-flash")
chat = model.start_chat()

def generate_response(message):
    """Generate chatbot response with relevant resource links."""
    message = message.lower().strip()  # Normalize input

    with current_app.app_context():
        # Define resource links for different topics
        resource_links = {
            "agriculture": [
                f'<a href="{url_for("educationalGuide")}" class="dynamic-link">Educational Guide</a>',
                f'<a href="{url_for("farmTools")}" class="dynamic-link">Farm Tools</a>',
                f'<a href="{url_for("initiatives")}" class="dynamic-link">Sustainability Initiatives</a>'
            ],
            "products": [
                f'<a href="{url_for("buy_product")}" class="dynamic-link">Our Products</a>'
            ],
            "carbon": [
                f'<a href="{url_for("carbonFootprintTracker")}" class="dynamic-link">Carbon Footprint Tracker</a>'
            ],
            "about": [
                f'<a href="{url_for("aboutUs")}" class="dynamic-link">About Us</a>'
            ],
            "contact": [
                f'<a href="{url_for("contactUs")}" class="dynamic-link">Contact Us</a>'
            ],
            "account": [
                f'<a href="{url_for("sign_up")}" class="dynamic-link">Sign Up</a>',
                f'<a href="{url_for("login")}" class="dynamic-link">Login</a>'
            ],
        }

    # Keywords mapped to resource categories
    keyword_mapping = {
        "agriculture": "agriculture",
        "farm": "agriculture",
        "tools": "agriculture",
        "products": "products",
        "sell" : "products",
        "carbon" : "carbon",
        "about" : "about",
        "contact" : "contact",
        "call" : "contact",
        "email" : "contact",
        "sign" : "account",
        "log in" : "account",
        "login" : "account"
    }

    matched_links = []

    # Check if any keyword is found in the message
    for keyword, category in keyword_mapping.items():
        if keyword in message:
            matched_links.extend(resource_links[category])

    # If relevant links are found, generate response
    if matched_links:
        prompt = f"Provide a short and concise answer for the following query: {message}"
        response = chat.send_message(prompt)
        bot_response = response.text

        # Append resource links
        bot_response += "<br>Find out more:<br>" + "<br>".join(matched_links)
        return bot_response

    # Default response for unrelated topics
    return "Sorry, I do not understand."


