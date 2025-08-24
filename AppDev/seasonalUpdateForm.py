import spacy
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from spacy.matcher import PhraseMatcher
from fuzzywuzzy import process
from datetime import date as dt_date

nlp = spacy.load('en_core_web_sm')

AGRICULTURE_KEYWORDS = [
    # existing
    "crop", "harvest", "yield", "irrigation", "fertilizer", "soil",
    "livestock", "organic farming", "sustainability", "pesticide", "climate change", "Rain",
    "Summer", "Dry", "Wet", "Weather", "Protect", "fruits", "Vegetables", "Hide", "Your",

    # general/agronomy
    "farm", "farmer", "field", "greenhouse", "nursery", "orchard", "pasture",
    "seed", "seedling", "germination", "sowing", "planting", "transplanting",
    "pruning", "weeding", "mulch", "mulching", "tillage", "no-till", "cover crop",
    "compost", "manure", "residue management",

    # soil & nutrients
    "nitrogen", "phosphorus", "potassium", "npk", "micronutrients", "soil ph", "salinity",
    "loam", "clay", "silt", "sand", "soil moisture", "soil test", "cation exchange",

    # water & weather
    "drip irrigation", "sprinkler", "canal", "reservoir", "rainfall", "evapotranspiration",
    "drought", "flood", "frost", "hail", "heatwave", "storm", "monsoon", "el niño", "la niña",
    "humidity", "precipitation", "forecast",

    # pests/diseases/weeds
    "pest", "disease", "weed", "aphid", "locust", "borer", "mite", "nematode",
    "blight", "mildew", "rust", "wilt", "leaf spot",
    "insecticide", "herbicide", "fungicide", "biocontrol",
    "ipm", "integrated pest management", "resistance management", "pheromone trap",

    # machinery & storage
    "tractor", "combine", "sprayer", "planter", "harvester",
    "silo", "cold storage", "post-harvest", "grading", "packing", "cold chain",

    # smart/precision ag
    "precision agriculture", "satellite", "ndvi", "sensor", "drone", "iot", "vra", "mapping",

    # sustainability
    "agroforestry", "regenerative agriculture", "carbon sequestration", "buffer strip", "windbreak",

    # livestock
    "poultry", "dairy", "cattle", "goat", "sheep", "ruminant", "grazing", "forage", "silage", "beekeeping",

    # crops/examples
    "wheat", "rice", "maize", "corn", "soybean", "cotton", "sugarcane", "coffee", "tea",
    "banana", "apple", "mango", "tomato", "potato", "onion", "chili", "pepper", "cucumber",
    "lentil", "chickpea", "pulse", "grain", "oilseed",

    # operations/market
    "extension service", "cooperative", "subsidy", "farmgate price", "commodity price", "input cost"
]

AGRICULTURE_ACTION_PHRASES = [
    # existing
    "protect your crops", "improve soil quality", "rotate your crops", "use organic fertilizer",
    "reduce water usage", "install irrigation systems", "prevent soil erosion", "monitor crop health",
    "practice sustainable farming", "control pests", "increase crop yield", "plant drought-resistant crops",
    "reduce greenhouse gases", "apply compost", "harvest at the right time", "store seeds properly",

    # new actions
    "apply mulch", "scout for pests", "set pheromone traps", "calibrate sprayer",
    "calibrate irrigation schedule", "clean irrigation filters", "flush drip lines",
    "test soil ph", "apply lime", "apply npk fertilizer", "top-dress nitrogen", "apply foliar feed",
    "establish cover crops", "tarp and solarize soil", "check soil moisture before watering",
    "install drip irrigation", "repair field drainage", "thin seedlings", "harden off seedlings",
    "stake and trellis plants", "prune damaged branches", "sanitize tools",
    "rotate grazing paddocks", "vaccinate livestock", "deworm livestock",
    "service tractor and equipment", "pre-cool produce after harvest", "store grain in airtight silo",
    "maintain the cold chain", "introduce beneficial insects", "apply biological control agents",
    "update farm records", "back up farm data", "subscribe to weather alerts"
]

ALL_AGRICULTURE_TERMS = AGRICULTURE_KEYWORDS + AGRICULTURE_ACTION_PHRASES

matcher = PhraseMatcher(nlp.vocab)
patterns = [nlp.make_doc(term) for term in ALL_AGRICULTURE_TERMS]
matcher.add("AGRICULTURE_TERMS", patterns)

def validate_not_past(form, field):
    if field.data < dt_date.today():
        raise ValidationError("The date cannot be in the past.")


def get_fuzzy_suggestions(input_text):
    suggestions = process.extract(input_text, ALL_AGRICULTURE_TERMS, limit=3)
    return [match[0] for match in suggestions]

# Custom validator
def validate_agriculture_content(form, field):
    input_text = field.data.strip()
    doc = nlp(input_text)


    matches = matcher(doc)
    if not matches:
        suggestions = get_fuzzy_suggestions(input_text)
        raise ValidationError(
            "Please provide agriculture-related input. Here are some suggestions:\n"
            f"- {suggestions[0]}\n"
            f"- {suggestions[1]}\n"
            f"- {suggestions[2]}"
        )
class SeasonalUpdateForm(FlaskForm):

    update = StringField(
        'Update',
        validators=[
            DataRequired(message="Please enter an update title."),
            Length(min=2, max=20, message="Title must be between 2 and 20 characters."),
            Regexp(r'.*[A-Za-z]+.*', message="Title must contain at least one letter."),
            validate_agriculture_content
        ],
        render_kw={"placeholder": "Enter update title..."}
    )


    

    content = StringField(
        'Update Content',
        validators=[
            DataRequired(message="Please provide update content."),
            Length(min=2, max=50, message="Content must be between 2 and 50 characters."),
            Regexp(r'.*[A-Za-z]+.*', message="Content must contain at least one letter."),
            validate_agriculture_content
        ],
        render_kw={"placeholder": "Enter update content..."}
    )
    date = DateField(
        'Date',
        format='%Y-%m-%d',
        validators=[
            DataRequired(message="Please select a date."),
            validate_not_past
        ],
        render_kw={"placeholder": "YYYY-MM-DD"}
    )

    season = SelectField(
        'Choose the season:',
        choices=[
            ('summer', 'Summer'),
            ('spring', 'Spring'),
            ('autumn', 'Autumn'),
            ('winter', 'Winter')
        ],
        validators=[DataRequired(message="Please select a season.")]
    )
    submit = SubmitField('Create Update')

