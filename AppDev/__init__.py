import User
import base64
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
import hashlib
import io
from io import BytesIO
import os
import pathlib
import random
import secrets
import shelve
import smtplib
import socket
import tempfile
import time
import uuid  # For unique transaction IDs
import re

import MySQLdb.cursors
import bleach
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from deepface import DeepFace
from dotenv import load_dotenv
from flask import Flask, Response, flash, g, jsonify, make_response, redirect, render_template, request, send_file, \
    session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
from flask_uploads import IMAGES, UploadSet
from flask_wtf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
import jwt
from markupsafe import Markup
import matplotlib.pyplot as plt
import pandas as pd
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.pdfencrypt import StandardEncryption
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
import requests
import stripe
from transformers import pipeline
from twilio.rest import Client
from werkzeug.utils import secure_filename
import google.generativeai as genai
import folium
from folium.plugins import HeatMap
import ipaddress

from FeaturedArticles import get_featured_articles
from Filter import main_blueprint
from Forms import ChangeDetForm, ChangePswdForm, CreateAdminForm, CreateProductForm, LoginForm, ResetPass, \
    ResetPassRequest, SignUpForm
from chatbot import generate_response
from modelsProduct import Product, db
from seasonalUpdateForm import SeasonalUpdateForm
import re

app = Flask(__name__)
csrf = CSRFProtect()

load_dotenv()

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "500 per hour"])
UPLOAD_FOLDER = 'static/uploads/'
images = UploadSet('images', IMAGES)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
otp_store = {}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALGORITHM = 'pbkdf2_sha256'
SECRET_KEY = 'asdsa8f7as8d67a8du289p1eu89hsad7y2189eha8'
stripe.api_key = "sk_test_51Qrle9CddzoT6fzjpqNPd1g3UV8ScbnxiiPK5uYT0clGPV82Gn7QPwcakuijNv4diGpcbDadJjzunwRcWo0eOXvb00uDZ2Gnw6"
fernet_key = os.getenv("RECOVERY_ENC_KEY")
if isinstance(fernet_key, str):
    fernet_key = fernet_key.encode()

fernet = Fernet(fernet_key)

app.register_blueprint(main_blueprint)
app.config['SECRET_KEY'] = '5791262abcdefg'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=90)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cropzyssp@gmail.com'
app.config['MAIL_PASSWORD'] = 'wivz gtou ftjo dokp'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.permanent_session_lifetime = timedelta(minutes=90)
db.init_app(app)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
MAIL_USE_TLS = True
EMAIL_SENDER = "cropzyssp@gmail.com"
EMAIL_PASSWORD = "wivz gtou ftjo dokp"
mail = Mail(app)
# SETUP UR DB CONFIG ACCORDINGLY
# DON'T DELETE OTHER CONFIGS JUST COMMENT AWAY IF NOT USING

# GLEN SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'glen'
# app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306

# BRANDON SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'brandon'
# app.config['MYSQL_PASSWORD'] = 'Pa$$w0rd'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306
#
# #SACHIN SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'glen'
# app.config['MYSQL_PASSWORD'] = 'dbmsPa55'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306
#
# #SACHIN SQL DB CONFIG
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'              # or your MySQL username
app.config['MYSQL_PASSWORD'] = 'mysql'       # match what you set in Workbench
app.config['MYSQL_DB'] = 'sspCropzy'
#
# #SADEV SQL DB CONFIG
# app.secret_key = 'asd9as87d6s7d6awhd87ay7ss8dyvd8bs'
# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'Pa$$w0rd'
# app.config['MYSQL_DB'] = 'ssp_db'
# app.config['MYSQL_PORT'] = 3306

mysql = MySQL(app)

with app.app_context():
    db.create_all()

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_self_signed_cert(cert_file='certs/cert.pem', key_file='certs/key.pem'):
    cert_path = pathlib.Path(cert_file)
    key_path = pathlib.Path(key_file)
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if cert_path.exists() and key_path.exists():
        print("✅ SSL certs already exist. Skipping generation.")
        return

    print("🔐 Generating self-signed SSL certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FlaskApp"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ Certificate saved to", cert_file)
    print("✅ Private key saved to", key_file)


def sanitize_input(user_input):
    allowed_tags = ['a', 'b', 'i', 'em', 'strong']
    allowed_attributes = {'a': ['href']}

    return bleach.clean(user_input, tags=allowed_tags, attributes=allowed_attributes)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:  # Check if user is logged in
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt_token')

        if not token:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))

        user_data = verify_jwt_token(token)
        if not user_data:
            flash("Invalid or expired token. Please log in again.", "danger")
            return redirect(url_for('login'))

        session_id = session.get('current_session_id')
        if session_id:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""
                SELECT logout_time FROM user_session_activity
                WHERE id = %s AND user_id = %s
            """, (session_id, user_data['user_id']))
            result = cursor.fetchone()
            cursor.close()

            if result and result['logout_time']:
                flash("Your session has been revoked. Please log in again.", "danger")
                response = make_response(redirect(url_for('login')))
                response.delete_cookie('jwt_token')
                return response

        g.user = user_data
        return f(*args, **kwargs)

    return decorated_function

def is_valid_date(s):
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False

def is_routable_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except ValueError:
        return False

def geo_lookup_ip(mysql, ip: str):
    """
    Return (lat, lon, country_code, city) or None if unknown.
    Caches results in ip_geo_cache to avoid repeated external calls.
    """
    if not is_routable_ip(ip):
        return None

    # 1) try cache
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT lat, lon, country_code, city FROM ip_geo_cache WHERE ip=%s", (ip,))
    row = cur.fetchone()
    if row and row["lat"] and row["lon"]:
        cur.close()
        return (row["lat"], row["lon"], row["country_code"], row["city"])

    # 2) call ipwho.is
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        j = r.json()
        if j.get("success") and j.get("latitude") and j.get("longitude"):
            lat = float(j["latitude"])
            lon = float(j["longitude"])
            cc = j.get("country_code", "UNK")
            city = j.get("city", "")
            # upsert cache
            cur.execute("""
                INSERT INTO ip_geo_cache (ip, country_code, city, lat, lon)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE country_code=VALUES(country_code),
                                        city=VALUES(city),
                                        lat=VALUES(lat),
                                        lon=VALUES(lon)
            """, (ip, cc, city, lat, lon))
            mysql.connection.commit()
            cur.close()
            return (lat, lon, cc, city)
    except Exception as e:
        print("[geo_lookup_ip] error:", e)

    cur.close()
    return None


def get_ip_geo_points(mysql, start_date=None, end_date=None, days=10):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if is_valid_date(start_date) and is_valid_date(end_date):
        cur.execute("""
            SELECT ip_address, COUNT(*) AS cnt
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
              AND ip_address IS NOT NULL AND ip_address <> ''
            GROUP BY ip_address
        """, (start_date, end_date))
    else:
        cur.execute("""
            SELECT ip_address, COUNT(*) AS cnt
            FROM logs
            WHERE DATE(date) >= CURDATE() - INTERVAL %s DAY
              AND ip_address IS NOT NULL AND ip_address <> ''
            GROUP BY ip_address
        """, (days - 1,))
    rows = cur.fetchall()
    cur.close()

    points = []
    for r in rows:
        ip = (r["ip_address"] or "").strip()
        if not ip:
            continue
        loc = geo_lookup_ip(mysql, ip)  # your existing helper
        if not loc:
            continue
        lat, lon, cc, city = loc
        points.append({
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "count": int(r["cnt"]),
            "country": cc,
            "city": city or ""
        })
    return points

@app.route("/ip_heatmap")
@jwt_required
def ip_heatmap():
    if g.user['status'] != 'admin':
        return render_template('404.html')

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    days = request.args.get("days", type=int, default=10)

    pts = get_ip_geo_points(mysql, start_date, end_date, days)

    # center map
    center_lat, center_lon = (1.3521, 103.8198)
    if pts:
        center_lat = sum(p['lat'] for p in pts) / len(pts)
        center_lon = sum(p['lon'] for p in pts) / len(pts)

    m = folium.Map(location=[center_lat, center_lon], zoom_start=2, control_scale=True, tiles="OpenStreetMap")

    heat_data = [[p["lat"], p["lon"], p["count"]] for p in pts]
    if heat_data:
        HeatMap(heat_data, radius=14, blur=20, max_zoom=6).add_to(m)

    for p in pts:
        popup_html = f"""
        <div style='font-size:13px'>
          <b>IP:</b> {p['ip']}<br/>
          <b>City:</b> {p['city']}<br/>
          <b>Country:</b> {p['country']}<br/>
          <b>Events:</b> {p['count']}<br/>
          <form method="POST" action="/block_ip" style="margin-top:6px">
            <input type="hidden" name="ip" value="{p['ip']}"/>
            <input class="btn btn-sm btn-danger" type="submit" value="Block IP"/>
          </form>
        </div>
        """
        folium.Marker([p["lat"], p["lon"]], tooltip=p["ip"], popup=folium.Popup(popup_html, max_width=250)).add_to(m)

    return m._repr_html_()


@app.route("/block_ip", methods=["POST"])
@jwt_required
def block_ip():
    if g.user["status"] != "admin":
        flash("Only admins can block IPs.", "danger")
        return redirect(url_for("logging_analytics"))

    ip = (request.form.get("ip") or "").strip()
    reason = "Manually blocked from heatmap"
    if not ip:
        flash("No IP provided.", "warning")
        return redirect(url_for("logging_analytics"))

    cur = mysql.connection.cursor()
    try:
        cur.execute("""INSERT INTO ip_blocklist (ip, reason, created_by)
                       VALUES (%s, %s, %s)
                       ON DUPLICATE KEY UPDATE reason=VALUES(reason)""",
                    (ip, reason, g.user["user_id"]))
        mysql.connection.commit()
        flash(f"Blocked IP: {ip}", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Failed to block IP ({ip}): {e}", "danger")
    finally:
        cur.close()

    return redirect(url_for("logging_analytics"))


# SUMMARIZER
# Configure Gemini API
genai.configure(api_key="AIzaSyD2fWMVBdWusPXpUhRlOfwOb5SwiZVMmyA")
model = genai.GenerativeModel("gemini-1.5-flash")

def generate_logs_summary(mysql):
    try:
        cursor = mysql.connection.cursor()
        today = datetime.now().date()
        ten_days_ago = today - timedelta(days=10)

        cursor.execute('''
            SELECT date, activity
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
            ORDER BY date DESC
        ''', (ten_days_ago, today))
        logs = cursor.fetchall()

        daily_activities = defaultdict(Counter)
        for date, activity in logs:
            if isinstance(date, str):
                date = datetime.strptime(date.strip(), '%Y-%m-%d').date()
            date_str = date.strftime('%Y-%m-%d')
            daily_activities[date_str][activity] += 1

        # Build prompt
        prompt = "Below are system logs for the past 10 days:\n\n"
        for date in sorted(daily_activities.keys(), reverse=True):
            prompt += f"{date}:\n"
            for activity, count in daily_activities[date].items():
                prompt += f" - {activity} (x{count})\n"
            prompt += "\n"

        # Generate summary
        response = model.generate_content(f"""
        Summarize the following system activity logs grouped by date.
        Focus on highlighting key events and general patterns (e.g., issues, normal activity, spikes, etc).

        {prompt}
        """)

        # Remove **bold markdown** from Gemini's summary
        cleaned_text = re.sub(r'\*\*(.*?)\*\*', r'\1', response.text)
        return cleaned_text

    except Exception as e:
        print(f"[Error] Failed to summarize logs: {e}")
        return "Error: Could not summarize logs."


def generate_log_report_pdf(filename, login_activity, category_summary, trend_data, trend_dates, pdf_encrypt=None, mysql=None):
    import io
    from datetime import datetime
    import numpy as np
    import matplotlib.pyplot as plt
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Frame, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet

    c = canvas.Canvas(filename, pagesize=A4, encrypt=pdf_encrypt)
    page_w, page_h = A4

    # ---------- Drawing helper: fit figure into a target box ----------
    def draw_chart(fig, x, y, target_w, target_h):
        img_io = io.BytesIO()
        fig.savefig(img_io, format='PNG', bbox_inches='tight', dpi=150)
        img_io.seek(0)
        image = ImageReader(img_io)

        fig_w_pt = fig.get_figwidth() * 72
        fig_h_pt = fig.get_figheight() * 72
        scale = min(target_w / fig_w_pt, target_h / fig_h_pt)
        w_pt = fig_w_pt * scale
        h_pt = fig_h_pt * scale

        x_draw = x + (target_w - w_pt) / 2
        y_draw = y + (target_h - h_pt) / 2

        c.drawImage(image, x_draw, y_draw, width=w_pt, height=h_pt, preserveAspectRatio=True, mask='auto')
        plt.close(fig)

    # Robust hour-bucket getter (supports dicts keyed by 0..23 or "HH:00")
    def get_hour_bucket(hour_str):
        # try "HH:00" key
        bucket = login_activity.get(hour_str)
        if bucket is not None:
            return bucket
        # try int key (00:00 -> 0, 13:00 -> 13)
        try:
            h_int = int(hour_str.split(":")[0])
            return login_activity.get(h_int, {})
        except Exception:
            return {}

    # ---------- Title (Page 1) ----------
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, page_h - 50, "Cropzy System Logging Analytics Report")
    c.setFont("Helvetica", 12)
    c.drawString(50, page_h - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ---------- Layout constants ----------
    MARGIN_L = 40
    MARGIN_R = 40
    MARGIN_T = 90
    MARGIN_B = 40
    GUTTER   = 24
    ROW_SPACING = 20

    FULL_L = 20
    FULL_R = 20
    FULL2_L = 10
    FULL2_R = 10

    col_w = (page_w - MARGIN_L - MARGIN_R - GUTTER) / 2
    left_x  = MARGIN_L
    right_x = MARGIN_L + col_w + GUTTER

    TREND_H  = 230
    MIDDLE_H = 260
    LOGIN_H  = 260

    # ---------- Prepare data (sanitization) ----------
    clean_labels, clean_values = [], []
    for k, v in (category_summary or {}).items():
        try:
            vv = 0 if v is None else float(v)
        except (TypeError, ValueError):
            vv = 0.0
        if np.isfinite(vv) and vv > 0:
            clean_labels.append(str(k))
            clean_values.append(int(vv))
    total = sum(clean_values)

    # =======================
    # PAGE 1
    # =======================
    y_cursor = page_h - MARGIN_T  # start below title block

    # --- Category table at top of Page 1 ---
    c.setFont("Helvetica-Bold", 14)
    c.drawString(MARGIN_L, y_cursor - 10, "Category Count")
    y_cursor -= 28

    table_width = page_w - MARGIN_L - MARGIN_R
    all_cats = ["Info", "Warning", "Error", "Critical"]
    table_data = [["Category", "Count"]]
    for cat in all_cats:
        table_data.append([cat, int(category_summary.get(cat, 0))])

    tbl = Table(table_data, colWidths=[table_width * 0.6, table_width * 0.4])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    tw, th = tbl.wrapOn(c, table_width, page_h)
    tbl.drawOn(c, MARGIN_L, y_cursor - th)
    y_cursor = y_cursor - th - ROW_SPACING

    # --- Trend (full width) under the table ---
    c.setFont("Helvetica-Bold", 12)
    label_trend_y = y_cursor - 14
    c.drawString(MARGIN_L, label_trend_y, "Logs Trend Over Time:")
    y_cursor = label_trend_y - 6  # small padding below label

    fig, ax = plt.subplots(figsize=(12, 3.2))
    safe_dates = list(trend_dates or [])
    for category, counts in (trend_data or {}).items():
        series = list(counts or [])
        n = min(len(safe_dates), len(series))
        if n:
            ax.plot(safe_dates[:n], series[:n], label=str(category))
    ax.set_title("Logs Trend Over Time")
    ax.set_xlabel("Date")
    ax.set_ylabel("Logs")
    ax.legend()
    ax.grid(True)
    trend_y = y_cursor - TREND_H
    draw_chart(fig, FULL_L, trend_y, page_w - FULL_L - FULL_R, TREND_H)

    # --- Middle row: Bar (left) + Pie (right) ---
    c.setFont("Helvetica-Bold", 12)
    label_mid_y = trend_y - ROW_SPACING - 14
    c.drawString(MARGIN_L, label_mid_y, "Logs Category Distribution:")
    middle_y = label_mid_y - 6 - MIDDLE_H

    fig, ax = plt.subplots(figsize=(5, 3))
    if clean_labels:
        ax.bar(clean_labels, clean_values)
        ax.set_ylabel("Count")
    else:
        ax.axis('off')
        ax.text(0.5, 0.5, "No category data", ha='center', va='center', fontsize=12)
    ax.set_title("Log Category Distribution (Bar)")
    draw_chart(fig, left_x, middle_y, col_w, MIDDLE_H)

    fig, ax = plt.subplots(figsize=(5, 3))
    if total > 0:
        ax.pie(clean_values, labels=clean_labels, autopct='%1.1f%%', startangle=140)
    else:
        ax.axis('off')
        ax.text(0.5, 0.5, "No category data", ha='center', va='center', fontsize=12)
    ax.set_title("Log Category Distribution")
    draw_chart(fig, right_x, middle_y, col_w, MIDDLE_H)

    # =======================
    # PAGE 2: Login (super wide) + AI Summary
    # =======================
    c.showPage()

    # Header
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN_L, page_h - 70, "Login Activity:")

    # --- Login Activity (super wide) ---
    fig, ax = plt.subplots(figsize=(13, 3.6))
    hours = [f"{i:02d}:00" for i in range(24)]
    for role in ['user', 'manager', 'admin']:
        role_data = [int((get_hour_bucket(h) or {}).get(role, 0) or 0) for h in hours]
        ax.plot(hours, role_data, label=role.capitalize())
    ax.set_title('Login Activity')
    ax.set_xlabel('Hour')
    ax.set_ylabel('Logins')
    ax.legend()
    ax.grid(True)
    login_chart_top = page_h - 80
    login_chart_y = login_chart_top - LOGIN_H
    draw_chart(fig, FULL2_L, login_chart_y, page_w - FULL2_L - FULL2_R, LOGIN_H)

    # --- AI Logs Summary below login chart ---
    styles = getSampleStyleSheet()
    styleN = styles["Normal"]
    styleN.fontSize = 10
    styleN.leading = 12

    ai_summary_text = generate_logs_summary(mysql) if mysql else "No AI summary available."

    c.setFont("Helvetica-Bold", 12)
    after_login_y = login_chart_y - 16
    c.drawString(MARGIN_L, after_login_y, "AI Logs Summary:")

    available_h = after_login_y - 12 - MARGIN_B
    paragraph = Paragraph(ai_summary_text, styleN)
    frame = Frame(MARGIN_L, MARGIN_B, page_w - MARGIN_L - MARGIN_R, available_h, showBoundary=0)
    frame.addFromList([paragraph], c)

    # Save PDF
    c.save()
    return filename



def hash_password(password, salt=None, iterations=260000):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


def get_user_country(ip_address):
    try:
        res = requests.get(f"https://ipwho.is/{ip_address}")
        data = res.json()
        if data.get('success', False):
            return data.get('country_code', 'Unknown')
        return "Unknown"
    except Exception as e:
        print("GeoIP Error:", e)
        return "Unknown"


def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except Exception as e:
        print("IP fetch error:", e)
        return "127.0.0.1"


def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


@app.route('/add_sample_products/')
def add_sample_products():
    sample_products = [
        # Organic Seeds
        Product(name="Organic Wheat Seeds", quantity=50, category="Organic Seeds", price=5.99, co2=2.5),
        Product(name="Organic Corn Seeds", quantity=60, category="Organic Seeds", price=4.99, co2=3.0),
        Product(name="Organic Tomato Seeds", quantity=40, category="Organic Seeds", price=6.49, co2=1.8),

        # Natural Fertilizers
        Product(name="Organic Compost", quantity=100, category="Natural Fertilizers", price=12.99, co2=0.8),
        Product(name="Vermicompost", quantity=80, category="Natural Fertilizers", price=15.99, co2=0.6),
        Product(name="Seaweed Fertilizer", quantity=50, category="Natural Fertilizers", price=18.49, co2=1.2),

        # Biodegradable Pest Control
        Product(name="Neem Oil Spray", quantity=70, category="Biodegradable Pest Control", price=9.99, co2=0.4),
        Product(name="Diatomaceous Earth", quantity=90, category="Biodegradable Pest Control", price=7.99, co2=0.5),

        # Eco-Friendly Farming Tools
        Product(name="Bamboo Hand Trowel", quantity=30, category="Eco-Friendly Farming Tools", price=8.99, co2=1.0),
        Product(name="Solar-Powered Irrigation Timer", quantity=20, category="Eco-Friendly Farming Tools", price=34.99,
                co2=2.2),

        # Regenerative Agriculture Products
        Product(name="Cover Crop Mix", quantity=25, category="Regenerative Agriculture", price=14.99, co2=2.8),
        Product(name="Biochar Soil Amendment", quantity=35, category="Regenerative Agriculture", price=19.99, co2=1.5)
    ]

    db.session.add_all(sample_products)
    db.session.commit()
    return "Sample sustainable agricultural products added!"


@app.route('/')
def home():
    # Retrieve JWT token from cookies
    token = request.cookies.get('jwt_token')
    user_info = None

    if token:
        # Decode and verify the token
        user_info = verify_jwt_token(token)

    # Fetch featured articles and updates
    articles = get_featured_articles()
    updates = []

    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])

    # Retrieve all products
    products = Product.query.all()

    if not products:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None, user_info=user_info)

    # Convert product data to Pandas DataFrame
    data = [{'name': product.name, 'category': product.category, 'co2': product.co2} for product in products]
    df = pd.DataFrame(data)

    # Ensure there is data before plotting
    if df.empty:
        return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=None,
                               chart2_data=None, chart3_data=None, user_info=user_info)

    # Chart 1 - CO₂ Emissions by Product
    plt.figure(figsize=(10, 5))
    plt.bar(df['name'], df['co2'], color='skyblue')
    plt.xlabel('Product Name')
    plt.ylabel('CO₂ Emissions (kg)')
    plt.title('CO₂ Emissions by Product')
    plt.xticks(rotation=45)
    plt.tight_layout()

    buffer1 = BytesIO()
    plt.savefig(buffer1, format='png')
    buffer1.seek(0)
    chart1_data = base64.b64encode(buffer1.getvalue()).decode('utf-8')
    buffer1.close()

    # Chart 2 - CO₂ Emissions by Product Category
    category_totals = df.groupby('category')['co2'].sum()
    plt.figure(figsize=(8, 5))
    plt.pie(category_totals, labels=category_totals.index, autopct='%1.1f%%', startangle=140)
    plt.title('CO₂ Emissions by Product Category')

    buffer2 = BytesIO()
    plt.savefig(buffer2, format='png')
    buffer2.seek(0)
    chart2_data = base64.b64encode(buffer2.getvalue()).decode('utf-8')
    buffer2.close()

    # Chart 3 - Highest vs. Lowest CO₂ Emission Products
    highest = df.nlargest(3, 'co2')
    lowest = df.nsmallest(3, 'co2')

    plt.figure(figsize=(10, 5))
    plt.bar(highest['name'], highest['co2'], color='red', label="Highest CO₂")
    plt.bar(lowest['name'], lowest['co2'], color='green', label="Lowest CO₂")
    plt.xlabel('Product Name')
    plt.ylabel('CO₂ Emissions (kg)')
    plt.title('Highest vs. Lowest CO₂ Emission Products')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()

    buffer3 = BytesIO()
    plt.savefig(buffer3, format='png')
    buffer3.seek(0)
    chart3_data = base64.b64encode(buffer3.getvalue()).decode('utf-8')
    buffer3.close()

    # Dynamic welcome message
    welcome_message = f"Welcome, {user_info['first_name']}!" if user_info else "Welcome to our site!"

    return render_template('/home/homePage.html', articles=articles, updates=updates, chart1_data=chart1_data,
                           chart2_data=chart2_data, chart3_data=chart3_data, welcome_message=welcome_message,
                           user_info=user_info)


@app.route('/buyProduct', methods=['GET'])
def buy_product():
    # Get selected categories (list of selected checkboxes)
    selected_categories = request.args.getlist('category')  # for multiple sections

    # Base query
    query = Product.query

    # Apply category filter (if any category is selected)
    if selected_categories:
        query = query.filter(Product.category.in_(selected_categories))

    # Get filtered products
    products = query.all()

    # Get all unique categories
    all_categories = {product.category for product in Product.query.all()}
    cart = session.get("cart", {})  # Retrieve cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())

    return render_template('/productPage/buyProduct.html',
                           products=products,
                           all_categories=all_categories,
                           selected_categories=selected_categories,
                           total_price=total_price)


@app.route('/createProduct', methods=['GET', 'POST'])
@jwt_required
def create_product():
    form = CreateProductForm()
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin', 'manager']:
        return render_template('404.html')

    # fetch categories from database
    categories = db.session.query(Product.category).distinct().all()
    category_choices = [(category[0], category[0]) for category in categories]

    form.category.choices = [('', 'Select Category')] + category_choices

    if request.method == 'POST':
        # reacptcha validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })
        if not r.json().get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('/productPage/createProduct.html', form=form, site_key=site_key)

        if form.validate_on_submit():
            name = form.product_name.data
            quantity = int(form.quantity.data)
            category = form.category.data
            price = float(form.price.data)
            co2 = float(form.co2.data)
            description = form.product_description.data

        # image upload
        image_file = form.product_image.data
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            filename = "default.jpg"

        new_product = Product(name=name, quantity=quantity, category=category, price=price, co2=co2,
                              description=description, image_filename=filename)

        db.session.add(new_product)
        db.session.commit()
        log_user_action(
            user_id=current_user['user_id'],
            session_id=current_user['session_id'],
            action=f"Created new product: {name} (Category: {category})"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Created New Product",
            item_name=name
        )

        return redirect(url_for('buy_product'))

    return render_template('/productPage/createProduct.html', form=form, site_key=site_key)


@app.route('/manageProduct')
@jwt_required
def manageProduct():
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin', 'manager']:
        return render_template('404.html')

    products = Product.query.all()  # Fetch all products from the database

    if not products:
        print("❌ No products found in the database.")  # Debugging message
        if request.args.get("export") == "csv":
            return "No products found.", 404
        return render_template('/productPage/manageProduct.html', products=[])

    # Handle CSV Export
    if request.args.get("export") == "csv":
        def generate():
            data = ["Product Name,Quantity,Category,Price,CO2,Description,Image Filename\n"]
            for product in products:
                data.append(
                    f"{product.name},{product.quantity},{product.category},{product.price},{product.co2},{product.description},{product.image_filename}\n")
            return "".join(data)

        response = Response(generate(), mimetype='text/csv')
        response.headers["Content-Disposition"] = "attachment; filename=products.csv"
        return response

    print(f"✅ Loaded {len(products)} products for management.")  # Debugging message
    return render_template('/productPage/manageProduct.html', products=products)


@app.route('/updateProduct/<int:id>/', methods=['GET', 'POST'])
@jwt_required
def update_product(id):
    product = Product.query.get_or_404(id)
    form = CreateProductForm(obj=product)  # Prepopulate form fields

    # Ensure category dropdown is populated
    categories = db.session.query(Product.category).distinct().all()
    category_choices = [(cat[0], cat[0]) for cat in categories]
    form.category.choices = category_choices

    if request.method == 'GET':
        form.product_name.data = product.name
        form.product_description.data = product.description

    if request.method == 'POST' and form.validate_on_submit():
        product.name = form.product_name.data
        product.quantity = int(form.quantity.data)
        product.category = form.category.data
        product.price = float(form.price.data)
        product.co2 = float(form.co2.data)
        product.description = form.product_description.data  # Ensure this is updated

        # Handle Image Upload
        image_file = form.product_image.data
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            product.image_filename = filename if filename else "default.png"

        db.session.commit()
        log_user_action(
            user_id=g.user['user_id'],
            session_id=g.user['session_id'],
            action=f"Updated product: {product.name} (ID: {product.id})"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Updated Product",
            item_name=product.name
        )

        return redirect(url_for('manageProduct'))

    return render_template('/productPage/updateProduct.html', form=form, product=product)


@app.route('/deleteProduct/<int:id>', methods=['POST'])
@jwt_required
def delete_product(id):
    product = Product.query.get_or_404(id)

    # delete image if its not default
    if product.image_filename != "default.jpg":
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(product)
    db.session.commit()
    log_user_action(
        user_id=g.user['user_id'],
        session_id=g.user['session_id'],
        action=f"Deleted product: {product.name} (ID: {product.id})"
    )
    notify_user_action(
        to_email=g.user['email'],
        action_type="Deleted Product",
        item_name=product.name
    )

    return redirect(url_for('manageProduct'))


@app.route('/view_products')
def view_products():
    products = Product.query.all()  # Fetch all products from the database

    if not products:
        return "<p style='color: red; font-size: 20px; text-align: center;'>No products found in the database!</p>"

    product_list = """
    <div style="text-align: center; font-family: Arial;">
        <h1 style="color: green;">Product List</h1>
        <table border="1" style="margin: auto; width: 80%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th>ID</th>
                <th>Name</th>
                <th>Quantity</th>
                <th>Category</th>
                <th>Price</th>
                <th>CO₂ Emissions (kg)</th>
                <th>Description</th>
            </tr>
    """

    for product in products:
        product_list += f"""
            <tr>
                <td>{product.id}</td>
                <td>{product.name}</td>
                <td>{product.quantity}</td>
                <td>{product.category}</td>
                <td>${"{:.2f}".format(product.price)}</td>
                <td>{product.co2} kg</td>
                <td>{product.description}</td>
            </tr>
        """

    product_list += "</table></div>"

    return product_list


@app.route('/clearProducts', methods=['POST', 'GET'])
def clear_products():
    try:
        num_deleted = db.session.query(Product).delete()  # Deletes all products
        db.session.commit()
        return f"Successfully deleted {num_deleted} products!"
    except Exception as e:
        db.session.rollback()
        return f"Error: {str(e)}"

    return product_list


@app.route('/carbonFootprintTracker', methods=['GET', 'POST'])
def carbonFootprintTracker():
    if 'selected_products' not in session:
        session['selected_products'] = []  # Initialize session storage

    products = Product.query.all()

    if request.method == 'POST':
        product_name = request.form.get('product')

        # Find the product from the database
        product = Product.query.filter_by(name=product_name).first()

        if product:
            # store product details
            session['selected_products'].append({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'co2': product.co2
            })
            session.modified = True  # save session changes

    # calculate co2 emission
    selected_products = session['selected_products']
    total_co2 = sum(product['co2'] for product in selected_products)

    co2_equivalent = ""
    goal_status = ""

    # co2 impact comparison
    if total_co2 > 0:
        if total_co2 < 10:
            co2_equivalent = "Equivalent to charging a smartphone 1,200 times."
        elif total_co2 < 30:
            co2_equivalent = "Equivalent to driving a car for 10 miles."
        elif total_co2 < 50:
            co2_equivalent = "Equivalent to running an AC for 3 hours."
        else:
            co2_equivalent = "Equivalent to 100kg of CO₂ emitted!"

    # co2 alternative suggestions
    suggested_alternatives = []
    for product in selected_products:
        if 'category' in product:
            low_co2_alternative = Product.query.filter(
                Product.category == product['category'], Product.co2 < product['co2']
            ).order_by(Product.co2).first()

            if low_co2_alternative:
                suggested_alternatives.append((product, low_co2_alternative))

    # co2 goal tracker
    target_co2_limit = 30  # Set a sustainable benchmark
    if total_co2 < target_co2_limit:
        goal_status = f"✅ You are within the sustainable limit! ({total_co2}kg CO₂)"
    else:
        goal_status = f"⚠️ Reduce emissions! Try staying under {target_co2_limit}kg CO₂."

    return render_template('carbonFootprintTracker.html',
                           products=products,
                           selected_products=selected_products,
                           total_co2=total_co2,
                           co2_equivalent=co2_equivalent,
                           suggested_alternatives=suggested_alternatives,
                           goal_status=goal_status)


@app.route('/deleteSelectedProduct/<int:product_id>', methods=['POST'])
def deleteSelectedProduct(product_id):
    if 'selected_products' in session:
        session['selected_products'] = [p for p in session['selected_products'] if p['id'] != product_id]
        session.modified = True  # Save session changes

    return redirect(url_for('carbonFootprintTracker'))  # Redirect back


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


@app.route('/contactUs', methods=['GET', 'POST'])
def contactUs():
    site_key = os.getenv("RECAPTCHA_SITE_KEY")
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })

        if not r.json().get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('contactUs.html', site_key=site_key)
        # first_name = request.form.get('inputFirstname')
        # last_name = request.form.get('inputLastname')
        # email = request.form.get('inputEmail')
        # phone = request.form.get('inputNumber')
        # purpose = request.form.get('flexRadioDefault')
        # additional_info = request.form.get('addInfo')

        flash('Your form has been submitted successfully!', 'success')
        return redirect(url_for('home'))  # Redirect to clear form

    return render_template('contactUs.html', site_key=site_key)


@app.route('/accountInfo')
@jwt_required
def accountInfo():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    # 🛠 Fix: MySQL stores BLOBs or bytes — decode to string first
    if user and user.get('recovery_code'):
        try:
            encrypted = user['recovery_code']
            if isinstance(encrypted, bytearray):  # MySQL may return bytearray
                encrypted = bytes(encrypted)
            decrypted_code = fernet.decrypt(encrypted).decode()
            user['recovery_code'] = decrypted_code
        except Exception as e:
            print(f"[Decryption Error] {e}")
            user['recovery_code'] = "[Decryption Failed]"

    return render_template('/accountPage/accountInfo.html', user=user, captcha_site_key=os.getenv("RECAPTCHA_SITE_KEY"))


@app.route('/accountSecurity', methods=['GET', 'POST'])
@jwt_required
def accountSecurity():
    user_id = g.user['user_id']
    session_id = g.user['session_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        selected_countries = request.form.getlist('allowed_countries')

        # Validation: Ensure at least one country is selected
        if not selected_countries:
            flash("You must select at least one country.", "danger")
            # Reload user to show current settings
            cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            cursor.close()
            return render_template('/accountPage/accountSecurity.html', user=user)

        country_str = ','.join(selected_countries)

        try:
            cursor.execute("UPDATE accounts SET countries = %s WHERE id = %s", (country_str, user_id))
            mysql.connection.commit()
            log_user_action(
                user_id=user_id,
                session_id=session_id,
                action=f"Updated allowed countries to: {country_str}"
            )
            flash("Allowed countries updated successfully.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Update failed: {str(e)}", "danger")

    # Always load user after possible update
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        return render_template('/accountPage/accountSecurity.html', user=user)

    flash("User data not found.", "danger")
    return redirect(url_for('login'))


@app.route('/accountHist')
@jwt_required
def accountHist():
    user_id = g.user['email']  # Get logged-in user ID

    # Get all transactions from session (if not found, return empty list)
    all_transactions = session.get("transactions", [])

    # DEBUGGING: Print transactions for testing
    print(f"All Transactions: {all_transactions}")
    print(f"Logged-in User ID: {user_id}")

    # Ensure transactions are correctly structured and filter them
    user_transactions = [t for t in all_transactions if t.get("email") == user_id]

    # DEBUGGING: Check filtered transactions
    print(f"User Transactions: {user_transactions}")

    # Apply Search Filter (if applicable)
    search_query = request.args.get("search", "").strip().lower()
    if search_query:
        user_transactions = [t for t in user_transactions if
                             search_query in t["id"].lower() or search_query in t["name"].lower()]

    return render_template('/accountPage/accountHist.html', transactions=user_transactions, search_query=search_query)


@app.route('/dashboard')
@jwt_required
def dashboard():
    jwt_user = g.user
    if jwt_user['status'] not in ['admin']:
        return render_template('404glen.html')

    user_id = jwt_user['user_id']
    session_id = jwt_user['session_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get current user info
    cursor.execute("SELECT id, first_name, last_name, email, gender, status FROM accounts WHERE id = %s", (user_id,))
    user_info = cursor.fetchone()

    if not user_info:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    # Get search and role filters
    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")  # multi-select

    # Build dynamic query
    query = "SELECT id, first_name, last_name, email, status FROM accounts WHERE 1=1"
    params = []

    if search_query:
        query += " AND (LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s OR LOWER(email) LIKE %s)"
        like_value = f"%{search_query}%"
        params += [like_value, like_value, like_value]

    if selected_roles:
        role_placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND status IN ({role_placeholders})"
        params += selected_roles

    cursor.execute(query, params)
    users = cursor.fetchall()
    cursor.close()
    log_user_action(
        user_id=user_id,
        session_id=session_id,
        action="Accessed admin dashboard"
    )

    notify_user_action(
        to_email=jwt_user['email'],
        action_type="Accessed Admin Dashboard",
        item_name="Dashboard View"
    )

    return render_template(
        'dashboard.html',
        user=user_info,
        users=users,
        search_query=search_query,
        selected_roles=selected_roles
    )


@app.route('/updateUserStatus/<int:id>', methods=['POST'])
@jwt_required
def update_user_status(id):
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] not in ['admin']:
        return render_template('404.html')

    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only staff can change user statuses.", "danger")
        return redirect(url_for('dashboard'))

    cursor = mysql.connection.cursor()
    # Fetch previous status before update (for user_action_log in session activity tracking)
    cursor.execute("SELECT email, status FROM accounts WHERE id = %s", (id,))
    user_record = cursor.fetchone()
    user_email = user_record[0]
    old_status = user_record[1]

    cursor.execute("UPDATE accounts SET status = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Updated user ID {id}'s status from '{old_status}' to '{new_status}'"
    )

    notify_user_action(
        to_email=user_email,
        action_type="Status Change",
        item_name=f"Your account status has been changed from '{old_status}' to '{new_status}'."
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Status Change",
        item_name=f"You changed user ID {id}'s status from '{old_status}' to '{new_status}'."
    )

    cursor.close()

    flash("User status updated successfully.", "success")
    return redirect(url_for('roleManagement'))


@app.route('/createAdmin', methods=['GET', 'POST'])
@jwt_required
def createAdmin():
    new_status = request.form.get('status')
    current_user = g.user
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if current_user['status'] not in ['admin']:
        return render_template('404.html')

    create_admin_form = CreateAdminForm(request.form)

    if request.method == 'POST':
        # ✅ reCAPTCHA validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })

        if not r.json().get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('createAdmin.html', form=create_admin_form, site_key=site_key)

        if create_admin_form.validate():
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Step 1: Check for duplicate email or phone number
            cursor.execute("SELECT * FROM accounts WHERE email = %s OR phone_number = %s",
                           (create_admin_form.email.data.lower(), create_admin_form.number.data))
            existing_user = cursor.fetchone()

            if existing_user:
                if existing_user['email'] == create_admin_form.email.data:
                    flash('Email is already registered. Please use a different email.', 'danger')
                elif existing_user['phone_number'] == create_admin_form.number.data:
                    flash('Phone number is already registered. Please use a different number.', 'danger')
                cursor.close()
                return redirect(url_for('createAdmin'))

            # Step 2: Sanitize all inputs after duplicate check
            first_name = sanitize_input(create_admin_form.first_name.data)
            last_name = sanitize_input(create_admin_form.last_name.data)
            gender = sanitize_input(create_admin_form.gender.data)
            status = sanitize_input(create_admin_form.status.data)
            phone_number = sanitize_input(create_admin_form.number.data)
            email = sanitize_input(create_admin_form.email.data.lower())

            # Step 4: Hash password and insert user
            hashed_password = hash_password(create_admin_form.pswd.data)

            cursor.execute('''
                INSERT INTO accounts (first_name, last_name, gender, phone_number, email, password, status, two_factor_status) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                first_name,
                last_name,
                gender,
                phone_number,
                email,
                hashed_password,
                status,
                'disabled'
            ))

            mysql.connection.commit()
            log_user_action(
                user_id=current_user['user_id'],
                session_id=current_user['session_id'],
                action=f"Created admin account for {email}"
            )

            notify_user_action(
                to_email=current_user['email'],
                action_type="Created Admin Account",
                item_name=f"You created an admin account for {email}."
            )

            cursor.close()

            flash('Admin account created successfully.', 'success')
            return redirect(url_for('createAdmin'))

    return render_template('createAdmin.html', form=create_admin_form, site_key=site_key)


@app.route('/updateLogStatus/<int:id>', methods=['POST'])
@jwt_required
def update_log_status(id):
    new_status = request.form.get('status')
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only admins can change log statuses.", "danger")
        return redirect(url_for('logging'))

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE logs SET status = %s WHERE id = %s", (new_status, id))
    mysql.connection.commit()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Updated log status (Log ID: {id}) to '{new_status}'"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Log Status Update",
        item_name=f"You changed the status of Log ID {id} to '{new_status}'."
    )

    cursor.close()

    flash("Log status updated successfully.", "success")
    return redirect(url_for('logging'))


@app.route('/delete_log/<int:id>', methods=['POST'])
@jwt_required
def delete_log(id):
    current_user = g.user

    if current_user['status'] != 'admin':
        flash("Only admins can delete logs.", "danger")
        return redirect(url_for('logging'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM logs WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()
    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Deleted log entry with ID: {id}"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Deleted Log Entry",
        item_name=f"You deleted the log entry with ID: {id}."
    )

    flash("Log deleted successfully.", "success")
    return redirect(url_for('logging'))


@app.route('/logging', methods=['GET'])
@jwt_required
def logging():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")
    selected_statuses = request.args.getlist("statuses")
    sort_by = request.args.get("sort_by", "date")
    sort_order = request.args.get("sort_order", "desc")
    start_date = request.args.get("start_date")

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (current_user['user_id'],))
    user_info = cursor.fetchone()

    query = "SELECT id, user_id, date, time, category, activity, status, ip_address FROM logs WHERE 1=1"
    params = []

    if selected_roles:
        placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND category IN ({placeholders})"
        params.extend(selected_roles)

    if selected_statuses:
        placeholders = ','.join(['%s'] * len(selected_statuses))
        query += f" AND status IN ({placeholders})"
        params.extend(selected_statuses)

    if search_query:
        query += " AND (LOWER(category) LIKE %s OR LOWER(activity) LIKE %s OR ip_address LIKE %s)"
        like_term = f"%{search_query}%"
        params.extend([like_term, like_term, like_term])

    if start_date:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")  # validate format
            query += " AND date >= %s"
            params.append(start_date)
        except ValueError:
            flash("Invalid date format provided.", "warning")

    sortable_columns = {
        "date": "date",
        "category": "FIELD(category, 'Critical', 'Error', 'Warning', 'Info')"
    }

    if sort_by in sortable_columns:
        order_clause = sortable_columns[sort_by]
        query += f" ORDER BY {order_clause} {'ASC' if sort_order == 'asc' else 'DESC'}"

    cursor.execute(query, params)
    logs = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) AS logs_count FROM logs")
    logs_result = cursor.fetchone()
    logs_count = logs_result['logs_count']

    cursor.close()

    current_date = date.today().isoformat()

    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action="Viewed log dashboard"
    )

    notify_user_action(
        to_email=current_user['email'],
        action_type="Viewed Logs",
        item_name="You accessed the log dashboard and viewed recent activities."
    )

    return render_template(
        'logging.html',
        user=user_info,
        users=logs,
        selected_roles=selected_roles,
        selected_statuses=selected_statuses,
        current_date=current_date,
        search_query=search_query,
        sort_by=sort_by,
        sort_order=sort_order,
        start_date=start_date,
        logs_count=logs_count
    )


@app.route('/logging_analytics', methods=['GET'])
@jwt_required
def logging_analytics():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    today = datetime.now().date()

    logs_summary = generate_logs_summary(mysql)

    today_str = datetime.today().strftime("%Y-%m-%d")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    num_days = request.args.get('days')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if start_date and end_date:
        # Custom date range logic
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
            GROUP BY DATE(date), category
            ORDER BY date
        """, (start_date, end_date))

        date_range = pd.date_range(start=start_date, end=end_date)
        dates_iso = [d.date().isoformat() for d in date_range]
        dates_display = [d.strftime('%d - %m - %Y') for d in date_range]
        display_start_date = start_date  # For display in template
        num_days = len(date_range)

    else:
        # Default to last N days
        num_days = int(num_days or 10)
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(date), category
            ORDER BY date
        """, (num_days - 1,))

        today = datetime.today().date()
        dates_iso = [(today - timedelta(days=i)).isoformat() for i in range(num_days - 1, -1, -1)]
        dates_display = [(today - timedelta(days=i)).strftime('%d - %m - %Y') for i in range(num_days - 1, -1, -1)]
        start_date_obj = datetime.now().date() - timedelta(days=num_days - 1)
        display_start_date = start_date_obj.strftime("%d/%m/%Y")

    log_data = cursor.fetchall()

    categories = ['Info', 'Warning', 'Error', 'Critical']
    chart_data = {date: {cat: 0 for cat in categories} for date in dates_iso}
    category_summary = {cat: 0 for cat in categories}

    for row in log_data:
        db_date = str(row['date'])
        cat = row['category']
        count = row['count']
        if db_date in chart_data and cat in chart_data[db_date]:
            chart_data[db_date][cat] = count
            category_summary[cat] += count

    current_time = datetime.now().strftime("%d-%m-%Y , %I:%M %p")
    current_day = datetime.now().strftime("%d-%m-%Y")

    cursor.execute("SELECT COUNT(*) AS closed_count FROM logs WHERE status = 'Closed'")
    closed_result = cursor.fetchone()
    closed_count = closed_result['closed_count']

    cursor.execute("SELECT COUNT(*) AS logs_count FROM logs")
    logs_result = cursor.fetchone()
    logs_count = logs_result['logs_count']

    # Determine which date to show login activity for
    login_date = request.args.get('login_date') or request.args.get('start_date') or today_str

    # Query login counts by hour and status
    cursor.execute("""
        SELECT HOUR(login_time) AS login_hour, status, COUNT(*) AS count
        FROM user_session_activity
        WHERE DATE(login_time) = %s
        GROUP BY login_hour, status
        ORDER BY login_hour, status
    """, (login_date,))
    login_activity_rows = cursor.fetchall()

    # Initialize hourly login dictionary
    login_activity = {hour: {'admin': 0, 'manager': 0, 'user': 0} for hour in range(24)}

    # Populate it
    for row in login_activity_rows:
        hour = int(row['login_hour'])
        status = row['status'].lower()
        count = row['count']
        if status in login_activity[hour]:
            login_activity[hour][status] = count

    cursor.close()

    return render_template(
        'logging_analytics.html',
        login_activity=login_activity,
        chart_data=chart_data,
        dates_iso=dates_iso,
        dates_display=dates_display,
        categories=categories,
        current_time=current_time,
        current_day=current_day,
        today_str=today_str,
        start_date=display_start_date,
        category_summary=category_summary,
        closed_count=closed_count,
        logs_count=logs_count,
        num_days=num_days,
        logs_summary=logs_summary,
        summary_date=today,
    )

@app.route("/generate_pdf_report")
@jwt_required
def download_pdf_report():
    current_user = g.user
    if current_user['status'] != 'admin':
        return render_template('404.html')

    flash("PDF password: First Name + Phone Number (no spaces, case-sensitive)", "info")

    # --- Build password: firstname + phone digits ---
    # Try a few common keys for first name and phone
    first_name = (
        (current_user.get('first_name')
         or current_user.get('firstname')
         or (current_user.get('name') or '').split(' ')[0]  # fallback: first token of full name
         or '').strip()
    )
    phone_raw = (
        current_user.get('phone')
        or current_user.get('phone_number')
        or current_user.get('mobile')
        or ''
    )
    phone_digits = re.sub(r'\D+', '', str(phone_raw))

    # Remove leading "65" if present
    if phone_digits.startswith("65"):
        phone_digits = phone_digits[2:]

    if not first_name or not phone_digits:
        return ("Missing first name or phone number for PDF password. "
                "Ensure the user profile has both.", 400)

    user_password = f"{first_name}{phone_digits}"
    # You can use the same value for ownerPassword, or keep a separate admin password if you want.
    enc = StandardEncryption(
        userPassword=user_password,
        ownerPassword=user_password,
        canPrint=1,    # allow printing
        canModify=0,   # disallow modifications
        canCopy=0      # disallow copying
    )

    # --- your existing date handling & queries (unchanged) ---
    today_str = datetime.today().strftime("%Y-%m-%d")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    num_days = request.args.get('days')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if start_date and end_date:
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) BETWEEN %s AND %s
            GROUP BY DATE(date), category
            ORDER BY date
        """, (start_date, end_date))
        date_range = pd.date_range(start=start_date, end=end_date)
        dates_iso = [d.date().isoformat() for d in date_range]
    else:
        num_days = int(num_days or 10)
        cursor.execute("""
            SELECT DATE(date) AS date, category, COUNT(*) AS count
            FROM logs
            WHERE DATE(date) >= CURDATE() - INTERVAL %s DAY
            GROUP BY DATE(date), category
            ORDER BY date
        """, (num_days - 1,))
        today = datetime.today().date()
        dates_iso = [(today - timedelta(days=i)).isoformat() for i in range(num_days - 1, -1, -1)]

    log_data = cursor.fetchall()
    categories = ['Info', 'Warning', 'Error', 'Critical']

    chart_data = {date: {cat: 0 for cat in categories} for date in dates_iso}
    category_summary = {cat: 0 for cat in categories}

    for row in log_data:
        db_date = str(row['date'])
        cat = row['category']
        count = row['count']
        if db_date in chart_data and cat in chart_data[db_date]:
            chart_data[db_date][cat] = count
            category_summary[cat] += count

    trend_dates = dates_iso
    trend_data = {cat: [chart_data[date][cat] for date in trend_dates] for cat in categories}

    login_date = request.args.get('login_date') or request.args.get('start_date') or today_str
    cursor.execute("""
        SELECT HOUR(login_time) AS login_hour, status, COUNT(*) AS count
        FROM user_session_activity
        WHERE DATE(login_time) = %s
        GROUP BY login_hour, status
        ORDER BY login_hour, status
    """, (login_date,))
    login_activity_rows = cursor.fetchall()

    login_activity = {f"{h:02d}:00": {'admin': 0, 'manager': 0, 'user': 0} for h in range(24)}
    for row in login_activity_rows:
        hour = int(row['login_hour'])
        status = str(row['status']).lower()
        count = row['count']
        if status in login_activity[f"{hour:02d}:00"]:
            login_activity[f"{hour:02d}:00"][status] = count

    cursor.close()

    # --- Generate encrypted PDF ---
    import tempfile
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    filepath = temp_file.name
    generate_log_report_pdf(
        filepath,
        login_activity,
        category_summary,
        trend_data,
        trend_dates,
        mysql=mysql,
        pdf_encrypt=enc  # <- pass encryption
    )

    # The user password is first name + phone (digits). You can show a hint if desired.
    return send_file(filepath, as_attachment=True, download_name="Log_Report.pdf", mimetype='application/pdf')


# Info is the default value set for logs category
def admin_log_activity(mysql, activity, category="Info", user_id=None, status=None):
    """
    Logs an activity to the logs table.
    If the category is 'Critical', it will send email alerts to all admin users.

    Args:
        mysql: The MySQL connection object.
        activity (str): Description of the activity to log.
        category (str): Log category (e.g., 'Info', 'Warning', 'Error', 'Critical')
    """
    if not mysql:
        raise ValueError("MySQL connection object is required.")

    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    date = datetime.now().strftime('%Y-%m-%d')
    time = datetime.now().strftime('%I:%M %p')

    # Insert log into DB
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('''
                    INSERT INTO logs (user_id, date, time, category, activity, status, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (user_id, date, time, category, activity, 'Open', ip_addr))
        mysql.connection.commit()
    finally:
        cursor.close()

    # If critical, notify all admins
    if category.lower() == "critical":
        notify_all_admins(mysql, activity, date, time, ip_addr, category)


def notify_all_admins(mysql, message, date, time, ip_addr, category):
    """
    Sends an email notification to all admin users about a critical log event.
    """
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT email, first_name FROM accounts WHERE status = 'admin'")
        admins = cursor.fetchall()
        cursor.close()

        subject = "Subject: [ALERT] Critical Security Incident Detected"
        for admin in admins:
            alert_message = f"""
Dear {admin['first_name']},

A critical security incident has been detected and requires immediate attention:

Incident Details:
Severity    : {category}
Description : {message}
Date        : {date}
Time        : {time}
IP Address  : {ip_addr}

Please investigate this issue as soon as possible to ensure the security and integrity of the system.

If you require further context or logs, contact the security team or check the system alerts.    

This is an automated message. Please do not reply.  
For assistance, contact the Cropzy Security Team directly.

Regards,  
Cropzy Security Monitoring System
            """
            send_email(admin['email'], subject, alert_message)
    except Exception as e:
        print(f"Failed to send admin alerts: {e}")


@app.route('/roleManagement', methods=['GET', 'POST'])
@jwt_required
def roleManagement():
    new_status = request.form.get('status')
    current_user = g.user

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, first_name, last_name, email, status FROM accounts")
    users = cursor.fetchall()
    user_info = cursor.fetchone()

    if current_user['status'] not in ['admin', 'staff']:
        return render_template('404.html')

    # Get search and role filters
    search_query = request.args.get("search", "").strip().lower()
    selected_roles = request.args.getlist("roles")  # multi-select

    # Build dynamic query
    query = "SELECT id, first_name, last_name, email, status FROM accounts WHERE 1=1"
    params = []

    if search_query:
        query += " AND (LOWER(first_name) LIKE %s OR LOWER(last_name) LIKE %s OR LOWER(email) LIKE %s)"
        like_value = f"%{search_query}%"
        params += [like_value, like_value, like_value]

    if selected_roles:
        role_placeholders = ','.join(['%s'] * len(selected_roles))
        query += f" AND status IN ({role_placeholders})"
        params += selected_roles

    cursor.execute(query, params)
    users = cursor.fetchall()
    cursor.close()

    return render_template(
        'roleManagement.html',
        user=user_info,
        users=users,
        search_query=search_query,
        selected_roles=selected_roles
    )


@app.route('/signUp', methods=['GET', 'POST'])
@limiter.limit("500 per 1 minutes")
def sign_up():
    sign_up_form = SignUpForm(request.form)
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if request.method == 'POST':
        # recaptcha verification
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })

        if not r.json().get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('/accountPage/signUp.html', form=sign_up_form, site_key=site_key)

        if sign_up_form.validate():
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            # Check if email or phone number already exists
            cursor.execute("SELECT * FROM accounts WHERE email = %s OR phone_number = %s",
                           (sign_up_form.email.data, sign_up_form.number.data))
            existing_user = cursor.fetchone()

            first_name = sanitize_input(sign_up_form.first_name.data)
            last_name = sanitize_input(sign_up_form.last_name.data)
            gender = sanitize_input(sign_up_form.gender.data)
            phone_number = sanitize_input(sign_up_form.number.data)
            email = sanitize_input(sign_up_form.email.data.lower())

            if existing_user:
                if existing_user['email'] == sign_up_form.email.data:
                    flash('Email is already registered. Please use a different email.', 'danger')
                elif existing_user['phone_number'] == sign_up_form.number.data:
                    flash('Phone number is already registered. Please use a different number.', 'danger')
                cursor.close()
                return redirect(url_for('sign_up'))

            # Determine status based on email domain
            email = sign_up_form.email.data
            status = 'admin' if email.endswith('@cropzy.com') else 'user'

            # Hash the password before storing
            hashed_password = hash_password(sign_up_form.pswd.data)

            # Get user IP (use real IP for deployment)
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            # If testing locally, uncomment this line:
            # ip_address = requests.get("https://api.ipify.org").text

            # Get country code from IP

            if ip_address.startswith("127.") or ip_address.startswith("192.") or ip_address.startswith(
                    "10.") or ip_address.startswith("172."):
                ip_address = get_public_ip()

            current_country = get_user_country(ip_address)
            print(f"User IP: {ip_address}, Country: {current_country}")

            # Insert new user with hashed password
            cursor.execute('''
                INSERT INTO accounts (first_name, last_name, gender, phone_number, email, password, status, two_factor_status, countries) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                first_name,
                last_name,
                gender,
                '+65' + str(phone_number),
                email,
                hashed_password,
                status,
                'disabled',
                current_country
            ))

            user_id = cursor.lastrowid

            # Log registration
            admin_log_activity(mysql, "User signed up successfully", category="Critical", user_id=user_id,
                               status=status)

            notify_user_action(
                to_email=email,
                action_type="Sign Up Successful",
                item_name=f"Welcome to Cropzy, {first_name}! Your account has been successfully created."
            )

            mysql.connection.commit()
            cursor.close()

            flash('Sign up successful! Please log in.', 'info')
            return redirect(url_for('complete_signUp'))
    return render_template('/accountPage/signUp.html', form=sign_up_form, site_key=site_key)


@app.context_processor
def inject_user():
    token = request.cookies.get('jwt_token')
    user = verify_jwt_token(token) if token else None
    return dict(current_user=user)


@app.context_processor
def inject_user():
    token = request.cookies.get('jwt_token')
    user = verify_jwt_token(token) if token else None
    return dict(current_user=user)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("500 per 1 minutes")
def login():
    login_form = LoginForm(request.form)
    site_key = os.getenv("RECAPTCHA_SITE_KEY")
    # redirect
    if 'jwt_token' in request.cookies:
        return redirect(url_for('home'))

    if request.method == 'POST':
        # captcha validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })
        if not r.json().get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            response = make_response(render_template('/accountPage/login.html', form=login_form, site_key=site_key))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            return response

    if request.method == 'POST' and login_form.validate():
        email = sanitize_input(login_form.email.data.lower())
        password = login_form.pswd.data

        # for user action log purposes
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        user_agent = request.headers.get('User-Agent')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Hardcoded IP (Singapore - SG) for testing purposes
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

            # If running locally (private IP), use real public IP
            if ip_address.startswith("127.") or ip_address.startswith("192.") or ip_address.startswith(
                    "10.") or ip_address.startswith("172."):
                ip_address = get_public_ip()

            current_country = get_user_country(ip_address)
            print(f"User IP: {ip_address}, Country: {current_country}")

            # Ensure 'countries' is not None
            allowed_countries = user.get('countries') or ''
            allowed_list = [c.strip() for c in allowed_countries.split(',')] if allowed_countries else []

            if current_country not in allowed_list:
                flash("Login from your region is not allowed.", "danger")
                log_user_action(
                    user_id=user['id'],
                    session_id=None,
                    action=f"Login blocked - Disallowed region ({current_country}) | IP: {ip_address} | Agent: {user_agent}"
                )
                return redirect(url_for('login'))

            if is_account_frozen(user['id']):
                unfreeze_link = url_for('ajax_send_unfreeze_email', user_id=user['id'])
                message = Markup(
                    f"Account has been frozen. Send unfreeze email <a href='#' class='alert-link' onclick=\"sendUnfreezeRequest('{unfreeze_link}')\">here</a>.")
                flash(message, "danger")
                return redirect(url_for('login'))

            # Password validation
            stored_password_hash = user['password']
            if verify_password(password, stored_password_hash):
                if user.get('two_factor_status') == 'enabled':
                    send_otp_email(user['email'], user['id'], user['first_name'], user['last_name'])
                    session['pending_2fa_user_id'] = user['id']
                    session['pending_2fa_started_at'] = time.time()
                    session['pending_2fa_attempts'] = 0  # NEW
                    log_user_action(
                        user_id=user['id'],
                        session_id=None,
                        action=f"Login passed password check, pending OTP | IP: {ip_address} | Agent: {user_agent}"
                    )
                    return redirect(url_for('verify_otp', id=user['id']))
                else:
                    session_id = log_session_activity(user['id'], user['status'], 'login')
                    payload = {
                        'user_id': user['id'],
                        'first_name': user['first_name'],
                        'last_name': user['last_name'],
                        'email': user['email'],
                        'gender': user['gender'],
                        'phone': user['phone_number'],
                        'status': user['status'],
                        'session_id': session_id,
                        'exp': datetime.utcnow() + timedelta(hours=1)
                    }

                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                    response = make_response(redirect(url_for('home')))
                    response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')
                    flash('Login successful!', 'success')
                    log_user_action(
                        user_id=user['id'],
                        session_id=session_id,
                        action=f"Login successful (no 2FA) | IP: {ip_addr} | Agent: {user_agent}"
                    )
                    notify_user_action(
                        to_email=user['email'],
                        action_type="Login Notification",
                        item_name=f"Your Cropzy account was just logged in from IP: {ip_addr}\n\nDevice: {user_agent}"
                    )

                    return response

            flash('Incorrect password.', 'danger')
        else:
            flash('Email not found. Please sign up.', 'danger')
    # no cache
    response = make_response(render_template('/accountPage/login.html', form=login_form, site_key=site_key))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


account_sid = 'AC69fe3693aeb2b86b276600293ab078d5'
auth_token = 'e475d20188609c83fc90575507d297b1'
twilio_phone = '+13072882468'
client = Client(account_sid, auth_token)


def send_otp_email(email, user_id, first_name, last_name):
    """
    Generate a 6-digit OTP, store it with an expiration time,
    and send it to the specified email address.

    Args:
        email (str): Recipient email address.
        user_id (int): ID of the user to associate with the OTP.

    Returns:
        None
    """
    otp = f"{random.randint(0, 999999):06d}"
    expires = time.time() + 60  # OTP valid for 60 seconds

    # Store OTP and expiry time
    otp_store[user_id] = {"otp": otp, "expires": expires}

    # Prepare email content
    subject = "[Cropzy] Cropzy Login 2FA OTP Code"
    message = (f"Hello {first_name} {last_name},\n\nPlease enter the generated code below to authenticate yourself \n\n"
               f"Your OTP code is: {otp} It expires in 1 minute. "
               f"If you did not attempt to sign in to your account, your password may be compromised.\n\nVisit http://127.0.0.1:5000/accountSecurity to create a new, strong password for your Cropzy account.\n\n"
               f"Thanks,\nCropzy Support Team")

    # Call existing email sending function
    send_email(email, subject, message)


def send_otp_sms(phone_number, user_id, first_name, last_name):
    otp = f"{random.randint(0, 999999):06d}"
    expires = time.time() + 60  # OTP valid for 60 seconds

    # Store OTP and expiry time
    otp_store[user_id] = {"otp": otp, "expires": expires}

    try:
        message = client.messages.create(
            from_=twilio_phone,
            body=f'\n Use verification code {otp} for Cropzy authentication.',
            to=phone_number
        )
        print(f" SMS sent: {message.sid}")  # Debugger msg
    except Exception as e:
        print(f" Failed to send SMS: {e}")  # Debugger msg


@app.route('/sms-verify-otp/<int:id>', methods=['GET', 'POST'])
def sms_verify_otp(id):
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    # Send OTP on GET request
    if request.method == 'GET':
        # Generate and send OTP
        otp = f"{random.randint(0, 999999):06d}"
        expires = time.time() + 60  # 60 seconds expiry
        otp_store[id] = {"otp": otp, "expires": expires}

        # Fetch user phone
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            send_otp_sms(user['phone_number'], id, user['first_name'], user['last_name'])

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        record = otp_store.get(id)

        if not record:
            flash("No OTP found. Please login again.", "error")
            return redirect(url_for('login'))

        if time.time() > record['expires']:
            flash("OTP expired. Please login again.", "error")
            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('login'))

        if entered_otp == record['otp']:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
            user = cursor.fetchone()
            cursor.close()

            if not user:
                flash("User not found. Please login again.", "error")
                return redirect(url_for('login'))

            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)

            session_id = log_session_activity(user['id'], user['status'], 'login')

            payload = {
                'user_id': user['id'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'gender': user['gender'],
                'phone': user['phone_number'],
                'status': user['status'],
                'session_id': session_id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            response = make_response(redirect(url_for('home')))
            response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

            log_user_action(
                user_id=user['id'],
                session_id=session_id,
                action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
            )

            notify_user_action(
                to_email=user['email'],
                action_type="Login Notification (2FA)",
                item_name=f"Your Cropzy account was just logged in via 2FA from IP: {ip_addr}\n\nDevice: {user_agent}"
            )

            flash("Login successful!", "success")
            return response
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('/accountPage/sms_auth.html', id=id)


def generate_recovery_code(id):
    code = f"{random.randint(0, 999999):06d}"  # Generate 12-digit code

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if user exists
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return False  # User not found

    # Update recovery code
    encrypted_code = fernet.encrypt(code.encode())
    cursor.execute("UPDATE accounts SET recovery_code = %s WHERE id = %s", (encrypted_code, id))

    mysql.connection.commit()
    cursor.close()

    return code


@app.route('/setup_face_id/<int:id>', methods=['GET', 'POST'])
@jwt_required
def setup_face_id(id):
    current_email = g.user['email']

    if request.method == 'POST':
        base64_img = request.form.get('face_image')

        if not base64_img or "," not in base64_img:
            flash("Face capture failed. Please try again.", "danger")
            return redirect(request.url)

        image_data = base64_img.split(",")[1]
        img_bytes = base64.b64decode(image_data)

        # Save image bytes to database directly
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE accounts SET face = %s WHERE id = %s", (img_bytes, id))
        mysql.connection.commit()
        cursor.close()

        notify_user_action(
            to_email=g.user['email'],
            action_type="Face ID Setup",
            item_name="You have successfully registered a Face ID for your Cropzy account."
        )

        flash("Face ID registered successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template("accountPage/setup_face_id.html", id=id)


@app.route('/delete_face_id/<int:id>', methods=['POST'])
def delete_face_id(id):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE accounts SET face = NULL WHERE id = %s", (id,))
        mysql.connection.commit()
        cursor.close()

        flash("Face ID deleted successfully!", "success")
    except Exception as e:
        print(f"Failed to delete Face ID: {e}")
        flash("Failed to delete Face ID. Please try again.", "danger")

    return redirect(url_for('accountInfo'))


@app.route('/face_id/<int:id>', methods=['GET', 'POST'])
def face_id(id):
    if request.method == 'POST':
        base64_img = request.form.get('face_image')
        if not base64_img or "," not in base64_img:
            flash("Face not captured. Please click 'Capture Face' before submitting.", "danger")
            return redirect(request.url)

        # Save the newly captured face as a temporary file
        image_data = base64_img.split(",")[1]
        temp_filename = f"temp_face_scan_user_{id}.png"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        with open(temp_path, 'wb') as f:
            f.write(base64.b64decode(image_data))

        # Retrieve the stored face blob from the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT face FROM accounts WHERE id = %s", (id,))
        user_face_data = cursor.fetchone()
        cursor.close()

        if not user_face_data or not user_face_data['face']:
            flash("No registered face found. Please set up Face ID first.", "danger")
            return redirect(url_for('setup_face_id', id=id))

        # Save the registered face blob as an image
        registered_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{id}_face.png")
        with open(registered_path, 'wb') as f:
            f.write(user_face_data['face'])

        try:
            result = DeepFace.verify(
                img1_path=temp_path,
                img2_path=registered_path,
                model_name='VGG-Face',
                enforce_detection=False
            )

            if result["verified"]:
                # Fetch full user info
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
                user = cursor.fetchone()
                cursor.close()

                if not user:
                    flash("User not found. Please try again.", "danger")
                    return redirect(url_for('login'))

                session_id = log_session_activity(user['id'], user['status'], 'login')

                payload = {
                    'user_id': user['id'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'email': user['email'],
                    'gender': user['gender'],
                    'phone': user['phone_number'],
                    'status': user['status'],
                    'session_id': session_id,
                    'exp': datetime.utcnow() + timedelta(hours=1)
                }

                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                response = make_response(redirect(url_for('home')))
                response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

                # Optionally delete temp files
                if os.path.exists(temp_path): os.remove(temp_path)
                if os.path.exists(registered_path): os.remove(registered_path)

                log_user_action(
                    user_id=user['id'],
                    session_id=session_id,
                    action="Login successful (via Face ID)"
                )

                notify_user_action(
                    to_email=user['email'],
                    action_type="Face ID Login",
                    item_name="You have successfully logged in using Face ID."
                )

                flash("Face matched. Logged in successfully!", "success")
                return response
            else:
                flash("Face does not match. Access denied.", "danger")

        except Exception as e:
            flash(f"Error during face verification: {str(e)}", "danger")

    return render_template("accountPage/face_id.html", id=id)


@app.route('/more_auth/<int:id>')
def more_auth(id):
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    return render_template('/accountPage/more_auth.html', id=id, user=user)


@app.route('/2FA/<int:id>', methods=['POST'])
@jwt_required
def enable_two_factor(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Check if the user exists
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('accountInfo'))

    # If already enabled, don't update again
    if user['two_factor_status'] == 'enabled':
        flash("2FA is already enabled for this account.", "info")
    else:
        # Enable 2FA
        cursor.execute("UPDATE accounts SET two_factor_status = %s WHERE id = %s", ('enabled', id))
        mysql.connection.commit()
        flash('You have successfully enabled 2FA for this account', 'success')

        log_user_action(
            user_id=id,
            session_id=g.user['session_id'] if hasattr(g, 'user') and g.user.get('session_id') else None,
            action=f"Enabled 2FA"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Enabled 2FA",
            item_name="You have successfully enabled 2FA for your account."
        )

    generate_recovery_code(id)

    cursor.close()
    return redirect(url_for('accountInfo'))


@app.route('/disable2FA/<int:id>/', methods=['POST'])
@jwt_required
def disable_two_factor(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('accountInfo'))

    if user['two_factor_status'] == 'disabled':
        flash("2FA is already disabled for this account.", "info")
    else:
        cursor.execute("UPDATE accounts SET two_factor_status = %s, recovery_code = NULL WHERE id = %s",
                       ('disabled', id))
        mysql.connection.commit()
        flash("2FA has been disabled for this account.", "success")

        log_user_action(
            user_id=id,
            session_id=g.user['session_id'] if hasattr(g, 'user') and g.user.get('session_id') else None,
            action=f"Disabled 2FA"
        )

        notify_user_action(
            to_email=g.user['email'],
            action_type="Disabled 2FA",
            item_name="You have successfully disabled 2FA for your account."
        )

    cursor.close()
    return redirect(url_for('accountInfo'))


def log_session_activity(user_id, status, action):
    print(f"[DEBUG] Creating session log for user {user_id} at {datetime.now()}")
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)

    try:
        cursor = mysql.connection.cursor()
        session_id = None  # default

        if action == 'login':
            cursor.execute('''
                INSERT INTO user_session_activity (user_id, status, login_time, ip_address, user_agent)
                VALUES (%s, %s, NOW(), %s, %s)
            ''', (
                user_id,
                status,
                ip_addr,
                request.headers.get('User-Agent')
            ))

            session_id = cursor.lastrowid
            session['current_session_id'] = session_id
            session['user_id'] = user_id

        elif action == 'logout':
            cursor.execute('''
                UPDATE user_session_activity
                SET logout_time = NOW()
                WHERE user_id = %s AND logout_time IS NULL
                ORDER BY login_time DESC
                LIMIT 1
            ''', (user_id,))

        # Diagnostic
        cursor.execute('SELECT DATABASE()')
        current_db = cursor.fetchone()
        print("[DEBUG] Connected to DB:", current_db)

        mysql.connection.commit()
        cursor.close()
        print("[DEBUG] Log saved to DB")
        return session_id

    except Exception as e:
        print("[ERROR] Session log failed:", e)
        return None


def log_user_action(user_id, session_id, action):
    if not user_id or not session_id:
        print("[WARN] Missing user_id or session_id, skipping action log")
        return
    try:
        timestamp = datetime.utcnow()
        cursor = mysql.connection.cursor()
        cursor.execute('''
            INSERT INTO user_actions_log (user_id, session_id, action, timestamp)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, session_id, action, timestamp))
        mysql.connection.commit()
        cursor.close()
        print(f"[DEBUG] Action logged: {action} at {timestamp}")
    except Exception as e:
        print("[ERROR] Action log failed:", e)


@app.route('/export_activity_pdf')
@jwt_required
def export_activity_pdf():
    user_id = g.user['user_id']
    filter_type = request.args.get("filter", "all")

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    query = "SELECT * FROM user_session_activity WHERE user_id = %s"
    params = [user_id]

    if filter_type == "active":
        query += " AND logout_time IS NULL"
    elif filter_type == "revoked":
        query += " AND logout_time IS NOT NULL"
    elif filter_type.startswith("last_"):
        try:
            limit = int(filter_type.split("_")[1])
            query += " ORDER BY login_time DESC LIMIT %s"
            params.append(limit)
        except:
            pass
    else:
        query += " ORDER BY login_time DESC"

    cursor.execute(query, tuple(params))
    sessions = cursor.fetchall()

    # Fetch all related actions
    session_ids = [s['id'] for s in sessions]
    actions_by_session = {sid: [] for sid in session_ids}

    if session_ids:
        format_strings = ','.join(['%s'] * len(session_ids))
        cursor.execute(f"SELECT * FROM user_actions_log WHERE session_id IN ({format_strings}) ORDER BY timestamp",
                       tuple(session_ids))
        actions = cursor.fetchall()
        for action in actions:
            actions_by_session[action['session_id']].append(action)

    cursor.close()

    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"<b>Session Activity History</b>", styles['Title']))
    elements.append(Spacer(1, 0.3 * inch))

    for session in sessions:
        login = session['login_time']
        logout = session['logout_time'] or "Active Now"
        ip = session['ip_address']
        agent = session['user_agent']
        revoked_by = session.get('revoked_by', 'N/A')
        revoked_at = session.get('revoked_at', 'N/A')

        session_info = f"""
        <b>Session ID:</b> {session['id']}<br/>
        <b>Login Time:</b> {login} <br/>
        <b>Logout Time:</b> {logout} <br/>
        <b>IP Address:</b> {ip} <br/>
        <b>Device Info:</b> {agent} <br/>
        <b>Revoked By:</b> {revoked_by} <br/>
        <b>Revoked At:</b> {revoked_at} <br/>
        """
        elements.append(Paragraph(session_info, styles['Normal']))
        elements.append(Spacer(1, 0.1 * inch))

        # Actions for this session
        actions = actions_by_session.get(session['id'], [])
        if actions:
            elements.append(Paragraph("<b>Actions:</b>", styles['Heading4']))
            for a in actions:
                action_line = f"{a['timestamp']} — {a['action']}"
                elements.append(Paragraph(action_line, styles['Code']))
        else:
            elements.append(Paragraph("<i>No actions recorded for this session.</i>", styles['Italic']))

        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph("<hr/>", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name='session_activity.pdf', mimetype='application/pdf')


@app.route('/send_activity_email_token/<int:id>')
@jwt_required
def send_activity_email_token(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    token = serializer.dumps({'id': id}, salt='activity-verification')
    link = url_for('confirm_activity_access', token=token, _external=True)

    msg = Message(
        "[Cropzy] Session Activity Verification",
        sender=EMAIL_SENDER,
        recipients=[user['email']]
    )
    msg.body = f"Click to confirm access to session activity (valid for 5 minutes):\n\n{link}"
    mail.send(msg)

    flash("Verification email sent. Please check your inbox.", "info")
    return redirect(url_for('home'))


@app.route('/confirm_activity_access/<token>')
def confirm_activity_access(token):
    try:
        data = serializer.loads(token, salt='activity-verification', max_age=300)
        user_id = data['id']

        # Update user's verification timestamp in DB
        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE accounts SET activity_verified_at = %s WHERE id = %s
        """, (datetime.utcnow(), user_id))
        mysql.connection.commit()
        cursor.close()

        return render_template("accountPage/verification_success.html")

    except Exception:
        flash("Verification link expired or invalid.", "danger")
        return redirect(url_for('verify_before_activity'))


@app.route('/verification_success_message/<token>')
def verification_success_message(token):
    return render_template("accountPage/verification_success.html", token=token)


@app.route('/face_verify_activity/<int:id>', methods=['GET', 'POST'])
@jwt_required
def face_verify_activity(id):
    if request.method == 'POST':
        base64_img = request.form.get('face_image')
        if not base64_img or "," not in base64_img:
            flash("Face not captured.", "danger")
            return redirect(request.url)

        image_data = base64_img.split(",")[1]
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_verify_user_{id}.png")
        with open(temp_path, 'wb') as f:
            f.write(base64.b64decode(image_data))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT face FROM accounts WHERE id = %s", (id,))
        user_face_data = cursor.fetchone()
        cursor.close()

        if not user_face_data or not user_face_data['face']:
            flash("No registered face found.", "danger")
            return redirect(url_for('setup_face_id', id=id))

        registered_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{id}_face.png")
        with open(registered_path, 'wb') as f:
            f.write(user_face_data['face'])

        try:
            result = DeepFace.verify(
                img1_path=temp_path,
                img2_path=registered_path,
                model_name='VGG-Face',
                enforce_detection=False
            )
            os.remove(temp_path)
            os.remove(registered_path)

            if result["verified"]:
                cursor = mysql.connection.cursor()
                cursor.execute("""
                    UPDATE accounts SET activity_verified_at = %s WHERE id = %s
                """, (datetime.utcnow(), id))
                mysql.connection.commit()
                cursor.close()

                flash("Face verified. Access granted.", "success")
                return redirect(url_for('activity_history'))
            else:
                flash("Face does not match.", "danger")

        except Exception as e:
            flash(f"Face verification error: {str(e)}", "danger")

    return render_template("accountPage/face_id_activity.html", id=id)


@app.route('/verify_before_activity')
@jwt_required
def verify_before_activity():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('accountPage/verify_activity_choice.html', id=g.user['user_id'], user=user)


@app.route('/activity_history')
@jwt_required
def activity_history():
    user_id = g.user['user_id']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT activity_verified_at FROM accounts WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    cursor.close()

    if not result or not result['activity_verified_at']:
        return redirect(url_for('verify_before_activity'))

    last_verified = result['activity_verified_at']
    if (datetime.utcnow() - last_verified).total_seconds() > 300:
        # Clear it from DB
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE accounts SET activity_verified_at = NULL WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cursor.close()
        flash("Access expired. Please re-verify to view session activity.", "warning")
        return redirect(url_for('verify_before_activity'))

    time_left = 300 - int((datetime.utcnow() - last_verified).total_seconds())

    # --- Fetch session activity logic here ---
    filter_type = request.args.get("filter", "all")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    query = "SELECT * FROM user_session_activity WHERE user_id = %s"
    params = [user_id]

    if filter_type == "active":
        query += " AND logout_time IS NULL"
    elif filter_type == "revoked":
        query += " AND logout_time IS NOT NULL"
    elif filter_type.startswith("last_"):
        try:
            limit = int(filter_type.split("_")[1])
            query += " ORDER BY login_time DESC LIMIT %s"
            params.append(limit)
        except:
            pass
    else:
        query += " ORDER BY login_time DESC"

    cursor.execute(query, tuple(params))
    sessions = cursor.fetchall()
    cursor.close()

    for s in sessions:
        session_id = s['id']
        action_cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        action_cursor.execute("""
            SELECT * FROM user_actions_log
            WHERE session_id = %s
            ORDER BY timestamp ASC
        """, (session_id,))
        s['actions'] = action_cursor.fetchall()
        action_cursor.close()

    review_changes = session.pop('review_changes', None)

    return render_template("accountPage/activity.html",
                           sessions=sessions,
                           selected_filter=filter_type,
                           time_left=time_left,
                           review_changes=review_changes)


@app.route('/revoke_session/<session_id>', methods=['POST'])
@jwt_required
def revoke_session(session_id):
    current_user_id = g.user['user_id']
    current_user_status = g.user['status']  # 'admin' or 'user'

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get original session owner
    cursor.execute("SELECT user_id FROM user_session_activity WHERE id = %s", (session_id,))
    session_row = cursor.fetchone()

    if not session_row:
        flash("Session not found.", "danger")
        return redirect(url_for('activity_history'))

    session_owner_id = session_row['user_id']

    # Determine who revoked it
    revoked_by = 'self' if session_owner_id == current_user_id else current_user_status
    revoked_by_id = current_user_id
    revoked_at = datetime.utcnow()

    # Update the session row
    cursor.execute("""
        UPDATE user_session_activity
        SET logout_time = %s,
            revoked_by = %s,
            revoked_by_id = %s,
            revoked_at = %s
        WHERE id = %s
    """, (revoked_at, revoked_by, revoked_by_id, revoked_at, session_id))

    mysql.connection.commit()
    cursor.close()

    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')

    log_user_action(
        user_id=current_user_id,
        session_id=g.user.get('session_id'),
        action=f"Revoked an active session | Revoked by: {revoked_by} | IP: {ip_addr} | Agent: {user_agent}"
    )

    notify_user_action(
        to_email=g.user['email'],
        action_type="Revoked Session",
        item_name=f"You revoked a session from IP {ip_addr}"
    )

    flash("Session has been revoked successfully.", "success")
    return redirect(url_for('activity_history'))


@app.route('/check_session_validity')
def check_session_validity():
    token = request.cookies.get('jwt_token')
    if not token:
        return jsonify({"valid": False})

    user_data = verify_jwt_token(token)
    if not user_data:
        return jsonify({"valid": False})

    session_id = user_data.get('session_id')
    user_id = user_data.get('user_id')

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT logout_time FROM user_session_activity
        WHERE id = %s AND user_id = %s
    """, (session_id, user_id))
    result = cursor.fetchone()
    cursor.close()

    if result and result['logout_time']:
        return jsonify({"valid": False})

    return jsonify({"valid": True})

@app.route('/flag_session/<int:session_id>', methods=['POST'])
@jwt_required
def flag_session(session_id):
    user_id = g.user['user_id']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, user_id FROM user_session_activity WHERE id=%s", (session_id,))
    s = cursor.fetchone()
    if not s or s['user_id'] != user_id:
        cursor.close()
        flash("Session not found.", "danger")
        return redirect(request.referrer or url_for('accountHist'))

    reason = request.form.get('reason', 'OTHER')
    details = (request.form.get('details') or '').strip()

    cursor2 = mysql.connection.cursor()
    cursor2.execute("""
        INSERT INTO session_flags (session_id, user_id, reason, details)
        VALUES (%s,%s,%s,%s)
    """, (session_id, user_id, reason, details))
    mysql.connection.commit()
    cursor2.close()

    # fetch actions and detect
    cursor.execute("""
        SELECT action
        FROM user_actions_log
        WHERE session_id = %s
        ORDER BY timestamp DESC
    """, (session_id,))
    actions = [r['action'] for r in cursor.fetchall()]
    cursor.close()

    findings = detect_sensitive_changes(actions)
    if findings:
        session['review_changes'] = findings
        flash("We noticed important account changes in this session. Please review.", "warning")
        # IMPORTANT: go to the page that renders the modal
        return redirect(url_for('activity_history'))
    else:
        flash("Thanks—We’ve recorded your report for this session.", "success")
        # you can still go back to activity_history for consistency
        return redirect(url_for('activity_history'))



@app.route('/admin/session_flags')
@jwt_required
def view_session_flags():
    jwt_user = g.user
    if jwt_user['status'] not in ['admin']:
        return render_template('404glen.html')

    user_id = jwt_user['user_id']
    session_id = jwt_user['session_id']


    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT
            sf.id,
            sf.session_id,
            sf.user_id              AS flagged_user_id,
            sf.created_at           AS flagged_at,
            sf.details,             -- category: unknown_login / suspicious_activity / unrecognized_actions / other
            sf.reason,              -- free text
            a.first_name,
            a.last_name,
            a.email
        FROM session_flags sf
        JOIN accounts a ON a.id = sf.user_id
        ORDER BY sf.created_at DESC
    """)
    flags = cur.fetchall()
    cur.close()

    log_user_action(
        user_id=user_id,
        session_id=session_id,
        action="Viewed session flags"
    )

    notify_user_action(
        to_email=jwt_user['email'],
        action_type="Viewed Session Flags",
        item_name="Admin Session Flags Page"
    )

    return render_template( "/accountPage/admin_session_flags.html", flags=flags)

CHANGE_VERBS = [
    "change", "changed", "update", "updated", "set", "modified", "modify",
    "enable", "enabled", "disable", "disabled", "turn on", "turn off",
    "toggle", "reset", "register", "registered", "enroll", "enrolled",
    "save", "saved", "edit", "edited", "configure", "configured", "setup", "set up"
]

# verbs that imply no change (view-only)
VIEW_VERBS = ["view", "viewed", "access", "accessed", "open", "opened", "visit", "visited", "display", "displayed"]

# subjects we care about -> (keywords, label, endpoint)
SUBJECTS = [
    # Security
    (("2fa", "two factor", "two-factor"),         "2FA status changed",           "accountInfo"),
    (("password",),                                "Password changed",             "accountSecurity"),
    (("face id", "faceid", "biometric"),           "Face ID settings changed",     "accountInfo"),
    # Profile
    (("email",),                                   "Email changed",                "accountInfo"),
    (("phone", "phone number"),                    "Phone number changed",         "accountInfo"),
    (("first name", "last name", "full name", "name"), "Name changed",            "accountInfo"),
    (("gender",),                                  "Gender changed",               "accountInfo"),
    # Broad phrasing that your app might log
    (("profile", "account details", "account info"), "Profile details changed",    "accountInfo"),
]

def _contains_any(text, words):
    return any(w in text for w in words)

def detect_sensitive_changes(action_rows):
    """
    action_rows: list[str] of user_actions_log.action for a single session.
    Returns: list[{label, category?, endpoint}]  (category is derived from endpoint)
    """
    found = {}

    for raw in action_rows:
        line = (raw or "").lower()

        # quick skip for pure view lines
        if _contains_any(line, VIEW_VERBS) and not _contains_any(line, CHANGE_VERBS):
            continue

        # only consider lines with some change verb
        if not _contains_any(line, CHANGE_VERBS):
            continue

        for keys, label, endpoint in SUBJECTS:
            if _contains_any(line, keys):
                category = "Security" if endpoint == "accountSecurity" else "Profile"
                found[label] = {"label": label, "category": category, "endpoint": endpoint}

    return list(found.values())


@app.route('/verify-otp/<int:id>', methods=['GET', 'POST'])
def verify_otp(id):
    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)
    user_agent = request.headers.get('User-Agent')

    print(f"[DEBUG] OTP form submitted for user_id={id} at {datetime.now()}")

    # Ensure correct session state for 2FA
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    # ---- Session lifetime check (2 minutes max on 2FA page) ----
    started_at = session.get('pending_2fa_started_at')
    if not started_at or (time.time() - started_at) > 120:
        otp_store.pop(id, None)
        session.pop('pending_2fa_user_id', None)
        session.pop('pending_2fa_started_at', None)
        session.pop('pending_2fa_attempts', None)
        flash("Your verification session expired. Please login again.", "error")
        return redirect(url_for('login'))

    # Calculate remaining seconds for the UI timer
    remaining_seconds = max(0, 120 - int(time.time() - started_at))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        record = otp_store.get(id)

        if not record:
            flash("No OTP found. Please login again.", "error")
            return redirect(url_for('login'))

        # OTP expiration (separate from session lifetime)
        if time.time() > record['expires']:
            flash("OTP expired. Please login again.", "error")
            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_2fa_started_at', None)
            session.pop('pending_2fa_attempts', None)
            return redirect(url_for('login'))

        # ---- Track failed attempts ----
        attempts = session.get('pending_2fa_attempts', 0)

        if entered_otp == record['otp']:
            # Success: clear OTP/session markers
            otp_store.pop(id, None)
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_2fa_started_at', None)
            session.pop('pending_2fa_attempts', None)

            # Fetch user details
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
            user = cursor.fetchone()
            cursor.close()

            if not user:
                flash("User not found. Please login again.", "error")
                return redirect(url_for('login'))

            session_id = log_session_activity(user['id'], user['status'], 'login')

            payload = {
                'user_id': user['id'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'email': user['email'],
                'gender': user['gender'],
                'phone': user['phone_number'],
                'status': user['status'],
                'session_id': session_id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }

            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            response = make_response(redirect(url_for('home')))
            response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

            log_user_action(
                user_id=user['id'],
                session_id=session_id,
                action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
            )

            notify_user_action(
                to_email=user['email'],
                action_type="Login Success (2FA)",
                item_name=f"You logged in via OTP from IP {ip_addr} using {user_agent}."
            )

            flash("Login successful!", "success")
            return response

        else:
            # Wrong OTP
            attempts += 1
            session['pending_2fa_attempts'] = attempts

            if attempts >= 3:
                flash("Too many incorrect OTP attempts. Please login again.", "error")
                otp_store.pop(id, None)
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_started_at', None)
                session.pop('pending_2fa_attempts', None)
                return redirect(url_for('login'))

            flash(f"Invalid OTP. Attempt {attempts}/3.", "error")

    # On GET or after wrong OTP, render page with timer info
    return render_template('/accountPage/two_factor.html', id=id, remaining_seconds=remaining_seconds)


@app.route('/resend-otp/<int:id>', methods=['GET'])
def resend_otp(id):
    # Ensure only users in 2FA process can request resend
    if 'pending_2fa_user_id' not in session or session['pending_2fa_user_id'] != id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    # Fetch user info for email
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, email, first_name, last_name FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found. Please login again.", "error")
        return redirect(url_for('login'))

    # Send new OTP
    send_otp_email(user['email'], user['id'], user['first_name'], user['last_name'])
    session['pending_2fa_started_at'] = time.time()  # NEW
    session['pending_2fa_attempts'] = 0  # NEW
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp', id=id))


@app.route('/recovery_auth/<int:id>', methods=['GET', 'POST'])
def recovery_auth(id):
    if request.method == 'POST':
        input_code = request.form.get('recovery_code')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            stored_code = result['recovery_code']

            if input_code == stored_code:
                generate_recovery_code(id)

                # ✅ Only one log here
                session_id = log_session_activity(result['id'], result['status'], 'login')

                payload = {
                    'user_id': result['id'],
                    'first_name': result['first_name'],
                    'last_name': result['last_name'],
                    'email': result['email'],
                    'gender': result['gender'],
                    'phone': result['phone_number'],
                    'status': result['status'],
                    'session_id': session_id,
                    'exp': datetime.utcnow() + timedelta(hours=1)
                }

                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                response = make_response(redirect(url_for('home')))
                response.set_cookie('jwt_token', token, httponly=True, secure=True, samesite='Strict')

                hostname = socket.gethostname()
                ip_addr = socket.gethostbyname(hostname)
                user_agent = request.headers.get('User-Agent')
                # ✅ Use user action log instead of logging a new session
                log_user_action(
                    user_id=result['id'],
                    session_id=session_id,
                    action=f"Login successful (via 2FA) | IP: {ip_addr} | Agent: {user_agent}"
                )

                notify_user_action(
                    to_email=result['email'],
                    action_type="Login Success (Recovery Code)",
                    item_name=f"You logged in using a recovery code from IP {ip_addr} using {user_agent}."
                )

                flash('Recovery successful. You are now logged in.', 'success')
                return response

    return render_template('/accountPage/recovery_code.html', id=id)


@app.route('/logout')
def logout():
    token = request.cookies.get('jwt_token')
    session_id = None
    user_id = None

    if token:
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            session_id = data.get('session_id')
            user_id = data.get('user_id')
        except:
            pass

    if session_id and user_id:
        cursor = mysql.connection.cursor()
        cursor.execute('''
            UPDATE user_session_activity
            SET logout_time = NOW()
            WHERE id = %s AND user_id = %s
        ''', (session_id, user_id))
        mysql.connection.commit()
        cursor.close()

    log_user_action(
        user_id=user_id,
        session_id=session_id,
        action="User logged out"
    )

    response = make_response(redirect(url_for('login')))
    response.delete_cookie('jwt_token')
    flash('You have been logged out.', 'success')
    return response


@app.route('/complete_signUp')
def complete_signUp():
    return render_template('/accountPage/complete_signUp.html')


@app.route('/changeDets/<int:id>/', methods=['GET', 'POST'])
def change_dets(id):
    change_dets_form = ChangeDetForm(request.form)

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        cursor.close()
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_dets_form.validate():
        entered_password = change_dets_form.pswd.data
        stored_password_hash = user['password']  # assuming this is hashed

        # Check current password before updating
        if user:
            stored_password = user['password']

            # Update database with new user details
            cursor.execute('''
                UPDATE accounts
                SET first_name = %s,
                    last_name = %s,
                    gender = %s,
                    phone_number = %s,
                    email = %s
                WHERE id = %s
            ''', (
                change_dets_form.first_name.data,
                change_dets_form.last_name.data,
                change_dets_form.gender.data,
                change_dets_form.number.data,
                change_dets_form.email.data,
                id
            ))

            mysql.connection.commit()

            if 'user_id' in session:
                log_user_action(session['user_id'], session.get('current_session_id'), "Changed account details")

            notify_user_action(
                to_email=change_dets_form.email.data,
                action_type="Account Update",
                item_name="Your account details were updated successfully."
            )

            cursor.close()

            # Update session
            session['first_name'] = change_dets_form.first_name.data
            session['last_name'] = change_dets_form.last_name.data
            session['gender'] = change_dets_form.gender.data
            session['phone'] = change_dets_form.number.data
            session['email'] = change_dets_form.email.data

        flash("Details updated successfully!", "success")
        return redirect(url_for('accountInfo'))

    # Pre-fill form fields from the DB
    change_dets_form.first_name.data = user['first_name']
    change_dets_form.last_name.data = user['last_name']
    change_dets_form.gender.data = user['gender']
    change_dets_form.number.data = user['phone_number']
    change_dets_form.email.data = user['email']

    cursor.close()
    return render_template('/accountPage/changeDets.html', form=change_dets_form)


@app.route('/changePswd/<int:id>/', methods=['GET', 'POST'])
@jwt_required
def change_pswd(id):
    change_pswd_form = ChangePswdForm(request.form)
    user_id = g.user['user_id']  # ✅ Get from JWT

    user_id = session.get('user_id')
    if not user_id or user_id != id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user = cursor.fetchone()

    if not user:
        flash("User not found!", "danger")
        cursor.close()
        return redirect(url_for('accountInfo'))

    if request.method == 'POST' and change_pswd_form.validate():
        current_pswd = change_pswd_form.current_pswd.data
        new_pswd = change_pswd_form.new_pswd.data
        confirm_pswd = change_pswd_form.confirm_pswd.data

        # Using plaintext comparison (insecure; follow your current code pattern)
        if user['password'] != current_pswd:
            flash("Incorrect current password.", "danger")
            cursor.close()
            return redirect(url_for('change_pswd', id=id))

        if new_pswd != confirm_pswd:
            flash("New passwords do not match.", "danger")
            cursor.close()
            return redirect(url_for('change_pswd', id=id))

        # Update new password in the DB (still plaintext)

        mysql.connection.commit()
        cursor.close()

        # ✅ Log user action
        log_user_action(user_id, session.get('current_session_id'), "Changed password")

        notify_user_action(
            to_email=user['email'],
            action_type="Password Change",
            item_name="Your password has been successfully changed. If this wasn't you, reset your password immediately."
        )
        # Update session value too
        session['password'] = confirm_pswd

        flash("Password changed successfully!", "success")
        return redirect(url_for('accountInfo'))

    return render_template('/accountPage/changePswd.html', form=change_pswd_form)


@app.route('/deleteMyAccount/<int:id>', methods=['POST'])
@jwt_required
def delete_user(id):
    current_user = g.user

    if current_user['user_id'] != id:
        flash("You are not authorized to delete this account.", "danger")
        return redirect(url_for('accountInfo'))

    recaptcha_response = request.form.get('g-recaptcha-response')
    if not recaptcha_response:
        flash("Please complete the CAPTCHA.", "danger")
        return redirect(url_for('accountInfo'))

    verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
        'response': recaptcha_response
    }
    response = requests.post(verify_url, data=payload).json()
    if not response.get('success'):
        flash("CAPTCHA verification failed. Please try again.", "danger")
        return redirect(url_for('accountInfo'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()

    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"User deleted own account (ID: {id})"
    )
    flash("Your account has been deleted successfully!", "success")
    return redirect(url_for('logout'))

@app.route('/deleteUser/<int:id>', methods=['POST'])
@jwt_required
def admin_delete_user(id):
    current_user = g.user
    if current_user['status'] != 'admin':
        flash("You are not authorized to delete this account.", "danger")
        return redirect(url_for('accountInfo'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (id,))
    user_to_delete = cursor.fetchone()

    if not user_to_delete:
        cursor.close()
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM accounts WHERE id = %s", (id,))
    mysql.connection.commit()
    cursor.close()

    log_user_action(
        user_id=current_user['user_id'],
        session_id=current_user['session_id'],
        action=f"Admin deleted user account (ID: {id})"
    )
    flash("User account deleted successfully.", "success")
    return redirect(url_for('dashboard'))

@app.route("/create_update", methods=['GET', 'POST'])
@jwt_required
def create_update():
    form = SeasonalUpdateForm()
    site_key = os.getenv("RECAPTCHA_SITE_KEY")

    if form.validate_on_submit():
        # reCAPTCHA validation
        recaptcha_response = request.form.get('g-recaptcha-response')
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            'secret': os.getenv("RECAPTCHA_SECRET_KEY"),
            'response': recaptcha_response
        })
        if not r.json().get('success'):
            flash("reCAPTCHA failed.", "danger")
            return render_template('/home/update.html', form=form, site_key=site_key)

        # Decode JWT
        token = request.cookies.get('jwt_token')
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id, user_email = decoded['user_id'], decoded['email']
            session_id = decoded.get('session_id')
        except:
            flash("Invalid session token.", "danger")
            return redirect(url_for('login'))

        # Save pending update
        update_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data
        }

        pending_id = str(uuid.uuid4())
        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending = db.get('pending_updates', {})
            pending[pending_id] = {
                'user_id': user_id,
                'session_id': session_id,
                'email': user_email,  # ensure this is stored
                'update_data': update_data
            }
            db['pending_updates'] = pending

        # Send verification email
        send_create_verification_email(user_email, pending_id)

        flash("A verification email has been sent. Please confirm to complete your update.", "info")
        return redirect(url_for('home'))

    return render_template('/home/update.html', title='Create Update', form=form, site_key=site_key, is_edit=False)


def send_create_verification_email(email, pending_id):
    token = serializer.dumps({'pending_id': pending_id}, salt='create-update-verification')
    confirm_url = url_for('finalize_create', token=token, _external=True)

    msg = Message("[Cropzy] Confirm Your Seasonal Update", sender=EMAIL_SENDER, recipients=[email])
    msg.body = f"""Hello,

You recently attempted to create a seasonal update on Cropzy.

Please confirm your identity by clicking the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this, you can ignore this email.
"""
    mail.send(msg)


@app.route('/finalize_create/<token>')
def finalize_create(token):
    try:
        data = serializer.loads(token, salt='create-update-verification', max_age=300)
        pending_id = data.get('pending_id')

        if not pending_id:
            flash("Invalid or expired token.", "danger")
            return redirect(url_for('home'))

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending = db.get('pending_updates', {})
            entry = pending.pop(pending_id, None)
            db['pending_updates'] = pending

            if not entry:
                flash("This update has already been confirmed or expired.", "warning")
                return redirect(url_for('home'))

            updates = db.get('updates', [])
            updates.append(entry['update_data'])
            db['updates'] = updates

        log_user_action(
            user_id=entry['user_id'],
            session_id=entry['session_id'],
            action=f"Confirmed and created seasonal update: {entry['update_data']['title']}"
        )

        notify_user_action(
            to_email=entry['email'],
            action_type="Created Seasonal Update",
            item_name=entry['update_data']['title']
        )

        return redirect(url_for('home'))

    except Exception as e:
        flash("Something went wrong or the link has expired.", "danger")
        return redirect(url_for('home'))


@app.route('/delete_update/<int:index>', methods=['POST'])
@jwt_required
def delete_update(index):
    # Save index in session and send email
    session['delete_pending_index'] = index

    token = serializer.dumps({
        'user_id': g.user['user_id'],
        'email': g.user['email']
    }, salt='delete-update-verification')

    confirm_url = url_for('finalize_delete', token=token, _external=True)

    msg = Message("[Cropzy] Confirm Deletion of Update", sender=EMAIL_SENDER, recipients=[g.user['email']])
    msg.body = f"""Hello,

You requested to delete one of your seasonal updates on Cropzy.

To confirm this deletion, please click the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this action, you can safely ignore this message.
"""
    mail.send(msg)

    flash("Verification email sent. Please confirm to delete the update.", "info")
    return redirect(url_for('home'))


@app.route('/finalize_delete/<token>')
def finalize_delete(token):
    try:
        data = serializer.loads(token, salt='delete-update-verification', max_age=300)
        user_id = data['user_id']
        user_email = data['email']
        index = session.pop('delete_pending_index', None)

        if index is None:
            flash("No pending deletion found or session expired.", "warning")
            return redirect(url_for('home'))

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            updates = db.get('updates', [])
            if 0 <= index < len(updates):
                removed = updates.pop(index)
                db['updates'] = updates

                log_user_action(user_id, session.get('current_session_id'),
                                f"Deleted seasonal update: {removed['title']}")

                # ✅ Send email notification
                notify_user_action(
                    to_email=user_email,
                    action_type="Deleted Seasonal Update",
                    item_name=removed['title']
                )

                flash(f"Update \"{removed['title']}\" deleted successfully!", "success")
            else:
                flash("Invalid update index.", "danger")

    except Exception:
        flash("Verification link expired or invalid.", "danger")

    return redirect(url_for('home'))


@app.route('/edit_update/<int:index>', methods=['GET', 'POST'])
@jwt_required
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
        # Save the edit temporarily
        edited_data = {
            'title': form.update.data,
            'content': form.content.data,
            'date': form.date.data.strftime('%d-%m-%Y'),
            'season': form.season.data
        }

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            db['pending_edits'] = db.get('pending_edits', {})
            db['pending_edits'][str(index)] = {
                'user_id': g.user['user_id'],
                'session_id': g.user.get('session_id'),
                'data': edited_data
            }

        # Send verification email
        token = serializer.dumps({
            'user_id': g.user['user_id'],
            'index': index,
            'email': g.user['email']
        }, salt='edit-update-verification')

        confirm_url = url_for('finalize_edit', token=token, _external=True)

        msg = Message(
            "[Cropzy] Confirm Edit of Seasonal Update",
            sender=EMAIL_SENDER,
            recipients=[g.user['email']]
        )
        msg.body = f"""Hello,

You attempted to edit a seasonal update on Cropzy.

To confirm and apply your edit, click the link below (valid for 5 minutes):
{confirm_url}

If you did not initiate this, you may ignore this message.
"""
        mail.send(msg)

        flash("Edit submitted. Please confirm via the email sent to you.", "info")
        return redirect(url_for('home'))

    # Pre-fill the form with current update data
    form.update.data = update.get('title', '')
    form.content.data = update.get('content', '')
    form.date.data = datetime.strptime(update.get('date', '01-01-2025'), '%d-%m-%Y')
    form.season.data = update.get('season', '')

    return render_template('/home/update.html', title='Edit Update', form=form, is_edit=True, index=index)


@app.route('/finalize_edit/<token>')
def finalize_edit(token):
    try:
        data = serializer.loads(token, salt='edit-update-verification', max_age=300)
        user_id = data['user_id']
        user_email = data['email']
        index = str(data['index'])

        with shelve.open('seasonal_updates.db', writeback=True) as db:
            pending_edits = db.get('pending_edits', {})
            updates = db.get('updates', [])

            if index not in pending_edits:
                flash("No pending edit found or already confirmed.", "warning")
                return redirect(url_for('home'))

            edit_entry = pending_edits.pop(index)
            db['pending_edits'] = pending_edits

            if 0 <= int(index) < len(updates):
                updates[int(index)] = edit_entry['data']
                db['updates'] = updates

                log_user_action(
                    user_id,
                    edit_entry['session_id'],
                    f"Edited seasonal update: {edit_entry['data']['title']}"
                )

                # ✅ Send confirmation notification
                notify_user_action(
                    to_email=user_email,
                    action_type="Edited Seasonal Update",
                    item_name=edit_entry['data']['title']
                )

                flash("Update successfully edited.", "success")
            else:
                flash("Invalid update index.", "danger")

    except Exception:
        flash("Verification link is invalid or expired.", "danger")

    return redirect(url_for('home'))


@app.route('/request_delete/<int:index>', methods=['GET'])
@jwt_required
def request_delete(index):
    with shelve.open('seasonal_updates.db') as db:
        updates = db.get('updates', [])
        if 0 <= index < len(updates):
            update = updates[index]

            if 'user_id' in session:
                log_user_action(
                    session['user_id'],
                    session.get('current_session_id'),
                    f'Requested delete confirmation for seasonal update: {update["title"]}'
                )

            return render_template('/home/confirm_delete.html', update=update, index=index)
        else:
            flash('Invalid update index.', 'danger')
            return redirect(url_for('home'))


@app.route('/update_cart', methods=['POST'])
def update_cart():
    product_id = request.form.get("product_id")
    action = request.form.get("action")
    cart = session.get("cart", {})

    if product_id in cart:
        if action == "increase":
            cart[product_id]['quantity'] += 1
        elif action == "decrease":
            cart[product_id]['quantity'] -= 1
            if cart[product_id]['quantity'] <= 0:
                del cart[product_id]

    session["cart"] = cart  # update session cart
    session.modified = True  # save changes

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action=f"Updated cart: Product ID {product_id}, Action {action}"
        )

    return redirect(url_for('buy_product'))


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    cart = session.get("cart", {})

    product = Product.query.get(product_id)
    if not product:
        flash("❌ Product not found!", "danger")
        return redirect(url_for('buy_product'))

    if str(product_id) in cart:
        cart[str(product_id)]['quantity'] += 1
    else:
        cart[str(product_id)] = {
            "name": product.name,
            "price": float(product.price),
            "image": url_for('static', filename='uploads/' + (product.image_filename or 'default.jpg')),
            # ✅ Include Image
            "quantity": 1
        }

    session["cart"] = cart
    session["show_cart"] = True
    session.modified = True

    flash(f"✅ {product.name} added to cart!", "success")

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action=f"Added to cart: {product.name} (ID {product.id})"
        )

    return redirect(url_for('buy_product'))


@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    session["cart"] = {}
    session.modified = True
    flash("🛒 Cart cleared!", "info")

    if 'user_id' in session:
        log_user_action(
            user_id=session['user_id'],
            session_id=session.get('current_session_id'),
            action="Cleared shopping cart"
        )

    return redirect(url_for('buy_product'))


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    cart = session.get("cart", {})

    if not cart:
        return redirect(url_for('buy_product'))

    session["customer"] = {
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "phone": request.form.get("phone"),
        "address_line1": request.form.get("address_line1"),
        "address_line2": request.form.get("address_line2"),
        "province": request.form.get("province"),
        "postal_code": request.form.get("postal_code"),
    }
    session.modified = True

    line_items = [
        {
            "price_data": {
                "currency": "usd",
                "product_data": {"name": item["name"]},
                "unit_amount": int(item["price"] * 100),
            },
            "quantity": item["quantity"],
        }
        for item in cart.values()
    ]

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="payment",
            customer_email=request.form.get("email"),
            success_url=url_for('thank_you', _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for('checkout', _external=True),
        )
        return redirect(checkout_session.url)
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route('/checkout', methods=['GET'])
@login_required
def checkout():
    cart = session.get("cart", {})  # Get cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())  # Calculate total price

    return render_template('/checkout/checkout.html', cart=cart, total_price=total_price)


def notify_user_action(to_email, action_type, item_name=None, details=None):
    """
    Send a general-purpose email notification to the user.

    Parameters:
    - to_email: Recipient's email address.
    - action_type: What action occurred (e.g., "Deleted Product", "Edited Update").
    - item_name: Optional name/title of the item involved.
    - details: Optional extra details to include in the email.
    """
    try:
        subject = f"[Cropzy] {action_type}"
        message = f"The following action was performed on your Cropzy account:\n\n"
        message += f"Action: {action_type}\n"

        if item_name:
            message += f"Item: {item_name}\n"

        if details:
            message += f"Details: {details}\n"

        message += f"\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        message += "\nIf you did not authorize this action, please contact support immediately.\n\n- Cropzy Team"

        # Construct and send email
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(app.config['MAIL_USERNAME'], to_email, msg.as_string())
        server.quit()

        print(f"[DEBUG] Notification sent to {to_email}")

    except Exception as e:
        print(f"[ERROR] Failed to send notification: {e}")


def send_email(to_email, subject, message):
    """Send an email using SMTP."""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        server.quit()
        print(f"Email sent successfully to {to_email}")

    except Exception as e:
        print(f"❌ Email failed to send: {e}")


@app.route('/thank_you')
def thank_you():
    session_id = request.args.get('session_id')
    if not session_id:
        return "Invalid request", 400

    try:
        stripe_session = stripe.checkout.Session.retrieve(session_id)

        if stripe_session.payment_status == "paid":
            order = session.get("cart", {})
            customer = session.get("customer", {})
            total_price = sum(item['price'] * item['quantity'] for item in order.values())
            order_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            transaction_id = str(uuid.uuid4())[:6]  # Generate a random transaction ID

            if "transactions" not in session:
                session["transactions"] = []

            session["transactions"].append({
                "id": transaction_id,
                "user_id": session.get("user_id"),  # Store the logged-in user ID
                "name": customer.get("name", "N/A"),
                "email": customer.get("email", "N/A"),
                "total": total_price,
                "date": order_date,
                "products": [
                    {
                        "product_name": item["name"],
                        "price": item["price"],
                        "quantity": item["quantity"]
                    }
                    for item in order.values()
                ]
            })
            session.modified = True

            if 'user_id' in session:
                log_user_action(
                    user_id=session['user_id'],
                    session_id=session.get('current_session_id'),
                    action=f"Completed purchase - Transaction ID: {transaction_id}, Total: ${total_price}"
                )

            # send confirmation email
            if customer.get("email"):
                email_subject = "Order Confirmation"
                email_message = f"""
                Thank you for your purchase, {customer.get('name', 'Customer')}!\n
                Transaction ID: {transaction_id}
                Total Price: ${total_price}
                Date: {order_date}
                """
                send_email(customer.get("email"), email_subject, email_message)

            # clear cart after payment
            session.pop("cart", None)
            session.pop("customer", None)

            return render_template('checkout/thanks.html', order=order, customer=customer,
                                   total_price=total_price, order_date=order_date,
                                   transaction_id=transaction_id)
        else:
            return "Payment not confirmed", 400
    except Exception as e:
        return f"Error retrieving session: {str(e)}", 500


@app.route('/transactions', methods=['GET'])
def transactions():
    transactions = session.get("transactions", [])  # Get transaction history from session

    # Search Filter (If user enters a search term)
    search_query = request.args.get("search", "").strip().lower()
    if search_query:
        transactions = [t for t in transactions if search_query in t["id"].lower() or search_query in t["name"].lower()]

    return render_template('checkout/transaction.html', transactions=transactions, search_query=search_query)


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    cart = session.get("cart", {})  # Retrieve cart from session
    total_price = sum(item["price"] * item["quantity"] for item in cart.values())  # Calculate total price

    return render_template('/checkout/cart.html', cart=cart, total_price=total_price)


@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')

    if not user_message:
        return jsonify({'response': "Please provide a message!"})

    bot_response = generate_response(user_message)
    return jsonify({'response': bot_response})


def send_reset_pass(email, user_id):
    try:
        token = secrets.token_urlsafe(32)
        sg_time = datetime.utcnow() + timedelta(hours=8)
        expires_at = sg_time + timedelta(minutes=1)

        # Store token in DB
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO password_resets (email, token, expires_at) VALUES (%s, %s, %s)",
            (email, token, expires_at))
        mysql.connection.commit()
        cursor.close()

        # Construct URL
        reset_url = url_for('reset_password', token=token, _external=True)
        subject = "[Cropzy] Reset Your Password"
        message = (
            f"Hi,\n\n"
            f"We received a request to reset your password. You can reset it by clicking the link below:\n\n"
            f"{reset_url}\n\n"
            f"This link will expire in 10 minutes.\n\n"
            f"Thanks,\nCropzy Support")
        send_email(email, subject, message)

    except Exception as e:
        print(f"[ERROR] Failed to send reset password email: {e}")


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPassRequest(request.form)

    if request.method == 'POST' and form.validate():
        email = form.email.data  # Define this helper to fetch user_id
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            send_reset_pass(email, user[0])

        # Always show same message regardless
        flash("If an account with that email exists, a reset link has been sent.", "info")

    return render_template("accountPage/reset_pass_request.html", form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPass(request.form)
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT email, expires_at FROM password_resets WHERE token = %s", (token,))
    row = cursor.fetchone()

    if not row:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('reset_password_request'))

    email, expires_at = row
    if datetime.now() > expires_at:
        flash("Reset link has expired.", "danger")
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST' and form.validate():
        new_password = form.new_pswd.data
        confirm_password = form.confirm_pswd.data

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token, _external=True))
        else:
            hashed_pw = hash_password(new_password)
            cursor.execute("UPDATE accounts SET password = %s WHERE email = %s", (hashed_pw, email))
            cursor.execute("DELETE FROM password_resets WHERE token = %s", (token,))
            mysql.connection.commit()
            cursor.close()

        flash("Password reset successfully.", "success")
        return redirect(url_for('login'))

    cursor.close()
    return render_template("accountPage/reset_pass.html", form=form)


@app.after_request
def set_clickjacking_protection(response):
    # Endpoints allowed to be embedded inside iframes from same-origin
    allowed_iframe_endpoints = {'ip_heatmap'}

    if request.endpoint in allowed_iframe_endpoints:
        # allow only same-origin dashboard to embed the heatmap
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self';"
    else:
        # keep strict defaults everywhere else
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'none';"
    return response


@app.route('/freeze_account/<int:user_id>', methods=['POST'])
def freeze_account(user_id):
    cursor = mysql.connection.cursor()

    cursor.execute(
        "INSERT INTO frozen_account (user_id, reason, frozen_at, is_frozen) VALUES (%s, %s, NOW(), TRUE)",
        (user_id, 'Manual freeze by user'))

    mysql.connection.commit()
    cursor.close()
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('jwt_token')
    flash("Account has been frozen.", "danger")

    return response  # Or wherever you're managing users


def is_account_frozen(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT is_frozen FROM frozen_account WHERE user_id = %s ORDER BY frozen_at DESC LIMIT 1",
                   (user_id,))
    freeze_entry = cursor.fetchone()
    cursor.close()

    # Return True if most recent freeze entry exists and is active
    return freeze_entry and freeze_entry['is_frozen'] == True


# Helper: Send Unfreeze Email
def send_unfreeze_email(user_id, email):
    try:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=1)

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO unfreeze_requests (user_id, token, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, token, expires_at))
        mysql.connection.commit()

        unfreeze_url = url_for('unfreeze_account', token=token, _external=True)
        subject = "[Cropzy] Unfreeze Your Account"
        message = (
            f"Hi,\n\n"
            f"Your account was frozen. To unfreeze it, please click the link below:\n\n"
            f"{unfreeze_url}\n\n"
            f"This link will expire in 10 minutes.\n\n"
            f"Best,\nCropzy Support"
        )
        send_email(email, subject, message)

    except Exception as e:
        print(f"[ERROR] Failed to send unfreeze email: {e}")


@app.route('/unfreeze/<token>')
def unfreeze_account(token):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM unfreeze_requests WHERE token = %s", (token,))
    request_row = cursor.fetchone()

    if not request_row:
        flash("Invalid or expired unfreeze link.", "danger")
        return redirect(url_for('login'))

    if datetime.utcnow() > request_row['expires_at']:
        flash("This unfreeze link has expired.", "danger")
        return redirect(url_for('login'))

    user_id = request_row['user_id']
    cursor.execute("UPDATE frozen_account SET is_frozen = FALSE WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM unfreeze_requests WHERE token = %s", (token,))
    mysql.connection.commit()
    cursor.close()

    flash("Your account has been unfrozen. You can now log in.", "success")
    return redirect(url_for('login'))


@app.route('/send_unfreeze_email', methods=['POST'])
def ajax_send_unfreeze_email():
    user_id = request.args.get('user_id')  # or from request.json

    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not logged in.'}), 403

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    send_unfreeze_email(user_id, user['email'])
    return jsonify({'status': 'success', 'message': 'Unfreeze email sent.'})


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("errors/429.html", error=str(e)), 429

@app.route('/404_NOT_FOUND')
def notfound():
    return render_template('404.html')

if __name__ == "__main__":
    generate_self_signed_cert()

    app.run(ssl_context=("certs/cert.pem", "certs/key.pem"), host="127.0.0.1", port=443, debug=True)
