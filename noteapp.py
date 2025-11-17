"""
Notes App with Google OAuth, Email OTP Verification, Notes CRUD and JWT integration
Author: Your Name
"""

# ================= Standard Library Imports ================= #
import os
import random
import pathlib
import sqlite3
from datetime import timedelta

# ================= Third-Party Imports ================= #
import requests
from flask import (
    Flask, render_template, request, redirect,
    session, flash, abort, make_response
)
from flask_mail import Mail, Message
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

# JWT
from flask_jwt_extended import (
    JWTManager, create_access_token,
    verify_jwt_in_request, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)


# ================= Flask App Initialization ================= #
app = Flask(__name__)
app.secret_key = "supersecretkey"  # move to env var in prod

# ---------------- Flask-Mail Configuration ---------------- #
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME="patelshiv2018@gmail.com",   # your Gmail (move to env)
    MAIL_PASSWORD="nmlbkibaefkzptni",          # app password (move to env)
    MAIL_DEFAULT_SENDER="patelshiv2018@gmail.com"
)
mail = Mail(app)

# ---------------- Google OAuth Configuration ---------------- #
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = (
    "209387052955-6hcf31lqld7dobsssbvinhn6fnta02cu.apps.googleusercontent.com"
)
client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent,
    "client_secret.json"
)

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# ---------------- JWT Configuration ---------------- #
# NOTE: Move JWT_SECRET_KEY to env var for production.
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "superjwtsecret")
# We'll store tokens in cookies for this web app so browser can hold them.
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
# For local dev set Secure False; in production set True and use HTTPS
app.config['JWT_COOKIE_SECURE'] = False
# Path for access cookie
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
# For simplicity in this example, disable cookie CSRF. In prod, enable CSRF protection.
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
# Token lifetime (adjust as needed)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

jwt = JWTManager(app)


# ================= Middleware ================= #
@app.after_request
def add_header(response):
    """Disable caching for security."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ================= Helper functions for auth ================= #
def get_current_userid():
    """
    Return logged-in user id from session or from a valid JWT.
    Returns None if neither exists / valid.
    """
    # 1) Prefer session (keeps your current behavior)
    userid = session.get('userid')
    if userid:
        return userid

    # 2) Otherwise, try JWT in cookies (or header)
    try:
        # optional=True to avoid raising if no token
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            # we store identity as the numeric user id
            return identity
    except Exception:
        pass

    return None


# ================= Google OAuth Routes ================= #
@app.route("/google_login")
def google_login():
    """Redirect user to Google login page."""
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="select_account"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    """Handle Google OAuth callback."""
    flow.fetch_token(authorization_response=request.url)

    if session.get("state") != request.args.get("state"):
        abort(500)  # State does not match

    # Get user info from Google
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    google_id = id_info.get("sub")
    username = id_info.get("name")
    email = id_info.get("email")

    # Save to session
    session.update({
        "google_id": google_id,
        "username": username,
        "email": email
    })

    # Insert into database if new user
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM register WHERE email=?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.execute(
            "INSERT INTO register (username, email, password) VALUES (?, ?, ?)",
            (username, email, "1234")  # default password for Google users
        )
        conn.commit()
        user_id = cursor.lastrowid
    else:
        user_id = user[0]

    session["userid"] = user_id
    conn.close()

    # Create JWT access token and set as cookie
    access_token = create_access_token(identity=user_id)
    resp = redirect("/display")
    set_access_cookies(resp, access_token)
    return resp


# ================= Auth & User Routes ================= #
@app.route("/")
def home_page():
    return render_template("home.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login_user", methods=["POST"])
def login_user():
    """Login with email and password."""
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password FROM register WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and user[2] == password:
        # keep session behavior
        session.update({"email": email, "userid": user[0]})

        # create JWT and set cookie
        access_token = create_access_token(identity=user[0])
        resp = redirect("/display")
        set_access_cookies(resp, access_token)
        return resp
    else:
        flash("Invalid email or password!", "danger")
        return redirect("/login")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/register_user", methods=["POST"])
def register_user():
    """Register user and send OTP."""
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    # Check if email already exists
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM register WHERE email=?", (email,))
    existing_user = cursor.fetchone()
    conn.close()

    if existing_user:
        flash("⚠️ This email is already registered. Please login instead.", "warning")
        return redirect("/register")

    # Generate and save OTP
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['temp_user'] = {"username": username, "email": email, "password": password}

    # Send OTP email
    try:
        msg = Message("Your OTP Verification Code", recipients=[email])
        msg.body = f"Hello {username},\n\nYour OTP is {otp}. It is valid for 5 minutes.\n\nThanks!"
        mail.send(msg)
        flash("OTP has been sent to your email!", "info")
    except Exception as e:
        print("❌ Email sending failed:", e)
        flash("Could not send OTP email. Please check email config.", "danger")
        print("👉 Your OTP (testing mode):", otp)  # Debug

    return render_template("register.html", otp_sent=True, username=username, email=email, password=password)


@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    """Verify OTP and save user in DB."""
    user_otp = request.form['otp']

    if session.get("otp") == user_otp:
        user = session['temp_user']
        conn = sqlite3.connect("notes.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO register (username, email, password) VALUES (?, ?, ?)",
            (user['username'], user['email'], user['password'])
        )
        conn.commit()
        conn.close()

        session.pop("otp", None)
        session.pop("temp_user", None)

        flash("Registration successful! Please login.", "success")
        return redirect("/login")
    else:
        flash("Invalid OTP. Please try again.", "danger")
        return render_template("register.html", otp_sent=True)


@app.route("/resetpassword")
def reset_password():
    return render_template("resetpassword.html")


@app.route("/reset_password", methods=["POST"])
def resetpassword():
    """Reset user password."""
    email = request.form['email']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        flash("❌ Passwords do not match. Please try again.", "danger")
        return redirect("/resetpassword")

    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM register WHERE email=?", (email,))
    user = cursor.fetchone()

    if user:
        cursor.execute("UPDATE register SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        flash("Password reset successful! Please login.", "success")
        redirect_url = "/login"
    else:
        flash("No account found with that email.", "danger")
        redirect_url = "/resetpassword"

    conn.close()
    return redirect(redirect_url)


@app.route("/logout")
def logout():
    # Clear session and remove JWT cookie
    session.clear()
    resp = redirect("/login")
    unset_jwt_cookies(resp)
    flash("Logged out successfully!", "info")
    return resp


# ================= Notes CRUD ================= #
def get_notes_for_user(userid):
    """Fetch notes for the given user id."""
    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, topic, notes FROM note1 WHERE user_id=?", (userid,))
    rows = cursor.fetchall()
    conn.close()
    return rows


@app.route("/display")
def display_notes():
    """Display all notes."""
    userid = get_current_userid()
    if not userid:
        return redirect("/login")
    notes = get_notes_for_user(userid)
    return render_template("notes.html", notes=notes)


@app.route("/submit", methods=["POST"])
def add_note():
    """Add new note."""
    userid = get_current_userid()
    if not userid:
        return redirect("/login")

    topic = request.form['topic']
    notes = request.form['note']

    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO note1 (topic, notes, user_id) VALUES (?, ?, ?)", (topic, notes, userid))
    conn.commit()
    conn.close()
    return redirect("/display")


@app.route("/delete/<int:id>", methods=["POST"])
def delete(id):
    """Delete a note by ID (only if owned by the user)."""
    userid = get_current_userid()
    if not userid:
        return redirect("/login")

    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()
    # delete only if note belongs to this user
    cursor.execute("DELETE FROM note1 WHERE id=? AND user_id=?", (id, userid))
    conn.commit()
    conn.close()
    return redirect("/display")


@app.route("/update/<int:id>", methods=["GET", "POST"])
def update(id):
    """Update a note by ID (only if owned by the user)."""
    userid = get_current_userid()
    if not userid:
        return redirect("/login")

    conn = sqlite3.connect("notes.db")
    cursor = conn.cursor()

    if request.method == "POST":
        topic = request.form["topic"]
        notes = request.form["note"]
        # update only if note belongs to this user
        cursor.execute("UPDATE note1 SET topic=?, notes=? WHERE id=? AND user_id=?", (topic, notes, id, userid))
        conn.commit()
        conn.close()
        return redirect("/display")
    else:
        # fetch only if note belongs to this user
        cursor.execute("SELECT id, topic, notes FROM note1 WHERE id=? AND user_id=?", (id, userid))
        note = cursor.fetchone()
        conn.close()
        if not note:
            flash("Note not found or you do not have permission to edit it.", "danger")
            return redirect("/display")
        return render_template("update.html", note=note)


# ================= Run App ================= #
if __name__ == "__main__":
    app.run(debug=True)
