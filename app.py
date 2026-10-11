from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from datetime import datetime
import sqlite3
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "local-development-key-change-before-deployment"

# File upload configuration
UPLOAD_FOLDER = os.path.join(app.root_path, "user_uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB maximum

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Connect to the SQLite database
def get_db_connection():
    connection = sqlite3.connect("securevault.db")
    connection.row_factory = sqlite3.Row
    return connection


# Create the users table if it doesn't exist
def initialize_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# Homepage
@app.route("/")
def home():
    return render_template("index.html")


# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to access your dashboard.", "error")
        return redirect(url_for("login"))

    connection = get_db_connection()

    try:
        user = connection.execute(
            "SELECT username, email, created_at FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()
    finally:
        connection.close()

    if user is None:
        session.clear()
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    user_folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        str(session["user_id"])
    )

    files = []

    if os.path.isdir(user_folder):
        for filename in os.listdir(user_folder):
            file_path = os.path.join(user_folder, filename)

            if os.path.isfile(file_path):
                files.append({
                    "name": filename,
                    "size": os.path.getsize(file_path)
                })

    total_files = len(files)

    return render_template(
        "dashboard.html",
        user=user,
        files=files,
        total_files=total_files
    )

# File upload
@app.route("/upload", methods=["POST"])
def upload_file():
    # Make sure the user is logged in
    if "user_id" not in session:
        flash("Please log in before uploading files.", "error")
        return redirect(url_for("login"))

    # Check that a file was submitted
    if "file" not in request.files:
        flash("No file was selected.", "error")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("Please select a file.", "error")
        return redirect(url_for("dashboard"))

    # Sanitize the filename
    filename = secure_filename(file.filename)

    if not filename:
        flash("Invalid filename.", "error")
        return redirect(url_for("dashboard"))

    # Create a separate folder for each user
    user_folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        str(session["user_id"])
    )

    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)

    # Prevent overwriting an existing file
    if os.path.exists(file_path):
        flash("A file with that name already exists.", "error")
        return redirect(url_for("dashboard"))

    # Save the uploaded file
    file.save(file_path)

    flash("File uploaded successfully!", "success")
    return redirect(url_for("dashboard"))


# User registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate the form
        if not username or not email or not password or not confirm_password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
            return redirect(url_for("register"))

        if len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        # Hash the password before storing it
        password_hash = generate_password_hash(password)

        connection = get_db_connection()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            connection.commit()

        except sqlite3.IntegrityError:
            flash(
                "That username or email is already registered.",
                "error"
            )
            return redirect(url_for("register"))

        finally:
            connection.close()

        flash("Account created successfully!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your email and password.", "error")
            return redirect(url_for("login"))

        connection = get_db_connection()

        try:
            user = connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        finally:
            connection.close()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True)