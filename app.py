from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
app = Flask(__name__)
app.secret_key = "local-development-key-change-before-deployment"


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


# Login route
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
        return redirect(url_for("home"))

    return render_template("login.html")


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True)