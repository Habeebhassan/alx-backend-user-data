#!/usr/bin/env python3
"""
Flask app to manage authentication.
Provides routes for user registration,
login, session management, and password
reset functionality.

Modules:
    - flask: Provides routing and HTTP
    methods for handling requests.
    - auth: Auth class that handles
    user-related authentication tasks.
"""

from flask import (
    Flask,
    request,
    jsonify,
    abort,
    redirect,
    url_for
)
from auth import Auth

app = Flask(__name__)
AUTH = Auth()

@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """
    Return a JSON response:
    {"message": "Bienvenue"}

    Returns:
        str: JSON welcome message.
    """
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """
    Register new users with provided
    email and password.

    Args:
        email (str): User email.
        password (str): User password.

    Returns:
        str: JSON response confirming
        user creation or failure message.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": f"{email}", "message": "user created"})

@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """
    Log in a user if valid
    credentials are provided. Create
    a session for the user.

    Args:
        email (str): User email.
        password (str): User password.

    Returns:
        str: JSON response indicating
        successful login and session creation.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    resp = jsonify({"email": f"{email}", "message": "logged in"})
    resp.set_cookie("session_id", session_id)
    return resp

@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """
    Log out a user by destroying
    their session and clearing cookies.

    Returns:
        str: Redirects to home on success.
        Abort 403 if session is invalid.
    """
    session_id = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(session_id)

    if user is None or session_id is None:
        abort(403)

    AUTH.destroy_session(user.id)
    return redirect("/")

@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """
    Get a user's email from
    the session_id in cookies.

    Returns:
        str: JSON with user email.
        Abort 403 if session invalid.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)

    if user:
        return jsonify({"email": f"{user.email}"}), 200
    abort(403)

@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """
    Generate a reset token for
    resetting a user's password.

    Args:
        email (str): User's email.

    Returns:
        str: JSON with reset token.
        Abort 403 if user not found.
    """
    email = request.form.get("email")

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": f"{email}", "reset_token": f"{reset_token}"})

@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """
    Update a user's password using
    the provided reset token.

    Args:
        email (str): User's email.
        reset_token (str): Password reset token.
        new_password (str): New password.

    Returns:
        str: JSON message confirming
        password update. Abort 403
        if token is invalid.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": f"{email}", "message": "Password updated"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
