#!/usr/bin/env python3
"""Set up a basic flask app
"""
from flask import Flask, jsonify, request, abort, make_response
from user import User
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def index():
    """
    Return json respomse
    {"message": "Bienvenue"}
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """
    route to register new user
    """
    email = request.form.get("email")
    passwd = request.form.get("password")

    try:
        user = AUTH.register_user(email, passwd)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Login route"""
    email = request.form.get("email")
    passwd = request.form.get("password")

    if not AUTH.valid_login(email, passwd):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_d", session_id)

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
