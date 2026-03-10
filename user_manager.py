import hashlib
import sqlite3
import json
import os
import logging

# Load secret from environment to avoid hardcoding secrets in source
SECRET_KEY = os.environ.get("SECRET_KEY")
DB_PATH = "users.db"

logging.basicConfig(level=logging.INFO)


def get_user(username):
    """Retrieve a single user by username using a parameterized query.

    Raises sqlite3.Error on database errors.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cursor.fetchone()
    except sqlite3.Error:
        logging.exception("Database error while fetching user")
        raise


def hash_password(password):
    """Hash a password using SHA-256.

    Returns the hex digest of the SHA-256 hash of the provided password.
    """
    if not isinstance(password, (str, bytes)):
        raise TypeError("password must be a str or bytes")
    if isinstance(password, str):
        password = password.encode("utf-8")
    return hashlib.sha256(password).hexdigest()


def load_user_session(session_data):
    """Safely load session data from JSON (not pickle).

    Accepts either a JSON string or bytes. Raises ValueError for invalid data.
    """
    try:
        if isinstance(session_data, (bytes, bytearray)):
            session_data = session_data.decode("utf-8")
        return json.loads(session_data)
    except (TypeError, json.JSONDecodeError) as e:
        logging.exception("Failed to load session data safely")
        raise ValueError("Invalid session data") from e


def calculate_discount(price, rate):
    """Calculate the price after applying the discount rate.

    The rate must be between 0 and 1 inclusive. Raises ValueError otherwise.
    """
    try:
        rate_val = float(rate)
    except (TypeError, ValueError):
        raise ValueError("rate must be a number")
    if rate_val < 0 or rate_val > 1:
        raise ValueError("rate must be between 0 and 1")
    discount = price * rate_val
    return price - discount


def get_all_users(role):
    """Retrieve all users with a given role using a parameterized query.

    Returns a list of rows. Raises sqlite3.Error on database errors.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE role = ?", (role,))
            results = cursor.fetchall()
            return results
    except sqlite3.Error:
        logging.exception("Database error while fetching all users")
        raise


def process_data(data):
    """Process a sequence of items by doubling each item.

    Uses structured logging instead of printing. Non-multipliable items are skipped with a warning.
    """
    logging.info("Processing data: %s", data)
    if not isinstance(data, (list, tuple)):
        raise TypeError("data must be a list or tuple")
    result = []
    for item in data:
        try:
            result.append(item * 2)
        except TypeError:
            logging.warning("Skipping item that cannot be multiplied: %r", item)
    return result
