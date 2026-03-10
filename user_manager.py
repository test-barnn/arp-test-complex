import hashlib
import sqlite3
import json
import os
import logging

# SECRET_KEY must be provided via environment variable for security
SECRET_KEY = os.environ.get("SECRET_KEY")
DB_PATH = "users.db"

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    # Basic configuration if the application hasn't configured logging
    logging.basicConfig(level=logging.INFO)


def get_user(username):
    """Return a single user by username using a parameterized query.

    Prevents SQL injection by using sqlite3 parameter substitution. If the
    database or table is not present, the function will return None and log
    the database error instead of raising an OperationalError to callers.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cursor.fetchone()
    except sqlite3.Error:
        logger.exception("Database error while fetching user: %s", username)
        return None


def hash_password(password):
    """Hash a password using SHA-256 (minimum)."""
    if password is None:
        raise TypeError("password must be provided")
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def load_user_session(session_data):
    """Safely load session data from a JSON string or bytes.

    Rejects arbitrary pickle data and raises ValueError for invalid JSON.
    """
    if isinstance(session_data, (bytes, bytearray)):
        try:
            text = session_data.decode("utf-8")
        except Exception as e:
            raise TypeError("session_data bytes must be UTF-8 encoded") from e
    elif isinstance(session_data, str):
        text = session_data
    else:
        raise TypeError("session_data must be bytes or str containing JSON")

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Explicitly surface invalid session formats
        raise ValueError("Invalid session data: not valid JSON") from e


def calculate_discount(price, rate):
    """Calculate discounted price.

    Raises ValueError if rate is out of the range [0, 1].
    """
    try:
        numeric_rate = float(rate)
    except Exception as e:
        raise TypeError("rate must be numeric") from e

    if numeric_rate < 0 or numeric_rate > 1:
        raise ValueError("rate must be between 0 and 1 inclusive")

    discount = price * numeric_rate
    return price - discount


def get_all_users(role):
    """Return all users with the given role using a parameterized query.

    Uses context manager for the connection and handles sqlite3-specific errors.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE role = ?", (role,))
            results = cursor.fetchall()
            return results
    except sqlite3.Error:
        # Log database-specific errors and re-raise for caller handling
        logger.exception("Database error while fetching users by role")
        raise


def process_data(data):
    """Process a list of numeric items by doubling each value.

    Uses structured logging and validates inputs. The function validates item
    types and raises TypeError for invalid inputs.
    """
    logger.info("Processing data: %s", data)
    if not isinstance(data, (list, tuple)):
        raise TypeError("data must be a list or tuple of numeric values")

    result = []
    for item in data:
        if not isinstance(item, (int, float)):
            raise TypeError("all items in data must be numeric")
        result.append(item * 2)
    return result
