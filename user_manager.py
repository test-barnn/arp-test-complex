import hashlib
import sqlite3
import pickle
import os

# CODE SMELL: hardcoded secret
SECRET_KEY = "supersecret123"
DB_PATH = "users.db"

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SECURITY BUG: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(password):
    # SECURITY BUG: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def load_user_session(session_data):
    # SECURITY BUG: unsafe deserialization
    return pickle.loads(session_data)

def calculate_discount(price, rate):
    # BUG: no validation, returns negative for rate > 1
    discount = price * rate
    return price - discount

def get_all_users(role):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # CODE SMELL: another SQL injection
    cursor.execute(f"SELECT * FROM users WHERE role = '{role}'")
    results = cursor.fetchall()
    # CODE SMELL: bare except
    try:
        conn.close()
    except:
        pass
    return results

def process_data(data):
    # CODE SMELL: print in production code
    print(f"Processing data: {data}")
    # CODE SMELL: TODO left in code
    # TODO: add proper validation here
    result = []
    for item in data:
        result.append(item * 2)
    return result
```

**File 2: `requirements.txt`** — has vulnerable packages
```
flask==1.0.0
requests==2.18.0
pyyaml==3.12
cryptography==2.1.4
Pillow==8.0.0
pytest>=7.0.0
