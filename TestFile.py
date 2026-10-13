
from flask import Flask, request, render_template_string, session
import sqlite3
import subprocess
import os
import pickle
import hashlib

app = Flask(__name__)

# FLAW 1: Hardcoded secret key
app.secret_key = "admin123"

DATABASE = "test_users.db"


def get_db():
    # FLAW 2: No robust database configuration or controls
    return sqlite3.connect(DATABASE)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)

    cursor.execute("""
        INSERT INTO users (username, password, role)
        SELECT 'admin', 'admin123', 'admin'
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE username = 'admin'
        )
    """)

    conn.commit()
    conn.close()


@app.route("/")
def home():
    # FLAW 3: Exposes internal application details
    return """
        <h1>Internal User Portal</h1>
        <p>Debug mode and internal routes are enabled.</p>
        <a href="/search?name=admin">Search Users</a>
        <a href="/login">Login</a>
    """


@app.route("/search")
def search_users():
    username = request.args.get("name", "")

    conn = get_db()
    cursor = conn.cursor()

    # FLAW 4: SQL injection through string concatenation
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "'"
    )

    try:
        cursor.execute(query)
        users = cursor.fetchall()
    except Exception as exc:
        # FLAW 5: Exposes database errors to the user
        conn.close()
        return f"Database error: {exc}", 500

    conn.close()

    # FLAW 6: Reflected XSS through unescaped input
    html = f"""
        <h2>Search results for: {username}</h2>
        <ul>
    """

    for user in users:
        html += f"<li>{user[1]} - {user[2]}</li>"

    html += "</ul>"
    return html


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
            <form method="POST">
                <input name="username" placeholder="Username">
                <input name="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    cursor = conn.cursor()

    # FLAW 7: SQL injection in authentication
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username +
        "' AND password = '" + password + "'"
    )

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as exc:
        conn.close()
        return f"Login query failed: {exc}", 500

    conn.close()

    if user:
        # FLAW 8: No session regeneration or additional protections
        session["user_id"] = user[0]
        session["username"] = user[1]
        session["role"] = user[2]

        return f"Welcome, {username}!"

    return "Invalid credentials", 401


@app.route("/admin")
def admin():
    # FLAW 9: Authorization relies on a client-controlled session role
    if session.get("role") == "admin":
        return "Admin panel: sensitive system information"
    return "Access denied", 403


@app.route("/run")
def run_command():
    command = request.args.get("cmd", "")

    # FLAW 10: User input reaches a shell command
    result = subprocess.getoutput("echo " + command)

    return f"<pre>{result}</pre>"


@app.route("/download")
def download_file():
    filename = request.args.get("file", "")

    # FLAW 11: Path traversal; no safe directory restriction
    path = os.path.join("uploads", filename)

    try:
        with open(path, "r", encoding="utf-8") as file:
            # FLAW 12: Potential sensitive file disclosure
            return file.read()
    except Exception as exc:
        return f"File error: {exc}", 404


@app.route("/save_state", methods=["POST"])
def save_state():
    data = request.get_data()

    # FLAW 13: Unsafe deserialization of untrusted data
    try:
        obj = pickle.loads(data)
        return str(obj)
    except Exception as exc:
        return f"Deserialization error: {exc}", 400


@app.route("/profile")
def profile():
    # FLAW 14: No authentication check
    username = request.args.get("username", "admin")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, password, role FROM users "
        "WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        # FLAW 15: Exposes stored credentials
        return {
            "username": user[0],
            "password": user[1],
            "role": user[2]
        }

    return {"error": "User not found"}, 404


@app.route("/hash")
def weak_hash():
    password = request.args.get("password", "")

    # FLAW 16: Fast, unsalted hash unsuitable for password storage
    hashed = hashlib.md5(password.encode()).hexdigest()

    return {"hash": hashed}


if __name__ == "__main__":
    init_db()

    # FLAW 17: Debug mode exposes a development debugger
    # Keep this application bound to localhost only.
    app.run(host="127.0.0.1", port=5000, debug=True)
# Connect to the database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create a sample table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT
    )
""")

cursor.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    ("alice", "password123")
)
conn.commit()

# Vulnerable login function
def login(username, password):
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    print("Executing query:", query)
    cursor.execute(query)

    result = cursor.fetchone()

    if result:
        print("Login successful!")
    else:
        print("Invalid username or password.")

# Get user input
username = input("Enter username: ")
password = input("Enter password: ")

login(username, password)

conn.close()
Why is this vulnerable?
The following code is the problem:

python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password = '"
    + password
    + "'"
)
Direct concatenation: User input is inserted into SQL without proper parameterization.

SQL injection risk: Special SQL characters in the input can change the query's intended logic.

Potential impact: An attacker may bypass authentication or manipulate database queries, depending on the database and application context.

How to fix it
Use parameterized queries instead:

python
def login(username, password):
    query = """
        SELECT * FROM users
        WHERE username = ? AND password = ?
    """

    cursor.execute(query, (username, password))
    result = cursor.fetchone()

    if result:
        print("Login successful!")
    else:
        print("Invalid username or password.")
