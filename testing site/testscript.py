from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(__name__,template_folder=".")
app.secret_key = "secret_key"  # For session management

# Initialize database
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'password')")
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("index.html")

# 🔥 SQL Injection Vulnerable Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        # ❌ UNSAFE: SQL Injection Vulnerability
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cur.execute(query)
        user = cur.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect("/dashboard")
        else:
            return "Login Failed"

    return render_template("login.html")

# 🔥 SQL Injection Vulnerable Search
@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        query = request.form["query"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        # ❌ UNSAFE: SQL Injection Vulnerability
        sql_query = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        cur.execute(sql_query)
        results = cur.fetchall()
        conn.close()

        return render_template("search.html", results=results)

    return render_template("search.html", results=[])

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return f"Welcome {session['user']}! <a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
