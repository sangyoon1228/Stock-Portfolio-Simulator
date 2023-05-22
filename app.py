import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    user_id = session["user_id"]
    username = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]["username"]
    cash1 = usd(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"])
    portfolio = db.execute("SELECT symbol, name, price, total_shares, total_cost FROM totals WHERE id = ?;", user_id)
    return render_template("bought.html", cash1=cash1, portfolio=portfolio, username=username)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        #if the user does not input a stock symbol just redirect back to the quote page
        if not request.form.get("symbol"):
            return apology("Missing Symbol", 400)
        #check to see if the lookup is successful
        if not lookup(request.form.get("symbol")):
            return apology("Stock does not exist", 400)
        #check that the nubmer of shares is an integer greater than 0
        elif not request.form.get("shares") or float(request.form.get("shares")) <= 0:
            return apology("Must input a positive number of stocks", 400)

        stock = lookup(request.form.get("symbol"))
        name = stock["name"]
        price = stock["price"]
        symbol = stock["symbol"]
        shares = float(request.form.get("shares"))
        user_id = session["user_id"]
        total_price = price * shares
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        #check to make sure that the user has enough money
        if cash < total_price:
            return apology("Insufficient Funds", 400)
        #update the user table
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (cash - total_price), user_id)
        #update the purchases table (id, symbol, name, price, total_shares) VALUES (?, ?, ?, ?, ?);", user_id, symbol, name, price, shares)
        if float(db.execute("SELECT COUNT(symbol) AS symbol_count FROM totals WHERE id = ? AND symbol = ?;", user_id, symbol)[0]["symbol_count"]) == 0:
            db.execute("INSERT INTO totals (id, symbol, name, price, total_shares, total_cost) VALUES (?, ?, ?, ?, ?, ?);", user_id, symbol, name, price, shares, total_price)
            db.execute("INSERT INTO purchases (id, shares, symbol, name, price, total) VALUES (?, ?, ?, ?, ?, ?);", user_id, shares, symbol, name, price, total_price)
        else:
            current_shares = float(db.execute("SELECT SUM(shares) AS share_total FROM purchases WHERE id = ? AND symbol = ?", user_id, symbol)[0]["share_total"])
            updated_shares = current_shares + shares
            updated_cost = float(db.execute("SELECT total_cost FROM totals WHERE id = ? AND symbol = ?", user_id, symbol)[0]["total_cost"]) + total_price
            db.execute("INSERT INTO purchases (id, shares, symbol, name, price, total) VALUES (?, ?, ?, ?, ?, ?);", user_id, shares, symbol, name, price, total_price)
            db.execute("UPDATE totals SET total_shares = ?, total_cost = ? WHERE id = ? AND symbol = ?;", updated_shares, updated_cost, user_id, symbol)
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    portfolio = db.execute("SELECT * FROM purchases WHERE id = ?;", user_id)
    return render_template("history.html", portfolio=portfolio)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    if request.method == "POST":
        #if the user does not input a stock symbol just redirect back to the quote page
        if not request.form.get("symbol"):
            return apology("Missing symbol", 400)
        #check to see if the lookup is successful
        if not lookup(request.form.get("symbol")):
            return apology("Stock does not exist", 400)
        else:
            stock = lookup(request.form.get("symbol"))
            return render_template("quoted.html", name=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
     # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        #ensure that the username does not already exist
        elif db.execute("SELECT COUNT(username) AS exist FROM users WHERE username = ?", request.form.get("username"))[0]["exist"] > 0:
            return apology("username already exists", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        #ensure that password is confirmed
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        #ensure that the password and the confirmation actually match each other
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        #save the username and the hash of the password and insert into the table
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        return redirect("/login")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    if request.method == "POST":
        share_count = float(db.execute("SELECT * FROM totals WHERE id = ? AND symbol = ?;", user_id, request.form.get("symbol"))[0]["total_shares"])
        #user does not input a symbol
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        #check to see if the user inputs a number of shares
        elif not request.form.get("shares"):
            return apology("missing shares", 400)
        #make sure that the user actually has the stock that they want to sell
        elif share_count < float(request.form.get("shares")):
            return apology("too many shares", 400)

        new_share = share_count - float(request.form.get("shares"))
        stock = lookup(request.form.get("symbol"))
        name = stock["name"]
        price = stock["price"]
        symbol = stock["symbol"]
        shares = float(request.form.get("shares"))
        total_price = price * shares
        total_cost = float(db.execute("SELECT * FROM totals WHERE id = ? AND symbol = ?;", user_id, request.form.get("symbol"))[0]["total_cost"])
        sold_cost = float(db.execute("SELECT * FROM totals WHERE id = ? AND symbol = ?;", user_id, request.form.get("symbol"))[0]["price"]) * float(request.form.get("shares"))
        new_cost = total_cost - sold_cost
        if new_share == 0:
            db.execute("DELETE FROM totals WHERE symbol = ? AND id = ?;", request.form.get("symbol"), user_id)
            db.execute("INSERT INTO purchases (id, shares, symbol, name, price, total) VALUES (?, ?, ?, ?, ?, ?);", user_id, -1*shares, symbol, name, price, total_price)
        else:
            db.execute("UPDATE totals SET total_cost = ?, total_shares = ? WHERE id = ? AND symbol = ?;", new_cost, new_share, user_id, symbol)
            db.execute("INSERT INTO purchases (id, shares, symbol, name, price, total) VALUES (?, ?, ?, ?, ?, ?);", user_id, -1*shares, symbol, name, price, total_price)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        cash += sold_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", cash, user_id)
        return redirect("/history")
    else:
        purchases = db.execute("SELECT * FROM purchases WHERE id = ? GROUP BY symbol;", user_id)
        return render_template("sell.html", purchases=purchases)
