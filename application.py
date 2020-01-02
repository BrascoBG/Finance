import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # select each symbol owned by the user and it's amount
    portfolio_symbols = db.execute("SELECT shares, symbol FROM portfolio WHERE id = :id",
                                   id=session["user_id"])

    # create a temp variable to store TOTAL value of shares
    total_shares_value = 0

    # update each symbol prices and total
    for portfolio_symbol in portfolio_symbols:
        symbol = portfolio_symbol["symbol"]
        shares = portfolio_symbol["shares"]
        stock = lookup(symbol)
        total = shares * stock["price"]
        total_shares_value += total
        db.execute("UPDATE portfolio SET price = :price, total = :total WHERE id = :id and symbol = :symbol",
                   price=usd(stock["price"]), total=usd(total), id=session["user_id"], symbol=symbol)

    # update user's cash
    user_cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])

    total_worth = total_shares_value + user_cash[0]["cash"]

    # print portfolio on index page
    latest_portfolio = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"])

    return render_template("index.html", stocks=latest_portfolio, cash=usd(user_cash[0]["cash"]), total=usd(total_worth))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        # ensure symbol exist
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol")

        # ensure number of shares is positive
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be a positive integer")
        except:
            return apology("Shares must be a positive integer")

        # check if user has enough money to buy
        money = db.execute("SELECT cash FROM users WHERE id= :id",
                           id=session["user_id"])

        if not money or float(money[0]["cash"]) < stock["price"] * shares:
            return apology("Not enough money")

        # update history
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES (:symbol, :shares, :price, :id)",
                   symbol=stock["symbol"], shares=shares,
                   price=usd(stock["price"]), id=session["user_id"])

        # update user cash
        db.execute("UPDATE users SET cash = cash - :purchase WHERE id = :id",
                   id=session["user_id"],
                   purchase=stock["price"] * float(shares))

        # select user shares of that symbol
        user_shares = db.execute("SELECT shares FROM portfolio \
                            WHERE id = :id AND symbol = :symbol",
                                 id=session["user_id"], symbol=stock["symbol"])

        # if it's a new investment, create new stock object
        if not user_shares:
            db.execute("INSERT INTO portfolio (name, shares, price, total, symbol, id) \
                        VALUES (:name, :shares, :price, :total, :symbol, :id)",
                       name=stock["name"], shares=shares, price=usd(stock["price"]),
                       total=usd(shares * stock["price"]),
                       symbol=stock["symbol"], id=session["user_id"])

        # otherwise, increment shares count + update portfolio
        else:
            shares_total = user_shares[0]["shares"] + shares
            db.execute("UPDATE portfolio SET shares = :shares \
                        WHERE id = :id AND symbol = :symbol",
                       shares=shares_total, id=session["user_id"],
                       symbol=stock["symbol"])

        # return to index
        return redirect(url_for("index"))


@app.route("/check", methods=["GET"])
def check():

    # Takes username as argument from username
    username = request.args.get('username')

    # If not user, then username is free
    users = db.execute("SELECT username FROM users WHERE username=:username", username=username)
    if not users:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histories = db.execute("SELECT * FROM histories WHERE id = :id", id=session["user_id"])
    return render_template("history.html", histories=histories)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
        rows = lookup(request.form.get("symbol"))

        if not rows:
            return apology("Invalid Symbol")

        return render_template("quoted.html", stock=rows)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted

        elif not request.form.get("confirmation"):
            return apology("must fill in password confirmation", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password doesn't match", 400)

        # Insert new user into users, storing the hash of the user's password
        hash = generate_password_hash(request.form.get("password"))
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"),
                            hash=hash)

        if not result:
            return apology("Username already exist", 400)

        # Remember which user has logged in
        session["user_id"] = result

        # Redirect user to home page
        return redirect(url_for("index"))

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html")

    else:
        # ensure symbol exist
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Invalid Symbol")

        # ensure number of shares is positive
        try:
            shares = int(request.form.get("shares"))
            if shares < 0:
                return apology("Shares must be a positive integer")
        except:
            return apology("Shares must be a positive integer")

        # select the shares of the stock
        user_shares = db.execute("SELECT shares FROM portfolio WHERE id = :id AND symbol = :symbol",
                                 id=session["user_id"], symbol=stock["symbol"])

        # check if enough shares to sell
        if not user_shares or int(user_shares[0]["shares"]) < shares:
            return apology("You don't hold enough shares to sell that quantity")

        # update history
        db.execute("INSERT INTO histories (symbol, shares, price, id) \
                    VALUES (:symbol, :shares, :price, :id)",
                   symbol=stock["symbol"], shares=-shares,
                   price=usd(stock["price"]), id=session["user_id"])

        # update user cash
        db.execute("UPDATE users SET cash = cash + :sale WHERE id = :id",
                   id=session["user_id"],
                   sale=stock["price"] * float(shares))

        # decrease number of shares of the stock
        total_shares = user_shares[0]["shares"] - shares

        # if shares is zero, remove from portfolio
        if total_shares == 0:
            db.execute("DELETE FROM portfolio WHERE id = :id AND symbol = :symbol",
                       id=session["user_id"], symbol=stock["symbol"])

        # else update portfolio shares
        else:
            db.execute("UPDATE portfolio SET shares = :shares WHERE id = :id AND symbol = :symbol",
                       shares=total_shares, id=session["user_id"], symbol=stock["symbol"])

        # return to index
        return redirect(url_for("index"))


@app.route("/loan", methods=["GET", "POST"])
@login_required
def loan():
    """Get a loan."""

    if request.method == "POST":

        # ensure must be integers
        try:
            loan = int(request.form.get("loan"))
            if loan < 0:
                return apology("Loan must be positive amount")
            elif loan > 5000:
                return apology("Cannot loan more than $5,000 at once")
        except:
            return apology("Loan must be positive integer")

        # update user cash (increase)
        db.execute("UPDATE users SET cash = cash + :loan WHERE id = :id",
                   loan=loan, id=session["user_id"])

        # return to index
        return redirect(url_for("index"))

    else:
        return render_template("loan.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
