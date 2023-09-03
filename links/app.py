import sqlite3
import random
import string
import os
import bcrypt
import qrcode
from flask import (
    Flask,
    render_template,
    flash,
    g,
    session,
    redirect,
    send_from_directory,
    request,
)
from forms import LoginForm, RegisterForm, LinkForm
from datetime import datetime


app = Flask(__name__)
app.secret_key = b"nooneknow"

DATABASE = "links.sqlite"


def get_user_from_db(username):
    user_data = (
        data_base()
        .execute("SELECT * FROM users WHERE name = ?", (username,))
        .fetchone()
    )
    return user_data


@app.before_request
def global_vars():
    g.logged = False
    if session.get("logged_in"):
        g.logged = True


def data_base():
    if not hasattr(g, "data_base"):
        g.data_base = sqlite3.connect(DATABASE)
        g.data_base.row_factory = sqlite3.Row
    return g.data_base


def generate_short_url():
    characters = string.ascii_letters + string.digits
    short_url = "".join(random.choice(characters) for _ in range(6))
    return short_url


def add_long_url_to_db(long_url, user_id):
    short_url = generate_short_url()
    data_base().execute(
        "INSERT INTO link (user_id, long, short) VALUES (?, ?, ?)",
        (user_id, long_url, short_url),
    )
    data_base().commit()
    return short_url


def generate_qr_code(link, filename):
    qr_code = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr_code.add_data(link)
    qr_code.make(fit=True)

    img = qr_code.make_image(fill_color="black", back_color="white")
    img.save(filename)


def is_name_available(new_name):
    result = (
        data_base()
        .execute("SELECT COUNT(*) FROM link WHERE short = ?", (new_name,))
        .fetchone()
    )
    return result[0] == 0


def update_link_name(user_id, old_name, new_name):
    data_base().execute(
        "UPDATE link SET short = ? WHERE user_id = ? AND short = ?",
        (new_name, user_id, old_name),
    )
    data_base().commit()


@app.route("/")
def frontpage():
    return render_template("index.html")


@app.route("/logout", endpoint="logout")
def logoutpage():
    session.pop("logged_in", None)
    flash("You are logged off, good luck!")
    return redirect("/")


@app.route("/register", endpoint="register", methods=["GET", "POST"])
def registerpage():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.name.data
        existing_user = get_user_from_db(username)
        if existing_user:
            flash("Username already taken. Please choose a different one.")
        else:
            salt = bcrypt.gensalt()
            password = form.password.data.encode("utf-8")
            password_hash = bcrypt.hashpw(password, salt)
            data_base().execute(
                "INSERT INTO users(name, password) VALUES(?, ?)",
                (username, password_hash),
            )
            data_base().commit()
            flash("You are registered!")
            return redirect("/")
    return render_template("registration.html", form=form)


@app.route("/login", endpoint="login", methods=["GET", "POST"])
def loginpage():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.name.data
        user_data = get_user_from_db(username)
        password = form.password.data.encode("utf-8")

        if user_data and bcrypt.checkpw(password, user_data["password"]):
            flash("You are logged in")
            session["user_id"] = user_data["id"]
            session["logged_in"] = True
            return redirect("/user")
        else:
            flash("Wrong password or name")
            return redirect("/login")
    return render_template("login.html", form=form)


@app.route("/user", endpoint="user", methods=["GET", "POST"])
def frontpage_user():
    form = LinkForm()
    if form.validate_on_submit() and session.get("logged_in"):
        long_url = form.link.data
        user_id = session["user_id"]
        short_url = generate_short_url()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        data_base().execute(
            "INSERT INTO link (user_id, long, short, timestamp) VALUES (?, ?, ?, ?)",
            (
                user_id,
                long_url,
                short_url,
                timestamp,
            ),
        )
        data_base().commit()

        qr_code_filename = f"static/qrcodes/{short_url}.png"
        generate_qr_code(long_url, qr_code_filename)

        flash("Link added successfully.")
        return redirect("/user")
    user_id = session.get("user_id")
    links = []
    if user_id:
        links = (
            data_base()
            .execute("SELECT * FROM link WHERE user_id = ?", (user_id,))
            .fetchall()
        )
    return render_template("user.html", form=form, links=links)


@app.route("/<short_link>")
def redirect_to_long_url(short_link):
    result = (
        data_base()
        .execute("SELECT long FROM link WHERE short = ?", (short_link,))
        .fetchone()
    )
    if result:
        data_base().execute(
            "UPDATE link SET count_click = count_click + 1 WHERE short = ?",
            (short_link,),
        )
        data_base().commit()

        return redirect(result["long"])


@app.route("/qrcodes/<filename>", endpoint="qrcodes")
def serve_qrcode(filename):
    return send_from_directory("static/qrcodes", filename)


@app.route("/delete/<int:link_id>", methods=["POST"])
def delete_link(link_id):
    user_id = session.get("user_id")
    link = (
        data_base()
        .execute("SELECT * FROM link WHERE id = ? AND user_id = ?", (link_id, user_id))
        .fetchone()
    )

    if not link:
        flash("Link not found")
    else:
        data_base().execute("DELETE FROM link WHERE id = ?", (link_id,))
        data_base().commit()
        flash("Link deleted successfully.")

    return redirect("/user")


@app.route("/user/change_name/<short_link>", methods=["POST"])
def change_link_name(short_link):
    if "user_id" in session:
        user_id = session["user_id"]
        new_name = request.form.get("new_name")
        if is_name_available(new_name):
            link_data = (
                data_base()
                .execute(
                    "SELECT * FROM link WHERE user_id = ? AND short = ?",
                    (user_id, short_link),
                )
                .fetchone()
            )
            if link_data:
                old_qr_code_filename = f"static/qrcodes/{short_link}.png"
                new_qr_code_filename = f"static/qrcodes/{new_name}.png"

                os.rename(old_qr_code_filename, new_qr_code_filename)

                generate_qr_code(link_data["long"], new_qr_code_filename)

                update_link_name(user_id, short_link, new_name)

                flash("Link name updated successfully.")
        else:
            flash("Name is already in use. Please choose another name.")

        return redirect("/user")
