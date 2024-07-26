from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash,
    session,
)
from forms import LoginForm
from flask_bcrypt import Bcrypt
import os
import pandas as pd
import io
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
ADMIN = os.environ.get("ADMIN")
bcrypt = Bcrypt(app)
# Contraseña hashada (esto deberías hacerlo una vez y guardarlo seguro)
hashed_password = bcrypt.generate_password_hash("hola123").decode("utf-8")


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(hashed_password, form.password.data):
            session["logged_in"] = True
            return redirect(url_for("download_page"))
        else:
            flash("Contraseña incorrecta. Inténtalo de nuevo.")
    return render_template("./auth/login.html", form=form)


@app.route("/download_page")
def download_page():
    if not session.get("logged_in"):
        flash("Ingrese la contraseña primero: ")
        return redirect(url_for("login"))
    return render_template("./auth/download.html")


@app.route("/download")
def download():
    if not session.get("logged_in"):
        flash("Por favor, inicia sesión primero.")
        return redirect(url_for("login"))

    data = {"Column1": [1, 2, 3], "Column2": [4, 5, 6]}
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)

    send_file(output, download_name="archivo.xlsx", as_attachment=True)
    session.pop("logged_in", None)

    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    flash("Se cerro la sesion")
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    form = LoginForm()
    param = request.args.get("param")
    if param == ADMIN:
        if form.validate_on_submit():
            if bcrypt.check_password_hash(hashed_password, form.password.data):
                session["logged_in"] = True
                return "Se inicio en admin"
            else:
                flash("Contraseña incorrecta. Inténtalo de nuevo.")
        return render_template("./auth/admin.html", form=form)
    else:
        flash("Usted no es admin")
        return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
