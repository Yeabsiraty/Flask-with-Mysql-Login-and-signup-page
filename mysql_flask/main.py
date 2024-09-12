from flask import Flask, render_template,redirect,flash,get_flashed_messages,url_for,session
from flask_wtf import FlaskForm,CSRFProtect
from wtforms import StringField,PasswordField,EmailField,IntegerField
from wtforms.validators import DataRequired,Length
from werkzeug.security import check_password_hash,generate_password_hash
from flask_mysqldb import MySQL,MySQLdb
from datetime import timedelta
from bleach import clean
from html import escape

app = Flask(__name__)

app.config["SECRET_KEY"] = "abebe"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '7890'
app.config['MYSQL_DB'] = 'test'
app.secret_key = "thisis1211sexret@#Q@#NSD"
app.permanent_session_lifetime = timedelta(minutes=5)
csrf = CSRFProtect(app)
mysql = MySQL(app)

class login_form(FlaskForm):
    email = EmailField("email/phone",validators=[DataRequired("This field is required"),Length(min=5)],render_kw={"placeholder": "Email / Phone"})
    password = PasswordField("password",validators=[DataRequired("This field is required")],render_kw={"placeholder": "password"})

class signup_form(FlaskForm):
    f_name = StringField("first name",validators=[DataRequired("First Name is required")],render_kw={"placeholder": "First Name"})
    l_name = StringField("last name",validators=[DataRequired("Last Name is required")],render_kw={"placeholder": "Last Name"})
    email = EmailField("email",validators=[DataRequired("Email is required")],render_kw={"placeholder": "Email"})
    phone = IntegerField("phone",validators=[DataRequired("Phone number is required")],render_kw={"placeholder": "Phone"})
    password = PasswordField("Password",validators=[DataRequired("Password is required")],render_kw={"placeholder": "Password"})
    c_pass = PasswordField("Confirm Password",validators=[DataRequired("Password is required")],render_kw={"placeholder": "Confirm Password"})

@app.route("/" ,methods = ["GET","POST"])
@app.route("/login",methods = ["GET","POST"])
def login():
    form = login_form()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("select * from user where email = %s",(email,))
        result = cur.fetchone()
        if result and check_password_hash(result['pass_key'],password):
            data = result["F_name"]
            session.permanent = True
            session["F_name"] = data
            flash(f"Welcome {session["F_name"]}!","success")
            return redirect(url_for("home"))
        else:
            flash("email or password is not correct","error")

    return render_template("login.html",form = form,show = False)

@app.route("/signup",methods=["GET","POST"])
def signup():
    form = signup_form()
    if form.validate_on_submit():
        f_name = form.f_name.data
        l_name = form.l_name.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data
        c_pass = form.c_pass.data
        if password == c_pass:
            pass_me = generate_password_hash(password)
            cure = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            check = cure.execute("select * from user where email = %s",[email])
            check2 = cure.execute("select * from user where phone = %s",[phone])
            if check:
                flash("email alrady exist please login","error")
            elif check2:
                flash("phone number is already exist!","error")
            else:
                result = cure.execute("insert into user(F_name,L_name,email,phone,pass_key)values(%s,%s,%s,%s,%s)",(f_name,l_name,email,phone,pass_me))
                mysql.connection.commit()
                if result:
                    session.permanent = True
                    session["F_name"] = f_name
                    return redirect(url_for("home"))
                else:
                    flash("not registered please try again","error")
        else:
            flash("password is not match","error")
    return render_template("signup.html",form = form, show = False)


@app.route("/home")
def home():
    if "F_name" in session:
        return render_template("home.html",show = True)
    else:
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
        session.clear()
        return redirect (url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
