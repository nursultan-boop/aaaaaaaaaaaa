from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt
from datetime import datetime
import requests
import psycopg2
def check_in_db(address):
    conn = psycopg2.connect("dbname=solana user=postgres password='123'")
    cur = conn.cursor()
    cur.execute("SELECT * FROM solana where url='"+address+"'")
    if(cur.rowcount==0):
        return False
    return True 
    
db = SQLAlchemy()
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = r"postgresql://postgres:123@localhost:5432/solana"

with app.app_context():
    db.init_app(app)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'secretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


class solana(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(50), nullable=False)
    information = db.Column(db.String(20), nullable=False)


@app.route('/nft_page', methods=['POST', 'GET'])
def nft_page():
    if request.method == "POST":
        returnValue=""
        address = request.form.get('title')
        conn = psycopg2.connect("dbname=solana user=postgres password='123'")
        cur = conn.cursor()
        cur.execute("SELECT information FROM solana where url='"+address+"'")
        records = cur.fetchall()
        if len(records)>0:
            returnValue=records[0][0]
        else:
            url = "https://solana-gateway.moralis.io/nft/mainnet/{}/metadata".format(address)
            headers = {
                "accept": "application/json",
                "X-API-Key": "OjvXHY7ltVwY7xKG1p9HtQmLfKuRiodrazyFMLx2ZAAzECrZY7soe5LMcTTIvj8z"
                }
            returnValue = requests.get(url, headers=headers).text
            conn = psycopg2.connect("dbname=solana user=postgres password='123'")
            cur = conn.cursor()
            cur.execute("insert into solana(url,information) values('{}','{}')".format(address, returnValue))
            conn.commit()
       
        return '''
                <h1>{}</h1>
                  '''.format(returnValue)
    else:
        return render_template('nft_page.html')




@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template("reg.html", form=form)


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.username == form.username.data).first()
        hashed_pwd = bcrypt.generate_password_hash(form.data["password"], 10)
        if user:
            if bcrypt.check_password_hash(hashed_pwd, user.password):
                login_user(user)
        return redirect(url_for('nft_page'))
    return render_template("index.html", form=form)


@app.route('/about')
def about():
    return render_template("about.html")




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True, port=3000)
