
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import json


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)


# User class for database

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.fname}', '{self.lname}', '{self.email}')"
    

# Post class for database

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.content}')"
    

# Login manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])

def register():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if email already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        # Hash password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create new user
        new_user = User(fname=fname, lname=lname, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])

def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist')
            return redirect(url_for('login'))

        # Check if password is correct
        if not check_password_hash(user.password, password):
            flash('Incorrect password')
            return redirect(url_for('login'))

        # Login user
        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.fname)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/fetch_data')
def fetch_data():
    # Fetching keys from environment variables
    CRYPTOPUNKS_KEY = os.environ.get("CRYPTOPUNKS_KEY")
    MUTANTAPE_KEY = os.environ.get("MUTANTAPE_KEY")
    ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY")

    # Cryptopunks

    cryptopunks_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={CRYPTOPUNKS_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
    cryptopunks_response = requests.get(cryptopunks_url)
    cryptopunks_data = cryptopunks_response.json()

    # MutantApe
 
    mutantape_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={MUTANTAPE_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
    mutantape_response = requests.get(mutantape_url)
    mutantape_data = mutantape_response.json()

    # You can do something with the fetched data here (e.g., store it, display it, etc.)
    print("Cryptopunks Data:")
    print(cryptopunks_data)
    print("\n")

    print("MutantApe Data:")
    print(mutantape_data)

    return "Data fetched successfully."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)









