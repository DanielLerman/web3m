from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from elasticsearch import Elasticsearch, NotFoundError
from datetime import datetime
import os
import requests
import json
import logging
from elasticsearch.helpers import scan

# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

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
    
class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def __repr__(self):
        return f"Post('{self.title}', '{self.content}')"
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

def get_eth_to_usd_exchange_rate():
        response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd")
        data = response.json()
        return data.get("ethereum", {}).get("usd")

           

@app.route('/fetch_data')
def fetch_data():
        CRYPTOPUNKS_KEY = os.environ.get("CRYPTOPUNKS_KEY")
        MUTANTAPE_KEY = os.environ.get("MUTANTAPE_KEY")
        ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY")

        # Cryptopunks
        cryptopunks_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={CRYPTOPUNKS_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
        cryptopunks_response = requests.get(cryptopunks_url)
        cryptopunks_data = json.loads(cryptopunks_response.text)
        # logging.info("Cryptopunks Data: %s", cryptopunks_data)
        process_and_store_data(cryptopunks_data, "Cryptopunks")

        # MutantApe
        mutantape_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={MUTANTAPE_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
        mutantape_response = requests.get(mutantape_url)
        mutantape_data = json.loads(mutantape_response.text)
        # logging.info("MutantApe Data: %s", mutantape_data)
        process_and_store_data(mutantape_data, "MutantApe")

        return "Data fetched and processed successfully."


ELASTIC_PASSWORD  = os.environ.get("ELASTIC_PASSWORD")
CLOUD_ID  = os.environ.get("CLOUD_ID")

client = Elasticsearch(
    cloud_id=CLOUD_ID,
    basic_auth=("elastic",ELASTIC_PASSWORD)
)
client.info()

def process_and_store_data(data, project_name):
    try:
        print("API Response Data:", data)
        hourly_gas_fees = {}  # To store average gas fees per hour
        
        if 'result' in data and isinstance(data['result'], list):
            for entry in data['result']:
                try:
                    print("Entry:", entry)
                    timestamp = int(entry.get('timeStamp', 0))
                    gas_price = int(entry.get('gasPrice', 0)) / 1e9  # Convert from Gwei to ETH
                    gas_fee = gas_price * int(entry.get('gasUsed', 0)) / 1e18  # Convert to ETH
                    hour = datetime.utcfromtimestamp(timestamp).hour

                    if hour not in hourly_gas_fees:
                        hourly_gas_fees[hour] = []

                    hourly_gas_fees[hour].append(gas_fee)
                except Exception as entry_error:
                    print("Error processing entry:", entry_error)

            # Calculate average gas fees for each hour
            avg_gas_fees = {hour: sum(fees) / len(fees) for hour, fees in hourly_gas_fees.items()}

            # Get current Ether-to-USD exchange rate
            eth_to_usd_exchange_rate = get_eth_to_usd_exchange_rate()

            avg_gas_fees_usd = {hour: avg_fee * eth_to_usd_exchange_rate for hour, avg_fee in avg_gas_fees.items()}

            # Prepare a list of documents for Elasticsearch indexing
            docs_to_index = []
            for hour, avg_fee_usd in avg_gas_fees_usd.items():
                entry = data['result'][0]  # Use the first entry to get the timestamp
                timestamp = int(entry.get('timeStamp', 0))
                timestamp_str = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                avg_fee_eth = avg_gas_fees[hour]  # Get the average gas fee in ETH for the current hour

                # Prepare the document to be indexed in Elasticsearch
                doc = {
                    'project_name': project_name,
                    'hour': hour,
                    'timestamp': timestamp_str,
                    'average_gas_fee_eth': avg_fee_eth,
                    'average_gas_fee_usd': avg_fee_usd
                }
                docs_to_index.append(doc)

            # Index the documents in Elasticsearch
            index_name = "gas-fees-index"
            for doc in docs_to_index:
                response = client.index(index=index_name, body=doc)
                logging.info("Indexed document successfully: %s", response)

    except NotFoundError:
        logging.error("Index not found. Ensure the index exists before indexing data.")
    except Exception as process_error:
        print("Error processing data:", process_error)




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003)

   





