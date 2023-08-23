# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv 

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_envvar('FLASK_APP_SETTINGS')  # Set configuration from an environment variable

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from . import routes  # Import routes
        db.create_all()  # Create database tables if not exists

    return app
