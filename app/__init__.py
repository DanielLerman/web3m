# from flask import Flask
# from .config import Config
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager

# db = SQLAlchemy()
# login_manager = LoginManager()

# def create_app():
#     app = Flask(__name__)
#     db.init_app(app)
#     app.config.from_object(Config)

#     db.init_app(app)  # Initialize the SQLAlchemy extension
#     login_manager.init_app(app)

#     with app.app_context():
#         from . import auth 
#         app.register_blueprint(auth.auth_bp)

#     return app
