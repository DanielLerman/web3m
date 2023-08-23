# app/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Post  # Import your models
from . import db

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

# Add your other route definitions here
