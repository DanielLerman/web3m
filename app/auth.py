from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, db 
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist')
            return redirect(url_for('auth.login'))  # Use 'auth.login' instead of 'login'

        # Check if password is correct
        if not check_password_hash(user.password, password):
            flash('Incorrect password')
            return redirect(url_for('auth.login'))  # Use 'auth.login' instead of 'login'

        # Login user
        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
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
            return redirect(url_for('auth.register'))  # Use 'auth.register' instead of 'register'

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('auth.register'))  # Use 'auth.register' instead of 'register'

        # Hash password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create new user
        new_user = User(fname=fname, lname=lname, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))  # Use 'auth.login' instead of 'login'

    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ... other authentication-related routes ...
