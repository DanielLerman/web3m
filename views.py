from flask import Blueprint, render_template, redirect ,url_for

views=Blueprint(__name__,'views')

@views.route('/')
def home():
    return render_template('index.html') 

@views.route('/best-time-to-buy')
def best_time_to_buy():
    return redirect(url_for('views./'))
