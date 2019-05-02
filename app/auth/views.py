from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm
from .. import db



@auth.route('/login', methods=['GET', 'POST'])
def login():
    """Renders login view located at /login endpoint"""
    if current_user.is_authenticated:
        return redirect(request.args.get('next') or url_for('main.index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, True)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    """Logs user out of his session and redirects to login view"""
    logout_user()
    return redirect(url_for('auth.login'))
