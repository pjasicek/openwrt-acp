from flask import render_template, session, redirect, url_for, current_app
from .. import db
from ..models import User
from ..email import send_email
from . import main
from .forms import NameForm
from flask_login import login_required, current_user


@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html')


@main.route('/devices', methods=['GET', 'POST'])
def devices():
    return render_template('devices.html')


@main.route('/statistics', methods=['GET', 'POST'])
def statistics():
    return render_template('statistics.html')


@main.route('/network', methods=['GET', 'POST'])
def network():
    return render_template('network.html')


@main.route('/secret')
@login_required
def secret():
    return 'Only authorized personnel'
