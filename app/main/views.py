from flask import render_template, session, redirect, url_for, current_app, request, jsonify, Response
from .. import db
from ..models import User, Openwrt, GlobalState
from ..email import send_email
from . import main, openwrt_api
from flask_login import login_required, current_user
from pprint import pprint
from sqlalchemy import func
from time import sleep, time
from threading import Thread
import main as main_root
from .. import socketio
from flask_socketio import emit




@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
    openwrts = Openwrt.query.all()
    for openwrt in openwrts:
        print(openwrt)
    return render_template('index.html', openwrts=openwrts)


@main.route('/openwrts/<string:openwrt_name>', methods=['GET', 'POST'])
@login_required
def openwrts(openwrt_name):
    openwrt = Openwrt.query.filter(func.lower(Openwrt.name) == func.lower(openwrt_name)).first()
    print('openwrt: ' + openwrt_name)
    if openwrt is None:
        return render_template('404.html')
    return render_template('openwrt_detail.html', openwrt=openwrt)


@main.route('/img/<img>')
def static_img(img):
    imgpath = 'img/' + img;
    return redirect(url_for('static', filename=imgpath))


######### AJAX API
@main.route('/openwrt/comment', methods=['POST'])
@login_required
def openwrt_comment():
    content = request.json
    pprint(content)
    openwrt = Openwrt.query.filter_by(name=content["openwrt_name"]).first();
    if openwrt is not None:
        openwrt.comment = content["comment"]
        print('comment: ' + openwrt.comment)
        db.session.commit()
        return jsonify(success=True)

    return jsonify(success=False), 404


@main.route('/openwrt/refresh_all', methods=['POST'])
@login_required
def refresh_all():
    if openwrt_api.test_and_set_refresh() is False:
        return jsonify(success=False, message="Refresh already in progress"), 409

    # Refresh OpenWRTs in background
    thr = Thread(target=openwrt_api.refresh_all_openwrts, args=[main_root.app])
    thr.start()

    return jsonify(success=True)


@main.route('/openwrt/refresh_status')
@login_required
def refresh_status():
    return openwrt_api.refresh_status.to_json()


@socketio.on('connect', namespace='/ws')
def test_connect():
    socketio.emit('refresh_status', openwrt_api.refresh_status.toJSON(), namespace='/ws')


##################################
