from flask import render_template, session, redirect, url_for, current_app, request, jsonify, Response, flash
from .. import db
from ..models import User, Openwrt, GlobalState, Network, WirelessNetwork
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
import json
from datetime import datetime
from .forms import AddNetworkForm, AddWirelessForm
import ipaddress


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"%s: %s" % (
                getattr(form, field).label.text,
                error
            ), category='error')


################## APs / DEVICES ##################
@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
    openwrts = Openwrt.query.all()
    for openwrt in openwrts:
        print(openwrt)
    return render_template('index.html', openwrts=openwrts)


################## NETWORKS ##################

@main.route('/network', methods=['GET', 'POST'])
@login_required
def network():
    networks = Network.query.all()
    for network in networks:
        print(network)
    return render_template('network.html', networks=networks)


@main.route('/network/new', methods=['GET', 'POST'])
@login_required
def new_network():
    form = AddNetworkForm()
    if form.is_submitted():
        if form.validate():
            network = Network(name=form.name.data,
                              network_addr=form.network.data,
                              gateway=form.gateway.data,
                              vlan=int(form.vlan.data)
                              )
            db.session.add(network)
            db.session.commit()
            return redirect(url_for('main.network'))
        else:
            flash_errors(form)
    return render_template('network_detail.html', form=form, new=True)


@main.route('/network/edit/<string:network_name>', methods=['GET', 'POST'])
@login_required
def edit_network(network_name):
    network = Network.query.filter(Network.name == network_name).first()
    if network is None:
        return render_template('404.html')
    else:
        form = AddNetworkForm()
        form.is_edit = True
        if request.method == 'GET':
            form.name.data = network_name
            form.network.data = network.network_addr
            form.gateway.data = network.gateway
            form.vlan.data = network.vlan
        else:
            if form.is_submitted():
                if form.validate():
                    network.name = form.name.data
                    network.network_addr = form.network.data
                    network.gateway = form.gateway.data
                    network.vlan = form.vlan.data
                    db.session.commit()
                    return redirect(url_for('main.network'))
                else:
                    flash_errors(form)
        return render_template('network_detail.html', form=form, new=False, network=network)


@main.route('/network/delete/<string:network_name>', methods=['GET', 'POST'])
@login_required
def delete_network(network_name):
    network = Network.query.filter(Network.name == network_name).first()
    if network is None:
        return render_template('404.html')
    else:
        db.session.delete(network)
        db.session.commit()
        return redirect(url_for('main.network'))


################## WIRELESS ##################

@main.route('/wireless', methods=['GET', 'POST'])
@login_required
def wireless():
    wireless_networks = WirelessNetwork.query.all()
    for wireless in wireless_networks:
        print(wireless)
    return render_template('wireless.html', wireless_networks=wireless_networks)


@main.route('/wireless/new', methods=['GET', 'POST'])
@login_required
def new_wireless():
    form = AddWirelessForm()
    if form.is_submitted():
        if form.validate():
            vlan = 0
            if form.is_vlan.data is True:
                vlan = int(form.vlan.data)
            wireless_network = WirelessNetwork(ssid=form.ssid.data,
                                               enabled=form.enabled.data,
                                               security_type=form.security.data,
                                               password=form.password.data,
                                               is_vlan=form.is_vlan.data,
                                               vlan=vlan
                              )
            db.session.add(wireless_network)
            db.session.commit()
            return redirect(url_for('main.wireless'))
        else:
            flash_errors(form)
    return render_template('wireless_detail.html', form=form, new=True)


@main.route('/wireless/edit/<string:wireless_name>', methods=['GET', 'POST'])
@login_required
def edit_wireless(wireless_name):
    wireless = WirelessNetwork.query.filter(WirelessNetwork.ssid == wireless_name).first()
    if wireless is None:
        return render_template('404.html')
    else:
        form = AddWirelessForm()
        form.is_edit = True
        if request.method == 'GET':
            form.ssid.data = wireless_name
            form.enabled.data = wireless.enabled
            form.security.data = wireless.security_type
            form.password.data = wireless.password
            form.is_vlan.data = wireless.vlan > 1 and wireless.vlan < 4097
            form.vlan.data = wireless.vlan
        else:
            if form.is_submitted():
                if form.validate():
                    wireless.ssid = form.ssid.data
                    wireless.enabled = form.enabled.data
                    wireless.security_type = form.security.data
                    if wireless.security_type == "Open":
                        wireless.password = ""
                    else:
                        wireless.password = form.password.data
                    wireless.is_vlan = form.is_vlan.data
                    if form.is_vlan.data == True:
                        wireless.vlan = form.vlan.data
                    else:
                        wireless.vlan = 1
                    db.session.commit()
                    return redirect(url_for('main.wireless'))
                else:
                    flash_errors(form)
        return render_template('wireless_detail.html', form=form, new=False, wireless=wireless)


@main.route('/wireless/delete/<string:wireless_name>', methods=['GET', 'POST'])
@login_required
def delete_wireless(wireless_name):
    wireless = WirelessNetwork.query.filter(WirelessNetwork.ssid == wireless_name).first()
    if wireless is None:
        return render_template('404.html')
    else:
        db.session.delete(wireless)
        db.session.commit()
        return redirect(url_for('main.wireless'))


################## STATISTICS ##################


@main.route('/statistics', methods=['GET', 'POST'])
@login_required
def statistics():
    return render_template('statistics.html')


@main.route('/openwrts/<string:openwrt_name>', methods=['GET', 'POST'])
@login_required
def openwrts(openwrt_name):
    openwrt = Openwrt.query.filter(func.lower(Openwrt.name) == func.lower(openwrt_name)).first()
    print('openwrt: ' + openwrt_name)
    if openwrt is None:
        return render_template('404.html')
    else:
        boardinfoJson = json.loads(openwrt_api.get_luci_result(openwrt, 'sys', {"id": 1, "method": "exec", "params": [
            "ubus call system board"]}))
        print(boardinfoJson)

        infoJson = json.loads(openwrt_api.get_luci_result(openwrt, 'sys', {"id": 1, "method": "exec", "params": [
            "ubus call system info"]}))
        print(infoJson)

        loadavg = openwrt_api.get_luci_result(openwrt, 'sys', {"id": 1, "method": "exec", "params": [
            "cat /proc/loadavg"]})

        syslog = openwrt_api.get_luci_result(openwrt, 'sys', {"id": 1, "method": "syslog", "params": []})
        dmesg = openwrt_api.get_luci_result(openwrt, 'sys', {"id": 1, "method": "dmesg", "params": []})

        return render_template('openwrt_detail.html', openwrt=openwrt, boardinfoJson=boardinfoJson,
                               infoJson=infoJson, uptime=openwrt_api.seconds_to_timeformat(
                infoJson['uptime']), localtime=datetime.utcfromtimestamp(infoJson['localtime']), loadavg=loadavg,
                               syslog=syslog, dmesg=dmesg)


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
