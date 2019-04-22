from flask import render_template, session, redirect, url_for, current_app, request, jsonify, Response, flash
from .. import db
from ..models import User, Openwrt, Network, WirelessNetwork, OpenwrtComments
from . import main, openwrt_api
from flask_login import login_required, current_user
from pprint import pprint
from sqlalchemy import func
import main as main_root
from .. import socketio
from flask_socketio import emit
import json
from datetime import datetime
from .forms import AddNetworkForm, AddWirelessForm
import gevent


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
        print(openwrt.channel)
    return render_template('index.html', openwrts=openwrts, openwrt_subnet=openwrt_api.openwrt_network)


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
    form.network.choices = [("", "---")] + [(s.name, s.name) for s in Network.query.all()]
    if form.is_submitted():
        if form.validate():
            # vlan = 0
            # if form.is_vlan.data is True:
            #     vlan = int(form.vlan.data)
            wireless_network = WirelessNetwork(ssid=form.ssid.data,
                                               enabled=form.enabled.data,
                                               security_type=form.security.data,
                                               password=form.password.data
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
        form.network.choices = [("", "---")] + [(s.name, s.name) for s in Network.query.all()]
        form.is_edit = True
        if request.method == 'GET':
            form.ssid.data = wireless_name
            form.enabled.data = wireless.enabled
            form.security.data = wireless.security_type
            form.password.data = wireless.password
            form.network.data = wireless.network
            form.hide_ssid.data = wireless.hide_ssid
            form.isolate_clients.data = wireless.isolate_clients
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
                    wireless.network = form.network.data
                    wireless.hide_ssid = form.hide_ssid.data
                    wireless.isolate_clients = form.isolate_clients.data
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


@main.route('/clients', methods=['GET', 'POST'])
@login_required
def clients():
    openwrts = Openwrt.query.all()

    # ssid: ap_mgmt
    # client_mac:
    # client_ip:
    # signal:
    # noise:
    # tx_rate:
    # tx_packets:
    # rx_rate:
    # rx_packets:
    assoc_list = []
    for openwrt in openwrts:
        if openwrt.luci is False:
            continue

        wireless_devices = []
        all_devices = openwrt_api.get_luci_result(openwrt.ip_address, 'sys',
                                                  {"id": 1, "method": "net.devices", "params": []})

        for device in all_devices:
            if device.startswith("wlan"):
                wireless_devices.append(device)

        print(wireless_devices)

        arptable_raw = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
            "cat /proc/net/arp | tail -n +2 | awk '{print $1,$4}'"]})
        arptable_lines = arptable_raw.split('\n')
        arptable_dict = {}
        # arp_line: '192.168.1.147 ac:af:b9:5f:4a:5e\n
        for arp_line in arptable_lines:
            if not arp_line:
                break

            arp_line = arp_line.upper()
            arp_pair = arp_line.split(' ')
            arptable_dict[arp_pair[1]] = arp_pair[0]

        for wireless_device in wireless_devices:
            wireless_info = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "wifi.getiwinfo",
                                                                                    "params": [wireless_device]})

            stations = wireless_info['assoclist']
            if not stations:
                continue

            for client_mac in stations:
                client_info = {}
                client_assoc_info = stations[client_mac]

                client_info['ssid'] = wireless_info['ssid']
                client_info['client_mac'] = client_mac
                if client_mac in arptable_dict:
                    client_info['client_ip'] = arptable_dict[client_mac]
                else:
                    client_info['client_ip'] = 'Unknown'
                client_info['signal'] = client_assoc_info['signal']
                client_info['noise'] = client_assoc_info['noise']
                tx_rate_mbit = client_assoc_info['tx_rate'] / 1024.0
                client_info['tx_rate'] = f'{tx_rate_mbit:.1f}'
                client_info['tx_packets'] = client_assoc_info['tx_packets']
                rx_rate_mbit = client_assoc_info['rx_rate'] / 1024.0
                client_info['rx_rate'] = f'{rx_rate_mbit:.1f}'
                client_info['rx_packets'] = client_assoc_info['rx_packets']

                assoc_list.append(client_info)

    print(assoc_list)

    return render_template('clients.html', assoc_list=assoc_list)


@main.route('/openwrts/<string:openwrt_name>', methods=['GET', 'POST'])
@login_required
def openwrts(openwrt_name):
    openwrt = Openwrt.query.filter(func.lower(Openwrt.name) == func.lower(openwrt_name)).first()
    print('openwrt: ' + openwrt_name)
    if openwrt is None:
        return render_template('404.html')
    else:
        boardinfoJson = json.loads(
            openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
                "ubus call system board"]}))
        print(boardinfoJson)

        infoJson = json.loads(
            openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
                "ubus call system info"]}))
        print(infoJson)

        loadavg = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
            "cat /proc/loadavg"]})

        ifconfig = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
            "ifconfig"]})

        iwinfo = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
            "iwinfo"]})

        syslog = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "syslog", "params": []})
        dmesg = openwrt_api.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "dmesg", "params": []})

        return render_template('openwrt_detail.html', openwrt=openwrt, boardinfoJson=boardinfoJson,
                               infoJson=infoJson, uptime=openwrt_api.seconds_to_timeformat(
                infoJson['uptime']), localtime=datetime.utcfromtimestamp(infoJson['localtime']), loadavg=loadavg,
                               syslog=syslog, dmesg=dmesg, ifconfig=ifconfig, iwinfo=iwinfo)


@main.route('/img/<img>')
@login_required
def static_img(img):
    imgpath = 'img/' + img;
    return redirect(url_for('static', filename=imgpath))


######### AJAX API
@main.route('/openwrt/comment', methods=['POST'])
@login_required
def openwrt_comment():
    content = request.json
    pprint(content)
    openwrt = Openwrt.query.filter_by(name=content["openwrt_name"]).first()
    if openwrt is not None:
        openwrt.comment = content["comment"]
        # print('comment: ' + openwrt.comment)

        openwrt_comment = OpenwrtComments.query.filter_by(id=openwrt.eth0_mac).first()
        if openwrt_comment is None:
            new_comment = OpenwrtComments(id=openwrt.eth0_mac, comment=openwrt.comment)
            db.session.add(new_comment)
        else:
            openwrt_comment.comment = openwrt.comment

        db.session.commit()
        return jsonify(success=True)

    return jsonify(success=False), 404


@main.route('/openwrt/refresh_all', methods=['POST'])
@login_required
def refresh_all():
    if not main_root.glob_update_lock.acquire(blocking=0):
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": "",
                       "reason": "Cannot re-scan network - other OpenWrt update is in progress."},
                      namespace='/ws')
        return jsonify(success=False, message="Refresh already in progress"), 409

    gevent.spawn(openwrt_api.refresh_all_openwrts, main_root.app, main_root.glob_update_lock)

    return jsonify(success=True)


@main.route('/openwrt/refresh_status')
@login_required
def refresh_status():
    return openwrt_api.refresh_status.to_json()


@main.route('/openwrt/update/<openwrt_name>', methods=['POST'])
@login_required
def update_openwrt(openwrt_name):
    print('openwrt update')
    return jsonify(success=True)


@socketio.on('connect', namespace='/ws')
@login_required
def test_connect():
    socketio.emit('refresh_status', openwrt_api.refresh_status.toJSON(), namespace='/ws')


@socketio.on('update_channel', namespace='/ws')
@login_required
def ws_update_openwrt(msg):
    openwrt_name = msg['openwrt_name']
    channel = msg['channel']

    if openwrt_name is None:
        print('not ok')

    openwrt = Openwrt.query.filter(func.lower(Openwrt.name) == func.lower(openwrt_name)).first()
    if openwrt is None:
        return render_template('404.html')

    # glob_update_lock.acquire()

    if not main_root.glob_update_lock.acquire(blocking=0):
        main_root.glob_update_lock.release()
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": openwrt_name,
                       "reason": "Cannot update channel, another update is running."},
                      namespace='/ws')
        return

    openwrt.update_in_progress = True
    db.session.commit()

    main_root.glob_update_lock.release()

    openwrt_api.call_luci(openwrt.ip_address, 'uci',
                          {'method': 'set', 'params': ["wireless", "radio0", "channel", channel]})

    ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci', {"method": "commit", "params": ["wireless"]})
    if ret is not "-":
        socketio.emit('update_status', {"status_type": "finished", "openwrt_name": openwrt_name},
                      namespace='/ws')
        openwrt.channel = msg['channel']
    else:
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": openwrt_name,
                       "reason": "Channel update failed."},
                      namespace='/ws')

    openwrt.update_in_progress = False
    db.session.commit()

    return


@socketio.on('update_openwrt', namespace='/ws')
@login_required
def ws_update_openwrt(msg):
    openwrt_name = msg['openwrt_name']
    if openwrt_name is None:
        print('not ok')

    print('openwrt update')
    openwrt = Openwrt.query.filter(func.lower(Openwrt.name) == func.lower(openwrt_name)).first()
    print('openwrt: ' + openwrt_name)
    if openwrt is None:
        return render_template('404.html')

    # if not openwrt.update_lock.acquire(blocking=False):
    #     socketio.emit('update_status',
    #                   {"status_type": "error", "openwrt_name": openwrt_name, "reason": "Update is already in progress."},
    #                   namespace='/ws')
    #     return

    # this prevents race conditions, database "test-and-set" is not really atomic
    # glob_update_lock.acquire()

    if not main_root.glob_update_lock.acquire(blocking=0):
        # glob_update_lock.release()
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": openwrt_name,
                       "reason": "Update is already in progress."},
                      namespace='/ws')
        return

    openwrt.update_in_progress = True
    db.session.commit()

    socketio.emit('update_status', {"status_type": "started", "openwrt_name": openwrt_name}, namespace='/ws')

    # Delete all non-default networks
    # - all anonymous interfaces
    # - all switch vlans > 2
    all_network = openwrt_api.get_luci_result(openwrt.ip_address, 'uci',
                                              {"id": 1, "method": "get_all", "params": ["network"]})
    if all_network is "-":
        # openwrt.update_lock.release()
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": openwrt_name, "reason": "LuCI error."},
                      namespace='/ws')
        openwrt.update_in_progress = False
        db.session.commit()
        main_root.glob_update_lock.release()
        return
    print(all_network)

    network_whitelist = ["wan_dev", "lan_dev", "wan6", "globals", "loopback", "lan", "wan"]
    networks_to_delete = []
    for key in all_network:
        network_info = all_network[key]
        if key in network_whitelist:
            continue
        if network_info[".type"] == "switch_vlan":
            if network_info["vlan"] != "1" and network_info["vlan"] != "2":
                networks_to_delete.append(key)
        if network_info[".type"] == "interface":
            networks_to_delete.append(key)

    print("will delete networks: " + str(networks_to_delete))

    for nw in networks_to_delete:
        print('deleting network: ' + nw)
        ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci', {"method": "delete", "params": ["network", nw]})
        if ret is not "-":
            print('deleted: ' + nw)
        else:
            print('could not delete: ' + nw)

    curr_vlan_idx = 3
    conf_networks = Network.query.all()
    for nw in conf_networks:
        # 1) Create VLAN on OpenWrt switch
        ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci',
                                          {"method": "section",
                                           "params": ["network", "switch_vlan", "switch_vlan_" + str(nw.vlan),
                                                      {"device": "switch0",
                                                       "ports": "0t 4t",
                                                       "vlan": str(curr_vlan_idx),
                                                       "vid": str(nw.vlan)}]})
        curr_vlan_idx += 1

        # 2) Create Network
        ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci',
                                          {"method": "section",
                                           "params": ["network", "interface", nw.name,
                                                      {"proto": "none",
                                                       "type": "bridge",
                                                       "ifname": "eth0." + str(nw.vlan)}]})

    # Wireless
    all_wireless = openwrt_api.get_luci_result(openwrt.ip_address, 'uci',
                                               {"id": 1, "method": "get_all", "params": ["wireless"]})
    if all_wireless is "-":
        # openwrt.update_lock.release()
        socketio.emit('update_status',
                      {"status_type": "error", "openwrt_name": openwrt_name, "reason": "LuCI error."},
                      namespace='/ws')
        openwrt.update_in_progress = False
        db.session.commit()
    print("will delete wireless: " + str(all_wireless))

    # First delete all wireless interfaces on the device
    wifis_to_delete = []
    for key in all_wireless:
        if not key.startswith('radio'):
            wifis_to_delete.append(key)

    for wifi in wifis_to_delete:
        print('deleting wifi: ' + wifi)
        ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci', {"method": "delete", "params": ["wireless", wifi]})
        if ret is not "-":
            print('deleted: ' + wifi)
        else:
            print('could not delete: ' + wifi)

    conf_wireless_networks = WirelessNetwork.query.all()
    for wifi in conf_wireless_networks:

        if not wifi.enabled:
            continue

        ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci',
                                          {"method": "section",
                                           "params": ["wireless", "wifi-iface", wifi.ssid,
                                                      {"device": "radio0",
                                                       "mode": "ap",
                                                       "ssid": wifi.ssid,
                                                       "network": wifi.network}]})
        if wifi.security_type == "Open":
            openwrt_api.call_luci(openwrt.ip_address, 'uci',
                                  {'method': 'set', 'params': ["wireless", wifi.ssid, "encryption", "none"]})
        else:
            openwrt_api.call_luci(openwrt.ip_address, 'uci',
                                  {'method': 'set', 'params': ["wireless", wifi.ssid, "encryption", "psk2"]})
            openwrt_api.call_luci(openwrt.ip_address, 'uci',
                                  {'method': 'set', 'params': ["wireless", wifi.ssid, "key", wifi.password]})

        openwrt_api.call_luci(openwrt.ip_address, 'uci',
                              {'method': 'set', 'params': ["wireless", wifi.ssid, "hidden", wifi.hide_ssid * 1]})
        openwrt_api.call_luci(openwrt.ip_address, 'uci',
                              {'method': 'set', 'params': ["wireless", wifi.ssid, "isolate", wifi.isolate_clients * 1]})

    # ret = openwrt_api.get_luci_result(openwrt, 'uci', {"method": "apply", "params": ["network", "wireless"]})
    # if ret is not "-":
    #     print('wireless changes commited')

    ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci', {"method": "commit", "params": ["network"]})
    if ret is not "-":
        print('network changes commited')

    ret = openwrt_api.get_luci_result(openwrt.ip_address, 'uci', {"method": "commit", "params": ["wireless"]})
    if ret is not "-":
        print('wireless changes commited')

    socketio.emit('update_status', {"status_type": "finished", "openwrt_name": msg['openwrt_name']}, namespace='/ws')

    # openwrt.update_lock.release()
    openwrt.update_in_progress = False
    db.session.commit()
    main_root.glob_update_lock.release()

    return

##################################
