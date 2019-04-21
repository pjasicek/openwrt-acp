import os
import sys
import time
from .. import db
from ..models import Openwrt, OpenwrtComments
from flask import jsonify
from threading import Lock
from platform import system as system_name
from .. import socketio
import json
from datetime import datetime
from os import system as system_call
import paramiko
from paramiko import SSHClient, SSHConfig
import requests
import config
import gevent
import socket
import ipaddress
import gevent
from flask import render_template


class RefreshStatus():
    total_openwrts = 0
    updated_openwrts = 0
    current_openwrt = ""
    timestamp = time.time()

    def toJSON(self):
        json = {'total_openwrts': self.total_openwrts, 'updated_openwrts': self.updated_openwrts,
                'current_openwrt': self.current_openwrt,
                'timestamp': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S %d.%m.%Y')}
        return json


class RefrehStrategy():
    TRY_EVERYTHING = 1
    SSH_ONLY = 2


class OpenwrtApi():
    def __init__(self, refresh_strategy=RefrehStrategy.TRY_EVERYTHING):
        self.is_refreshing = False
        self.refresh_status = RefreshStatus()
        self.refresh_lock = Lock()
        self.assoc_clients_update_lock = Lock()
        self.is_updating_assoc_clients = False
        self.is_windows = system_name().lower() == "windows"
        # TODO: change later to read from config
        self.luci_username = ''
        self.luci_password = ''
        self.ssh_username = ''
        self.ssh_password = ''
        self.ssh_keyfile = ''
        self.openwrt_token_cache = {}
        self.active_openwrts = {}
        self.openwrt_network = ''

        self.intervals = (
            ('d', 86400),  # 60 * 60 * 24
            ('h', 3600),  # 60 * 60
            ('m', 60),
        )

    def init_app(self, app):
        self.luci_username = app.config['OPENWRT_USERNAME']
        self.luci_password = app.config['OPENWRT_PASSWORD']
        self.ssh_username = app.config['OPENWRT_USERNAME']
        self.ssh_password = app.config['OPENWRT_PASSWORD']
        self.ssh_keyfile = app.config['OPENWRT_SSH_KEYFILE']
        self.openwrt_network = app.config['OPENWRT_NETWORK']

    ######################### Controller -> OpenWRT common methods

    def test_ping(self, ip_address):
        # Test if http port is open - more reliable and faster than ping
        # - if the port is not open, luci is not working => we dont need to try anything else
        s = socket.socket()
        s.settimeout(1.0)
        ok = False
        try:
            s.connect((ip_address, 80))
            ok = True
        except Exception as e:
            ok = False
        finally:
            s.close()

        if ok is True:
            print("OK for: " + ip_address)

        return ok

        # cmd = "ping -n 2 -w 2000 " + ip_address + " > nul" if system_name().lower() == "windows" \
        #    else "ping -c 2 -W 2 " + ip_address + " >/dev/null"
        # p = gevent.subprocess.Popen(cmd, stdout=gevent.subprocess.PIPE, stderr=gevent.subprocess.PIPE, shell=True)
        # p.wait(10.0)
        # return p.returncode == 0

    def test_luci(self, ip_address, username, password):
        ret = False
        # endpoint = "http://" + ip_address + "/cgi-bin/luci/rpc/sys"
        # payload = {"id": "1", "method": "hostname", "params": []}
        endpoint = "http://" + ip_address + "/cgi-bin/luci/rpc/auth"
        payload = {"id": "1", "method": "login", "params": [username, password]}

        print('endpoint:' + endpoint)
        try:
            r = requests.post(endpoint, json=payload, timeout=5)
            # print(r.text)
            # print(r.status_code)
            response_json = json.loads(r.text)
            if r.status_code == 200 and response_json["result"] is not None:
                ret = True
        except Exception as e:
            print('luci post failed:')
            print(e)

        return ret

    def test_ssh(self, ip_address, username, password, key):
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_address, username=username, password=password,
                        key_filename=key, timeout=2)

            return ssh.get_transport().is_active()
        except Exception as e:
            return False

    def get_luci_auth_token(self, openwrt_ip):
        endpoint = "http://" + openwrt_ip + "/cgi-bin/luci/rpc/auth"
        payload = {"id": "1234", "method": "login", "params": [self.luci_username, self.luci_password]}

        try:
            r = requests.post(endpoint, json=payload, timeout=5)
            response_json = json.loads(r.text)
            if r.status_code == 200 and response_json["result"] is not None:
                # print('LuCI auth OK')
                return response_json["result"]
        except Exception as e:
            print('luci post failed:')
            print(e)

        return None

    # @openwrt: db model
    # @lib: uci, fs, sys, ipkg, auth
    # @json_data: in json, sent to openwrt
    def call_luci(self, openwrt_ip, lib, json_data, auth_retry=True, timeout=5):
        # print('call_luci: ' + openwrt.ip_address + ', ' + lib + ', ' + str(json_data))

        auth_token = ''
        if openwrt_ip in self.openwrt_token_cache:
            auth_token = self.openwrt_token_cache[openwrt_ip]
        endpoint = "http://" + openwrt_ip + "/cgi-bin/luci/rpc/" + lib + "?auth=" + auth_token

        try:
            req = requests.post(endpoint, json=json_data, timeout=timeout)
            if req.status_code == 403:
                if auth_retry == True:
                    # print('call_luci: Forbidden, retrying')
                    auth_token = self.get_luci_auth_token(openwrt_ip)
                    if auth_token is not None:
                        # print('call_luci: retry login OK')
                        self.openwrt_token_cache[openwrt_ip] = auth_token
                        return self.call_luci(openwrt_ip, lib, json_data, auth_retry=False)
                    else:
                        print('call_luci: retry login failed')
                        return None
                else:
                    # print('call_luci: Forbidden')
                    return None
            elif req.status_code == 200:
                # print('call_luci: OK')
                return json.loads(req.text)
            else:
                print('call failed. status_code: ' + str(req.status_code) + ', reply: ' + req.text)
        except Exception as e:
            print("call_luci failed: " + str(e))
            return None

        return None

    def get_hostname(self, auth_retry=True):

        return ""

    def get_luci_result(self, openwrt_ip, lib, json_data):
        ret = self.call_luci(openwrt_ip, lib, json_data)
        if ret is None:
            return "-"
        # print(ret)
        if ret["result"] is None:
            return "-"
        return ret["result"]

    def seconds_to_timeformat(self, seconds, granularity=4):
        result = []

        for name, count in self.intervals:
            value = seconds // count
            if value:
                seconds -= value * count
                if value == 1:
                    name = name.rstrip('s')
                result.append("{}{}".format(value, name))
        return ' '.join(result[:granularity])

    ######################### OpenWRTs status refresh

    def test_and_set_refresh(self):
        with self.refresh_lock:
            if self.is_refreshing is True:
                return False
            else:
                self.is_refreshing = True
                return True

    def test_and_set_assoc_clients(self):
        with self.assoc_clients_update_lock:
            if self.is_updating_assoc_clients is True:
                return False
            else:
                self.is_updating_assoc_clients = True
                return True

    def test_openwrt_ping_async(self, ip_address, openwrt_list):
        ping_ok = self.test_ping(ip_address)
        if ping_ok is True:
            openwrt_list.append(ip_address)

    def scan_mgmt_network(self, range):
        openwrt_list = []
        pool = gevent.pool.Pool(255)
        for ip in ipaddress.IPv4Network(range):
            ip_string = str(ip)
            if ip_string.endswith('.0') or ip_string.endswith('.255'):
                continue

            # This will will self.openwrt_list with available openwrts in the predefined mgmt network
            pool.spawn(self.test_openwrt_ping_async, ip_string, openwrt_list)

        pool.join()

        return openwrt_list

    def refresh_all_openwrts(self, app, lock):
        with app.app_context():
            self.is_refreshing = True

            # Discover all of them first
            openwrt_online_list = self.scan_mgmt_network(self.openwrt_network)

            print(openwrt_online_list)

            openwrts = Openwrt.query.all()

            curr_active_openwrts = {}
            self.refresh_status.total_openwrts = len(openwrt_online_list)
            self.refresh_status.updated_openwrts = 0

            # Clear from database
            db.session.query(Openwrt).delete()

            for openwrt_ip in openwrt_online_list:
                openwrt = Openwrt()
                openwrt.name = "OpenWRT" + openwrt_ip[openwrt_ip.rfind('.') + 1:]
                openwrt.ip_address = openwrt_ip

                try:
                    self.refresh_status.current_openwrt = openwrt.name
                    socketio.emit('refresh_status', self.refresh_status.toJSON(), namespace='/ws')

                    # If ping fails dont try anything else
                    openwrt.ping = self.test_ping(openwrt.ip_address)

                    if openwrt.ping == False:
                        # Invalidate everything
                        openwrt.ping = False
                        openwrt.luci = False
                        openwrt.ssh = False
                        openwrt.hostname = '-'
                        openwrt.firmware = '-'
                        openwrt.uptime = '-'
                        openwrt.clients = '-'
                        openwrt.channel = 'auto'
                    else:
                        openwrt.luci = self.test_luci(openwrt.ip_address, app.config['OPENWRT_USERNAME'],
                                                      app.config['OPENWRT_PASSWORD']
                                                      )
                        openwrt.ssh = self.test_ssh(openwrt.ip_address, app.config['OPENWRT_USERNAME'],
                                                    app.config['OPENWRT_PASSWORD'], app.config['OPENWRT_SSH_KEYFILE'])

                        boardinfoJson = json.loads(
                            self.get_luci_result(openwrt.ip_address, 'sys', {"id": 1, "method": "exec", "params": [
                                "ubus call system board"]}))

                        openwrt.hostname = boardinfoJson['hostname']
                        openwrt.firmware = boardinfoJson['release']['description']

                        uptime_result = self.get_luci_result(openwrt.ip_address, 'sys',
                                                             {"id": 1, "method": "uptime", "params": []})
                        openwrt.uptime = self.seconds_to_timeformat(uptime_result)

                        openwrt.channel = self.get_luci_result(openwrt.ip_address, 'uci',
                                                               {"id": 1, "method": "get",
                                                                "params": ["wireless", "radio0", "channel"]})

                        openwrt.eth0_mac = self.get_luci_result(openwrt.ip_address, 'sys',
                                                                {"id": 1, "method": "exec", "params": [
                                                                    "cat /sys/class/net/eth0/address"]})

                        # Get associated stations
                        num_clients = 0
                        wireless_devices = []
                        all_devices = self.get_luci_result(openwrt.ip_address, 'sys',
                                                                  {"id": 1, "method": "net.devices", "params": []})
                        for device in all_devices:
                            if device.startswith("wlan"):
                                wireless_devices.append(device)

                        for wireless_device in wireless_devices:
                            wireless_info = self.get_luci_result(openwrt.ip_address, 'sys',
                                                                        {"id": 1, "method": "wifi.getiwinfo",
                                                                         "params": [wireless_device]})
                            stations = wireless_info['assoclist']
                            if not stations:
                                continue
                            else:
                                for client_mac in stations:
                                    num_clients += 1

                        openwrt.clients = num_clients

                        # Match comment to stored eth0_mac:comment pair if applicable
                        openwrt_comment = OpenwrtComments.query.filter_by(id=openwrt.eth0_mac).first()
                        if openwrt_comment is not None:
                            openwrt.comment = openwrt_comment.comment

                    db.session.add(openwrt)

                    db.session.commit()

                    self.refresh_status.updated_openwrts += 1
                    self.refresh_status.timestamp = time.time()

                    curr_active_openwrts[openwrt.ip_address] = openwrt.__json__()

                    print(openwrt.__json__())

                    # socketio.emit('openwrt_refreshed', openwrt.__json__(), namespace='/ws')

                except Exception as e:
                    print('Exception:')
                    print(e)

                    db.session.add(openwrt)
                    db.session.commit()

                    continue

            self.active_openwrts = curr_active_openwrts
            socketio.emit('refresh_status', self.refresh_status.toJSON(), namespace='/ws')

            #openwrts = Openwrt.query.all()
            #table = render_template('openwrt_overview_table.html', openwrts=openwrts)
            #socketio.emit('openwrts_updated', {"table": table}, namespace='/ws')
            socketio.emit('openwrts_updated', {"status":"ok"}, namespace='/ws')

            lock.release()
            self.is_refreshing = False

    def refresh_openwrt(self, openwrt_name):
        self.refresh_status.total_openwrts = 1
        self.refresh_status.updated_openwrts = 0
        for x in range(0, self.refresh_status.total_openwrts):
            time.sleep(0.5)
            self.refresh_status.updated_openwrts += 1
            self.refresh_status.timestamp = time.time()
