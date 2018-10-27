import os
import sys
import time
from .. import db
from ..models import Openwrt
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
        self.is_windows = system_name().lower() == "windows"
        self.refresh_strategy = refresh_strategy
        # TODO: change later to read from config
        self.luci_username = ''
        self.luci_password = ''
        self.ssh_username = ''
        self.ssh_password = ''
        self.ssh_keyfile = ''


    def init_app(self, app):
        self.luci_username = app.config['OPENWRT_USERNAME']
        self.luci_password = app.config['OPENWRT_PASSWORD']
        self.ssh_username = app.config['OPENWRT_USERNAME']
        self.ssh_password = app.config['OPENWRT_PASSWORD']
        self.ssh_keyfile = app.config['OPENWRT_SSH_KEYFILE']


    ######################### Controller -> OpenWRT common methods

    def test_ping(self, ip_address):
        parameters = "-n 2 -w 2000 > nul" if system_name().lower() == "windows" else "-c 2 -W 2 >/dev/null"
        return system_call("ping " + parameters + " " + ip_address) == 0

    def test_luci(self, ip_address, username, password):
        ret = False
        # endpoint = "http://" + ip_address + "/cgi-bin/luci/rpc/sys"
        # payload = {"id": "1", "method": "hostname", "params": []}
        endpoint = "http://" + ip_address + "/cgi-bin/luci/rpc/auth"
        payload = {"id": "1", "method": "login", "params": [username, password]}

        print('endpoint:' + endpoint)
        try:
            r = requests.post(endpoint, json=payload, timeout=2)
            print(r.text)
            print(r.status_code)
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

    def get_luci_auth_token(self, openwrt):
        endpoint = "http://" + openwrt.ip_address + "/cgi-bin/luci/rpc/auth"
        payload = {"id": "1234", "method": "login", "params": [self.luci_username, self.luci_password]}

        try:
            r = requests.post(endpoint, json=payload, timeout=2)
            response_json = json.loads(r.text)
            if r.status_code == 200 and response_json["result"] is not None:
                print('LuCI auth OK')
                return response_json["result"]
        except Exception as e:
            print('luci post failed:')
            print(e)

        return None

    # @openwrt: db model
    # @lib: uci, fs, sys, ipkg, auth
    # @json_data: in json, sent to openwrt
    def call_luci(self, openwrt, lib, json_data, auth_retry=True, timeout=2):
        print('call_luci: ' + openwrt.ip_address + ', ' + lib + ', ' + str(json_data))

        endpoint = "http://" + openwrt.ip_address + "/cgi-bin/luci/rpc/" + lib + "?auth=" + openwrt.auth_token

        try:
            req = requests.post(endpoint, json=json_data, timeout=timeout)
            if req.status_code == 403:
                if auth_retry == True:
                    print('call_luci: Forbidden, retrying')
                    auth_token = self.get_luci_auth_token(openwrt)
                    if auth_token is not None:
                        print('call_luci: retry login OK')
                        openwrt.auth_token = auth_token
                        return self.call_luci(openwrt, lib, json_data, auth_retry=False)
                    else:
                        print('call_luci: retry login failed')
                        return None
                else:
                    print('call_luci: Forbidden')
                    return None
            elif req.status_code == 200:
                print('call_luci: OK')
                return json.loads(req.text)
            else:
                print('call failed. status_code: ' + str(req.status_code) + ', reply: ' + req.text)
        except Exception as e:
            print("call_luci failed: " + str(e))
            return None

        return None

    def get_hostname(self, auth_retry=True):

        return ""

    ######################### OpenWRTs status refresh

    def test_and_set_refresh(self):
        with self.refresh_lock:
            if self.is_refreshing is True:
                return False
            else:
                self.is_refreshing = True
                return True

    def refresh_all_openwrts(self, app):
        with app.app_context():
            self.is_refreshing = True

            openwrts = Openwrt.query.all()

            self.refresh_status.total_openwrts = len(openwrts)
            self.refresh_status.updated_openwrts = 0
            for openwrt in openwrts:
                try:
                    self.refresh_status.current_openwrt = openwrt.name
                    socketio.emit('refresh_status', self.refresh_status.toJSON(), namespace='/ws')

                    # If ping fails dont try anything else
                    openwrt.ping = self.test_ping(openwrt.ip_address)
                    if openwrt.ping == False:
                        # Invalidate everything
                        openwrt.luci = False
                        openwrt.ssh = False
                        openwrt.hostname = '-'
                        openwrt.firmware = '-'
                        openwrt.uptime = '-'
                        openwrt.clients = '-'
                        openwrt.down = '-'
                        openwrt.up = '-'
                    else:
                        openwrt.luci = self.test_luci(openwrt.ip_address, app.config['OPENWRT_USERNAME'],
                                                       app.config['OPENWRT_PASSWORD']
                                                       )
                        openwrt.ssh = self.test_ssh(openwrt.ip_address, app.config['OPENWRT_USERNAME'],
                                                    app.config['OPENWRT_PASSWORD'], app.config['OPENWRT_SSH_KEYFILE'])

                        hostname_result = self.call_luci(openwrt, 'sys', {"id": 1, "method": "hostname", "params": []})
                        if hostname_result != None:
                            openwrt.hostname = hostname_result["result"]

                        fw_version = self.call_luci(openwrt, 'sys', {"id": 1, "method": "exec", "params": [
                            "source /etc/openwrt_release; echo $DISTRIB_DESCRIPTION"]})
                        if fw_version != None:
                            openwrt.firmware = fw_version["result"]

                        uptime_result = self.call_luci(openwrt, 'sys', {"id": 1, "method": "uptime", "params": []})
                        if uptime_result != None:
                            openwrt.uptime = time.strftime("%Hh %Mm %Ss", time.gmtime(int(uptime_result["result"])))

                    db.session.commit()

                    self.refresh_status.updated_openwrts += 1
                    self.refresh_status.timestamp = time.time()

                    socketio.emit('openwrt_refreshed', openwrt.__json__(), namespace='/ws')

                except Exception as e:
                    print('Exception:')
                    print(e)
                    continue

            socketio.emit('refresh_status', self.refresh_status.toJSON(), namespace='/ws')

            self.is_refreshing = False

    def refresh_openwrt(self, openwrt_name):
        self.refresh_status.total_openwrts = 1
        self.refresh_status.updated_openwrts = 0
        for x in range(0, self.refresh_status.total_openwrts):
            time.sleep(0.5)
            self.refresh_status.updated_openwrts += 1
            self.refresh_status.timestamp = time.time()
