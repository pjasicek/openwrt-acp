import os
import sys
import time
from .. import db
from ..models import Openwrt, OpenwrtComments
from threading import Lock
from platform import system as system_name
from .. import socketio
import json
from datetime import datetime
import paramiko
from paramiko import SSHClient, SSHConfig
import requests
import socket
import ipaddress
import gevent


class RefreshStatus():
    """Contains snapshot of last network scan status"""
    total_openwrts = 0
    updated_openwrts = 0
    current_openwrt = ""
    timestamp = time.time()

    def toJSON(self):
        json = {'total_openwrts': self.total_openwrts, 'updated_openwrts': self.updated_openwrts,
                'current_openwrt': self.current_openwrt,
                'timestamp': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S %d.%m.%Y')}
        return json


class OpenwrtApi():
    """Class used for communcation with OpenWrt via JSON-RPC"""

    def __init__(self):
        self.refresh_status = RefreshStatus()
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
        """Tests if port 80 is reachable on given @ip_address. Returns True if port is reachable"""

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

    def test_luci(self, ip_address, username, password):
        """
        Tests if LuCI interface is available

        Arguments:
        ip_address: OpenWrt IP address
        username: LuCI login username (should be same as SSH)
        password: LuCI login password (should be same as SSH)

        Returns:
            True if luci can be accessed, false otherwise
        """

        ret = False
        endpoint = "http://" + ip_address + "/cgi-bin/luci/rpc/auth"
        payload = {"id": "1", "method": "login", "params": [username, password]}

        try:
            r = requests.post(endpoint, json=payload, timeout=5)
            response_json = json.loads(r.text)
            if r.status_code == 200 and response_json["result"] is not None:
                ret = True
        except Exception as e:
            print('luci post failed:')
            print(e)

        return ret

    def test_ssh(self, ip_address, username, password, key):
        """
        Tests if SSH connection is available

        Arguments:
        ip_address: IP address where SSH server runs
        username: SSH username
        password: SSH password
        key: SSH private key file (preferred method of authentication)

        Returns:
            True if SSH can be connected to
        """
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_address, username=username, password=password,
                        key_filename=key, timeout=2)

            return ssh.get_transport().is_active()
        except Exception as e:
            return False

    def get_luci_auth_token(self, openwrt_ip):
        """
        Gets authentication token from LuCI for further protected requests

        Arguments:
        ip_address: OpenWrt IP address

        Returns:
            Authentication token (string) on success, None on failure
        """
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

    def call_luci(self, openwrt_ip, lib, json_data, auth_retry=True, timeout=5):
        """
        Sends HTTP POST request to LuCI conforming to JSON-RPC API

        Arguments:
        openwrt_ip: OpenWrt IP address
        lib: JSON-RPC library - 'uci', 'sys', 'fs' or 'ipkg'
        json_data: JSON data to be passed as requuest payload
        auth_retry: Retry on first failure caused by unauthorized access (try to reauthenticate)
        timeout: Request max timeout

        Returns:
            JSON response on success, None on failure
        """

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

    def get_luci_result(self, openwrt_ip, lib, json_data):
        """Simple wrapper over call_luci - directly returns result JSON or '-' on failure"""

        ret = self.call_luci(openwrt_ip, lib, json_data)
        if ret is None:
            return "-"
        # print(ret)
        if ret["result"] is None:
            return "-"
        return ret["result"]

    def seconds_to_timeformat(self, seconds, granularity=4):
        """
        Formats number of seconds to pretty time string

        Arguments:
        seconds: Number of seconds
        granularity: Granularity of the output (if granularity=2 then string contains only minutes and seconds)

        Returns:
            Time string
        """
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

    def test_openwrt_ping_async(self, ip_address, openwrt_list):
        """
        Asynchronously tests if openwrt port 80 is reachable on the network

        Arguments:
        ip_address: openwrt IP address
        openwrt_list: Where to store the result

        Returns:
            Nothing
        """

        ping_ok = self.test_ping(ip_address)
        if ping_ok is True:
            openwrt_list.append(ip_address)

    def scan_mgmt_network(self, range):
        """
        Scans availability of all openwrts on given network

        Arguments:
        range: Network subnet strubg, e.g. '192.168.1.0/24'

        Returns:
            List of reachable openwrt ip addresses on given network segment
        """

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
        """
        Scans the openwrt subnet and refreshes status of all openwrts in it.
        This method drops Openwrt database table and fills again with latest values.

        Arguments:
        app: Flask application context
        lock: Lock object for OpenWrt access synchronization - released when update is done

        Returns:
            Nothing
        """

        with app.app_context():
            self.is_refreshing = True

            # Discover all of them first
            openwrt_online_list = self.scan_mgmt_network(self.openwrt_network)

            print(openwrt_online_list)

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

                    # print(openwrt.__json__())
                    # socketio.emit('openwrt_refreshed', openwrt.__json__(), namespace='/ws')

                except Exception as e:
                    print('Exception:')
                    print(e)

                    db.session.add(openwrt)
                    db.session.commit()

                    continue

            self.active_openwrts = curr_active_openwrts
            socketio.emit('refresh_status', self.refresh_status.toJSON(), namespace='/ws')

            # openwrts = Openwrt.query.all()
            # table = render_template('openwrt_overview_table.html', openwrts=openwrts)
            # socketio.emit('openwrts_updated', {"table": table}, namespace='/ws')
            socketio.emit('openwrts_updated', {"status": "ok"}, namespace='/ws')

            lock.release()
