from dotenv import load_dotenv
from pathlib import Path

# Load config
env_path = Path('.') / 'config.env'
load_dotenv(dotenv_path=env_path)

import os
from gevent import monkey

monkey.patch_all()
from flask_migrate import Migrate
from app import create_app, db, socketio
from app.models import User, Openwrt, Network, WirelessNetwork
from app.main import openwrt_api
from time import sleep
from threading import Thread
import gevent
import json
from threading import Lock


# Create and initialize flask application and its components
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
glob_update_lock = Lock()


recreate_db=True

# Create default database configurations
with app.app_context():
    if recreate_db is True:
        db.drop_all()
        db.create_all()

        with open('data/openwrts.json') as openwrtJsonFile:
            openwrtsJson = json.load(openwrtJsonFile)

        for openwrtJson in openwrtsJson["openwrts"]:
            openwrt = Openwrt(name=openwrtJson["name"], ip_address=openwrtJson["ip_address"])
            db.session.add(openwrt)

        with open('data/networks_default.json') as networksJsonFile:
            networksJson = json.load(networksJsonFile)

        for networkJson in networksJson["networks"]:
            network = Network(name=networkJson["name"],
                              network_addr=networkJson["network_addr"],
                              gateway=networkJson["gateway"],
                              vlan=networkJson["vlan"],
                              is_dhcp_mode=networkJson["is_dhcp_mode"],
                              dhcp_range_from=networkJson["dhcp_range_from"],
                              dhcp_range_to=networkJson["dhcp_range_to"],
                              dhcp_lease_time=networkJson["dhcp_lease_time"])
            db.session.add(network)

        with open('data/ssid_default.json') as wirelessNetworksJsonFile:
            ssidsJson = json.load(wirelessNetworksJsonFile)

        for ssidJson in ssidsJson["ssids"]:
            ssid = WirelessNetwork(ssid=ssidJson["ssid"],
                                   enabled=ssidJson["enabled"],
                                   security_type=ssidJson["security_type"],
                                   password=ssidJson["password"],
                                   vlan=ssidJson["vlan"],
                                   network=ssidJson["network"])
            db.session.add(ssid)

    # Always create user from config file
    db.session.query(User).delete()
    login_user = User(username=app.config['LOGIN_USERNAME'], password=app.config['LOGIN_PASSWORD'])
    db.session.add(login_user)

    db.session.commit()


scan_interval = int(app.config['OPENWRT_SCAN_INTERVAL_SECONDS'])

def background_refresh_job(app):
    """Spawns OpenWrt network scan at configured intervals"""

    while True:
        sleep(scan_interval)

        # Get lock
        if glob_update_lock.acquire(blocking=0):
            print('Spawning refresh_all_openwrts job ...')
            # Refresh OpenWRTs in background
            gevent.spawn(openwrt_api.refresh_all_openwrts, app, glob_update_lock)


if scan_interval is not 0:
    refresh_thread = Thread(target=background_refresh_job, args=[app])
    refresh_thread.setDaemon(True)
    refresh_thread.start()

migrate = Migrate(app, db)


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User)


@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


if __name__ == '__main__':
    socketio.run(app, debug=True, threaded=True)
