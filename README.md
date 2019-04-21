# OpenWrt ACP

OpenWrt ACP is a web tool which is used for centralized configuration of multiple OpenWrt access points. In the tool you define VLANs + ESSIDs and then deploy this configuration to OpenWrt devices in the managed network.

## Requirements

* Python 3.7

## Installation and running

```
git clone https://github.com/pjasicek/openwrt-acp
$ cd openwrt-acp
$ pip install -r requirements.txt   # You can setup python virtual environment if you do not want these packages system-wide
$ FLASK_APP=main.py           # on Windows: $ set FLASK_APP=main.py
$ FLASK_ENV=development       # on Windows: $ set FLASK_ENV=development 
$ FLASK_DEBUG=0               # on Windows: $ set FLASK_DEBUG=0
$ python -m flask run --with-threads
```

## Configuration
See config.env file for configuration (users/passwords, openwrt ap subnet)

## Screenshots

![alt tag](https://i.postimg.cc/HL59gXnG/screenshot-156.png)
![alt tag](https://i.postimg.cc/jSnzHPzW/screenshot-157.png)
![alt tag](https://i.postimg.cc/7LvSmhVK/screenshot-158.png)
![alt tag](https://i.postimg.cc/MTqVJLgR/screenshot-159.png)
