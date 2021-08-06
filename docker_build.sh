#!/bin/bash
apt install python3-setuptools -y
python3 -m pip install -r requirements.txt
chmod 777 ./Plugins/infoGather/subdomain/ksubdomain/ksubdomain_linux