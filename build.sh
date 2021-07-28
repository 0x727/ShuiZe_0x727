#!/bin/bash
apt install python3 -y
apt install python3-pip --fix-missing -y
apt install python3-setuptools -y
apt install tmux -y
python3 -m pip install --upgrade pip
python3 -m pip install openpyxl==2.6.4
python3 -m pip install Cython
python3 -m pip install -r requirements.txt
chmod 777 ./Plugins/infoGather/subdomain/ksubdomain/ksubdomain_linux