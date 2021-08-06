apt-get update
apt install git --fix-missing -y
apt install vim -y
apt install tmux -y
rm /usr/bin/python3
ln -s /usr/local/bin/python3.8 /usr/bin/python3
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
chmod 777 ./Plugins/infoGather/subdomain/ksubdomain/ksubdomain_linux