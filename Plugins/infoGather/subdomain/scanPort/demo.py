import requests

url = r'http://127.0.0.1:9080/'
res = requests.get(url=url, timeout=10, verify=False)