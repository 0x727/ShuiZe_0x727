import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from queue import Queue
from threading import Thread
import json
import re

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
TIMEOUT = 10

def get_ip_address(ip_Queue, ip_address_dict, num):
    while not ip_Queue.empty():
        ip = ip_Queue.get()
        url = r'http://whois.pconline.com.cn/ipJson.jsp?ip={}&json=true'.format(ip)
        try:
            res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
            text = res.text
            json_text = json.loads(text)
            address = json_text['addr']
            ip_address_dict[ip] = address
            print('[{}] {}'.format(ip, address))
        except Exception as e:
            print('[error] get_ip_address: {}'.format(e.args))



def run_getIpAddress(ip_list):
    ip_Queue = Queue(-1)
    ip_address_dict = {}         # 字典，key为IP，value为归属地

    # 存到队列里
    for ip in ip_list:
        ip_Queue.put(ip)

    threads = []
    for num in range(50):
        t = Thread(target=get_ip_address, args=(ip_Queue, ip_address_dict, num))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return ip_address_dict
    # print(web_Titles)
