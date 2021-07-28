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


# 泛微oa
class Detect(threading.Thread):
    name = 'fanwei'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url.rstrip('/')
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):
        # 任意文件上传
        self.upload1()

        # 漏洞2
        self.bridgeRead()


        if not self.isExist:
            return False
        else:
            return True

    # 泛微OA v9.0 前台任意文件上传getshell
    def upload1(self):
        uploadOperation_url = self.url + '/page/exportImport/uploadOperation.jsp'
        try:
            res = requests.get(url=uploadOperation_url, headers=self.headers, proxies=self.proxies, verify=False, allow_redirects=False)
            if res.status_code == 200:
                self.isExist = True
                tqdm.write(Fore.RED + '[泛微OA v9.0 uploadOperation] {}'.format(self.url))
                self.vul_list.append(['泛微OA v9.0 uploadOperation', self.url, 'Yes {}'.format(uploadOperation_url)])
        except Exception as e:
            return False

    # 泛微云桥 E-Bridge 2018 2019 任意文件读取
    def bridgeRead(self):
        bridgeRead_url = self.url + '/wxjsapi/saveYZJFile'
        try:
            res = requests.get(url=bridgeRead_url, headers=self.headers, proxies=self.proxies, verify=False, allow_redirects=False)
            if res.status_code == 200:
                self.isExist = True
                tqdm.write(Fore.RED + '[泛微E-Bridge 任意文件读取] {}'.format(self.url))
                self.vul_list.append(['泛微E-Bridge 任意文件读取', self.url, 'Yes {}'.format(bridgeRead_url)])
        except Exception as e:
            return False



if __name__ == '__main__':
    from queue import Queue

    vul_list = []
    # proxy = r'192.168.168.148:10086'
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    requests_proxies = None
    url = r'http://www.domain.com'
    Detect(url, vul_list, requests_proxies).run_detect()

    tqdm.write(Fore.BLACK + '-' * 50 + '结果 ' + '-' * 50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))

