import requests
import threading
import hashlib
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
import sys
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# CMS识别
class Detect(threading.Thread):
    name = 'CMS'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue      # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies             # 代理
        self.banner = {'41eca7a9245394106a09b2534d8030df': '泛微OA',         #       E-Weaver EOffice    e-Bridge 协同商务系统 协同办公OA
                       'c27547e27e1d2c7514545cd8d5988946': '泛微OA',
                       '9b1d3f08ede38dbe699d6b2e72a8febb': '泛微OA',
                       '281348dd57383c1f214ffb8aed3a1210': '泛微OA',
                       'ed0044587917c76d08573577c8b72883': '通达OA',
                       'cdc85452665e7708caed3009ecb7d4e2': '致远OA',
                       '17ac348fcce0b320e7bfab3fe2858dfa': '致远OA',
                       '57f307ad3764553df84e7b14b7a85432': '致远OA',
                       '3c8df395ec2cbd72782286d18a286a9a': '致远OA',
                       '2f761c27b6b7f9386bbd61403635dc42': '致远OA',
                       '055c3de1ef212cc16bec218c3ae08ca7': '致远OA',
                       '0488faca4c19046b94d07c3ee83cf9d6': 'SpringBoot',
                       '4644f2d45601037b8423d45e13194c93': 'Tomcat',
                       '33dbbf77f72ca953995538615aa68f52': 'Tomcat',
                       '48ee373f098d8e96e53b7dd778f09ff4': '齐治堡垒机',
                       'b7405d88bf3171526350904569e5514e': 'Fortigate SSL VPN',
                       '07f3ae71515d9b347f9c2724fbd9a6d1': 'iOffice',
                       'ad74ff8f9a2f630fc2c5e6b3aa0a5cb8': 'Coremail',
                       '04d9541338e525258daf47cc844d59f3': 'BIG-IP',
                       '0b24d4d5c7d300d50ee1cd96059a9e85': 'Sangfor Edr',
                       'd8d7c9138e93d43579ebf2e384745ba8': 'RuiJie EG',
                       '799f70b71314a7508326d1d2f68f7519': 'Jboss',
                       '1b24a7a916a0e0901e381a0d6131b28d': 'Jboss',
                       '3c8c8a2f01d7e06527cbd7b3d43fbba0': '协达OA',
                       '302464c3f6207d57240649926cfc7bd4': '蓝凌OA',
                       'ed7d5c39c69262f4ba95418d4f909b10': 'Solr',
                       '0fbe700fd7d07ec8d30ef8b3ac261484': 'Zabbix',
                       '79a95f4f1c2cc36eea51fe66450acfa2': 'Nexus',
                       '0c295d21ff53bdd0a95499db97acf0dd': 'Nexus',
                       'a91fbd46e52b1c1f8778906024bc9e15': 'NSFOCUS',
                       "20760ee267465f92c8a70ab7b9406106": '360新天擎',
                       "9252bd07dbb6277f7ae898da87dada3a": '网康下一代防火墙',
                       "966e60f8eb85b7ea43a7b0095f3e2336": 'Confluence'
                       }

        # 漏洞名-CMS目录下的漏洞插件
        self.cmsname_py = {"泛微OA": "fanwei.py", "通达OA": "tongda.py", "致远OA": "zhiyuan.py",
                           "SpringBoot": "SpringBoot.py", "Tomcat": "Tomcat.py", '齐治堡垒机': 'qizhi.py',
                           'Fortigate SSL VPN': 'Fortigate.py', 'Coremail': 'Coremail.py', 'BIG-IP': 'BIG-IP.py',
                           'Sangfor Edr': 'SangforEdr.py', 'RuiJie EG': 'RuiJie.py', 'Solr': 'Solr.py', 'Zabbix': 'Zabbix.py'}

        self.md5s = self.banner.keys()

        self.vulCmsPath = os.getcwd() + '/Plugins/Vul/CMS/'
        # self.vulCmsPath = os.getcwd() + '/../CMS/'     # 测试用
        if self.vulCmsPath not in sys.path:
            sys.path.append(self.vulCmsPath)  # 添加环境变量


    def run(self):
        while not self.alive_Web_queue.empty():
            alive_web = self.alive_Web_queue.get()
            self.pbar.set_postfix(url=alive_web, vul=self.name)  # 进度条的显示
            self.run_detect(alive_web.rstrip('/'))
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.alive_Web_queue.task_done()

    # 只需要修改下面的代码就行
    def run_detect(self, url):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        favicon_url = r'{}/favicon.ico'.format(url)
        m1 = hashlib.md5()
        try:
            m1.update(requests.get(url=favicon_url, headers=headers, proxies=self.proxies, timeout=20, verify=False, allow_redirects=False).content)
            the_md5 = m1.hexdigest()
            # print(the_md5)
            if the_md5 in self.md5s:
                cmsName = self.banner[the_md5]
                tqdm.write(Fore.RED + '[{}] {}'.format(cmsName, url))

                if self.attack_cms_vul(url, self.cmsname_py[cmsName]):      # 检测出漏洞
                    pass
                else:
                    self.vul_list.append([cmsName, url, 'Maybe'])       # 未检测出漏洞
        except Exception as e:
            pass

    def attack_cms_vul(self, url, pyName):

        vulCmsList = filter(lambda x: (True, False)[x[-3:] == 'pyc' or x[-5:] == '__.py' or x[:2] == '__'], os.listdir(self.vulCmsPath))  # 获取漏洞脚本

        if pyName in vulCmsList:
            md = __import__(pyName[:-3])  # 导入类
            try:
                if hasattr(md, 'Detect'):
                    detect = getattr(md, 'Detect')  # 获取类
                    # tqdm.write(detect.name)
                    if detect(url, self.vul_list, self.proxies).run_detect():         # 检测出漏洞
                        return True
                    else:                            # 未检测出漏洞
                        return False
            except Exception as e:
                # tqdm.write(str(e.args))
                return False
        else:
            return False


if __name__ == '__main__':
    from queue import Queue

    alive_web = ['']
    vul_list = []
    # proxy = r''
    # requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
    # requests_proxies = None
    requests_proxies = {'http': "192.168.144.178:9999", 'https': "192.168.144.178:9999"}
    alive_Web_queue = Queue(-1)  # 将存活的web存入队列里
    for _ in alive_web:
        alive_Web_queue.put(_)

    threads = []
    thread_num = 100  # 漏洞检测的线程数目

    pbar = tqdm(total=alive_Web_queue.qsize(), desc="检测漏洞", ncols=150)  # total是总数

    for num in range(1, thread_num + 1):
        t = Detect(alive_Web_queue, pbar, vul_list, requests_proxies)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    tqdm.write(Fore.BLACK + '-'*50 + '结果' + '-'*50)
    for vul in vul_list:
        tqdm.write(Fore.BLACK + str(vul))