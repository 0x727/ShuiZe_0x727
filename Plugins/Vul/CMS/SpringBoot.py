import requests
from termcolor import cprint
from queue import Queue
from threading import Thread
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


class Detect:
    name = 'SpringBoot'
    # 参考文章：https://www.cnblogs.com/junsec/p/12066305.html
    def __init__(self, url, vul_list, requests_proxies):
        self.url = url
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        # /jolokia'执行远程代码
        # /trace 路径获取用户认证字段信息
        # /env 路径获取这些服务的配置信息修改配置信息
        # /health 路径可探测到站点 git 项目地址：
        # /heapdump 路径获取后台用户账号密码泄露
        # self.unauthPath = ["/jolokia/list", "/autoconfig",  "/env", "/monitor/env", "/actuator/env",
        #                    "/trace", "/health", "/loggers", "/metrics",
        #                    "/heapdump", "/info", "/dump", "/configprops", "/mappings", "/auditevents", "/beans"]

        # actuator/heapdump文件会很大
        self.unauthPath = ['actuator/env', 'mappings', 'flyway', 'actuator/trace', 'trace', 'liquibase', 'metrics',
                           'shutdown', 'actuator/dump', 'actuator/mappings', 'actuator/logfile', 'actuator/shutdown',
                           'features', 'actuator/health', 'auditevents', 'health', 'env', 'version', 'configprops', 'list', 'heapdump',
                           'actuator', 'info', 'cloudfoundryapplication', 'loggers', 'beans',
                           'actuator/restart', 'swagger-ui.html', 'autoconfig', 'jolokia', 'logfile', 'dump']

        self.unauthQueue = Queue(-1)
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        self.Exist = False

    def run_detect(self):
        # 未授权路径
        self.unauth()

        if self.Exist == True:
            return True
        else:
            return False

    # 只需要修改下面的代码就行
    def unauth(self):
        def run():
            while not self.unauthQueue.empty():
                unauthUrl = self.unauthQueue.get()
                # tqdm.write(Fore.WHITE + '[test Spring] {}'.format(unauthUrl))
                try:
                    res = requests.get(url=unauthUrl, headers=self.headers, proxies=self.proxies, timeout=10)
                    if '":{"' in res.text:
                        tqdm.write(Fore.RED + '[SpringBoot] {} Length: [{}]'.format(unauthUrl, len(res.text)))
                        self.vul_list.append(['SpringBoot', unauthUrl, 'YES Length: [{}] maybe actuator/heapdump'.format(len(res.text))])
                        self.Exist = True
                    else:
                        pass
                except Exception as e:
                    pass

                self.unauthQueue.task_done()


        for path in self.unauthPath:
            self.unauthQueue.put(self.url + '/' + path)

        threads = []
        for i in range(10):
            t = Thread(target=run)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()



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
