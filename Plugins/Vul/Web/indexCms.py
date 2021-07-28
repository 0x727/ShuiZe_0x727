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


# 首页 CMS识别
class Detect(threading.Thread):
    name = 'index CMS'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue      # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies             # 代理
        self.banner = {'Jhsoft': '金和OA',         #
                        'iOffice': '红帆OA'
                       }
        self.bannerContents = self.banner.keys()


        # 漏洞名-CMS目录下的漏洞插件
        self.cmsname_py = {"金和OA": "Jinher.py", "红帆OA": "iOffice.py"}



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
        try:
            res = requests.get(url=url, headers=headers, proxies=self.proxies, timeout=20, verify=False)
            text = res.text
            # print(res.text)
            for bannerContent in self.bannerContents:
                if bannerContent in text:
                    cmsName = self.banner[bannerContent]
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
    requests_proxies = None
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