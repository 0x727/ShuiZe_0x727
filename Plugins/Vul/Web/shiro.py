import requests
import threading
from termcolor import cprint
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


class Detect(threading.Thread):
    name = 'shiro'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue      # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理


    def run(self):
        while not self.alive_Web_queue.empty():
            alive_web = self.alive_Web_queue.get()
            self.pbar.set_postfix(url=alive_web, vul=self.name)     # 进度条的显示
            self.run_detect(alive_web.rstrip('/'))
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.alive_Web_queue.task_done()

    # 只需要修改下面的代码就行
    def run_detect(self, url):
        shiro_headers = {'Cookie': 'rememberMe=1',
                         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}

        try:
            res = requests.get(url=url, headers=shiro_headers, allow_redirects=False, proxies=self.proxies, timeout=10)
            res_setcookies = res.headers['Set-Cookie']
            if 'rememberMe=deleteMe' in res_setcookies:
                tqdm.write(Fore.RED + '[shiro] {}'.format(url))
                self.vul_list.append(['shiro', url, 'Maybe'])
            elif res.status_code == 302 or res.status_code == 304:
                res = requests.get(url=url, headers=shiro_headers, proxies=self.proxies, timeout=10)
                redirect_url = res.url
                redirect_res = requests.get(url=redirect_url, headers=shiro_headers, allow_redirects=False, proxies=self.proxies, timeout=10)
                res_setcookies = redirect_res.headers['Set-Cookie']
                if 'rememberMe=deleteMe' in res_setcookies:
                    tqdm.write(Fore.RED + '[shiro] {}'.format(redirect_url))
                    self.vul_list.append(['shiro', redirect_url, 'Maybe'])
            else:
                pass
                # print('[shiro -] {}'.format(url))
        except Exception as e:
            # tqdm.write(Fore.WHITE + '[shiro error] {}: {}'.format(url, e.args))
            pass

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
    thread_num = 10  # 漏洞检测的线程数目


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