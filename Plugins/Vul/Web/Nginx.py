from termcolor import cprint
import requests
import threading
import re
requests.packages.urllib3.disable_warnings()
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


# Nginx漏洞
class Detect(threading.Thread):
    name = 'Nginx'

    def __init__(self, alive_Web_queue, pbar, vul_list, requests_proxies):
        threading.Thread.__init__(self)
        self.alive_Web_queue = alive_Web_queue  # 存活web的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list  # 存储漏洞的名字和url
        self.proxies = requests_proxies  # 代理
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

    def run(self):
        while not self.alive_Web_queue.empty():
            alive_web = self.alive_Web_queue.get()
            self.pbar.set_postfix(url=alive_web, vul=self.name)  # 进度条的显示
            self.run_detect(alive_web.rstrip('/'))
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.alive_Web_queue.task_done()


    def run_detect(self, url):
        # Nginx解析漏洞
        self.NginxPHP(url)

    # Nginx解析漏洞
    def NginxPHP(self, url):
        # 判断图片路径是否存在
        def existImage(image_url):
            try:
                res = requests.get(url=image_url, headers=self.headers, proxies=self.proxies, timeout=10, verify=False, allow_redirects=False)
                if res.status_code == 200:
                    return True
                else:
                    return False
            except Exception as e:
                # print('[-] {} is error: {}'.format(image_url, e.args))
                return False

        # 判断是否存在nginx解析漏洞
        def checkNginxVul(vul_url):
            try:
                res = requests.get(url=vul_url, headers=self.headers, proxies=self.proxies, timeout=10, verify=False, allow_redirects=False)
                resHeaders = res.headers
                if res.status_code == 200 and b'\x00' in res.content:  # 存在nginx解析漏洞的网站，后缀加了/.php后，状态码还是200，并且能够解析图片，那么肯定会有b'\x00'存在，如果不解析，那么就没有b'\x00'
                    if 'Content-Type' in resHeaders.keys() and 'text/html' in resHeaders['Content-Type']:
                        tqdm.write(Fore.RED + '[+] {} is nginx vul!'.format(vul_url))
                        return True
                    else:
                        # print('[-] {} Not exist nginx vul!'.format(vul_url))
                        return False
                else:
                    # print('[-] {} Not exist nginx vul!'.format(vul_url))
                    return False
            except Exception as e:
                # print('[-] {} is error: {}'.format(vul_url, e.args))
                return False

        image_ext = ['ico', 'jpg', 'gif', 'png', 'jpeg']
        image_ext_compile = '"([{}]?[^"]+\.({}))"'.format(url, '|'.join(image_ext))
        # print(image_ext_compile)

        try:
            p = re.compile(image_ext_compile)
            res = requests.get(url=url, headers=self.headers, proxies=self.proxies, timeout=10, verify=False, allow_redirects=False)
            rets = p.findall(res.text)

            image_urls = []

            if rets:
                for _ in rets:
                    if url in _[0]:
                        image_url = _[0]
                    else:
                        image_url = url + '/' + _[0]
                    # print(image_url)
                    image_urls.append(image_url)

                error_count = 0
                for image_url in image_urls:
                    if error_count > 10:         # 过滤一些网站匹配出太多的图片
                        break
                    else:
                        if existImage(image_url):
                            # print('[~] {} image url is exist!'.format(image_url))
                            vul_url = image_url + '/.php'
                            if checkNginxVul(vul_url):
                                self.vul_list.append(['Nginx', vul_url, 'Yes'])
                                return True
                            else:
                                return False
                        else:
                            error_count += 1
                            # print('[-] [{}] {} image url is not exist.'.format(self.alive_Web_queue.qsize(), image_url))
            # 没匹配到图片
            else:
                pass
                # print('[-] {} is not have image url.'.format(url))
        except Exception as e:
            pass
            # print('[-] {} is error: {}'.format(url, e.args))


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