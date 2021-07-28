import requests
import re
from queue import Queue
import chardet
from threading import Thread
from urllib.parse import urlparse
from Plugins.infoGather.webInfo.getWebInfo import run_getWebInfo
from tqdm import *
from colorama import Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)

requests.packages.urllib3.disable_warnings()

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
proxies = None
TIMEOUT = 10
get_num = 0
host_Queue = Queue(-1)
title_patten = re.compile('<title>(.*)?</title>', re.IGNORECASE)        # 忽略大小写
background_path = ['admin', 'login', 'system', 'manager', 'admin.jsp', 'login.jsp', 'admin.php', 'login.php',
                   'admin.aspx', 'login.aspx', 'admin.asp', 'login.asp']


def get_web_title(url):     # 返回存活的url和标题。即使状态码不是200，url也可能是存活的，并且存在着比如weblogic等漏洞
    try:
        res = requests.get(url=url, headers=headers, timeout=TIMEOUT, proxies=proxies, verify=False)
        webCode = res.status_code
    except Exception as e:
        # print(e.args)
        return True, '', 'VPS访问不了 切换IP访问'

    try:
        cont = res.content
        # 获取网页的编码格式
        charset = chardet.detect(cont)['encoding']
        # 对各种编码情况进行判断
        html_doc = cont.decode(charset)
    except Exception:
        html_doc = res.text

    try:
        # self.title_patten = re.compile('<title>(.*)?</title>')
        webTitle = re.search(title_patten, html_doc).group(1)
        # print(webTitle)
        if len(webTitle) > 200:
            webTitle = ''
        return True, webCode, webTitle
    except AttributeError:            # 当正则匹配没有匹配出来的情况下：捕获异常("'NoneType' object has no attribute 'group'",)
        webTitle = ''
        return True, webCode, webTitle
    except Exception:
        return False, '', ''


# 探测后台地址
def detect_background(url_path):
    alive, webCode, webTitle = get_web_title(url_path)
    if alive and webCode == 200:
        return '[{}] {} {}'.format(webCode, url_path, webTitle)
    else:
        return ''



def getWebTitle(host_Queue, pbar, web_Titles, ip_address_dict, num):
    def run_webtitle(url):
        ip = urlparse(url).netloc.split(":")[0]

        try:
            address = ip_address_dict[ip]
        except:
            address = ''

        alive, webCode, webTitle = get_web_title(url)  # 返回url是否存活，以及存活web的标题

        if not alive:
            tqdm.write(Fore.WHITE + '[{}] [t{}] {} die'.format(host_Queue.qsize(), num, url))
            return

        if webTitle == 'VPS访问不了 切换IP访问':
            if 'https' in url:
                tqdm.write(Fore.WHITE + '{} {} {}'.format(url, webTitle, address))
                web_Titles.append([url, 65535, webTitle, '', '', ''])
                return
            else:
                url = url.replace('http', 'https')
                alive, webCode, webTitle = get_web_title(url)  # 返回url是否存活，以及存活web的标题
                if webTitle == 'VPS访问不了 切换IP访问':
                    tqdm.write(Fore.WHITE + '{} {} {}'.format(url.replace('https', 'http'), webTitle,
                                                       address))
                    web_Titles.append([url.replace('https', 'http'), 65535, webTitle, '', '', ''])
                    return

        # print(webCode)
        if 'https' not in url and (webCode != 200 or webTitle == ''):
            url = url.replace('http', 'https')
            alive, webCode, webTitle = get_web_title(url)  # 返回url是否存活，以及存活web的标题
            # print(webCode, webTitle)
        background = ''

        if alive:
            # 获取网站框架信息
            info = run_getWebInfo(url)

            # 扫后台
            for path in background_path:
                # print(url+'/'+path)
                background += detect_background(url + '/' + path)

            tqdm.write(Fore.RED + '{} {} {} {} {} {}'.format(url, webCode, webTitle, address, info,
                                                        background))
            web_Titles.append([url, webCode, webTitle, address, info, background])
        else:
            tqdm.write(Fore.WHITE + '{} die'.format(url))


    while not host_Queue.empty():
        url = host_Queue.get()
        pbar.set_postfix(url=url, name='run_webtitle')  # 进度条的显示

        run_webtitle(url.rstrip('/'))
        pbar.update(1)  # 每完成一个任务，进度条也加+1
        host_Queue.task_done()






def run_getWebTitle(web_host_port, ip_address_dict, requests_proxies, threadNum):
    global proxies
    proxies = requests_proxies
    web_Titles = []           # 存放域名标题
    # 存到队列里
    for host in web_host_port:
        host_Queue.put(host)

    threads = []

    pbar = tqdm(total=host_Queue.qsize(), desc="获取网站标题", ncols=150)  # total是总数

    for num in range(threadNum):
        t = Thread(target=getWebTitle, args=(host_Queue, pbar, web_Titles, ip_address_dict, num))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    pbar.close()
    return web_Titles
    # print(web_Titles)

if __name__ == '__main__':
    web_host_port = ['']


    web_Titles = run_getWebTitle(web_host_port, {}, {}, 50)

    tqdm.write(Fore.BLACK + '-' * 50 + '结果' + '-' * 50)
    for webTitle in web_Titles:
        tqdm.write(Fore.BLACK + str(webTitle))
