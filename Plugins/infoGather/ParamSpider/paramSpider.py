import requests
from threading import Thread
from queue import Queue
from urllib.parse import urlparse
import re
import chardet

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

# 黑名单后缀
# black_ext = ['jpg', 'jpeg', 'gif', 'png', 'ico', 'swf', 'css', 'js', 'jhtml', 'htm', 'html', 'doc', 'pdf', 'mso', 'docx', 'xls', 'xlsx', ';']

# 白名单
white_ext = ['asp', 'aspx', 'php', 'jsp', 'jspx', 'html', 'htm', 'jhtml']

# 后台地址关键字
htPath = ['admin', 'login', 'system']

TIMEOUT = 20
title_patten = re.compile('<title>(.*)?</title>', re.IGNORECASE)        # 忽略大小写

def getWebTitle(res):
    webTitle = ''
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
    except Exception:
        pass
    finally:
        return webTitle

# 获取动态链接和后台地址
def getLinks(domain):
    # 动态链接
    paramLinks = []
    # 后台地址
    htLinks = []

    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        res = requests.get(url=url, headers=headers)
        text = res.text
        # with open('test.txt', 'wt') as f:
        #     f.write(text)

        # with open('test.txt', 'rt') as f:
        #     text = f.read()

        # 获取动态链接
        allParamNames = []                              # [['q', 'buyType', 'catNo', 'page'], ['id', 'flag']]
        links = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]', text)))
        for link in links:
            link = link.strip()
            paramName = []                     # 参数名字列表
            query = urlparse(link).query        # q=*&buyType=4&catNo=11660&page=1
            for each in query.split('=')[:-1]:
                paramName.append(each.split('&')[-1])   # ['q', 'buyType', 'catNo', 'page']
            paramName.sort()                            # 排序
            if paramName not in allParamNames:
                allParamNames.append(paramName)
                # print(link, paramName)
                paramLinks.append(link)



        # 获取后台地址
        for link in text.split('\n'):
            link = link.strip()
            if link.rsplit('.')[-1].lower() in white_ext:
                for eachHT in htPath:
                    if eachHT in link.rsplit('/')[-1].lower() and len(link.rsplit('/')[-1].lower()) < 20:
                        htLinks.append(link)
                        pass


    except Exception as e:
        pass

    return paramLinks, htLinks


def detectAlive(linksQueue, aliveLinks, paramLinksDemo, htLinksDemo):
    while not linksQueue.empty():
        url = linksQueue.get()
        try:
            res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
            code = res.status_code
            if code != 404 and code < 500 and code != 403:
                print('[{}] [{}] {}'.format(linksQueue.qsize(), code, url))
                if url in paramLinksDemo:
                    title = ''
                else:
                    title = getWebTitle(res)
                aliveLinks.append([url, title])
        except Exception as e:
            pass
            # print('[-] {} {}'.format(url, e.args))


def getParamLinks(domain):

    # 动态链接   后台地址           并没有进行过存活筛选
    paramLinksDemo, htLinksDemo = getLinks(domain)

    aliveLinks = []     # 所有的存活链接
    paramLinks, htLinks = [], []        # 存活的链接

    threads = []
    linksQueue = Queue(-1)      # 链接队列
    for link in paramLinksDemo + htLinksDemo:
        linksQueue.put(link)
        # print(link)

    for t_id in range(50):
        t = Thread(target=detectAlive, args=(linksQueue, aliveLinks, paramLinksDemo, htLinksDemo))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    for link in aliveLinks:
        if link[0] in paramLinksDemo:
            paramLinks.append(link[0])
        else:
            htLinks.append(link)


    return paramLinks, htLinks

if __name__ == '__main__':
    domain = ''
    paramLinks, htLinks = getParamLinks(domain)

    print('动态链接: {}'.format(len(paramLinks)))
    for link in paramLinks:
        print(link)

    print('后台链接: {}'.format(len(htLinks)))
    for link in htLinks:
        print(link)
