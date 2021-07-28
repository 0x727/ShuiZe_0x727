import requests
import re
from urllib.parse import quote, urlparse
import threading
from queue import Queue
from IPy import IP
from bs4 import BeautifulSoup

# 必应爬虫
class BingSpider:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        # site:domain inurl:admin inurl:login inurl:system 后台 系统
        self.wds = ['admin', 'login', 'system', 'register', 'upload', '后台', '系统', '登录']
        self.PAGES = 5   # 默认跑5页
        # print('Please wait a few time ...')
        self.TIMEOUT = 10
        self.bingSubdomains = []
        self.links = []
    def get_subdomain(self, host, each_wd, i):      # host 既可以是域名也可以是IP
        for page in range(1, self.PAGES + 1):
            q = 'site:{} {}'.format(host, each_wd)
            print('[{}] -> [page: {}]'.format(q, page))
            tmp = page - 2
            if tmp == -1:
                first_value = 1
            elif tmp == 0:
                first_value = 2
            else:
                first_value = tmp * 10 + 2
            url = r'https://www.bing.com/search?q={}&first={}'.format(quote(q), first_value)
            print(url)
            try:
                res = requests.get(url=url, headers=self.headers, timeout=10)
                soup = BeautifulSoup(res.text, 'html.parser')
                lis = soup.find_all('li', class_='b_algo')
                for li in lis:
                    li_a = li.find('a')
                    link = li_a['href']                      # 链接
                    title = li_a.get_text()                  # 标题
                    subdomain = urlparse(link).netloc         # 子域名
                    print('[{}] [page: {}]: {} {} {}'.format(q, page, link, title, subdomain))
                    self.bingSubdomains.append(subdomain)
                    self.links.append([each_wd, link, title])
            except Exception as e:
                print(e.args)
                # pass
    # 爬子域名
    def run_subdomain(self, domain):
        threads = []
        for i in range(len(self.wds)):
            t = threading.Thread(target=self.get_subdomain, args=(domain, self.wds[i], i))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        return list(set(self.bingSubdomains)), self.links
