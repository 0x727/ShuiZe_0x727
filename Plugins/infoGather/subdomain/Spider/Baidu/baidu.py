import requests
import re
from urllib.parse import quote, urlparse
import threading
from queue import Queue
from IPy import IP

# 百度爬虫
class BaiduSpider:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        # site:domain inurl:admin inurl:login inurl:system 后台 系统
        self.wds = ['inurl:admin', 'inurl:login', 'inurl:system', 'inurl:register', 'inurl:upload', '后台', '系统', '登录']
        self.PAGES = 5 # int(input('How many pages do you want BaiduSpider crawl: ')) # 5      # 默认跑5页
        # print('Please wait a few time ...')
        self.TIMEOUT = 10
        self.bdSubdomains = []
        self.links = []     #
    def keyword(self, wd, page=1):
        url = 'https://www.baidu.com/s?wd=%s&pn=%s0' % (wd, page - 1)
        # print(url)
        try:
            res = requests.get(url, headers=self.headers, timeout=self.TIMEOUT)
            bd_link_titles = re.findall(r'<div class="c-tools" id="\S*" data-tools=\'\{"title":"(.*)","url":"(.*)"\}\'>', res.text)
            # print('[{}] {}'.format(res.status_code, url))
            return bd_link_titles
        except Exception as e:
            return []

    def location(self, each_wd, baiduLink, title):
        try:
            link = requests.get(baiduLink, allow_redirects=False, timeout=self.TIMEOUT).headers.get('Location')
            self.links.append([each_wd, link, title])
            print('[{}] {} {}'.format(each_wd, link, title))
            return link
        except Exception as e:
            print('[{}] {} '.format(each_wd, e.args))
            return ''

    def get_subdomain(self, each_wd, i):
        for page in range(1, self.PAGES+1):
            wd = 'site:{} {}'.format(self.domain, each_wd)
            print('[{}] -> [page: {}]'.format(wd, page))
            wd = quote(wd)
            bd_link_titles = self.keyword(wd=wd, page=page)
            if bd_link_titles:
                for bd_link_title in bd_link_titles:
                    title, link = bd_link_title[0], bd_link_title[1]
                    subdomain = self.location(each_wd, link, title)
                    # subdomain = map(lambda x: 'http://{}'.format(urlparse(x).netloc), map(self.location, [each_wd] * len(retList), retList))
                    # for _ in subdomain:
                    self.bdSubdomains.append(urlparse(subdomain).netloc)

    # 爬子域名
    def run_subdomain(self, domain):
        self.domain = domain
        threads = []
        for i in range(len(self.wds)):
            t = threading.Thread(target=self.get_subdomain, args=(self.wds[i], i))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        # for each_wd in self.links:
        #     print('[{}] : {}'.format(each_wd, self.links[each_wd]))
            
        return list(set(self.bdSubdomains)), self.links

    # 爬后台，系统等地址
    def run_link(self, Subdomains_ips):
        self.Subdomains_ips = Subdomains_ips
        self.Queue = Queue(-1)
        hosts = []
        for ip_List in self.Subdomains_ips.values():
            for ip in ip_List:
                c_ip = str(IP(ip).make_net('255.255.255.0')).rsplit('.', 1)[0] + '.*'
                hosts.append(c_ip)
        for subdomain in self.Subdomains_ips.keys():
            hosts.append(subdomain)

        for host in list(set(hosts)):
            print(host)
            self.Queue.put(host)

        threads = []
        for i in range(10):
            t = threading.Thread(target=self.get_link, args=())
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        for each_wd in self.links:
            print('[{}] : {}'.format(each_wd, self.links[each_wd]))
            
        return list(set(self.bdSubdomains))


    def get_link(self):
        while not self.Queue.empty():
            host = self.Queue.get()
            for each_wd in self.wds:
                for page in range(1, 2):
                    wd = quote('site:{} {}'.format(host, each_wd))
                    retList = self.keyword(wd=wd, page=page)
                    if retList:
                        link = map(self.location, [each_wd] * len(retList), retList)
