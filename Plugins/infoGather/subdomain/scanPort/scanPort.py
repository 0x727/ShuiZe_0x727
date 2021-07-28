import re
from sys import version_info
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import socket
from threading import Thread
import chardet
import sqlite3

PY2, PY3 = (True, False) if version_info[0] == 2 else (False, True)
if PY2:
    from Queue import Queue
    from urlparse import urlparse
    from urllib2 import quote
else:
    from queue import Queue
    from urllib.parse import urlparse, quote

class scanPort:
    def __init__(self, domain, Hosts, infoGather_db_file, update_portServiceTableView_Signal):
        self.Hosts = Hosts      # 存放域名或者IP
        self.domain = domain
        self.threadsNum = 200
        self.queueHosts = Queue(-1)         # 将host里的数据存放到队列里
        self.queueTasks = Queue(-1)        # 存放host:port的任务队列
        self.port = [21,80,389,443,445,873,1433,1521,2181,2171,3306,3389,3690,5432,5800,5900,6379,7001,81,88,8000,8001,8080,8888,9200,9300,11211,27017,27018,50070,9584]
        self.allServerInfo = self.read_config('./ini/server_info.ini')  # 读取端口服务的正则表达式
        self.TIMEOUT = 20       # 延时
        self.port_info = {}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}
        self.title_patten = re.compile('<title>(.*)?</title>')
        self.hostWeb = []           # 存放开放Web服务的域名或IP
        self.hostNotWeb = []        # 存放不是开放Web服务的域名或IP
        self.portService = []       # 存放端口服务
        self.infoGather_db_file = infoGather_db_file
        self.noCDN_host = []
        self.update_portServiceTableView_Signal = update_portServiceTableView_Signal

    # 读取配置文件
    def read_config(self, configFile):
        allServerInfo = []
        try:
            with open(configFile, 'r') as f:
                for mark in f.readlines():
                    name, port, reg = mark.strip().split("|", 2)
                    allServerInfo.append([name, port, reg])
                return allServerInfo
        except:
            print('Configuration file read failed')

    # 存入数据库
    def save_to_sqlite_portService(self):
        conn = sqlite3.connect(self.infoGather_db_file)  # 创建数据库
        cu = conn.cursor()  # 能获得连接的游标
        try:
            cu.execute('create table portService (host varchar(50), port varchar(6), Service varchar(20), '
                       'code varchar(5), title varchar(50), headers varchar(500))')  # 创建表
        except Exception as e:
            pass

        for host, port, service, code, title, headers in self.portService:
            try:
                cu.execute("INSERT INTO portService(host, port, Service, code, title, headers) VALUES (?, ?, ?, ?, ?, ?)", (host, port, service, code, title, headers))
            except Exception as e:
                print(e.args)
        conn.commit()
        cu.close()

    def run(self):
        # 过滤cdn的host
        for host in self.Hosts:
            self.queueHosts.put(host)
        threads_1 = []
        for i in range(1, self.threadsNum + 1):
            t_1 = Thread(target=self.is_cdn)
            threads_1.append(t_1)
            t_1.start()
        for t_1 in threads_1:
            t_1.join()

        print('noCDN_host: {}'.format(self.noCDN_host))

        for host in self.noCDN_host:
            for port in self.port:
                self.queueTasks.put('{}:{}'.format(host, port))

        threads = []
        for i in range(1, self.threadsNum + 1):
            t = Thread(target=self.scan)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        self.save_to_sqlite_portService()

        return self.hostWeb

    def scan(self):
        while not self.queueTasks.empty():
            queueTask = self.queueTasks.get()
            try:
                host, port = queueTask.split(":")
                portInfo = self.recv_port_info(host, port)
                if portInfo != 'Close':
                    serverName = self.check_server(host, port, portInfo)
                    if serverName:      # 已经探测到服务（非WEB）
                        content = '[{}] [{}] [{}]'.format(host, port, serverName)   # [+] [127.0.0.1] [3306] [mysql]
                        print('\t[+] {}'.format(content))
                        self.portService.append((host, port, serverName, '', '', ''))
                        self.update_portServiceTableView_Signal.emit([host, port, serverName, '', '', ''])
                        # self.save(content)
                    else:  # 端口开放，但是没有探测出服务，检测是否是web服务
                        webHeaders, webTitle, webCode = self.get_web_title(host, port)
                        if webHeaders:  # 端口开放，Web服务
                            content = '[{}] [{}] [Web] [{}] [{}] [{}]'.format(host, port, webTitle, webCode, webHeaders)
                            self.hostWeb.append(':'.join((host, port))) # domain:port       host:port
                            self.portService.append((host, port, 'Web', webCode, webTitle, str(webHeaders)))
                            self.update_portServiceTableView_Signal.emit([host, port, 'Web', webCode, webTitle, str(webHeaders)])
                            # self.save(content)
                            print('\t[+] {}'.format(content)) # [+] [127.0.0.1] [443] [Web] [403] [{'Content-Type': 'text; charset=plain', 'Connection': 'close', 'Date': 'Sun, 23 Dec 2018 16:27:21 GMT', 'Content-Length': '0'}]
                        else:           # 端口开放，不是Web服务
                            content = '[{}] [{}]'.format(host, port)
                            print('\t[+] {} open'.format(content))
                            self.portService.append((host, port, 'Open', '', '', ''))
                            self.update_portServiceTableView_Signal.emit([host, port, 'Open', '', '', ''])
                            # self.save(content)
            except Exception:
                pass

    # 判断是否是cdn或者负载均衡
    def is_cdn(self):
        while not self.queueHosts.empty():
            host = self.queueHosts.get()
            try:
                socket.setdefaulttimeout(self.TIMEOUT / 2)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, 15421))
                print('\t[+] [{}] is cdn'.format(host))
            except Exception as e:       # 端口关闭
                print('\t[-] [{}] is not cdn'.format(host))
                self.noCDN_host.append(host)

    # 获取端口服务
    def recv_port_info(self, host, port):
        try:
            socket.setdefaulttimeout(self.TIMEOUT / 2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, int(port)))
        except Exception:       # 端口关闭
            return 'Close'
        try:
            portInfo = sock.recv(512)
            sock.close()
            if len(portInfo) > 2:
                return portInfo
            else:
                return 'Unknow'
        except Exception:
            return 'Unknow'

    # 从端口返回的信息里判断是哪种服务
    def check_server(self, host, port, portInfo):
        server = ''
        for serverInfo in self.allServerInfo:
            try:
                name, default_port, regular = serverInfo
                if int(default_port) == int(port):
                    server = name + "(default)"
                if regular:
                    for each in regular.split('|'):
                        matchObj = re.findall(bytes(each.encode('utf-8')), portInfo)
                        if matchObj:
                            server = name
                            content = '[{}] [{}] [{}]'.format(host, port, server)
                            # print('\t[+] {}'.format(content))
                            return server
                if server:
                    return server
            except Exception:
                continue
        return server

    # 未检测到的服务可能是开放web，尝试获取标题
    def get_web_title(self, host, port):

        url = 'https://{}'.format(host) if port == '443' else 'http://{}:{}'.format(host, port)

        try:
            res = requests.get(url=url, headers=self.headers, timeout=self.TIMEOUT, verify=False)
            webHeaders = res.headers
            webCode = res.status_code
        except Exception:
            return False, False, False

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
            webTitle = re.search(self.title_patten, html_doc).group(1)
            return webHeaders, webTitle, webCode
        except Exception:
            return webHeaders, 'None', webCode
