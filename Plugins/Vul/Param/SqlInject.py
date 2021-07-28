from termcolor import cprint
import requests
import threading
import re
import hashlib
from urllib.parse import urlparse
from collections import OrderedDict
from xml.dom import minidom
from queue import Queue
import time
import traceback
from tqdm import *
from colorama import Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)



# XML文件
PAYLOADS_XML = "./iniFile/SQLPayloads/payloads.xml"
ERROR_REGEXP_XML = "./iniFile/SQLPayloads/errors.xml"

# 盲注payload的时间
TIMEOUT_10 = 10
TIMEOUT_8 = 8
TIMEOUT_0 = 0


# 从xml中读取payload字典当中
def read_xml_payloads():
    payloads_dict = OrderedDict()  # payloads

    DOMTree = minidom.parse(PAYLOADS_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        payloads_dict[dbms] = []
        payloads = dbms_node.getElementsByTagName('payload')
        for payload in payloads:
            payload = payload.getAttribute("value")
            payloads_dict[dbms].append(payload)

    return payloads_dict

# 从xml中读取报错规则
def read_xml_errors():
    errors_regexp_dict = OrderedDict()  # 报错正则

    DOMTree = minidom.parse(ERROR_REGEXP_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        errors_regexp_dict[dbms] = []
        error_regexps = dbms_node.getElementsByTagName('error')
        for each in error_regexps:
            error_regexp = each.getAttribute("regexp")
            errors_regexp_dict[dbms].append(error_regexp)

    return errors_regexp_dict



class SQLInject(threading.Thread):
    name = '注入'

    def __init__(self, payloadLinks_queue, pbar, vul_list):
        threading.Thread.__init__(self)
        self.payloadLinks_queue = payloadLinks_queue      # 存活动态链接的队列
        self.pbar = pbar  # 进度条
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}

    def run(self):
        while not self.payloadLinks_queue.empty():
            param_link = self.payloadLinks_queue.get()
            self.pbar.set_postfix(url=param_link, vul=self.name)  # 进度条的显示
            self.run_detect(param_link.strip())
            self.pbar.update(1)  # 每完成一个任务，进度条也加+1
            self.payloadLinks_queue.task_done()

    # 调用各种漏洞检测方法
    def run_detect(self, url):
        url_timeout_8 = url.format(TIMEOUT=TIMEOUT_8)      # 延时
        alive_flag, res_timeout_8, cost_timeout_8 = self.runTime(url_timeout_8)

        # 判断注入类型-时间和报错
        if alive_flag and cost_timeout_8 > TIMEOUT_8 and 'TIMEOUT' in url:
            # 再次探测, 设置payload的超时为0，然后设置相应时间少于4秒则排除网络误报
            url_timeout_0 = url.format(TIMEOUT=TIMEOUT_0)
            alive_flag, res_timeout_0, cost_timeout_0 = self.runTime(url_timeout_0)
            if alive_flag and cost_timeout_0 < 4:
                # print('[{}] {}'.format(cost_timeout_0, url_timeout_0))
                url_timeout_10 = url.format(TIMEOUT=TIMEOUT_10)
                alive_flag, res_timeout_10, cost_timeout_10 = self.runTime(url_timeout_10)
                if alive_flag and cost_timeout_10 > TIMEOUT_10:
                    # print('[{}] {}'.format(cost_timeout_10, url_timeout_10))
                    tqdm.write(Fore.RED + '[SQL TIME] {}'.format(url_timeout_10))
                    self.vul_list.append(['SQL TIME', url_timeout_10, 'Yes TIMEOUT:{}'.format(cost_timeout_10)])
                    isTimeSql, regexp_ret = True, None
                else:
                    tqdm.write(Fore.WHITE + '[SQL TIME] {}'.format(url_timeout_10))
                    self.vul_list.append(['SQL TIME', url_timeout_10, 'Maybe'])
                    isTimeSql, regexp_ret = False, None
            else:
                tqdm.write(Fore.WHITE + '[SQL TIME] {}'.format(url_timeout_0))
                self.vul_list.append(['SQL TIME', url_timeout_0, 'Maybe'])
                isTimeSql, regexp_ret = False, None
        elif alive_flag:
            isErrorSql, dbms, regexp_ret = self.checkErrorSQL(res_timeout_8.text)
            if isErrorSql:
                tqdm.write(Fore.RED + '[{} SQL Error] [{}] [{}]'.format(dbms, url_timeout_8, regexp_ret))
                self.vul_list.append(['SQL Error', url_timeout_8, 'Yes [{}] {}'.format(dbms, regexp_ret)])

    # 耗费的时间
    def runTime(self, url):
        try:
            start_time = time.time()
            res = requests.get(url=url, headers=self.headers, timeout=20, verify=False, allow_redirects=False)
            end_time = time.time()
            cost_timeout =  end_time - start_time  # 获取盲注payload的响应时间
            return True, res, cost_timeout
        except Exception as e:
            return False, None, None

    # 通过正则匹配是否是报错注入
    def checkErrorSQL(self, text):
        # 判断是否存在报错注入的特征
        for dbms in errors_regexp_dict.keys():
            for regexp in errors_regexp_dict[dbms]:
                regexp_ret = re.search(regexp, text)  # 正则匹配出的结果
                if regexp_ret:
                    return True, dbms, regexp_ret.group(0)
        return False, None, None

def detect(param_Links):
    global errors_regexp_dict

    # payloads
    payloads_dict = read_xml_payloads()
    # 报错注入的正则规则
    errors_regexp_dict = read_xml_errors()

    # 带payload的动态链接
    payloadLinks = []
    # # 存储漏洞的名字和url
    vul_list = []


    for eachLink in param_Links:
        try:
            eachLink_parse = urlparse(eachLink)
            query = eachLink_parse.query
            for _ in query.split('&'):
                paramName, paramValue = _.split('=')
                for dbms in payloads_dict:
                    for payload in payloads_dict[dbms]:
                        newParamValue = paramValue + payload
                        newParam = paramName + '=' + newParamValue
                        newLink = eachLink.replace(_, newParam)
                        payloadLinks.append(newLink)
        except Exception as e:
            pass

    payloadLinks_queue = Queue(-1)  # 将存活的动态链接存入队列里
    for _ in payloadLinks:
        payloadLinks_queue.put(_)

    threads = []
    threadNum = 200  # 线程为20

    pbar = tqdm(total=payloadLinks_queue.qsize(), desc="检测漏洞", ncols=150)  # total是总数

    for num in range(1, threadNum + 1):
        t = SQLInject(payloadLinks_queue, pbar, vul_list)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    pbar.close()

    return vul_list

if __name__ == '__main__':
    from queue import Queue

    param_Links = ['http://192.168.144.137/sqli/Less-1/?id=1&type=2', 'http://192.168.144.137/sqli/Less-8/?id=1']

    vul_list = detect(param_Links)

    for vul in vul_list:
        print(vul)