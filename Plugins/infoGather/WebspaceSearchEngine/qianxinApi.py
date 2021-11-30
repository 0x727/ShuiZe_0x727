#coding=utf-8
import json
import requests
import base64
import json
import configparser
import time
import datetime
from urllib.parse import quote
from termcolor import cprint
import math
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
# cf.read("../../../iniFile/config.ini")      # 测试
secs = cf.sections()
apikey = cf.get('qianxin api', 'api-key')
MaxTotal = int(cf.get('qianxin api', 'qianxin_nums'))  # 查询的最大数据量

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

def query_ip(c_subnet):
    print('[qianxin] 查询：{}'.format(c_subnet))
    return query(c_subnet)

def query_domain(query_str):
    print('[qianxin] 查询：{}'.format(query_str))
    return query(query_str)


def filter_data(arr):
    qianxin_Results_tmp = []
    qianxin_web_host_port_tmp = []  # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    qianxin_service_host_port_tmp = []  # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测
    for each in arr:
        # print(each)
        host = each["url"]
        title = each["web_title"]
        ip = each["ip"]
        subdomain = each["domain"]
        port = each["port"]
        server = str(each["component"])
        protocol = each["protocol"]
        address = each["city"]
        company = each["company"]
        isp = each["isp"]
        updated_at = each["updated_at"]
        qianxin_Results_tmp.append(
            [host, title, ip, subdomain, port, server, protocol, address, company, isp, updated_at])

        # 返回开放http服务的ip和端口
        if 'http' in protocol and host:
            host_port = '{}:{}'.format(host, port)
            # print(host_port)
            qianxin_web_host_port_tmp.append(host_port)
        else:
            host_port = [protocol, ip, port]
            # print(host_port)
            qianxin_service_host_port_tmp.append(host_port)

    return qianxin_Results_tmp, qianxin_web_host_port_tmp, qianxin_service_host_port_tmp

def query(query_str):
    qianxin_Results = []
    qianxin_web_host_port = []  # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    qianxin_service_host_port = []     # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测

    qbase64 = str(base64.b64encode(query_str.encode(encoding='utf-8')), 'utf-8')
    # 第n页
    page = 1
    # 每页的数据量
    size = 50
    # 只看Web资产
    is_web = 1
    # 状态码200
    status_code = 200
    # 现在时间
    end_time = datetime.datetime.now()
    # 一年前时间
    start_time = str(int(end_time.strftime("%Y")) - 1) + "-" + end_time.strftime("%m-%d %H:%M:%S")
    # url编码
    end_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
    start_time = quote(start_time)
    end_time = quote(end_time)


    url = "https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page={}&page_size={}&is_web={}&status_code={}&start_time={}&end_time={}".format(
        apikey, qbase64, page, size, is_web, status_code, start_time, end_time
    )

    try:
        res = requests.get(url=url, headers=headers, timeout=10, verify=False)
        ret = json.loads(res.text)

        if ret["code"] == 401:
            cprint(ret, "red")
            return [], [], []

        data = ret["data"]
        # 查询的总共数量
        total = data["total"]
        # 消耗积分
        consume_quota = data["consume_quota"]
        # 今日剩余积分
        rest_quota = data["rest_quota"]
        print("[qianxin] 搜索结果数量: {} | {} | {}".format(total, consume_quota, rest_quota))

        total = MaxTotal if total > MaxTotal else total
        pages = total / size
        pages = math.ceil(pages)
        print('[qianxin] 限定查询的数量:{}'.format(total))
        print('[qianxin] 查询的页数:{}'.format(pages))

        print("[qianxin] page{}".format(1))

        arr = data["arr"]
        qianxin_Results_tmp, qianxin_web_host_port_tmp, qianxin_service_host_port_tmp = filter_data(arr)
        qianxin_Results.extend(qianxin_Results_tmp)
        qianxin_web_host_port.extend(qianxin_web_host_port_tmp)
        qianxin_service_host_port.extend(qianxin_service_host_port_tmp)


        if pages != 1:
            for page in range(2, pages + 1):
                print("[qianxin] page{}".format(page))


                try:
                    url = "https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page={}&page_size={}&is_web={}&status_code={}&start_time={}&end_time={}".format(
                        apikey, qbase64, page, size, is_web, status_code, start_time, end_time
                    )

                    res = requests.get(url=url, headers=headers, timeout=10, verify=False)
                    ret = json.loads(res.text)
                    if ret["code"] == 401:
                        cprint(ret, "red")
                        continue

                    arr = data["arr"]
                    qianxin_Results_tmp, qianxin_web_host_port_tmp, qianxin_service_host_port_tmp = filter_data(arr)
                    qianxin_Results.extend(qianxin_Results_tmp)
                    qianxin_web_host_port.extend(qianxin_web_host_port_tmp)
                    qianxin_service_host_port.extend(qianxin_service_host_port_tmp)

                except Exception as e:
                    print('[error] qianxin 查询 {} : {}'.format(query_str, e.args))

        return qianxin_Results, qianxin_web_host_port, qianxin_service_host_port


    except Exception as e:
        print('[error] qianxin 查询 {} : {}'.format(query_str, e.args))
        return [], [], []

