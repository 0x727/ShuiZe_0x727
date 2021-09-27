# coding:utf-8
import requests
import json
import math
import re
import configparser

# 域名查询语句domain:"xxx.com"
# c段查询语句ip:"xxx.xxx.xxx.0/24"
# query = r'domain:"xxx.com"'
# query = r'ip:"xxx.xxx.xxx.0/24'

cf = configparser.ConfigParser()
# cf.read("../../../iniFile/config.ini")      # 测试
cf.read("./iniFile/config.ini")
secs = cf.sections()
X_QuakeToken = cf.get('quake api', 'X-QuakeToken')

# 查询的最大数据量
MaxTotal = int(cf.get('quake nums', 'quake_nums'))
size = 50
TIMEMOUT = 20

def query_domain(query_str):
    print('[quake] 查询：{}'.format(query_str))
    return query(query_str)


def query_ip(query_str):
    print('[quake] 查询：{}'.format(query_str))
    return query(query_str)



def filter_data(data):
    quake_Results_tmp = []
    quake_web_host_port_tmp = []       # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    quake_service_host_port_tmp = []   # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测
    for each_data in data:
        '''host	标题	ip	子域名	端口	服务	协议	地址	查询语句	robots'''
        ip, port, host, name, title, path, product, province_cn, favicon, x_powered_by, cert = '', '', '', '', '', '', '', '', '', '', ''
        # print(each_data)
        # aaaa = json.dumps(each_data)
        # print(aaaa)

        ip = each_data['ip']  # ip
        port = each_data['port']  # port
        location = each_data['location']  # 地址
        service = each_data['service']

        province_cn = location['province_cn']  # 地址

        name = service['name']  # 协议
        product = service['product']  # 服务
        if 'cert' in service.keys():
            cert = service['cert']  # 证书
            cert = re.findall("DNS:(.*?)\n", cert)

        if 'http' in service.keys():
            http = service['http']
            host = http['host']  # 子域名
            title = http['title']  # title
            # x_powered_by = http['x_powered_by']
            # favicon = http['favicon']
            # path = http['path']  # 路径

        host, title, ip, subdomain, port, server, protocol, address, cert = host, title, ip, host, port, product, name, province_cn, cert
        quake_Result = [host, title, ip, subdomain, port, server, protocol, address, cert]
        quake_Results_tmp.append(quake_Result)

        # print('host: {}'.format(host))
        # print('title: {}'.format(title))
        # print('ip: {}'.format(ip))
        # print('subdomain: {}'.format(subdomain))
        # print('port: {}'.format(port))
        # print('server: {}'.format(server))
        # print('protocol: {}'.format(protocol))
        # print('address: {}'.format(address))
        # print('cert: {}'.format(cert))


        # 返回开放http服务的ip和端口
        if 'http' in protocol and host:
            host_port = '{}:{}'.format(host, port)
            # print(host_port)
            quake_web_host_port_tmp.append(host_port)
        else:
            host_port = [protocol, ip, port]
            # print(host_port)
            quake_service_host_port_tmp.append(host_port)

    return quake_Results_tmp, quake_web_host_port_tmp, quake_service_host_port_tmp




def query(query_str):
    quake_Results = []
    quake_web_host_port = []
    quake_service_host_port = []
    headers = {
        "X-QuakeToken": X_QuakeToken
    }
    data = {
        "query": query_str,
        "start": 0,
        "size": size
    }

    # 查询剩余积分
    try:
        response = requests.get(url="https://quake.360.cn/api/v3/user/info", headers=headers, json=data, timeout=TIMEMOUT)
        month_remaining_credit = response.json()["data"]["month_remaining_credit"]
        print('[quake] 积分剩余:{}'.format(month_remaining_credit))
    except Exception as e:
        print('[quake] api error')
        return [], [], []

    # 查询
    try:
        response = requests.post(url="https://quake.360.cn/api/v3/search/quake_service", headers=headers, json=data, timeout=TIMEMOUT)
    except Exception as e:
        print('[quake] error: {}'.format(e.args))
        return [], [], []

    if response.status_code != 200:
        print('[quake] api error')
        return [], [], []



    ret = response.json()
    # print(ret)

    if ret['meta'] == {}:
        print(ret['message'])
        return [], [], []


    meta = ret['meta']
    data = ret['data']

    total = meta['pagination']["total"]
    count = meta['pagination']['count']

    if total == 0:
        return [], [], []

    print('[quake] 总共数据量:{}'.format(total))
    total = MaxTotal if total > MaxTotal else total
    pages = total / count
    pages = math.ceil(pages)
    print('[quake] 限定查询的数量:{}'.format(total))
    print('[quake] 查询的页数:{}'.format(pages))

    print("[quake] page{}".format(1))
    quake_Results_tmp, quake_web_host_port_tmp, quake_service_host_port_tmp = filter_data(data)
    quake_Results.extend(quake_Results_tmp)
    quake_web_host_port.extend(quake_web_host_port_tmp)
    quake_service_host_port.extend(quake_service_host_port_tmp)

    if pages != 1:
        for page in range(2, pages+1):
            start = (page - 1) * size
            print("[quake] page{}".format(page))
            data = {
                "query": query_str,
                "start": start,
                "size": size
            }

            try:
                response = requests.post(url="https://quake.360.cn/api/v3/search/quake_service", headers=headers, json=data, timeout=TIMEMOUT)
                ret = response.json()
                data = ret['data']
                meta = ret['meta']
                quake_Results_tmp, quake_web_host_port_tmp, quake_service_host_port_tmp = filter_data(data)
                quake_Results.extend(quake_Results_tmp)
                quake_web_host_port.extend(quake_web_host_port_tmp)
                quake_service_host_port.extend(quake_service_host_port_tmp)
            except Exception as e:
                pass

    return quake_Results, quake_web_host_port, quake_service_host_port




if __name__ == '__main__':
    c_subnet = 'xxx.xxx.xxx.0'
    query_str = 'title:"xxx" AND country:"China"'
    quake_Results, quake_web_host_port, quake_service_host_port = query_ip(query_str)
    print(quake_Results)
    print(quake_web_host_port)
    print(quake_service_host_port)
    print(len(quake_Results))
