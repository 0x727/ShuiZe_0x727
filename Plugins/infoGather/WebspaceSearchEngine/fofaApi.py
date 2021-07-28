import requests
import base64
import json
import configparser


# 域名查询语句domain="xxx.com"
# c段查询语句ip="xxx.xxx.xxx.0/24"
# query = r'domain="xxx.com"'
# query = r'ip="xxx.xxx.xxx.0/24"'

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
secs = cf.sections()
email = cf.get('fofa api', 'EMAIL')
key = cf.get('fofa api', 'KEY')

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

size = 10000
page = 1

def query_ip(c_subnet):
    print('[fofa] 查询：{}'.format(c_subnet))
    return query(c_subnet)

def query_domain(query_str):
    print('[fofa] 查询：{}'.format(query_str))
    return query(query_str)

# 过滤出web服务
def filter_web(result):

    host, title, ip, domain, port, server, protocol, address = result

    # 返回开放http服务的ip和端口
    if 'http' in protocol or protocol == '':
        web_host_port = '{}'.format(host)       # web服务, host是IP:PORT
        return True, web_host_port
    else:   # 其他非web服务
        return False, [protocol, ip, int(port)]


def query(query_str):
    fofa_web_host_port = []  # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    fofa_service_host_port = []     # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测

    qbase64 = str(base64.b64encode(query_str.encode(encoding='utf-8')), 'utf-8')
    url = r'https://fofa.so/api/v1/search/all?email={}&key={}&qbase64={}&size={}&page={}&fields=host,title,ip,domain,port,server,protocol,city'.format(email, key, qbase64, size, page)
    try:
        ret = json.loads(requests.get(url=url, headers=headers, timeout=10, verify=False).text)
        fofa_Results = ret['results']
        for result in fofa_Results:
            isWeb, host_port = filter_web(result)
            if isWeb:
                fofa_web_host_port.append(host_port)
            else:
                fofa_service_host_port.append(host_port)
        return fofa_Results, fofa_web_host_port, fofa_service_host_port

    except Exception as e:
        print('[error] fofa 查询 {} : {}'.format(query_str, e.args))
        return [], [], []

