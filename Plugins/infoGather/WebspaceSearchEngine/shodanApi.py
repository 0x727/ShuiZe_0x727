# -*- coding: utf-8 -*-
# shodan：只能对主域名扫描（-u）
# eg：python3 scan.py -u pku.edu.cn -p shodan -o pku
import shodan
import configparser


# 域名查询语句hostname="xxx.com"
# c段查询语句net="xxx.xxx.xxx.0/24"
# query = r'hostname:"xxx.com"'
# query = r'net:"xxx.xxx.xxx.0/24'

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
secs = cf.sections()
SHODAN_API_KEY = cf.get('shodan api', 'SHODAN_API_KEY')

def query_ip(query_str):
    print('[shodan] 查询：{}'.format(query_str))
    return query(query_str)

def query_domain(query_str):
    print('[shodan] 查询：{}'.format(query_str))
    return query(query_str)

# 存储到数据库里
def filter_data(result):
    webSpace_web_host_port = []  # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    shodan_Result = []

    # ip和port字段是肯定存在的
    ip = result['ip_str']
    port = result['port']
    address = result['org']

    # 协议字段不一定存在
    protocol = result['_shodan'].get('module', '')  # http， http-simple-new

    # 如果是http协议
    if 'http' in protocol:
        http = result.get('http', '')
        if http:
            title = http['title'] if http['title'] else ''
            robots = http['robots'] if http['robots'] else ''
            host = http['host']
        else:
            host = ''
            title = ''
            robots = ''
    else:
        host = ''
        title = ''
        robots = ''

    server = result.get('product', '')

    if server == 'Elastic':         # shodan的elasticsearch结果是：server='Elastic'， protocol='http'   所以这里要进行筛选
        protocol = 'elastic'        # 把protocol设置为elastic，是为了和fofa匹配
        host = ''

    # title = result['title']
    # print(json.dumps(result))
    # print(protocol, server, host, ip, port, title, robots)  # webvpn.bdu.edu.cn 221.192.237.11 80 保定学院 内网登录 WebVPN # See http://www.robotstxt.org/robotstxt.html for documentation on how to use the robots.txt file
    shodan_Result = [host, title, ip, '', port, server, protocol, address, robots]

    # 返回开放http服务的ip和端口
    if protocol and host:
        host_port = '{}:{}'.format(host, port)
        return shodan_Result, True, host_port
    else:
        host_port = [protocol, ip, port]
        return shodan_Result, False, host_port




def query(query_str):
    shodan_web_host_port = []       # 存放开放web服务器的ip/domain和port，用来后面的cms识别
    shodan_service_host_port = []   # 存放非Web服务器的ip/domain和port，用来后面的未授权漏洞检测
    shodan_Results = []
    limit = 500
    counter = 0

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        for result in api.search_cursor(query_str):
            shodan_Result, isWeb, host_port = filter_data(result)
            shodan_Results.append(shodan_Result)
            if isWeb:
                shodan_web_host_port.append(host_port)
            else:
                shodan_service_host_port.append(host_port)

            counter += 1
            if counter >= limit:
                break


        return shodan_Results, shodan_web_host_port, shodan_service_host_port

    except shodan.APIError as e:
        print('Error: %s' % e)
        return shodan_Results,  shodan_web_host_port, shodan_service_host_port

if __name__ == '__main__':
    cf = configparser.ConfigParser()
    cf.read("../../../iniFile/config.ini")
    secs = cf.sections()
    SHODAN_API_KEY = cf.get('shodan api', 'SHODAN_API_KEY')

    c_subnet = ''
    query_str = 'net:"{}/24"'.format(c_subnet)
    shodan_Results, shodan_web_host_port, shodan_service_host_port = query_ip(query_str)
    print(shodan_Results)
    print(shodan_service_host_port)
    print(shodan_web_host_port)
    print(len(shodan_Results))
