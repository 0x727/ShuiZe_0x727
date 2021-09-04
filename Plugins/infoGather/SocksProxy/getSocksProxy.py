import requests
import base64
import json
import configparser
from threading import Thread
from queue import Queue
import random
import urllib3
from termcolor import cprint
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
secs = cf.sections()
email = cf.get('fofa api', 'EMAIL')
key = cf.get('fofa api', 'KEY')

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

size = 10000
page = 1

# 访问百度和谷歌
def curlWeb(socks5_proxys_queue, socksProxysDict):
    while not socks5_proxys_queue.empty():
        proxy = socks5_proxys_queue.get()
        requests_proxies = {"http": "socks5://{}".format(proxy), "https": "socks5://{}".format(proxy)}
        baidu_url = "https://www.baidu.com"
        google_url = "https://www.google.com"

        try:
            res2 = requests.get(url=google_url, headers=headers, timeout=10, verify=False, proxies=requests_proxies)
            if res2.status_code == 200:
                print("{} 成功访问谷歌 [{}]".format(proxy, res2.status_code))
                socksProxysDict["google"].append(proxy)
                continue
        except Exception as e:
            pass

        try:
            res = requests.get(url=baidu_url, headers=headers, timeout=10, verify=False, proxies=requests_proxies)
            if res.status_code == 200:
                print("{} 成功访问百度 [{}]".format(proxy, res.status_code))
                socksProxysDict["baidu"].append(proxy)
        except Exception as e:
            pass


def query_socks5():
    query_str = r'protocol=="socks5" && "Version:5 Method:No Authentication(0x00)" && country="CN"'
    qbase64 = str(base64.b64encode(query_str.encode(encoding='utf-8')), 'utf-8')
    url = r'https://fofa.so/api/v1/search/all?email={}&key={}&qbase64={}&size={}&page={}&fields=host,title,ip,domain,port,country,city,server,protocol'.format(email, key, qbase64, size, page)

    socks5_proxys = []
    try:
        ret = json.loads(requests.get(url=url, headers=headers, timeout=10, verify=False).text)
        fofa_Results = ret['results']
        for result in fofa_Results:
            host, title, ip, domain, port, country, city, server, protocol = result
            proxy = ip + ":" + port
            socks5_proxys.append(proxy)
    except Exception as e:
        print('[error] fofa 查询 {} : {}'.format(query_str, e.args))
        cprint("请检查fofa的api是否正确", 'red')

    return socks5_proxys


def run_getSocksProxy():
    socksProxysDict = {"baidu": [], "google": []}
    socks5_proxys = query_socks5()
    socks5_proxys_queue = Queue(-1)
    if socks5_proxys:
        # 随机取1000个代理ip
        for eachSocks5 in random.sample(socks5_proxys, 200):
            socks5_proxys_queue.put(eachSocks5)

        threads = []
        for num in range(100):
            t = Thread(target=curlWeb, args=(socks5_proxys_queue, socksProxysDict))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    return socksProxysDict



# if __name__ == '__main__':
#     cf = configparser.ConfigParser()
#     cf.read("../../../iniFile/config.ini")
#     secs = cf.sections()
#     email = cf.get('fofa api', 'EMAIL')
#     key = cf.get('fofa api', 'KEY')
#     run_getSocksProxy()



