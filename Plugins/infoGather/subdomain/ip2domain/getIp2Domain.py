import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from queue import Queue
from threading import Thread
from IPy import IP
import re

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
TIMEOUT = 10
cmp = re.compile(r'{"domain":"http:\\/\\/(.*?)","title":".*?"}')        # 正则匹配规则

def ip2domain(allTargets_Queue, domain, _domain, ip2domain_dict, num, newDomains):
    while not allTargets_Queue.empty():
        ip = allTargets_Queue.get()
        url = r'http://api.webscan.cc/?action=query&ip={}'.format(ip)
        print(url)
        try:
            res = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
            text = res.text
            if text != 'null':
                results = eval(text)
                domains = []
                for each in results:
                    domains.append(each['domain'])
                # domains = cmp.findall(text)
                if domains:
                    ip2domain_dict[ip] = domains
                    print('[{}] {}'.format(ip, domains))
                    if domain:
                        for each in domains:
                            if _domain in each and domain not in each and len(each) > 1:
                                newDomains.append(each)
        except Exception as e:
            print('[error] ip2domain: {}'.format(e.args))



def run_ip2domain(domain, allTargets_Queue):
    ip2domain_dict = {}         # 字典，key为IP，value为归属地
    newDomains = []
    if domain:      #
        _domain = domain.split('.')[0]      # baidu
    else:
        _domain = None

    threads = []
    for num in range(50):
        t = Thread(target=ip2domain, args=(allTargets_Queue, domain, _domain, ip2domain_dict, num, newDomains))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    return ip2domain_dict, list(set(newDomains))


if __name__ == '__main__':
    domain = ''
    allTargets_Queue = Queue(-1)
    allTargets_Queue.put('')
    allTargets_Queue.put('')
    ip2domain_dict, _newDomains = run_ip2domain(domain, allTargets_Queue)
    # for ip in ip2domain_dict:
    #     print('[{}] -> {}'.format(ip, ip2domain_dict[ip]))

    print(ip2domain_dict)
    subdomains = []
    for subdomain in ip2domain_dict.values():
        subdomains.extend(subdomain)

    setSubdomains = list(set(subdomains))
    print('[{}] {}'.format(len(setSubdomains), setSubdomains))
    print(_newDomains)

#