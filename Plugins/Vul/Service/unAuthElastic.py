import requests
from elasticsearch import Elasticsearch
from termcolor import cprint
import re

# ElasticSearch未授权漏洞检测
class Detect():
    name = 'elastic'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        # print('test elastic : {} {}'.format(self.ip, self.port))
        try:
            es = Elasticsearch("{}:{}".format(self.ip, self.port), timeout=20)  # 连接Elasticsearch,延时5秒
            es.indices.create(index='unauth_text')
            print('[+] connect to ：{}'.format(self.ip))
            print('[+] {} -> Successful creation of a unauth_text node'.format(self.ip))
            es.index(index="unauth_text", doc_type="test-type", id=2, body={"text": "text"})
            print('[+] {} -> Successfully insert data into node unauth_text'.format(self.ip))
            ret = es.get(index="unauth_text", doc_type="test-type", id=2)
            print('[+] {} -> Successful acquisition of node unauth_text data : {}'.format(self.ip, ret))
            es.indices.delete(index='unauth_text')
            print('[+] {} -> Clear test node unauth_text data'.format(self.ip))


            host = '{}:{}'.format(self.ip, self.port)
            try:
                print('[+] {} -> Trying to get node information：↓'.format(self.ip))
                text = es.cat.indices()
                nodes = re.findall(r'open ([^ ]*) ', text)
                cprint('[ok] -> [{}] {}:{} -> : {}'.format(self.name, self.ip, self.port, nodes), 'red')
                host = '{} {}'.format(host, nodes)
            except Exception:
                cprint('[ok] -> [{}] {}:{}'.format(self.name, self.ip, self.port), 'red')

            self.vul_list.append([self.name, host, 'Yes'])

        except Exception as e:
            print(e.args)


if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)