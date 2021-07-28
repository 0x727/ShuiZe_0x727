import requests
import redis
from termcolor import cprint

# redis未授权漏洞检测
class Detect():
    name = 'redis'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        # print('test redis : {} {}'.format(self.ip, self.port))
        try:
            r = redis.Redis(host=self.ip, port=self.port, socket_timeout=20)
            r.set('name', 'test')
            if r.get('name'):
                cprint('[ok] -> [{}] {}:{}'.format(self.name, self.ip, self.port), 'red')
                self.vul_list.append([self.name, '{}:{}'.format(self.ip, self.port), 'Yes'])
            else:
                print('[error] -> {}:{}'.format(self.ip, self.port))
        except Exception as e:
            print(e.args)

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)