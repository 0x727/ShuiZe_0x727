from kazoo.client import KazooClient
from termcolor import cprint

# Zookeeper未授权漏洞检测
class Detect():
    name = 'zookeeper'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        # print('test zookeeper : {}:{}'.format(self.ip, self.port))
        try:
            zk = KazooClient(hosts='{}:{}'.format(self.ip, self.port))
            zk.start()
            chidlrens = zk.get_children('/')
            if len(chidlrens) > 0:
                cprint('[ok] -> [{}] {}:{}   {}'.format(self.name, self.ip, self.port, chidlrens), 'red')
                self.vul_list.append([self.name, '{}:{} {}'.format(self.ip, self.port, chidlrens), 'Yes'])
            zk.stop()
        except Exception as e:
            pass

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)