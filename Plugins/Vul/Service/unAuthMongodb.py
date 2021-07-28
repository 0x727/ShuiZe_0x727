from pymongo import MongoClient
from termcolor import cprint

# mongodb未授权漏洞检测
class Detect():
    name = 'mongodb'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        # print('test mongodb : {} {}'.format(self.ip, self.port))
        try:
            conn = MongoClient(self.ip, self.port, socketTimeoutMS=5000)  # 连接MongoDB,延时5秒
            dbs = conn.database_names()
            conn.close()
            cprint('[ok] -> [{}] {}:{} database_names:{}'.format(self.name, self.ip, self.port, dbs), 'red')
            self.vul_list.append([self.name, '{}:{} {}'.format(self.ip, self.port, dbs), 'Yes'])
        except Exception as e:
            # print(e.args)
            pass

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)