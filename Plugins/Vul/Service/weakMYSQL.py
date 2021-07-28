import pymysql
from termcolor import cprint


# mysql弱口令爆破
class Detect():
    name = 'mysql'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list  # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        user = 'root'
        for password in weakPwdsList:
            password = password.strip()
            try:
                # 连接数据库
                connect = pymysql.Connect(host=self.ip, port=self.port, user=user, passwd=password, charset='utf8')
                connect.close()
                cprint('[+] [{}] [{}] [root:{}] successful!'.format(self.name, self.ip, password), 'red')
                self.vul_list.append([self.name, self.ip, 'Yes [{}:{}]'.format(user, password)])
                break
            except pymysql.OperationalError as e:
                if 'Access denied for user ' in str(e.args):
                    print('[-] [{}] [root:{}] mysql password error'.format(self.ip, password))
                elif "Can't connect to MySQL server" in str(e.args):
                    cprint('[Fail] [{}] not open mssql service'.format(self.ip), 'cyan')
                    break
            except Exception as e:
                pass

        '''
        # 账号密码错误
        pymysql.err.OperationalError: (1045, "Access denied for user 'root'@'172.18.82.177' (using password: YES)")

        # 没开mysql服务
        pymysql.err.OperationalError: (2003, "Can't connect to MySQL server on '172.18.89.21' ([Errno 61] Connection refused)")
        '''

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)