import pymssql
from termcolor import cprint

# mssql弱口令爆破
class Detect():
    name = 'mssql'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        user = 'sa'
        database = 'master'

        for password in weakPwdsList:
            password = password.strip()
            try:
                # 一定要加tds_version='7.0'，否则会报错
                conn = pymssql.connect(host=self.ip, user=user, password=password, database=database, charset='utf8', tds_version='7.0')
                conn.close()
                cprint('[+] [{}] [{}] [sa:{}] successful!'.format(self.name, self.ip, password), 'red')
                self.vul_list.append([self.name, self.ip, 'Yes [{}:{}]'.format(user, password)])
                break
            except pymssql.OperationalError as e:
                if '18456' in str(e.args):
                    print('[-] [{}] [sa:{}] mssql password error'.format(self.ip, password))
                elif '20009' in str(e.args):
                    cprint('[Fail] [{}] not open mssql service'.format(self.ip), 'cyan')
                    break
            except Exception as e:
                pass

        '''
        # 账号密码错误
        pymssql.OperationalError: (18456, b"\xe7\x94\xa8\xe6\x88\xb7 'sa' \xe7\x99\xbb\xe5\xbd\x95\xe5\xa4\xb1\xe8\xb4\xa5\xe3\x80\x82DB-Lib error message 18456, severity 14:\nGeneral SQL Server error: Check messages from the SQL Server\nDB-Lib error message 20002, severity 9:\nAdaptive Server connection failed\n")
        # mssql服务没开
        pymssql.OperationalError: (20009, b'DB-Lib error message 20009, severity 9:\nUnable to connect: Adaptive Server is unavailable or does not exist\nNet-Lib error during Connection refused (61)\n')
        '''


if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)