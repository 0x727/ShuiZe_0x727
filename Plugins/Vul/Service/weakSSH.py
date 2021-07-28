import paramiko
from termcolor import cprint

# ssh弱口令爆破
class Detect():
    name = 'ssh'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        username = 'root'

        # 创建一个ssh的客户端，用来连接服务器
        ssh = paramiko.SSHClient()
        # 创建一个ssh的白名单
        know_host = paramiko.AutoAddPolicy()
        # 加载创建的白名单
        ssh.set_missing_host_key_policy(know_host)

        for password in weakPwdsList:
            password = password.strip()
            try:
                # 连接服务器
                ssh.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=username,
                    password=password
                )
                cprint('[+] [{}] [{}] [root:{}] successful!'.format(self.name, self.ip, password), 'red')
                self.vul_list.append([self.name, self.ip, 'Yes [{}:{}]'.format(username, password)])
                ssh.close()
                break
            except paramiko.ssh_exception.AuthenticationException as e:
                print('[-] [{}] [root:{}] ssh password error'.format(self.ip, password))
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                cprint('[Fail] [{}] not open ssh service'.format(self.ip), 'cyan')
                break
            except paramiko.ssh_exception.SSHException as e:
                pass
            except Exception as e:
                pass

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)