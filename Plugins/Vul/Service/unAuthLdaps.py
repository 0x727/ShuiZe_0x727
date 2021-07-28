import ldap3
from termcolor import cprint

# Ldaps未授权漏洞检测
class Detect():
    name = 'ldaps'

    def __init__(self, ip, port, vul_list):
        self.ip = ip
        self.port = port
        self.vul_list = vul_list                    # 存储漏洞的名字和url

    # 只需要修改下面的代码就行
    def run_detect(self, weakPwdsList):
        # print('test ldaps : {}:389'.format(self.ip))
        try:
            server = ldap3.Server(host=self.ip, port=389, allowed_referral_hosts=[('*', False)], get_info=ldap3.ALL,
                                  connect_timeout=30)       # port就默认使用389，因为ldap查出来的端口是636，但是实际利用得用389端口
            conn = ldap3.Connection(server, auto_bind=True)
            if len(server.info.naming_contexts) > 0:
                for _ in server.info.naming_contexts:
                    if conn.search(_, '(objectClass=inetOrgPerson)'):
                        naming_contexts = _.encode('utf8')
                        # print naming_contexts
                        cprint('[ok] -> [{}] {} : {}'.format(self.name, self.ip, naming_contexts), 'red')
                        self.vul_list.append([self.name, '{}:389 {}'.format(self.ip, naming_contexts), 'Yes'])
                        break
        except Exception as e:
            pass

if __name__ == '__main__':
    ip = r'ip'
    port = 0000
    vul_list = []
    Detect(ip, port, vul_list).run_detect([])
    print(vul_list)