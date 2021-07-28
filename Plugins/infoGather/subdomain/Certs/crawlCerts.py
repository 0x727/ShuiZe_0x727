import socket
import ssl
from queue import Queue
from threading import Thread

# 抓取https域名的证书dns信息
class crawlCerts:
    def __init__(self, domain, subdomains):
        self.domain = domain
        self._domain = domain.split('.')[0]
        self.newDomains = []
        self.subdomains = subdomains
        self.subdomains_Queue = Queue(-1)
        self.TIMEOUT = 10           # sockets超时
        self.threadsNum = 20
        self.threads = []           # 存放多线程

        self.cacert_path = r'./Plugins/infoGather/subdomain/Certs/cacert.pem'
        # self.cacert_path = r'../../../../Plugins/infoGather/subdomain/Certs/cacert.pem'       # 测试用
        self.certsSubdomains = []       # 存放子域名
        self.trustedDomainDict = {}     # key为子域名，value为证书信息

    def run(self):
        for _ in self.subdomains:
            self.subdomains_Queue.put(_)

        for i in range(1, self.threadsNum + 1):
            t = Thread(target=self.craw_certs)
            self.threads.append(t)
            t.start()
        for t in self.threads:
            t.join()

        return list(set(self.certsSubdomains)), self.trustedDomainDict, list(set(self.newDomains))

    def craw_certs(self):
        while not self.subdomains_Queue.empty():
            subdomain = self.subdomains_Queue.get()
            print('req certs -> {}'.format(subdomain))
            try:
                s = socket.socket()
                s.settimeout(self.TIMEOUT)
                c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=self.cacert_path)
                c.settimeout(10)
                c.connect((subdomain, 443))
                cert = c.getpeercert()
                dns_domains = [each[1] for each in cert['subjectAltName']]
                for trustedDomain in dns_domains:
                    print("[{}] Found Trusted Domains [{}]".format(subdomain, trustedDomain))
                    if self._domain in trustedDomain:
                        self.certsSubdomains.append(trustedDomain.strip('*.'))
                        if '.{}'.format(self.domain) not in trustedDomain:
                            self.newDomains.append(trustedDomain.strip('*.'))
                self.trustedDomainDict[subdomain] = dns_domains

            except Exception as e:
                pass
                # print(e.args)
                #print("    [-] %s" % (subdomain))


if __name__ == '__main__':
    domain = ''
    subdomains = ['']
    certsSubdomains, trustedDomainDict, newDomains = crawlCerts(domain, subdomains).run()
    print(certsSubdomains)
    print(trustedDomainDict)
    print(newDomains)