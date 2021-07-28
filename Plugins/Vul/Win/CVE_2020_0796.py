import threading
from termcolor import cprint
import socket
import struct
import socks
from queue import Queue

pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

class Detect(threading.Thread):
    name = 'CVE-2020-0796'

    def __init__(self, alive_host_queue, vul_list, proxy):
        threading.Thread.__init__(self)
        self.alive_host_queue = alive_host_queue      # 存活主机的队列
        self.vul_list = vul_list                    # 存储漏洞的名字和url
        self.setProxy(proxy)

    def setProxy(self, proxy):
        if proxy:
            socks.set_default_proxy(socks.SOCKS5, proxy.split(':')[0], int(proxy.split(':')[1]))  # 设置socks代理
            socket.socket = socks.socksocket  # 必须得有，否则代理不进去
            socket.setdefaulttimeout(0.01)  # 0.01恰好

    def run(self):
        while not self.alive_host_queue.empty():
            alive_host = self.alive_host_queue.get()            # 127.0.0.1
            self.run_detect(alive_host)

    # 只需要修改下面的代码就行
    def run_detect(self, ip):
        sock = socket.socket(socket.AF_INET)
        sock.settimeout(3)

        try:
            sock.connect((str(ip), 445))
            sock.send(pkt)

            nb, = struct.unpack(">I", sock.recv(4))
            res = sock.recv(nb)

            if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
                pass
            else:
                cprint('[CVE-2020-0796] {}'.format(ip), 'red')
                self.vul_list.append(['CVE-2020-0796', ip, 'Yes'])
        except:
            sock.close()



if __name__ == '__main__':
    from queue import Queue
    alive_host = ['192.168.168.148']
    vul_list = []
    proxy = "1.1.1.1:1111"


    alive_host_queue = Queue(-1)  # 将存活的web存入队列里
    for _ in alive_host:
        alive_host_queue.put(_)

    threads = []
    thread_num = 1  # 漏洞检测的线程数目
    for num in range(1, thread_num + 1):
        t = Detect(alive_host_queue, vul_list, proxy)  # 实例化漏洞类，传递参数：存活web的队列，  存储漏洞的列表
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    print(vul_list)