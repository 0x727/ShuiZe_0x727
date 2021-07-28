import IPy
from queue import Queue
from threading import Thread
import socket
import socks
import configparser
from termcolor import cprint
from tqdm import *
from colorama import Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)



cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
# cf.read("../../../../iniFile/config.ini")     # 测试用
secs = cf.sections()

# web端口
_web_ports = eval(cf.get('web ports', 'web_ports'))
web_ports = []

# 服务端口
service_ports_dict = eval(cf.get('service ports dict', 'service_ports_dict'))


for port in _web_ports:
    if '-' in str(port):
        for _ in range(int(port.split('-')[0]), int(port.split('-')[1]) + 1):
            web_ports.append(_)
    else:
        web_ports.append(port)


# 检测IP是否存活
def ipIsAlive(allTargets_Queue, aliveIps_Queue, pbar):
    def run_detect():
        # print('test : {}'.format(tgtIp))
        isAlive = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        address = (tgtIp, 80)
        try:
            s.connect(address)
            # print('[+] 第[{}:{}]条进程 {} : open [{}] protcol:{}'.format(self.num, pid, tgtIp, tgtPort, protocol))
            tqdm.write(Fore.RED + '[+] {} is alive'.format(tgtIp))
            isAlive = True
        except socks.GeneralProxyError as e:  # Socket error: 0x05: Connection refused 是存活IP
            socket_err = str(e.socket_err)
            if socket_err == '0x05: Connection refused':
                tqdm.write(Fore.RED + '[+] {} is alive'.format(tgtIp))
                isAlive = True
            elif socket_err == '0x04: Host unreachable':
                # tqdm.write(Fore.WHITE + '[-] {} is die'.format(tgtIp))
                isAlive = False
        except Exception as e:
            err_num = e.args[0]
            if err_num == 61:
                tqdm.write(Fore.RED + '[+] {} is alive: {}'.format(tgtIp, e.args))
                isAlive = True
            else:
                # tqdm.write(Fore.WHITE + '[-] {} is die: {}'.format(tgtIp, e.args))
                isAlive = False
        finally:
            s.close()

        if isAlive:
            aliveIps_Queue.put(tgtIp)

    while not allTargets_Queue.empty():
        tgtIp = allTargets_Queue.get()
        pbar.set_postfix(ip=tgtIp, state='alive or die')  # 进度条的显示
        run_detect()
        pbar.update(1)  # 每完成一个任务，进度条也加+1
        allTargets_Queue.task_done()





# 多线程扫描端口
def scanPortMultiThr(allTargetsPorts_Queue, pbar, num, web_host_port, service_host_port):
    def scanPort():

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (tgtIp, int(tgtPort))
        try:
            s.connect(address)
            tqdm.write(Fore.RED + '[+] [t{}] {} open [{}]'.format(num, tgtIp, tgtPort))

            # print('[+] 第[{}:{}]条进程 {} : open [{}] protcol:{}'.format(self.num, pid, tgtIp, tgtPort, protocol))
            s.close()
        except Exception as e:
            # tqdm.write(Fore.WHITE + '[-] [t{}] {} closed [{}]'.format(num, tgtIp, tgtPort))
            s.close()
            return

        if tgtPort in web_ports:
            web_host_port.append('http://{}:{}'.format(tgtIp, tgtPort))
        else:
            service_host_port.append([service_ports_dict[tgtPort], tgtIp, int(tgtPort)])

    while not allTargetsPorts_Queue.empty():
        tgtIp, tgtPort = allTargetsPorts_Queue.get()
        pbar.set_postfix(ipPort='{}:{}'.format(tgtIp, tgtPort), name='scanPort')  # 进度条的显示
        scanPort()
        pbar.update(1)  # 每完成一个任务，进度条也加+1
        allTargetsPorts_Queue.task_done()


def scanPortThread(allTargets_Queue, web_ports, service_ports_dict):
    web_host_port, service_host_port, alive_host_List = [], [], []

    allTargetsPorts_Queue = Queue(-1)


    aliveIps_Queue = Queue(-1)
    threadNum = 30  # 十条线程

    pbar = tqdm(total=allTargets_Queue.qsize(), desc="探测内网主机存活", ncols=150)  # total是总数
    threads = []
    for num in range(1, threadNum + 1):
        t = Thread(target=ipIsAlive, args=(allTargets_Queue, aliveIps_Queue, pbar))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    pbar.close()


    while not aliveIps_Queue.empty():
        ip = aliveIps_Queue.get()
        alive_host_List.append(ip)

    ports = web_ports + list(service_ports_dict.keys())
    for port in ports:
        for ip in alive_host_List:
            allTargetsPorts_Queue.put([ip, port])

    threads = []

    pbar = tqdm(total=allTargetsPorts_Queue.qsize(), desc="扫描内网端口开放", ncols=150)  # total是总数

    for num in range(1, threadNum + 1):
        t = Thread(target=scanPortMultiThr, args=(allTargetsPorts_Queue, pbar, num, web_host_port, service_host_port))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    pbar.close()

    return web_host_port, service_host_port, alive_host_List

# 运行扫描端口
def run_ScanPort(allTargets_Queue, proxy):



    # 设置代理
    if proxy:
        socks.set_default_proxy(socks.SOCKS5, proxy.split(':')[0], int(proxy.split(':')[1]))  # 设置socks代理
        socket.socket = socks.socksocket  # 必须得有，否则代理不进去
        socket.setdefaulttimeout(0.01)  # 0.01恰好



    web_host_port, service_host_port, alive_host_List = scanPortThread(allTargets_Queue, web_ports, service_ports_dict)

    return web_host_port, service_host_port, alive_host_List

if __name__ == '__main__':

    allTargets_Queue = Queue(-1)

    from IPy import IP

    ips = IP('192.168.144.0/24')

    for ip in ips:
        allTargets_Queue.put(str(ip))

    proxy = None
    web_host_port, service_host_port, alive_host_List = run_ScanPort(allTargets_Queue, proxy)
    print(web_host_port)
    print(service_host_port)
    print(alive_host_List)