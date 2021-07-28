import socket
from queue import Queue
from threading import Thread
from tqdm import *
from colorama import Fore
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全都用tqdm.write(url)打印     能够打印在进度条上方，并将进度条下移一行。
# 存在漏洞可能得需要红色，使用   tqdm.write(Fore.RED + url)   打印则有颜色
# 打印一些错误需要灰色 使用   tqdm.write(Fore.WHITE + url)
# 打印漏洞结果 使用   tqdm.write(Fore.BLACK + url)


def oxid(alive_host_Queue, pbar, alive_hostname_ips):
    def run_detect():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((ip, 135))
            buffer_v1 = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
            buffer_v2 = b"\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
            sock.send(buffer_v1)
            packet = sock.recv(1024)
            sock.send(buffer_v2)
            packet = sock.recv(4096)
            packet_v2 = packet[42:]
            packet_v2_end = packet_v2.find(b"\x09\x00\xff\xff\x00\x00")
            packet_v2 = packet_v2[:packet_v2_end]
            hostname_list = packet_v2.split(b"\x00\x00")
            tqdm.write(Fore.RED + "[*] " + ip)
            result = [ip]
            for h in hostname_list:
                h = h.replace(b'\x07\x00', b'')
                h = h.replace(b'\x00', b'')
                if h == b'':
                    continue
                h = h.decode('utf-8')
                tqdm.write(Fore.RED + "\t[->] {}".format(h))
                result.append(h)
            alive_hostname_ips.append(result)
        except Exception as e:
            pass
        finally:
            sock.close()

    while not alive_host_Queue.empty():
        ip = alive_host_Queue.get()
        pbar.set_postfix(oxid=ip, name='get_IntranetHostName and IP')  # 进度条的显示
        run_detect()
        pbar.update(1)  # 每完成一个任务，进度条也加+1
        alive_host_Queue.task_done()



def run_getMoreIp(alive_host_List):
    alive_hostname_ips = []

    alive_host_Queue = Queue(-1)
    for alive_host in alive_host_List:
        alive_host_Queue.put(alive_host)


    threads = []

    pbar = tqdm(total=alive_host_Queue.qsize(), desc="检测漏洞", ncols=150)  # total是总数

    for num in range(1, 20):
        t = Thread(target=oxid, args=(alive_host_Queue, pbar, alive_hostname_ips))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    pbar.close()

    return alive_hostname_ips

if __name__ == '__main__':
    alive_host_List = ['192.168.168.143', '192.168.30.134', '192.168.30.140', '192.168.30.131']
    alive_hostname_ips = run_getMoreIp(alive_host_List)

    print(alive_hostname_ips)

    for _ in alive_hostname_ips:
        print(_)