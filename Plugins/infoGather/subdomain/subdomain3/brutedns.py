# -*- encoding: utf-8 -*-
'''
    author:yanxiu0614@gmail.com
    org:Monster Zero Team
'''
import os
import sys
import json
import time
import csv
import random
import platform



from queue import Queue
from functools import reduce


import gevent
import argparse
from gevent import monkey

monkey.patch_all()

import dns.resolver
from Plugins.infoGather.subdomain.subdomain3.config import config
from IPy import IP


# import logging
# logging.basicConfig(
#     level=logging.DEBUG,
#     filename="brute.log",
#     filemode="a",
#     datefmt='%(asctime)s-%(levelname)s-%(message)s'
# )


class Brutedomain:
    def __init__(self, args, Subdomains_ips):
        self.Subdomains_ips = Subdomains_ips
        self.target_domain = args['domain']
        self.check_env()
        self.cname_flag = args['cname']
        if not (self.target_domain):
            print('usage: brutedns.py -h')
            sys.exit(1)

        self.level = args['level']
        self.sub_dict = args['sub_file']
        self.speed = args['speed']
        self.default_dns = True if args['default_dns'] == "y" else False
        self.next_sub_dict = args['next_sub_file']
        self.other_result = args['other_file']

        self.timeout = 10
        self.resolver = dns.resolver.Resolver(configure=self.default_dns)
        self.resolver.lifetime = self.timeout
        self.resolver.timeout = self.timeout
        
        self.found_count = 0
        self.cmdline=""
        self.queues = Queue()
        self.queue_sub = Queue()
        self.cdn_set = set()
        self.cname_set = set()
        self.white_filter_subdomain=set()
        self.cname_block_dict = dict()
        self.ip_block_dict = dict()
        self.ip_all_dict = dict()
        self.ip_flag_dict = dict()
        self.active_ip_dict = dict()
        self.ip_count_dict = dict()
        self.black_ip_dict=dict()
        self.ip_subdomain_dict=dict()


        self.set_next_sub = self.load_next_sub_dict()
        self.set_cdn = self.load_cdn()

        self.load_sub_dict_to_queue()
        self.extract_next_sub_log()

        self.segment_num = self.judge_speed(self.speed)

        if not self.default_dns:
            self.nameservers = self.load_nameservers()
            self.check_nameservers()

 


    def check_env(self):
        filename = 'result/{name}/{name}'.format(name=self.target_domain)
        if os.path.isfile(filename + ".csv"):
            new_filename = filename + "_" + str(os.stat(filename + ".csv").st_mtime).replace(".", "")
            os.rename(filename + ".csv", new_filename + ".csv")
        if os.path.isfile(filename + "_deal.csv"):
            if not new_filename:
                new_filename = filename + "_" + str(os.stat(filename + "_deal.csv").st_mtime).replace(".", "")
            os.rename(filename + "_deal.csv", new_filename + "_deal.csv")

        if (platform.system() != "Windows"):
            try:
                self.cmdline="\r\n"
                os.system("ulimit -n 65535")
            except Exception:
                pass
        else:
            self.cmdline="\r"

    def load_cdn(self):
        cdn_set = set()
        with open('./iniFile/subdomain3/cdn_servers.txt', 'r') as file_cdn:
            for cname in file_cdn:
                cdn_set.add(cname.strip())
        return cdn_set

    def load_next_sub_dict(self):
        next_sub_set = set()
        with open(self.next_sub_dict, 'r') as file_next_sub:
            for next_sub in file_next_sub:
                next_sub_set.add(next_sub.strip())
        return next_sub_set

    def load_sub_dict_to_queue(self):
        with open(self.sub_dict, 'r') as file_sub:
            for sub in file_sub:
                domain = "{sub}.{target_domain}".format(sub=sub.strip(), target_domain=self.target_domain)
                self.queues.put(domain)

    def load_nameservers(self):
        nameserver_set = set()
        with open('./iniFile/subdomain3/name_servers.txt', 'r') as nameservers:
            for nameserver in nameservers:
                nameserver_set.add(nameserver.strip())
        return nameserver_set

    def load_result_from_other(self):
        log_type = type(self.other_result)
        other_subdomain_list = list()
        if (log_type == str):
            try:
                subdomain_log = open('{target_domain}'.format(target_domain=self.other_result), 'r')
                other_result = [subdomain.strip() for subdomain in subdomain_log]
                subdomain_log.close()
            except Exception:
                print('subdomain log is not exist')
                sys.exit(1)
        elif (log_type == list):
            other_result = self.other_result
        else:
            other_result = []
        for subdomain in other_result:
            other_subdomain_list.append(subdomain.strip().strip("."))
        return other_subdomain_list


    def extract_next_sub_log(self):
        other_subdomain_list = self.load_result_from_other()
        for subdomain in other_subdomain_list:
            if (('.' + str(self.target_domain)) in subdomain):
                self.queues.put(subdomain)
            subname = subdomain.strip(".").replace(self.target_domain,"").strip(".")
            if subname!="":
                sub_list = subname.split(".")
                for sub in sub_list:
                    self.set_next_sub.add(sub.strip())

    def check_nameservers(self):
        print("[+] Seraching fastest nameserver,it will take a few minutes")
        server_info = {}
        i = 0
        sys.stdout.write(self.cmdline + '[+] Searching nameserver process:' + str(round(i * 100.00 / len(self.nameservers), 2)) + "% ")
        sys.stdout.flush()
        for nameserver in self.nameservers:
            i = i + 1
            self.resolver.nameservers = [nameserver]
            self.resolver.lifetime = 3
            start = time.time()
            for _ in range(2):
                random_str = str(random.randint(1, 1000))
                domain_list = [random_str + "testnamservspeed.com" for _ in range(200)]
                coroutines = [gevent.spawn(self.query_domain, l) for l in domain_list]
                gevent.joinall(coroutines)
            end = time.time()
            cost = end - start
            server_info[nameserver] = cost
            sys.stdout.write('\r'+ '[+] Searching nameserver process:' + str(round(i * 100.00 / len(self.nameservers), 2)) + "% ")
            sys.stdout.flush()
        nameserver = sorted(server_info.items(), key=lambda server_info: server_info[1])[0][0]
        print(self.cmdline)
        print("[+] Search completed,fastest nameserver: " + nameserver)
        self.ip_block_dict = dict()
        self.cname_block_dict = dict()
        self.resolver.lifetime = self.timeout
        self.resolver.nameservers = [nameserver]


    def check_cdn(self, cname_list, domain):
        for cname in cname_list:
            cname = cname.lower().rstrip(".")
            domain = domain.lower()
            for cdn in self.set_cdn:
                if (cdn in cname):
                    return True
            if (domain in cname):
                cname_list = cname.split(domain)
                if (cname_list[1] != ""):
                    self.cdn_set.add(cname_list[1].strip("."))
                    return True
            elif ('cdn' in cname or 'cache' in cname):
                self.cdn_set.add(cname)
                return True
            self.cname_set.add(cname)
        return False


    def get_type_id(self, name):
        return dns.rdatatype.from_text(name)

    def query_domain(self, domain):
        list_ip, list_cname = [], []
        try:
            record = self.resolver.query(domain)
            for A_CNAME in record.response.answer:
                for item in A_CNAME.items:
                    if item.rdtype == self.get_type_id('A'):
                        list_ip.append(str(item))
                        self.ip_block_dict[domain] = list_ip
                    elif (item.rdtype == self.get_type_id('CNAME')):
                        list_cname.append(str(item))
                        self.cname_block_dict[domain] = list_cname
        except dns.exception.Timeout:
            self.queues.put(domain)
        except Exception as e:
            pass


    def get_block(self):
        domain_list = list()
        if (self.queues.qsize() > self.segment_num):
            for _ in range(self.segment_num):
                domain_list.append(self.queues.get())
        else:
            for _ in range(self.queues.qsize()):
                domain_list.append(self.queues.get())
        return domain_list
    
    def get_black_subdomain(self):
        temp_list=list()
        temp_set=set()
        for subdomain_list in self.black_ip_dict.values():
            temp_list.extend(subdomain_list)
        black_subdomain=set(temp_list)-self.white_filter_subdomain
        for domain in  black_subdomain:
            for next_sub in self.set_next_sub:
                subdomain = "{next}.{domain}".format(next=next_sub, domain=domain)
                temp_set.add(subdomain)
        return temp_set

    def judge_speed(self, speed):
        if (speed == "low"):
            segment_num = config.low_segment_num
        elif (speed == "high"):
            segment_num = config.high_segment_num
        else:
            segment_num = config.medium_segment_num
        return segment_num

    
    def generate_sub(self):
        try:
            domain = self.queue_sub.get_nowait()
            for next_sub in self.set_next_sub:
                subdomain = "{next}.{domain}".format( next=next_sub.strip(), domain=domain)
                self.queues.put_nowait(subdomain)
            return True
        except Exception as e:
            return False


    def deweighting_subdomain(self):
        temp_list = list()
        for subdomain, ip_list in self.ip_block_dict.items():
            ip_str = str(sorted(ip_list))
            if ip_str not in self.black_ip_dict.keys():
                if (self.ip_count_dict.__contains__(ip_str)):
                    self.ip_subdomain_dict[ip_str].append(subdomain)
                    if (self.ip_count_dict[ip_str] > config.ip_max_count):
                        temp_list.append(subdomain)
                    else:
                        self.ip_count_dict[ip_str] = self.ip_count_dict[ip_str] + 1
                else:
                    self.ip_subdomain_dict[ip_str]=[subdomain]
                    self.ip_count_dict[ip_str] = 1

                for ip in ip_list:
	                if ip in config.waiting_fliter_ip:
	                    temp_list.append(subdomain)
	                if (IP(ip).iptype() != 'PUBLIC' ):
	                    temp_list.append(subdomain)
            else:
                temp_list.append(subdomain)
            
        

        for ip_str,count in  self.ip_count_dict.items():
            if(count>10):
                i=0
                subdomain_list=self.ip_subdomain_dict[ip_str]
                min_subdomain=reduce(lambda x, y: x if len(x) < len(y) else y, subdomain_list)
                for subdomain in subdomain_list:
                    if("."+min_subdomain in subdomain):
                        i=i+1
                    if(i>10):
                        self.black_ip_dict[ip_str]=subdomain_list
                        break

        for  subdomain_list in self.black_ip_dict.values():
            temp_list.extend(subdomain_list)
        
        for subdomain in temp_list:
            try:
                del self.ip_all_dict[subdomain]
            except Exception:
                pass
            try:
                del self.cname_block_dict[subdomain]
                self.white_filter_subdomain.add(subdomain)
            except Exception:
                pass
            try:
                del self.ip_block_dict[subdomain]
            except Exception:
                pass

        self.found_count = self.ip_all_dict.__len__()
        self.ip_all_dict.update(self.ip_block_dict)
        
        for subdomain, ip_list in self.ip_block_dict.items():
            if (subdomain.count(".") < self.level):
                self.queue_sub.put(subdomain)
        self.ip_block_dict.clear()

    
    def handle_data(self):
        for subdomain, cname_list in self.cname_block_dict.items():
            if (self.check_cdn(cname_list, self.target_domain)):
                cname_list.append("Yes")
            else:
                cname_list.append("No")
            self.cname_block_dict[subdomain] = cname_list
        for subdomain, ip_list in self.ip_all_dict.items():
            for ip in ip_list:
                iptype=IP(ip).iptype()
                if (iptype != 'PUBLIC'):
                    self.ip_all_dict[subdomain] = "{iptype}({ip})".format(iptype=iptype,ip=ip)
                else:
                    try:
                        key_yes = self.cname_block_dict[subdomain][-1]
                    except KeyError:
                        key_yes = "No"
                    if (key_yes == "No"):
                        CIP = (IP(ip).make_net("255.255.255.0"))
                        if CIP in self.ip_flag_dict:
                            self.ip_flag_dict[CIP] = self.ip_flag_dict[CIP] + 1
                        else:
                            self.ip_flag_dict[CIP] = 1

                        if CIP in self.active_ip_dict:
                            active_ip_list = self.active_ip_dict[CIP]
                            if (ip not in active_ip_list):
                                active_ip_list.append(ip)
                        else:
                            active_ip_list = [ip]
                        self.active_ip_dict[CIP] = active_ip_list

    def raw_write_disk(self):
        for subdomain, ip_list in self.ip_all_dict.items():
            try:
                flag = self.dict_cname_all[subdomain].pop()
                cname_list = self.cname_block_dict[subdomain]
            except Exception:
                flag = "No"
                cname_list = "Null"
            self.Subdomains_ips[subdomain] = ip_list
            # writer.writerow([subdomain, flag, cname_list, ip_list])
        self.ip_all_dict.clear()
        self.cname_block_dict.clear()

    def deal_write_disk(self):
        ip_flags = sorted(
            self.ip_flag_dict.items(),
            key=lambda d: d[1],
            reverse=True)
        # with open('result/{name}/{name}_deal.csv'.format(name=self.target_domain), 'w') as csvfile:
        #     writer = csv.writer(csvfile)
        #     writer.writerow(['IP', 'frequency', 'active'])
        #     for ip_frequency in ip_flags:
        #         writer.writerow([ip_frequency[0], ip_frequency[1], self.active_ip_dict[ip_frequency[0]]])

    # def collect_cname(self):
    #     with open('result/cname.txt', 'a') as txt:
    #         for cname in self.cname_set:
    #             flag=False
    #             for cdn in self.set_cdn:
    #                 if(cdn in cname or self.target_domain in cname):
    #                     flag=True
    #             if(flag==False):
    #                 txt.write('{cname}'.format(cname=cname.strip())+self.cmdline)
    #     with open('result/cdn.txt', 'a') as txt:
    #         for cdn in self.cdn_set:
    #             txt.write('{cname}'.format(cname=cdn)+self.cmdline)

    def cmd_print(self, wait_size, start, end, i):
        scaned = self.segment_num * i
        cost = end - start
        sys.stdout.write(
                "\r"+ "[+] Bruting subdomain process domain: {domain} |scaned: {scaned}|found: {found_count} |speed:{velocity} |spend: {spend} min ".format(
                domain=self.target_domain,
                scaned=scaned,
                qsize=wait_size,
                found_count=self.found_count,
                velocity=round(scaned / cost, 1),
                spend=round(cost / 60, 1)))
        sys.stdout.flush()

    def run(self):
        start = time.time()
        print("[+] Begin to brute domain")
        i = 0
        while not self.queues.empty() or not self.queue_sub.empty():          
            i = i + 1
            domain_list = set(self.get_block())-self.get_black_subdomain()
            coroutines = [gevent.spawn(self.query_domain, l) for l in domain_list]
            try:
                gevent.joinall(coroutines)
            except KeyboardInterrupt:
                print('user stop')
                sys.exit(1)

            self.deweighting_subdomain()
            self.cmd_print(self.queues.qsize(), start, time.time(), i)

            if (self.queues.qsize() < 30000 and self.queue_sub.qsize()>0):
                while (self.queues.qsize() < 200000):
                    if not self.generate_sub():
                        break

        self.handle_data()
        self.raw_write_disk()
        self.deal_write_disk()
        # self.collect_cname()
        print(self.cmdline)
        print("[+] Brute over")

def run_subdomains(domain):
    args = {'cname': 'y', 'default_dns': 'n', 'domain': domain, 'file': None, 'level': 3,
              'next_sub_file': './iniFile/subdomain3/next_sub_full.txt', 'other_file': None, 'speed': 'fast', 'sub_file': './iniFile/subdomain3/sub_full.txt'}
    Subdomains_ips = {}


    brute = Brutedomain(args, Subdomains_ips)
    try:
        brute.run()
        # if ('y' in brute.cname_flag or 'Y' in brute.cname_flag):
        #     brute.collect_cname()
    except KeyboardInterrupt:
        print('user stop')

    return Subdomains_ips

# Subdomains_ips = run_subdomains('hbu.edu.cn')
# for k in Subdomains_ips:
#     print('{} : {}'.format(k, Subdomains_ips[k]))