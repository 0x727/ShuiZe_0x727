#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.1
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import multiprocessing
import gevent
from gevent import monkey
monkey.patch_all()
from gevent.queue import PriorityQueue
import re
import dns.resolver
import time
import signal
import os
import glob
from Plugins.infoGather.subdomain.lijiejie.lib.common import is_intranet, load_dns_servers, load_next_sub, print_msg, get_out_file_name, user_abort
# from lib.common import is_intranet, load_dns_servers, load_next_sub, print_msg, get_out_file_name, user_abort
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SubNameBrute:
    def __init__(self, target, options, process_num, dns_servers, next_subs,
                 scan_count, found_count, queue_size_list, tmp_dir):
        self.target = target.strip()
        self.options = options
        self.process_num = process_num
        self.dns_servers = dns_servers
        self.dns_count = len(dns_servers)
        self.next_subs = next_subs
        self.scan_count = scan_count
        self.scan_count_local = 0
        self.found_count = found_count
        self.found_count_local = 0
        self.queue_size_list = queue_size_list

        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(options['threads'])]
        for _r in self.resolvers:
            _r.lifetime = _r.timeout = 6.0
        self.queue = PriorityQueue()
        self.item_index = 0
        self.priority = 0
        self._load_sub_names()
        self.ip_dict = {}
        self.found_subs = set()
        self.ex_resolver = dns.resolver.Resolver(configure=False)
        self.ex_resolver.nameservers = dns_servers
        self.local_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, target, process_num), 'w')

    def _load_sub_names(self):
        if self.options['full_scan'] and self.options['file'] == 'subnames.txt':
            _file = './iniFile/dict/subnames_full.txt'
        else:
            if os.path.exists(self.options['file']):
                _file = self.options['file']
            elif os.path.exists('./iniFile/dict/%s' % self.options['file']):
                _file = './iniFile/dict/%s' % self.options['file']
            else:
                print_msg('[ERROR] Names file not found: %s' % self.options['file'])
                exit(-1)

        normal_lines = []
        wildcard_lines = []
        wildcard_list = []
        regex_list = []
        lines = set()
        with open(_file) as f:
            for line in f.readlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                if sub.find('{alphnum}') >= 0 or sub.find('{alpha}') >= 0 or sub.find('{num}') >= 0:
                    wildcard_lines.append(sub)
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_list:
                        wildcard_list.append(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
        if regex_list:
            pattern = '|'.join(regex_list)
            _regex = re.compile(pattern)
            for line in normal_lines[:]:
                if _regex.search(line):
                    normal_lines.remove(line)

        for item in normal_lines[self.process_num::self.options['process']]:
            self.priority += 1
            self.queue.put((self.priority, item))

        for item in wildcard_lines[self.process_num::self.options['process']]:
            self.queue.put((88888888, item))

    def put_item(self, item):
        num = item.count('{alphnum}') + item.count('{alpha}') + item.count('{num}')
        if num == 0:
            self.priority += 1
            self.queue.put((self.priority, item))
        else:
            self.queue.put((self.priority + num * 10000000, item))

    def _scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        while not self.queue.empty():
            try:
                item = self.queue.get(timeout=3.0)[1]
                self.scan_count_local += 1
                if time.time() - self.local_time > 3.0:
                    self.scan_count.value += self.scan_count_local
                    self.scan_count_local = 0
                    self.queue_size_list[self.process_num] = self.queue.qsize()
            except Exception as e:
                break
            try:
                if item.find('{alphnum}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                        self.put_item(item.replace('{alphnum}', _letter, 1))
                    continue
                elif item.find('{alpha}') >= 0:
                    for _letter in 'abcdefghijklmnopqrstuvwxyz':
                        self.put_item(item.replace('{alpha}', _letter, 1))
                    continue
                elif item.find('{num}') >= 0:
                    for _letter in '0123456789':
                        self.put_item(item.replace('{num}', _letter, 1))
                    continue
                elif item.find('{next_sub}') >= 0:
                    for _ in self.next_subs:
                        self.queue.put((0, item.replace('{next_sub}', _, 1)))
                    continue
                else:
                    sub = item

                if sub in self.found_subs:
                    continue

                cur_sub_domain = sub + '.' + self.target
                _sub = sub.split('.')[-1]
                try:
                    answers = self.resolvers[j].query(cur_sub_domain)
                except dns.resolver.NoAnswer as e:
                    answers = self.ex_resolver.query(cur_sub_domain)

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0']:
                        continue

                    if self.options['i'] and is_intranet(answers[0].address):
                        continue

                    try:
                        self.scan_count_local += 1
                        answers = self.resolvers[j].query(cur_sub_domain, 'cname')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.target) and cname not in self.found_subs:
                            self.found_subs.add(cname)
                            cname_sub = cname[:len(cname) - len(self.target) - 1]    # new sub
                            self.queue.put((0, cname_sub))

                    except:
                        pass

                    if (_sub, ips) not in self.ip_dict:
                        self.ip_dict[(_sub, ips)] = 1
                    else:
                        self.ip_dict[(_sub, ips)] += 1
                        if self.ip_dict[(_sub, ips)] > 30:
                            continue

                    self.found_count_local += 1
                    if time.time() - self.local_time > 3.0:
                        self.found_count.value += self.found_count_local
                        self.found_count_local = 0
                        self.queue_size_list[self.process_num] = self.queue.qsize()
                        self.local_time = time.time()

                    msg = cur_sub_domain.ljust(30) + ips
                    # print_msg(msg, line_feed=True)

                    self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()
                    try:
                        self.resolvers[j].query('lijiejietest.' + cur_sub_domain)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                        self.queue.put((999999999, '{next_sub}.' + sub))
                    except:
                        pass

            except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel) as e:
                pass
            except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                pass
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s %s\n' % (type(e), cur_sub_domain, str(e)))

    def run(self):
        threads = [gevent.spawn(self._scan, i) for i in range(self.options['threads'])]
        gevent.joinall(threads)


def run_process(target, options, process_num, dns_servers, next_subs, scan_count, found_count, queue_size_list,
                tmp_dir):
    signal.signal(signal.SIGINT, user_abort)
    s = SubNameBrute(target=target, options=options, process_num=process_num,
                     dns_servers=dns_servers, next_subs=next_subs,
                     scan_count=scan_count, found_count=found_count, queue_size_list=queue_size_list,
                     tmp_dir=tmp_dir)
    s.run()


def lijiejieRun(domain):
    # options, args = parse_args()
    options = {'file': 'subnames.txt', 'full_scan': False, 'i': False, 'threads': 200, 'process': 6, 'output': None}
    args = [domain]
    start_time = time.time()
    # make tmp dirs
    tmp_dir = './Plugins/infoGather/subdomain/lijiejie/tmp/%s_%s' % (args[0], int(time.time()))
    # tmp_dir = 'tmp/%s_%s' % (args[0], int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    multiprocessing.freeze_support()
    all_process = []
    dns_servers = load_dns_servers()
    next_subs = load_next_sub(options)
    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)
    queue_size_list = multiprocessing.Array('i', options['process'])

    try:
        print('[+] Init %s scan process.' % options['process'])
        for process_num in range(options['process']):
            p = multiprocessing.Process(target=run_process,
                                        args=(args[0], options, process_num,
                                              dns_servers, next_subs,
                                              scan_count, found_count,queue_size_list,
                                              tmp_dir)
                                        )
            all_process.append(p)
            p.start()

        while all_process:
            for p in all_process:
                if not p.is_alive():
                    all_process.remove(p)
            groups_count = 0
            for c in queue_size_list:
                groups_count += c
            msg = '[*] %s found, %s scanned in %.1f seconds, %s groups left' % (
                found_count.value, scan_count.value, time.time() - start_time, groups_count)
            print_msg(msg)
            time.sleep(1.0)
    except KeyboardInterrupt as e:
        for p in all_process:
            p.terminate()
        print('[ERROR] User aborted the scan!')
    except Exception as e:
        print(e)

    msg = '[+] All Done. %s found, %s scanned in %.1f seconds.' % (
        found_count.value, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    out_file_name = './Plugins/infoGather/subdomain/lijiejie/{}'.format(get_out_file_name(args[0], options))
    # out_file_name = '{}'.format(get_out_file_name(args[0], options))
    with open(out_file_name, 'w') as f:
        for _file in glob.glob(tmp_dir + '/*.txt'):
            with open(_file,'r') as tmp_f:
                content = tmp_f.read()
            f.write(content)
    print('[+] The output file is %s' % out_file_name)

