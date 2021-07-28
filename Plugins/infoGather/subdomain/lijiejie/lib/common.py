# common functions

import sys
import os
from gevent.pool import Pool
import dns.resolver
from Plugins.infoGather.subdomain.lijiejie.lib.consle_width import getTerminalSize
# from lib.consle_width import getTerminalSize

console_width = getTerminalSize()[0] - 2


def is_intranet(ip):
    ret = ip.split('.')
    if len(ret) != 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False


def print_msg(msg=None, left_align=True, line_feed=False):
    if left_align:
        sys.stdout.write('\r' + msg + ' ' * (console_width - len(msg)))
    else:  # right align
        sys.stdout.write('\r' + ' ' * (console_width - len(msg)) + msg)
    if line_feed:
        sys.stdout.write('\n')
    sys.stdout.flush()


def test_server(server, dns_servers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = resolver.timeout = 6.0
    try:
        resolver.nameservers = [server]
        answers = resolver.query('public-dns-a.baidu.com')    # test lookup an existed domain
        if answers[0].address != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            resolver.query('test.bad.dns.lijiejie.com')    # Non-existed domain test
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except:
            dns_servers.append(server)
        print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
    except:
        print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))


def load_dns_servers():
    print_msg('[+] Validate DNS servers', line_feed=True)
    dns_servers = []
    pool = Pool(10)
    for server in open('./iniFile/dict/dns_servers.txt').readlines():
    # for server in open('dict/dns_servers.txt').readlines():
        server = server.strip()
        if server:
            pool.apply_async(test_server, (server, dns_servers))
    pool.join()

    dns_count = len(dns_servers)
    print_msg('\n[+] %s available DNS Servers found in total' % dns_count, line_feed=True)
    if dns_count == 0:
        print_msg('[ERROR] No DNS Servers available!', line_feed=True)
        sys.exit(-1)
    return dns_servers


def load_next_sub(options):
    next_subs = []
    _set = set()
    # _file = './Plugins/infoGather/subdomain/lijiejie/dict/next_sub_full.txt' if False else './Plugins/infoGather/subdomain/lijiejie/dict/next_sub.txt'
    _file = './iniFile/dict/next_sub_full.txt' if options['full_scan'] else './iniFile/dict/next_sub.txt'
    with open(_file) as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                while tmp_set:
                    item = tmp_set.pop()
                    if item.find('{alphnum}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', _letter, 1))
                    elif item.find('{alpha}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', _letter, 1))
                    elif item.find('{num}') >= 0:
                        for _letter in '0123456789':
                            tmp_set.add(item.replace('{num}', _letter, 1))
                    elif item not in _set:
                        _set.add(item)
                        next_subs.append(item)
    return next_subs


def get_out_file_name(target, options):
    if options['output']:
        outfile = options['output']
    else:
        _name = os.path.basename(options['file']).replace('subnames', '')
        if _name != '.txt':
            _name = '_' + _name
        outfile = target + _name if not options['full_scan'] else target + '_full' + _name
    return outfile


def user_abort(sig, frame):
    exit(-1)
