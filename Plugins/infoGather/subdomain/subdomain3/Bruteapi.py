#encoding=utf8
from brutedns import Brutedomain


class cmd_args:
    def __init__(self):
        self.domain=''
        self.speed=''
        self.level=''
        self.cdn = ''
        self.sub_dict=''
        self.next_sub_dict =''
        self.default_dns = ''
        self.other_result=''

class Brute_subdomain_api:
    def run(self,domain, speed, level,default_dns,cdn,sub_dict,next_sub_dict,other_file):
        cmd_args.domain = domain
        cmd_args.speed = speed
        cmd_args.level = level
        cmd_args.sub_file = sub_dict
        cmd_args.default_dns= default_dns
        cmd_args.next_sub_file = next_sub_dict
        cmd_args.other_file = other_file
        cmd_args.cname='y'
        brute = Brutedomain(cmd_args)
        brute.run()
        return brute.found_count
