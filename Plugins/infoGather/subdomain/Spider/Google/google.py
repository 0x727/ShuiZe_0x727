from Spider.Google.googlesearch import search
from sys import version_info

PY2, PY3 = (True, False) if version_info[0] == 2 else (False, True)

if PY2:
    from urlparse import urlparse
else:
    from urllib.parse import urlparse

# 谷歌爬虫
class GoogleSpider:
    def __init__(self, domain, save_fold_path):
        self.domain = domain
        # site:domain inurl:admin inurl:login inurl:system 后台 系统
        self.wds = ['inurl:admin|login|register|upload|editor', '后台|系统']
        # print('Please wait a few time ...')
        self.STOP = 50      # 谷歌最多爬取20个结果
        self.save_fold_path = save_fold_path    # \result\0ca9b508e31f
        self.googleSubdomains = []

    def run(self):
        for wd in self.wds:
            with open('{}/googleSpider.txt'.format(self.save_fold_path), 'at') as f:
                key = 'site:*.{} {}'.format(self.domain, wd)
                f.writelines('[+] {} :\n'.format(key))
                print('\t[+] google search -> [{}]'.format(key))
                for each_result in search(key):
                    f.writelines('{}\n'.format(each_result))
                    parseRet = urlparse(each_result)
                    subdomain = parseRet.netloc
                    if self.domain in subdomain and subdomain not in self.googleSubdomains:
                        self.googleSubdomains.append(subdomain)

        return self.googleSubdomains
