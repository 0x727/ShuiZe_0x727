from googlesearch import search
import sys
from sys import version_info

PY2, PY3 = (True, False) if version_info[0] == 2 else (False, True)

if PY2:
    from urlparse import urlparse
else:
    from urllib.parse import urlparse

key = 'site:hbu.edu.cn 后台'# sys.argv[1]

urls = []

for each_result in search(key, stop=4):
    parseRet = urlparse(each_result)
    print(each_result, parseRet)
    url = parseRet.scheme + '://' + parseRet.netloc
    if key in parseRet.netloc and url not in urls:
        print(url, each_result)
        urls.append(url)

print('search {} Done!'.format(key))
