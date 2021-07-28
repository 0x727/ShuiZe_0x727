import requests
import re
from threading import Thread
from queue import Queue
import configparser
import time

'''
username
password
account
passwd
pwd
vpn
mail
jdbc
conn
'''


# github api 查询结果，返回json格式数据
def githubApiSearchCode(domain, page):
    # type=c搜索代码，s=indexed排序的类型，o=desc排序方式，page第几页，
    # q=搜索的关键字，q=signtool+sign+pfx+language:Batchfile  指定语言在q参数里，使用language参数
    # extension:pfx 指定后缀在q参数里，使用extension参数
    url = 'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q="{}"&page={}&per_page={}'.format(domain, page, per_page)
    # print(url)

    try:
        res = requests.get(url=url, headers=headers, timeout=10)
        json_text = res.json()
        return json_text
    except Exception as e:
        print('[-] curl api error.')
        # print("%s[-] error occurred: %s%s" % (fg('red'), e, attr(0)))
        return False

# 筛选api返回的json数据，匹配出子域名
def getSubdomain(raw_q, i, github_subdomains, save_fold_path, domain):
    while not raw_q.empty():
        raw_url = raw_q.get()
        try:
            res = requests.get(url=raw_url, headers=headers, timeout=10)
            text = res.text
            subdomains = cmp.findall(text)
            if subdomains:
                # print(subdomains)
                for subdomain in subdomains:
                    github_subdomains.add(subdomain)
                # print('[{}] {}'.format(len(subdomains), raw_url))
                    # print(subdomain)

            with open('{}/{}_github.txt'.format(save_fold_path, domain), 'at') as f:
                f.write('[------------------] {} [------------------] \n'.format(raw_url))
                f.write('{}\n'.format(text))

        except Exception as e:
            print('[-] {} errors: {}'.format(raw_url, e.args))

# 初始化参数
def init(domain):
    global cmp, per_page, query, headers
    cf = configparser.ConfigParser()
    cf.read("./iniFile/config.ini")
    github_token = cf.get('github api', 'GITHUB_TOKEN')  # github的api token
    regexp = r'[0-9a-zA-Z_\-\.]+\.' + domain.replace('.', '\.')             # 正则语法
    cmp = re.compile(regexp)                                                # 模式对象
    per_page = 30                                                           # 每页的结果个数
    headers = {"Authorization": "token " + github_token}                    # api的请求头



# 调用github子域名功能
def githubApiRun(domain, save_fold_path):
    init(domain)
    github_subdomains = set()

    json_text = githubApiSearchCode(domain, 1)
    try:
        total_count = json_text['total_count']
    except Exception as e:
        return []

    total_count = 300 if total_count > 300 else total_count

    pages = total_count // per_page           # 每页的数据是30个


    for page in range(1, pages):
        # print('curl page{}'.format(page))
        json_text = githubApiSearchCode(domain, page)
        if json_text and 'items' in json_text.keys():
            raw_q = Queue(-1)
            items = json_text['items']
            for item in items:
                raw_url = item['html_url'].replace('https://github.com/', 'https://raw.githubusercontent.com/').replace('/blob/', '/')
                raw_q.put(raw_url)

            threads = []
            for i in range(per_page):
                t = Thread(target=getSubdomain, args=(raw_q, i, github_subdomains, save_fold_path, domain))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()

        print('[page: {}] [num: {}]'.format(page, len(github_subdomains)))
        # time.sleep(2)

    github_subdomains = list(github_subdomains)
    # for _ in github_subdomains:
    #     print(_)

    # print('[total: {}] {}'.format(len(github_subdomains), github_subdomains))
    return github_subdomains

