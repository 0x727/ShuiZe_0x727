import requests
import configparser
import json
import re
import cloudscraper
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 10

# virustotal api 查询结果，返回json格式数据
def virustotal_api():
    print('Load VirusTotal api ...')
    virustotal_subdomains = []
    url = r'https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}'.format(virustotalApi, domain)
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        if res.status_code == 403:
            print('VirusTotal API error.')
            return []
        elif res.status_code == 200:
            ret_json = json.loads(res.text)
            if 'subdomains' in ret_json.keys():
                virustotal_subdomains = ret_json['subdomains']
        else:
            print('VirusTotal API No Subdomains.')
    except Exception as e:
        print('[-] curl virustotal api error.')

    print('[{}] {}'.format(len(virustotal_subdomains), virustotal_subdomains))
    return virustotal_subdomains

# ce.baidu.com api 查询结果，返回json格式数据
def ce_baidu_api():
    print('Load ce.baidu.com api ...')
    ce_baidu_subdomains = []
    url = r'http://ce.baidu.com/index/getRelatedSites?site_address={}'.format(domain)
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        ret_json = json.loads(res.text)
        if 'data' in ret_json.keys():
            for _ in ret_json['data']:
                ce_baidu_subdomains.append(_['domain'])
        else:
            print('ce.baidu.com API No Subdomains.')
    except Exception as e:
        print('[-] curl ce.baidu.com api error. {}'.format(e.args))

    print('[{}] {}'.format(len(ce_baidu_subdomains), ce_baidu_subdomains))
    return ce_baidu_subdomains

# url.fht.im api 查询结果，返回json格式数据
def fht_api():
    print('Load url.fht.im api ...')
    url = r'https://url.fht.im/domain_search?domain={}'.format(domain)
    fht_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=30)
        if 'No Captures found ' not in res.text:
            for _ in res.text.split('\n'):
                fht_subdomains.append(_)
        else:
            print('url.fht.im API No Subdomains.')
    except Exception as e:
        print('[-] curl url.fht.im api error. {}'.format(e.args))

    print('[{}] {}'.format(len(fht_subdomains), fht_subdomains))
    return fht_subdomains

def qianxun_api():
    print('Load qianxun api ...')
    qianxun_subdomains = []
    url = r'https://www.dnsscan.cn/dns.html'
    data = r'ecmsfrom=36.36.211.23&show=%e5%b9%bf%e4%b8%9c%e7%9c%81&num=&classid=0&keywords={}&page=1'.format(domain)       # 数据包
    subdomain_rule = r'rel="nofollow" target="_blank">(.*)</a></td>'        # 匹配子域名的正则
    subdomain_compilie = re.compile(subdomain_rule)
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    try:
        # 获取页数
        res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=30)
        html_text = res.text
        nums = int(re.findall('查询结果为:([\d]+)条', html_text)[0])
        pages = nums / 20
        if '.' in str(pages):
            pages = nums // 20 + 1
        else:
            pages = nums // 20

        # 第一页的子域名
        for subdomain in subdomain_compilie.findall(html_text):
            qianxun_subdomains.append(subdomain)

        # 第二页往后的子域名
        for i in range(2, pages + 1):

            data = r'ecmsfrom=36.36.211.23&show=%e5%b9%bf%e4%b8%9c%e7%9c%81&num=&classid=0&keywords={}&page={}'.format(domain, i)
            res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=TIMEOUT)
            for subdomain in subdomain_compilie.findall(res.text):
                qianxun_subdomains.append(subdomain)
    except Exception as e:
        print('[-] curl qianxun api error. {}'.format(e.args))

    print('[{}] {}'.format(len(qianxun_subdomains), qianxun_subdomains))
    return qianxun_subdomains

# https://api.sublist3r.com/search.php?domain=hbu.cn 查询结果 返回json
def sublist3r_api():
    print('Load sublist3r api ...')
    url = r'https://api.sublist3r.com/search.php?domain={}'.format(domain)
    sublist3r_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if text != 'null':
            for subdomain in eval(text):
                sublist3r_subdomains.append(subdomain)
        else:
            print('sublist3r API No Subdomains.')
    except Exception as e:
        print('[-] curl sublist3r api error. {}'.format(e.args))

    print('[{}] {}'.format(len(sublist3r_subdomains), sublist3r_subdomains))
    return sublist3r_subdomains

# https://crt.sh/?q=.hbu.cn&output=json
def crt_api():
    print('Load crt api ...')
    url = r'https://crt.sh/?q={}&output=json'.format(domain)
    crt_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if text != '[]':
            for _ in eval(text):
                subdomain = _['common_name']
                if '*.' in subdomain:
                    subdomain = subdomain.replace('*.', '')
                crt_subdomains.append(subdomain)
        else:
            print('crt API No Subdomains.')
    except Exception as e:
        print('[-] curl crt api error. {}'.format(e.args))

    crt_subdomains = list(set(crt_subdomains))
    print('[{}] {}'.format(len(crt_subdomains), crt_subdomains))
    return crt_subdomains

# https://api.certspotter.com/v1/issuances?domain=hbu.cn&include_subdomains=true&expand=dns_names
def certspotter_api():
    print('Load certspotter api ...')
    url = r'https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names'.format(domain)
    certspotter_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if 'not_allowed_by_plan' not in text:
            for _ in eval(text):
                for subdomain in _['dns_names']:
                    if domain in subdomain:
                        if '*.' in subdomain:
                            subdomain = subdomain.replace('*.', '')
                        certspotter_subdomains.append(subdomain)
        else:
            print('certspotter API No Subdomains.')
    except Exception as e:
        print('[-] curl certspotter api error. {}'.format(e.args))

    certspotter_subdomains = list(set(certspotter_subdomains))
    print('[{}] {}'.format(len(certspotter_subdomains), certspotter_subdomains))
    return certspotter_subdomains

# http://dns.bufferover.run/dns?q=.hbu.cn
def bufferover_api():
    print('Load bufferover api ...')
    url = r'http://dns.bufferover.run/dns?q=.{}'.format(domain)
    bufferover_subdomains = []
    error_num = 0           # 请求错误次数
    reqError = False         # 请求错误
    while error_num < 10 and not reqError:
        try:
            scraper = cloudscraper.create_scraper()         # 绕Cloudflare验证码
            res = scraper.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
            text = res.text
            FDNS_A_value = json.loads(text)['FDNS_A']
            if FDNS_A_value:
                for _ in FDNS_A_value:
                    subdomain = _.split(',')[-1]
                    bufferover_subdomains.append(subdomain)
            else:
                print('bufferover API No Subdomains.')
            reqError = True             # 绕过Cloudflare验证码
        except Exception as e:
            error_num += 1
            print('[-] [{}] curl bufferover api error. {}'.format(error_num, e.args))

    bufferover_subdomains = list(set(bufferover_subdomains))
    print('[{}] {}'.format(len(bufferover_subdomains), bufferover_subdomains))
    return bufferover_subdomains

# https://threatcrowd.org/searchApi/v2/domain/report/?domain=hbu.cn
def threatcrowd_api():
    print('Load threatcrowd api ...')
    url = r'https://threatcrowd.org/searchApi/v2/domain/report/?domain={}'.format(domain)
    threatcrowd_subdomains = []
    error_num = 0           # 请求错误次数
    reqError = False         # 请求错误
    while error_num < 10 and not reqError:      # 当没有绕过Cloudflare验证码时，并且重复次数小于50次时，一直循环
        try:
            scraper = cloudscraper.create_scraper()
            res = scraper.get(url=url, headers=headers, timeout=TIMEOUT)
            text = res.text
            text_json = json.loads(text)
            response_code = text_json['response_code']
            if response_code == '1':
                for subdomain in text_json['subdomains']:
                    threatcrowd_subdomains.append(subdomain)
            else:
                print('threatcrowd API No Subdomains.')
            reqError = True             # 绕过Cloudflare验证码
        except Exception as e:
            error_num += 1
            print('[-] [{}] curl threatcrowd api error. {}'.format(error_num, e.args))

    threatcrowd_subdomains = list(set(threatcrowd_subdomains))
    print('[{}] {}'.format(len(threatcrowd_subdomains), threatcrowd_subdomains))
    return threatcrowd_subdomains

# https://api.hackertarget.com/hostsearch/?q=hbu.cn
def hackertarget_api():
    print('Load hackertarget api ...')
    url = r'https://api.hackertarget.com/hostsearch/?q={}'.format(domain)
    hackertarget_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if text != 'error check your search parameter':
            for _ in text.split('\n'):
                subdomain = _.split(',')[0]
                hackertarget_subdomains.append(subdomain)
        else:
            print('hackertarget API No Subdomains.')
    except Exception as e:
        print('[-] curl hackertarget api error. {}'.format(e.args))

    hackertarget_subdomains = list(set(hackertarget_subdomains))
    print('[{}] {}'.format(len(hackertarget_subdomains), hackertarget_subdomains))
    return hackertarget_subdomains

# https://chaziyu.com/hbu.cn/
def chaziyu_api():
    print('Load chaziyu api ...')
    url = r'https://chaziyu.com/{}/'.format(domain)
    chaziyu_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        status_code = res.status_code
        if status_code != 404:
            results = re.findall(r'target="_blank">(.*\.{})</a></td>'.format(domain), text)
            for subdomain in results:
                chaziyu_subdomains.append(subdomain)
        else:
            print('chaziyu API No Subdomains.')
    except Exception as e:
        print('[-] curl chaziyu api error. {}'.format(e.args))

    print('[{}] {}'.format(len(chaziyu_subdomains), chaziyu_subdomains))
    return chaziyu_subdomains

# https://rapiddns.io/subdomain/hbu.cn#result
def rapiddns_api():
    print('Load rapiddns api ...')
    url = r'https://rapiddns.io/subdomain/{}#result'.format(domain)
    rapiddns_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        results = re.findall(r'target="_blank">(.*\.{})</a></td>'.format(domain), text)
        if results:
            for subdomain in results:
                rapiddns_subdomains.append(subdomain)
        else:
            print('rapiddns API No Subdomains.')
    except Exception as e:
        print('[-] curl rapiddns api error. {}'.format(e.args))

    print('[{}] {}'.format(len(rapiddns_subdomains), rapiddns_subdomains))
    return rapiddns_subdomains

# http://www.sitedossier.com/parentdomain/hbu.cn
def sitedossier_api():
    print('Load sitedossier api ...')
    url = r'http://www.sitedossier.com/parentdomain/{}'.format(domain)
    sitedossier_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        results = re.findall(r'<a href="/site/(.*\.{})">'.format(domain), text)
        if results:
            for subdomain in results:
                sitedossier_subdomains.append(subdomain)
        else:
            print('sitedossier API No Subdomains.')
    except Exception as e:
        print('[-] curl sitedossier api error. {}'.format(e.args))

    print('[{}] {}'.format(len(sitedossier_subdomains), sitedossier_subdomains))
    return sitedossier_subdomains

# http://sbd.ximcx.cn/
def ximcx_api():
    print('Load ximcx api ...')
    url = r'http://sbd.ximcx.cn/DomainServlet'
    data = {'domain': domain}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    ximcx_subdomains = []
    try:
        res = requests.post(url=url, data=data, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        results = json.loads(text)
        code = results['code']
        if code == 0:
            for _ in results['data']:
                subdomain = _['domain']
                ximcx_subdomains.append(subdomain)
        else:
            print('ximcx API No Subdomains.')
    except Exception as e:
        print('[-] curl ximcx api error. {}'.format(e.args))

    print('[{}] {}'.format(len(ximcx_subdomains), ximcx_subdomains))
    return ximcx_subdomains


def othersApiSearch():
    virustotal_subdomains = virustotal_api()
    ce_baidu_subdomains = ce_baidu_api()
    fht_subdomains = fht_api()
    qianxun_subdomains = qianxun_api()
    sublist3r_subdomains = sublist3r_api()
    crt_subdomains = crt_api()
    certspotter_subdomains = certspotter_api()
    bufferover_subdomains = bufferover_api()
    threatcrowd_subdomains = threatcrowd_api()
    hackertarget_subdomains = hackertarget_api()
    chaziyu_subdomains = chaziyu_api()
    rapiddns_subdomains = rapiddns_api()
    sitedossier_subdomains = sitedossier_api()
    ximcx_subdomains = ximcx_api()

    othersApiTotalSubdomains = []
    for name, value in locals().items():
        if 'subdomains' in name:
            othersApiTotalSubdomains.extend(value)
    return list(set(othersApiTotalSubdomains))


# 初始化参数
def init(_):
    global virustotalApi, headers, domain
    cf = configparser.ConfigParser()
    cf.read("./iniFile/config.ini")
    # cf.read("../../../../iniFile/config.ini")     # 测试用
    virustotalApi = cf.get('virustotal api', 'VIRUSTOTAL_API')  # virustotal Api
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    domain = _



# 调用virustotal|ce.baidu.com|www.threatcrowd.org|url.fht.im|qianxun|sublist3r的子域名收集脚本
def othersApiRun(domain):
    init(domain)
    othersApiTotalSubdomains = othersApiSearch()
    # print('[total: {}] {}'.format(len(virustotal_subdomains), virustotal_subdomains))
    return othersApiTotalSubdomains


# print(othersApiRun('hbu.edu.cn'))

if __name__ == '__main__':
    domain = ''
    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

    othersApiTotalSubdomains = othersApiRun(domain)
    print('[{}] {}'.format(len(othersApiTotalSubdomains), othersApiTotalSubdomains))