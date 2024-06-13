import requests
import configparser
import json
import re
import cloudscraper
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 60
headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}


# [废弃] ce.baidu.com api 查询结果，返回json格式数据
def run_ce_baidu(domain):
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

# [废弃] url.fht.im api 查询结果，返回json格式数据
def run_fht(domain):
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

# [废弃]
def run_qianxun(domain):
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

# [废弃] https://api.sublist3r.com/search.php?domain= 查询结果 返回json
def run_sublist3r(domain):
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

# [废弃] http://dns.bufferover.run/dns?q=.hbu.cn
def run_bufferover(domain):
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

# [废弃] https://threatcrowd.org/searchApi/v2/domain/report/?domain=hbu.cn
def run_threatcrowd(domain):
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

# [废弃] https://api.hackertarget.com/hostsearch/?q=hbu.cn
def run_hackertarget(domain):
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

# [废弃]http://sbd.ximcx.cn/
def run_ximcx(domain):
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





# virustotal api 查询结果，返回json格式数据
def run_virustotal(domain, virustotal_api):
    virustotal_context = {"refer": "virustotal", "subdomains": []}
    print('Load VirusTotal api ...')
    url = r'https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}'.format(virustotal_api, domain)
    # print(url)
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        if res.status_code == 403:
            print('VirusTotal API error.')
            # return []
        elif res.status_code == 200:
            ret_json = json.loads(res.text)
            if 'subdomains' in ret_json.keys():
                virustotal_context['subdomains'] = ret_json['subdomains']
        else:
            print('VirusTotal API No Subdomains.')
    except Exception as e:
        print('[-] curl virustotal api error.')

    print('[{}] {}'.format(len(virustotal_context['subdomains']), virustotal_context))
    return virustotal_context

# https://crt.sh/?q=.hbu.cn&output=json
def run_crt(domain):
    crt_context = {"refer": "crt", "subdomains": []}
    print('Load crt api ...')
    url = r'https://crt.sh/?q={}&output=json'.format(domain)
    crt_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if text != '[]':
            for _ in eval(text):
                # subdomain = _['common_name']
                # if '*.' in subdomain:
                #     subdomain = subdomain.replace('*.', '')
                # crt_subdomains.append(subdomain)
                name_value = _['name_value']
                subdomain = name_value.split('\n')
                crt_subdomains.extend(subdomain)
        else:
            print('crt API No Subdomains.')
    except Exception as e:
        print('[-] curl crt api error. {}'.format(e.args))

    crt_context['subdomains'].extend(list(set(crt_subdomains)))
    print('[{}] {}'.format(len(crt_context['subdomains']), crt_context))
    return crt_context

# https://api.certspotter.com/v1/issuances?domain=hbu.cn&include_subdomains=true&expand=dns_names
def run_certspotter(domain):
    certspotter_context = {"refer": "certspotter", "subdomains": []}
    print('Load certspotter api ...')
    url = r'https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names'.format(domain)
    certspotter_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        if 'not_allowed_by_plan' not in text:
            for _ in eval(text.replace('false', 'False')):
                # print(_)
                for subdomain in _['dns_names']:
                    if domain in subdomain:
                        if '*.' in subdomain:
                            subdomain = subdomain.replace('*.', '')
                        certspotter_subdomains.append(subdomain)
        else:
            print('certspotter API No Subdomains.')
    except Exception as e:
        print('[-] curl certspotter api error. {}'.format(e.args))

    certspotter_context['subdomains'].extend(list(set(certspotter_subdomains)))
    print('[{}] {}'.format(len(certspotter_context['subdomains']), certspotter_context))
    return certspotter_context

# https://chaziyu.com/hbu.cn/
def run_chaziyu(domain):
    chaziyu_context = {"refer": "chaziyu", "subdomains": []}
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

    chaziyu_context['subdomains'].extend(list(set(chaziyu_subdomains)))
    print('[{}] {}'.format(len(chaziyu_context['subdomains']), chaziyu_context))
    return chaziyu_context

# https://rapiddns.io/subdomain/hbu.cn#result
def run_rapiddns(domain):
    rapiddns_context = {"refer": "rapiddns", "subdomains": []}
    print('Load rapiddns api ...')
    url = r'https://rapiddns.io/subdomain/{}'.format(domain)
    rapiddns_subdomains = []
    try:
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = res.text
        # results = re.findall(r'target="_blank">(.*\.{})</a></td>'.format(domain), text)
        results = re.findall(r'<td>(.*)</td>'.format(domain), text)
        if results:
            for subdomain in results:
                if domain in subdomain:
                    rapiddns_subdomains.append(subdomain)
        else:
            print('rapiddns API No Subdomains.')
    except Exception as e:
        print('[-] curl rapiddns api error. {}'.format(e.args))

    rapiddns_context['subdomains'].extend(list(set(rapiddns_subdomains)))
    print('[{}] {}'.format(len(rapiddns_context['subdomains']), rapiddns_context))
    return rapiddns_context

# http://www.sitedossier.com/parentdomain/hbu.cn
def run_sitedossier(domain):
    sitedossier_context = {"refer": "sitedossier", "subdomains": []}
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

    sitedossier_context['subdomains'].extend(list(set(sitedossier_subdomains)))
    print('[{}] {}'.format(len(sitedossier_context['subdomains']), sitedossier_context))
    return sitedossier_context

# https://securitytrails.com/
def run_securitytrails(domain, securitytrails_api):
    securitytrails_context = {"refer": "securitytrails", "subdomains": []}
    print('Load securitytrails api ...')

    headers['apikey'] = securitytrails_api
    headers['Accept'] = 'application/json'
    securitytrails_subdomains = []

    try:
        url = "https://api.securitytrails.com/v1/ping"
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
    except Exception as e:
        print('[-] error: {}'.format(e.args))
        return securitytrails_context

    if res.status_code != 200:
        print('[-] securitytrails key错误')
        return securitytrails_context

    try:
        url = "https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false&include_inactive=true".format(domain)
        res = requests.get(url=url, headers=headers, verify=False, timeout=TIMEOUT)
        text = json.loads(res.text)
        subdomains = text['subdomains']
        for subdomain in subdomains:
            securitytrails_subdomains.append("{}.{}".format(subdomain, domain))

        securitytrails_context['subdomains'].extend(list(set(securitytrails_subdomains)))
        print('[{}] {}'.format(len(securitytrails_context['subdomains']), securitytrails_context))
        return securitytrails_context
    except Exception as e:
        print('[-] error: {}'.format(e.args))
        return securitytrails_context



def run_all_api(domain, virustotal_api, securitytrails_api):
    subdomainInterface_context_list = []

    '''
    测试数据
    virustotal_context = {'refer': 'virustotal', 'subdomains': ['www.hbu.cn', 'hb.hbu.cn', 'w.hbu.cn', 'szlx.hbu.cn', '20th.hbu.cn', 'oiceen.hbu.cn', 'mi.hbu.cn', 'zhaoban.hbu.cn', 'cs.hbu.cn', 'cc.hbu.cn', 'hbkjty.hbu.cn', 'tgw.hbu.cn', 'xxgk.hbu.cn', 'en.hbu.cn', 'mcmd.hbu.cn', 'faam.hbu.cn', 'xyh.hbu.cn', 'health.hbu.cn', 'chem.hbu.cn', 'zyxy.hbu.cn', 'wy.hbu.cn', 'uclan.hbu.cn', 'cea.hbu.cn', 'redline.hbu.cn', 'lib.hbu.cn', 'sat.hbu.cn', 'jxjy.hbu.cn', 'history.hbu.cn', 'iac.hbu.cn', 'graduate.hbu.cn', 'fy.hbu.cn', 'vpn.hbu.cn', 'rsc.hbu.cn', 'dxyqgx.hbu.cn', 'aqc.hbu.cn', 'jwc.hbu.cn', 'huli.hbu.cn', 'yjsy.hbu.cn', 'zhjw.hbu.cn', 'ciee.hbu.cn', 'jwold.hbu.cn', 'sysgl.hbu.cn', 'nic.hbu.cn', 'piic.hbu.cn', 'life.hbu.cn', 'archives.hbu.cn', 'gcb.hbu.cn', 'yxb.hbu.cn', 'portal.hbu.cn', 'zczx.hbu.cn', 'zhijian.hbu.cn', 'record.hbu.cn', 'cxcy.hbu.cn', 'ggw.hbu.cn', 'ec.hbu.cn', 'mpa.hbu.cn', 'mba.hbu.cn', 'cjxy.hbu.cn', 'smart.hbu.cn', 'yxy.hbu.cn', 'hbutv.hbu.cn', 'photo.hbu.cn', 'yzwh.hbu.cn', 'wxy.hbu.cn', 'newskc.hbu.cn', 'xiaoban.hbu.cn', 'yx.hbu.cn', 'skc.hbu.cn', 'v.hbu.cn', 'marx.hbu.cn', 'xsfwpt.hbu.cn', 'plat.hbu.cn', 'focus.hbu.cn', 'itest.hbu.cn', 'fkyq.hbu.cn', 'yxyjyjy.hbu.cn', 'oice.hbu.cn', 'xbzrb.hbu.cn', 'sysaqks.hbu.cn', 'rbwtyj.hbu.cn', 'wlxy.hbu.cn', 'bkjsd.hbu.cn', 'tyjxb.hbu.cn', 'pgb.hbu.cn', 'xb-zsb.hbu.cn', 'yiban.hbu.cn', 'law.hbu.cn', 'ssxh.hbu.cn', 'v02.hbu.cn', '100.hbu.cn', 'tuanwei.hbu.cn', 'jiaoyu.hbu.cn', 'jc.hbu.cn', 'hbshxh.hbu.cn', 'fzghc.hbu.cn', 'ceie.hbu.cn', 'dct.hbu.cn', 'wold.hbu.cn', 'sysaqjc.hbu.cn', 'wsbd.hbu.cn']}
    crt_context = {'refer': 'crt', 'subdomains': ['cxcy.hbu.cn', 'smart.hbu.cn', 'hbu.cn', 'cc.hbu.cn', 'oj.hbu.cn', 'healthcare.hbu.cn', 'redline.hbu.cn', 'hbu.edu.cn', 'v02.hbu.cn', 'v.hbu.cn', 'es.hbu.cn', 'dekt.hbu.cn']}
    certspotter_context = {'refer': 'certspotter', 'subdomains': ['cc.hbu.cn', 'hbu.cn']}
    chaziyu_context = {'refer': 'chaziyu', 'subdomains': ['news.hbu.cn', 'xsfwpt.hbu.cn', 'yktang.hbu.cn', 'fzghc.hbu.cn', 'iesc.hbu.cn', 'en.hbu.cn', 'icrc.hbu.cn', 'yzb.hbu.cn', 'www-cnki-net-s.v02.hbu.cn', 'int.hbu.cn', 'yzuuc.hbu.cn', 'dsxxzhuanti.hbu.cn', 'sjd.hbu.cn', 'wschool.hbu.cn', 'aqc.hbu.cn', 'video.hbu.cn', 'nlo.hbu.cn', 'zyxy.hbu.cn', 'pass.hbu.cn', 'law.hbu.cn', '100.hbu.cn', 'zhjw.hbu.cn', 'hbmcm.hbu.cn', 'csmx.hbu.cn', 'www-cnki-net.v02.hbu.cn', 'cxcy.hbu.cn', 'intl.hbu.cn', 'upload.news.hbu.cn', 'zczx.hbu.cn', 'cwc-query.hbu.cn', 'hxppt.hbu.cn', 'syl.hbu.cn', 'healthcare.hbu.cn', 'photo.hbu.cn', 'wsbd.hbu.cn', 'yiban.hbu.cn', 'xb-zsb.hbu.cn', 'xswyh.hbu.cn', 'zhaoban.hbu.cn', 'v.hbu.cn', 'yx.hbu.cn', 'vpn.hbu.cn', 'pgb.hbu.cn', 'museum.hbu.cn', 'huli.hbu.cn', 'itest.hbu.cn', 'xxgk.hbu.cn', 'media.news.hbu.cn', 'record.hbu.cn', 'www.news.hbu.cn']}
    rapiddns_context = {'refer': 'rapiddns', 'subdomains': ['nm.hbu.cn', 'zhjw.v.hbu.cn', 'gh.hbu.cn', 'mba.hbu.cn', 'hedashequ.hbu.cn', 'ygtx.hbu.cn', 'dxyqsblz.hbu.cn', 'bkjsd.hbu.cn', 'huli.hbu.cn', 'v02.hbu.cn', 'ecard.hbu.cn', 'focus.hbu.cn', 'ssxh.hbu.cn', 'redline.hbu.cn', 'jwc.hbu.cn', 'healthcare.hbu.cn', 'archives.hbu.cn', 'wkzx.hbu.cn', 'zhjw.hbu.cn', 'museum.hbu.cn', 'nic.hbu.cn', 'yx.hbu.cn', 'm.news.hbu.cn', 'history.hbu.cn', 'ciee.hbu.cn', 'yzuuc.hbu.cn', 'news.hbu.cn', 'hbshxh.hbu.cn', 'w.hbu.cn', 'cool.hbu.cn', 'v.hbu.cn', 'oiceen.hbu.cn', 'hbkjty.hbu.cn', 'ceie.hbu.cn', 'tyjxb.hbu.cn', 'wy.hbu.cn', 'oj.hbu.cn', 'en.hbu.cn', 'oice.hbu.cn', 'sjd.hbu.cn', 'xyh.hbu.cn', 'hbdxqks.hbu.cn', 'uclan.hbu.cn', 'chem.hbu.cn', 'jjs.hbu.cn', 'xxgk.hbu.cn', 'faam.hbu.cn', 'jiaoyu.hbu.cn', 'hbu.cn', 'www.news.hbu.cn', 'plat.hbu.cn', 'rbwtyj.hbu.cn', 'photo.hbu.cn', 'fkyq.hbu.cn', 'zhaoban.hbu.cn', 'sysgl.hbu.cn', 'upload.news.hbu.cn', 'dwb.hbu.cn', 'mail.hbu.cn', 'www.hbu.cn', 'cwc-query.hbu.cn', 'dct.hbu.cn', 'zczx.hbu.cn', 'sat.hbu.cn', 'xsfwpt.hbu.cn', 'sszx.hbu.cn', 'space.news.hbu.cn', 'wxy.hbu.cn', 'portal.hbu.cn', 'img.news.hbu.cn', 'xfpt.hbu.cn', 'graduate.hbu.cn', 'clc.hbu.cn', 'csmx.hbu.cn', 'cxcy.hbu.cn', 'itc.hbu.cn', 'nm2.hbu.cn', 'mi.hbu.cn', 'xaxq.hbu.cn', 'yjw.hbu.cn', 'dekt.hbu.cn', 'cjxy.hbu.cn', 'yxb.hbu.cn', 'wx.s.hbu.cn', 'tuanwei.hbu.cn', 'yiban.hbu.cn', 'skc.hbu.cn', 'gjzlfzh.hbu.cn', 'tgw.hbu.cn', 'cs.hbu.cn', 'lib.hbu.cn', 'xswyh.hbu.cn', 'mcmd.hbu.cn', 'yjsy.hbu.cn', 'vpn.hbu.cn', 'xiaoban.hbu.cn']}
    sitedossier_context = {'refer': 'sitedossier', 'subdomains': ['xxq.hbu.cn', 'sunny.hbu.cn', 'jc.hbu.cn', 'mpa.hbu.cn', 'hanlin.hbu.cn', 'jwc.hbu.cn', 'jn.hbu.cn', 'kj.hbu.cn', 'lab.hbu.cn', 'rsc.hbu.cn', 'st.hbu.cn', 'hdnews.hbu.cn', 'et.hbu.cn', 'mc.hbu.cn', 'mail.hbu.cn', 'stu.hbu.cn', 'wxy.hbu.cn', 'office.hbu.cn', 'xcb.hbu.cn', 'moodle.hbu.cn', 'gbkh.hbu.cn', 'ad.hbu.cn', 'history.hbu.cn', 'cmcic.hbu.cn', 'hb.hbu.cn', 'graduate.hbu.cn', 'xyh.hbu.cn', 'tuanwei.hbu.cn', 'ph.hbu.cn', 'ceie.hbu.cn', 'huli.hbu.cn', 'cces.hbu.cn', 'xyglc.hbu.cn', 'wy.hbu.cn', 'art.hbu.cn', 'journal.hbu.cn', 'cjxy.hbu.cn', 'job.hbu.cn', 'nic.hbu.cn', 'redline.hbu.cn', 'bb.hbu.cn', 'cc.hbu.cn', 'we.hbu.cn', 'sinto.hbu.cn', 'nm2.hbu.cn', 'bbs.hbu.cn', 'wushu.hbu.cn', 'protein.hbu.cn', 'skc.hbu.cn', 'vpdn.hbu.cn', 'jgdw.hbu.cn', 'su.hbu.cn', 'cwc.hbu.cn', 'hpdb.hbu.cn', 'ygzx.hbu.cn', 'xueke.hbu.cn', 'www.hbu.cn', 'jwc2.hbu.cn', 'gh.hbu.cn', 'xwb.hbu.cn', 'cmc.hbu.cn', 'hbmcm.hbu.cn', 'nm.hbu.cn', 'dangban.hbu.cn', 'pla.hbu.cn', 'hqjt.hbu.cn', 'hanlin2.hbu.cn', 'lib.hbu.cn', 'dxpll.hbu.cn', 'yxb.hbu.cn', 'family.hbu.cn', 'gzc.hbu.cn', 'acc.hbu.cn', 'chem.hbu.cn', 'course.hbu.cn', 'news.hbu.cn', 'sat.hbu.cn', 'ec.hbu.cn', 'manage.hbu.cn', 'mba.hbu.cn', 'fzghc.hbu.cn', 'zhaoban.hbu.cn', 'yxsyzx.hbu.cn', 'ce.hbu.cn', 'yxxk.hbu.cn', 'taibai.hbu.cn']}
    securitytrails_context = {'refer': 'securitytrails', 'subdomains': ['v.hbu.cn', 'yiban.hbu.cn', 'hqzc.hbu.cn', 'xiaoban.hbu.cn', 'jiaoyu.hbu.cn', 'tuanwei.hbu.cn', 'bkjsd.hbu.cn', 'zsys.hbu.cn', 'mi.en.hbu.cn', 'hzbx.hbu.cn', 'opac.hbu.cn', 'ecard.hbu.cn', 'hdyb.hbu.cn', 'cs.hbu.cn', 'yzb.hbu.cn', 'jc.hbu.cn', 'tyjxb.en.hbu.cn', 's1.hbu.cn', 'cz.hbu.cn', 'sksyzx.hbu.cn', 'media.news.hbu.cn', 'app.news.hbu.cn', 'hyqd.hbu.cn', 'zhaopin.hbu.cn', 'syl.hbu.cn', 'gbkh.hbu.cn', 'api.news.hbu.cn', 'rbwtyj.hbu.cn', 'zzb.hbu.cn', 'wx.hbu.cn', 'ecoen.en.hbu.cn', 'uclan.hbu.cn', 'ygtx.hbu.cn', 'mail-mx1.hbu.cn', 'v01.hbu.cn', 'cjxy.hbu.cn', 'chem.hbu.cn', 'wsbd.hbu.cn', 'yxyjyjy.hbu.cn', 'mpa.hbu.cn', 'jjc.hbu.cn', 'jcyxy.hbu.cn', 'xwxy.hbu.cn', 'space.news.hbu.cn', 'xxgk.hbu.cn', 'yxjytk.hbu.cn', 'xsfwpt.hbu.cn', 'health.hbu.cn', 'lawlab.hbu.cn', 'apimedia.news.hbu.cn', 'art.hbu.cn', 'zyxy.hbu.cn', 'phi.hbu.cn', 'sjd.hbu.cn', 'post.hbu.cn', 'ykt.hbu.cn', 'dwb.hbu.cn', 'n.hbu.cn', 'museum.hbu.cn', 'yjw.hbu.cn', 'dmapp.hbu.cn', 'history.hbu.cn', 'cnki.hbu.cn', 'jwcx.hbu.cn', 'cjxy1.hbu.cn', 'eqbd.hbu.cn', 'ctcis.hbu.cn', 'rsc.hbu.cn', 'ecoen.hbu.cn', 'sszx.hbu.cn', 'jjh.hbu.cn', '20th.hbu.cn', 'uclan.en.hbu.cn', 'zhishu-old.hbu.cn', 'yixueyuan.hbu.cn', 'hbdxcbs.hbu.cn', 'sysaqks.hbu.cn', 'idp.hbu.cn', 'hpc.hbu.cn', 'sapi.hbu.cn', 'ybtyrz.hbu.cn', 'protein.hbu.cn', 'cyberhanlin.hbu.cn', 'xxtb.hbu.cn', 'cxcy.hbu.cn', 'dangban.hbu.cn', 'ec.hbu.cn', 'ssxh.hbu.cn', 'itest.hbu.cn', 'dct.en.hbu.cn', 'dangxiao.hbu.cn', 'e6.hbu.cn', 'ceie.hbu.cn', 'skc.hbu.cn', 'yxb.hbu.cn', 'dxyqgx.hbu.cn', 'image.hbu.cn', 'szlx.hbu.cn', 'icrc.hbu.cn', 'oa.hbu.cn', 'mails.hbu.cn', 'its.hbu.cn', 'v02.hbu.cn', 'hbdxfy.en.hbu.cn', 'jdh.hbu.cn', 'hbshxh.hbu.cn', 'zhuoyue.hbu.cn', 'stumail.hbu.cn', 'sjfx.hbu.cn', 'szyx.hbu.cn', 'ss.hbu.cn', 'hxppt.hbu.cn', 'jn.hbu.cn', 'ks.mem.hbu.cn', 'hbbsk.hbu.cn', 'ygty.hbu.cn', 'nm3.hbu.cn', 'xswyh.hbu.cn', 'kj.hbu.cn', 'auth.hbu.cn', 'xyh.hbu.cn', 'sewm2011.hbu.cn', 'fzghc.hbu.cn', 'tiyubu.hbu.cn', 'fsct.hbu.cn', 'seal.hbu.cn', 'tyjxb.hbu.cn', 'wmxy.hbu.cn', 'gfxn.hbu.cn', 'ipv6.hbu.cn', 'plat.hbu.cn', 'ewx.hbu.cn', 'record.hbu.cn', 'rczp.hbu.cn', 'daycly.hbu.cn', 'caec.hbu.cn', 'test2.hbu.cn', 'dct.hbu.cn', 'marx.hbu.cn', 'oiceen.hbu.cn', 'pgb.hbu.cn', 'edata.hbu.cn', 'zczx.hbu.cn', 'xfpt.hbu.cn', 'oj.hbu.cn', 'dxyqsblz.hbu.cn', 'realestate.hbu.cn', 'ciee.hbu.cn', 'daima.hbu.cn', 'yxyfangzhen.hbu.cn', 'nm2.hbu.cn', 'rcgzb.hbu.cn', '100.hbu.cn', 'zgssyjh.hbu.cn', 'gjzlfzh.hbu.cn', 'ezf.hbu.cn', 'edm.hbu.cn', 'ns1.hbu.cn', 'hb.hbu.cn', 'jxjy.en.hbu.cn', 'm.news.hbu.cn', 'xueke.hbu.cn', 'yzuuc.hbu.cn', 'ir.hbu.cn', 'redline.hbu.cn', 'piic.hbu.cn', 'seat.hbu.cn', 'hbutv.hbu.cn', 'jz.100.hbu.cn', 'cdn.hbu.cn', 'clc.hbu.cn', 'cwc-query.hbu.cn', 'dwb.en.hbu.cn', 'mpacc.hbu.cn', 'www.hbu.cn', '1.law.hbu.cn', 'jxcg-2.hbu.cn', 'wschool.hbu.cn', 'face.hbu.cn', 'dg.hbu.cn', 'tyb.hbu.cn', 'ueq.hbu.cn', 'focus.hbu.cn', 'iesc.hbu.cn', 'graduate.hbu.cn', 'en.hbu.cn', 'mba.hbu.cn', 'p.hbu.cn', 'hbdxqks.hbu.cn', 'mgm.mem.hbu.cn', 'cpl.hbu.cn', 'zhishu.hbu.cn', 'wxfz.hbu.cn', 'portal.hbu.cn', 'itc2.hbu.cn', 'hxpgl.hbu.cn', 'mlci.hbu.cn', 'photo.hbu.cn', 'wkzx.hbu.cn', 'kjzy.hbu.cn', 'oice.hbu.cn', 'jinrongxi.hbu.cn', 'cool.hbu.cn', 'xaforum.hbu.cn', 'wold.hbu.cn', 'dsxxzhuanti.hbu.cn', 'et.hbu.cn', '12371.hbu.cn', 'c3.hbu.cn', 'ntp.hbu.cn', 'online.hbu.cn', 'yx.hbu.cn', 'sat2.hbu.cn', 'jjjxt.hbu.cn', 'wx.s.hbu.cn', 'enmanage.hbu.cn', 'jwold.hbu.cn', 'samp.hbu.cn', 'rendalifa.hbu.cn', 'zhfa.hbu.cn', 'kjy.hbu.cn', 'ecpe.hbu.cn', 'iot.hbu.cn', 'jxjy.hbu.cn', 'img.news.hbu.cn', 'news.hbu.cn', 'app.hbu.cn', 'hbzs.hbu.cn', 'ai.hbu.cn', 'nlo.hbu.cn', 'smart.hbu.cn', 'libprint.hbu.cn', 'w.hbu.cn', 'upload.news.hbu.cn', 'xwlw.hbu.cn', 'hp.hbu.cn', 'lcri.hbu.cn', 'vpn.hbu.cn', 'csmx.hbu.cn', 'zhijian.hbu.cn', 'faam.hbu.cn', 'twwx.hbu.cn', 'sysyzx.hbu.cn', 'mail.hbu.cn', 'enzhijian.hbu.cn', 'hbkjty.hbu.cn', 'v03.hbu.cn', 'ceie.en.hbu.cn', 'manage.hbu.cn', 'intl.hbu.cn', 'zhaoban.hbu.cn', 'md.hbu.cn', 'xaxq.hbu.cn', 'pass.hbu.cn', 'yktang.hbu.cn', 'sysaqjc.hbu.cn', 'ttc.hbu.cn', 'xcb.hbu.cn', 'cc.hbu.cn', 'photo.news.hbu.cn', 'moa.hbu.cn', 'ce.hbu.cn', 's.hbu.cn', 'applyoice.hbu.cn', 'm.hbu.cn', 'int.hbu.cn', 'yjsy.hbu.cn', 'ggw.hbu.cn', 'xbzrb.hbu.cn', 'phi.en.hbu.cn', 'xdjc.hbu.cn', 'xb-zsb.hbu.cn', 'c.hbu.cn', 'mem.hbu.cn', 'wy.hbu.cn', 'orthptera.hbu.cn', 'en.100.hbu.cn', 'weishao.hbu.cn', 'gh.hbu.cn', 'tb.hbu.cn', 'ks.hbu.cn', 'xwb.hbu.cn', 'law.hbu.cn', 'dekt.hbu.cn', 'chemparty.hbu.cn', 'cxstar.hbu.cn', 'es.hbu.cn', 'healthcare.hbu.cn', 'liuyan.hbu.cn', 'ic.hbu.cn', 'gwxy.hbu.cn', 'ca.hbu.cn', 'life.hbu.cn', 'whq.hbu.cn', 'sgztc.hbu.cn', 'lib.hbu.cn', 'test1.hbu.cn', 'moodle.hbu.cn', 'wxy.hbu.cn', 'sat.hbu.cn', 'yzwh.hbu.cn', 'wizsta.hbu.cn', 'yxysyjx.hbu.cn', 'aqc.hbu.cn', 'sysgl.hbu.cn', 'jingju.hbu.cn', 'dkgl.hbu.cn', 'opty.hbu.cn', 'office.hbu.cn', 'ns3.hbu.cn', 'jgdw.hbu.cn', 'jwkq.hbu.cn', 'itc.hbu.cn', 'tgw.hbu.cn', 'jwc.hbu.cn', 'archives.hbu.cn', 'ns.hbu.cn', 'hdoa.hbu.cn', 'zhjw.hbu.cn', 'wlsyzx.hbu.cn', 'jjs.hbu.cn', 'cnbksy.hbu.cn', 'huli.hbu.cn', 'dpcs2018.hbu.cn', 'nm.hbu.cn', 'cavr.hbu.cn', 'cpstteacher.hbu.cn', 'ygzx.hbu.cn', 'cea.hbu.cn', 'graduate1.hbu.cn', 'video.hbu.cn', 'zyxy.en.hbu.cn', 'app.100.hbu.cn', 'oqss.hbu.cn', 'herd.hbu.cn', 'wlxy.hbu.cn', 'yxy.en.hbu.cn', 'hedashequ.hbu.cn', 'vr.mem.hbu.cn', 'tongzhanbu.hbu.cn', 'lxxs.hbu.cn', 'iac.hbu.cn', 'hdljs.hbu.cn', 'xgb.hbu.cn', 'yzgl.hbu.cn', 'ysyx.hbu.cn', 'hp2.hbu.cn', 'mjgl.hbu.cn', 'bb.hbu.cn', 'mail.stumail.hbu.cn', 'fkyq.hbu.cn', 'www.news.hbu.cn', 'jw.hbu.cn', 'newitc.hbu.cn', 'hqjt.hbu.cn', 'nic.hbu.cn', 'gcb.hbu.cn', 'mcmd.hbu.cn', 'yxy.hbu.cn', 'zfgl.hbu.cn', 'mi.hbu.cn', 'newskc.hbu.cn', 'wenxy.hbu.cn', 'manage.news.hbu.cn']}
    
    virustotal_context = {'refer': 'virustotal', 'subdomains': ['ti.dbappsecurity.com.cn', 'www.dbappsecurity.com.cn', 'starmap.dbappsecurity.com.cn', 'zp.dbappsecurity.com.cn', 'webscan.dbappsecurity.com.cn', 'security.dbappsecurity.com.cn', 'bbs.dbappsecurity.com.cn', 'sumap.dbappsecurity.com.cn', 'seclab.dbappsecurity.com.cn', 'gongyi.dbappsecurity.com.cn', 'aht-cdn.dbappsecurity.com.cn', 'app-martech.dbappsecurity.com.cn', 'martech.dbappsecurity.com.cn', 'page-martech.dbappsecurity.com.cn', 'ailpha.dbappsecurity.com.cn', 'edu.dbappsecurity.com.cn', 'threat.dbappsecurity.com.cn', 'internal10.dbappsecurity.com.cn', 'ngfw-threat.dbappsecurity.com.cn', 'nssa.dbappsecurity.com.cn', 'daas.dbappsecurity.com.cn', 'baoxianfengkong.dbappsecurity.com.cn', 'aicso.dbappsecurity.com.cn', 'mail.dbappsecurity.com.cn', 'campus-intern.dbappsecurity.com.cn', 'campus.dbappsecurity.com.cn', 'job.dbappsecurity.com.cn', 'mbbs.dbappsecurity.com.cn', 'hub-martech.dbappsecurity.com.cn', 'console.dbappsecurity.com.cn', 'salescards-martech.dbappsecurity.com.cn', 'marketing-martech.dbappsecurity.com.cn', 'auto-martech.dbappsecurity.com.cn', 'internal9.dbappsecurity.com.cn', 'internal19.dbappsecurity.com.cn', 'leads-martech.dbappsecurity.com.cn', 'internal7.dbappsecurity.com.cn', 'internal20.dbappsecurity.com.cn', 'minio.dbappsecurity.com.cn', 'www1.dbappsecurity.com.cn', 'license.dbappsecurity.com.cn', 'img02-martech.dbappsecurity.com.cn', 'ahgw.dbappsecurity.com.cn', 'static-martech.dbappsecurity.com.cn', 'internal16.dbappsecurity.com.cn', 'internal28.dbappsecurity.com.cn', 'form.dbappsecurity.com.cn', 'sumapsdk.dbappsecurity.com.cn', 'download.dbappsecurity.com.cn', 'ehr.dbappsecurity.com.cn', 'dsmp-hangzhou.dbappsecurity.com.cn', 'greatagain.dbappsecurity.com.cn', 'product.dbappsecurity.com.cn', 'tapi.dbappsecurity.com.cn', 'oa.dbappsecurity.com.cn', 'smtp.dbappsecurity.com.cn', 'usm.dbappsecurity.com.cn', 'internal15.dbappsecurity.com.cn', 'edr-hr.dbappsecurity.com.cn', 'red.dbappsecurity.com.cn', 'internal18.dbappsecurity.com.cn', 'internal2.dbappsecurity.com.cn', 'edr.dbappsecurity.com.cn', 'internal14.dbappsecurity.com.cn', 'moa.dbappsecurity.com.cn', 'internal3.dbappsecurity.com.cn', 'update2.dbappsecurity.com.cn', 'qb.dbappsecurity.com.cn', 'wifi.dbappsecurity.com.cn', 'pop3.dbappsecurity.com.cn', 'asset.dbappsecurity.com.cn', 'slab.dbappsecurity.com.cn', 'auth.dbappsecurity.com.cn', 'internal11.dbappsecurity.com.cn', 'oa1.dbappsecurity.com.cn', 'vpn.dbappsecurity.com.cn', 'eit.dbappsecurity.com.cn', 'imap.dbappsecurity.com.cn', 'internal4.dbappsecurity.com.cn', 'm.dbappsecurity.com.cn', 'ztypt.dbappsecurity.com.cn', 'zhanting-threat.dbappsecurity.com.cn', 'aht.dbappsecurity.com.cn', 'file.dbappsecurity.com.cn', 'internal5.dbappsecurity.com.cn', 'www2.dbappsecurity.com.cn', 'aptcloud.dbappsecurity.com.cn', 'waf.dbappsecurity.com.cn']}
    crt_context = {'refer': 'crt', 'subdomains': ['mail.dbappsecurity.com.cn', 'baoxianfengkong.dbappsecurity.com.cn', 'dsmp-hangzhou.dbappsecurity.com.cn', 'dbappsecurity.com.cn', 'nssa.dbappsecurity.com.cn']}
    certspotter_context = {'refer': 'certspotter', 'subdomains': ['mail.dbappsecurity.com.cn', 'dbappsecurity.com.cn', 'www.dbappsecurity.com.cn']}
    chaziyu_context = {'refer': 'chaziyu', 'subdomains': ['www1.dbappsecurity.com.cn', 'ehr.dbappsecurity.com.cn', 'ailpha.dbappsecurity.com.cn', 'ti.dbappsecurity.com.cn', 'sumap.dbappsecurity.com.cn', 'internal6.dbappsecurity.com.cn', 'dsmp-hangzhou.dbappsecurity.com.cn', 'mssp.dbappsecurity.com.cn', 'bbs.dbappsecurity.com.cn', 'nssa.dbappsecurity.com.cn', 'gongyi.dbappsecurity.com.cn', 'display.dbappsecurity.com.cn', 'product.dbappsecurity.com.cn', 'vpn.dbappsecurity.com.cn', 'page-martech.dbappsecurity.com.cn', 'smtp.dbappsecurity.com.cn', 'moa.dbappsecurity.com.cn', 'download.dbappsecurity.com.cn', 'internal10.dbappsecurity.com.cn', 'ztypt.dbappsecurity.com.cn', 'internal2.dbappsecurity.com.cn', 'edr.dbappsecurity.com.cn', 'www.dbappsecurity.com.cn', 'seclab.dbappsecurity.com.cn', 'update.dbappsecurity.com.cn', 'waf.dbappsecurity.com.cn', 'zp.dbappsecurity.com.cn', 'anhengtong.dbappsecurity.com.cn', 'tapi.dbappsecurity.com.cn', 'mail.dbappsecurity.com.cn', 'oa.dbappsecurity.com.cn', 'aptcloud.dbappsecurity.com.cn', 'internal18.dbappsecurity.com.cn', 'aicso.dbappsecurity.com.cn']}
    rapiddns_context = {'refer': 'rapiddns', 'subdomains': ['www1.dbappsecurity.com.cn', 'ti.dbappsecurity.com.cn', 'mssp.dbappsecurity.com.cn', 'bbs.dbappsecurity.com.cn', 'nssa.dbappsecurity.com.cn', 'gongyi.dbappsecurity.com.cn', 'display.dbappsecurity.com.cn', 'ahgw.dbappsecurity.com.cn', 'page-martech.dbappsecurity.com.cn', 'dbappsecurity.com.cn', 'internal10.dbappsecurity.com.cn', 'threat.dbappsecurity.com.cn', 'aht-cdn.dbappsecurity.com.cn', 'seclab.dbappsecurity.com.cn', 'www.dbappsecurity.com.cn', 'webscan.dbappsecurity.com.cn', 'job.dbappsecurity.com.cn', 'mail.dbappsecurity.com.cn', 'aptcloud.dbappsecurity.com.cn', 'market.dbappsecurity.com.cn', 'aicso.dbappsecurity.com.cn', 'mbbs.dbappsecurity.com.cn']}
    sitedossier_context = {'refer': 'sitedossier', 'subdomains': ['www.dbappsecurity.com.cn']}
    securitytrails_context = {'refer': 'securitytrails', 'subdomains': ['www1.dbappsecurity.com.cn', 'soar.dbappsecurity.com.cn', 'ics.dbappsecurity.com.cn', 'zhanting-threat.dbappsecurity.com.cn', 'usm.dbappsecurity.com.cn', 'entry.dbappsecurity.com.cn', 'ncovapi1.threat.dbappsecurity.com.cn', 'display.dbappsecurity.com.cn', 'ahgw.dbappsecurity.com.cn', 'blue.dbappsecurity.com.cn', 'app-martech.dbappsecurity.com.cn', 'srm.dbappsecurity.com.cn', 'smtp.dbappsecurity.com.cn', 'moa.dbappsecurity.com.cn', 'download.dbappsecurity.com.cn', 'minio.dbappsecurity.com.cn', 'www.dbappsecurity.com.cn', 'seclab.dbappsecurity.com.cn', 'internal28.dbappsecurity.com.cn', 'sca.dbappsecurity.com.cn', 'waf.dbappsecurity.com.cn', 'wifi.dbappsecurity.com.cn', 'static-martech.dbappsecurity.com.cn', 'webscan.dbappsecurity.com.cn', 'imap.dbappsecurity.com.cn', 'internal31.dbappsecurity.com.cn', 'leads-martech.dbappsecurity.com.cn', 'aptcloud.dbappsecurity.com.cn', 'martech.dbappsecurity.com.cn', 'pop3.dbappsecurity.com.cn', 'abcd.dbappsecurity.com.cn', 'internal40.dbappsecurity.com.cn', 'support.dbappsecurity.com.cn', 'waf-threat.dbappsecurity.com.cn', 'starmap.dbappsecurity.com.cn', 'mbbs.dbappsecurity.com.cn', 'internal11.dbappsecurity.com.cn', 'irp.dbappsecurity.com.cn', 'internal17.dbappsecurity.com.cn', 'baoxianfengkong.dbappsecurity.com.cn', 'internal24.dbappsecurity.com.cn', 'internal21.dbappsecurity.com.cn', 'bbs.dbappsecurity.com.cn', 'security.dbappsecurity.com.cn', 'url2.dbappsecurity.com.cn', 'url1.dbappsecurity.com.cn', 'auth.dbappsecurity.com.cn', 'img02-martech.dbappsecurity.com.cn', 'gongyi.dbappsecurity.com.cn', 'internal3.dbappsecurity.com.cn', 'product.dbappsecurity.com.cn', 'internal1.dbappsecurity.com.cn', 'page-martech.dbappsecurity.com.cn', 'slab.dbappsecurity.com.cn', 'marketing-martech.dbappsecurity.com.cn', 'mmm.dbappsecurity.com.cn', 'internal5.dbappsecurity.com.cn', 'internal30.dbappsecurity.com.cn', 'aht-cdn.dbappsecurity.com.cn', 'www2.dbappsecurity.com.cn', 'internal39.dbappsecurity.com.cn', 'internal29.dbappsecurity.com.cn', 'internal36.dbappsecurity.com.cn', 'tapi.dbappsecurity.com.cn', 'console.dbappsecurity.com.cn', 'mail.dbappsecurity.com.cn', 'hub-martech.dbappsecurity.com.cn', 'oa.dbappsecurity.com.cn', 'internal13.dbappsecurity.com.cn', 'bugsnag.dbappsecurity.com.cn', 'itbook.dbappsecurity.com.cn', 'red.dbappsecurity.com.cn', 'internal27.dbappsecurity.com.cn', 'internal8.dbappsecurity.com.cn', 'ga4idc.dbappsecurity.com.cn', 'ailpha.dbappsecurity.com.cn', 'qb.dbappsecurity.com.cn', 'mainsoft.info.dbappsecurity.com.cn', 'mssp.dbappsecurity.com.cn', 'internal14.dbappsecurity.com.cn', 'internal7.dbappsecurity.com.cn', 'internal26.dbappsecurity.com.cn', 'internal25.dbappsecurity.com.cn', 'nssa.dbappsecurity.com.cn', 'greatagain.dbappsecurity.com.cn', 'wiki.info.dbappsecurity.com.cn', 'go.dbappsecurity.com.cn', 'daas.dbappsecurity.com.cn', 'api-martech.dbappsecurity.com.cn', 'internal16.dbappsecurity.com.cn', 'internal19.dbappsecurity.com.cn', 'internal10.dbappsecurity.com.cn', 'ztypt.dbappsecurity.com.cn', 'safelab.dbappsecurity.com.cn', 'campus.intern.dbappsecurity.com.cn', 'cminio.dbappsecurity.com.cn', 'campus-intern.dbappsecurity.com.cn', 'internal2.dbappsecurity.com.cn', 'internal34.dbappsecurity.com.cn', 'edr.dbappsecurity.com.cn', 'm.dbappsecurity.com.cn', 'eit.dbappsecurity.com.cn', 'erp.dbappsecurity.com.cn', 'zp.dbappsecurity.com.cn', 'sumapsdk.dbappsecurity.com.cn', 'aht.dbappsecurity.com.cn', 'internal23.dbappsecurity.com.cn', 'license.dbappsecurity.com.cn', 'netsecuritygame.dbappsecurity.com.cn', 'internal18.dbappsecurity.com.cn', 'ailpha-threat.dbappsecurity.com.cn', 'ngfw-threat.dbappsecurity.com.cn', 'aicso.dbappsecurity.com.cn', 'internal37.dbappsecurity.com.cn', 'iec.dbappsecurity.com.cn', 'internal15.dbappsecurity.com.cn', 'ehr.dbappsecurity.com.cn', 'internal33.dbappsecurity.com.cn', 'internal9.dbappsecurity.com.cn', 'update2.dbappsecurity.com.cn', 'update1.dbappsecurity.com.cn', 'ti.dbappsecurity.com.cn', 'sumap.dbappsecurity.com.cn', 'internal6.dbappsecurity.com.cn', 'service.dbappsecurity.com.cn', 'internal35.dbappsecurity.com.cn', 'campus.dbappsecurity.com.cn', 'oa1.dbappsecurity.com.cn', 'seal.dbappsecurity.com.cn', 'rd2.dbappsecurity.com.cn', 'asset.dbappsecurity.com.cn', 'apt-threat.dbappsecurity.com.cn', 'vpn.dbappsecurity.com.cn', 'ahcdemo.dbappsecurity.com.cn', 'threat.dbappsecurity.com.cn', 'file.dbappsecurity.com.cn', 'edu.dbappsecurity.com.cn', 'update.dbappsecurity.com.cn', 'jira.info.dbappsecurity.com.cn', 'internal38.dbappsecurity.com.cn', 'internal4.dbappsecurity.com.cn', 'gitlab.info.dbappsecurity.com.cn', 'online.dbappsecurity.com.cn', 'anhengtong.dbappsecurity.com.cn', 'internal20.dbappsecurity.com.cn', 'form.dbappsecurity.com.cn', 'job.dbappsecurity.com.cn', 'internal22.dbappsecurity.com.cn', 'gb.dbappsecurity.com.cn', 'open.hatlab.dbappsecurity.com.cn', 'internal12.dbappsecurity.com.cn', 'internal32.dbappsecurity.com.cn']}
    
    '''
    virustotal_context = run_virustotal(domain, virustotal_api)
    crt_context = run_crt(domain)
    certspotter_context = run_certspotter(domain)
    chaziyu_context = run_chaziyu(domain)
    rapiddns_context = run_rapiddns(domain)
    sitedossier_context = run_sitedossier(domain)
    securitytrails_context = run_securitytrails(domain, securitytrails_api)

    # ce_baidu_subdomains = run_ce_baidu()  # 废弃
    # fht_subdomains = run_fht()     # 废弃
    # qianxun_subdomains = run_qianxun()      # 废弃
    # sublist3r_subdomains = run_sublist3r()   # 废弃
    # bufferover_subdomains = run_bufferover() # 废弃
    # threatcrowd_subdomains = run_threatcrowd() # 废弃
    # hackertarget_subdomains = run_hackertarget() # 废弃
    # ximcx_subdomains = run_ximcx()  # 废弃


    subdomainInterface_context_list = []
    for name, value in locals().items():
        if 'context' in name and 'subdomainInterface_context_list' not in name:
            subdomainInterface_context_list.append(value)
    return subdomainInterface_context_list


# 调用virustotal|ce.baidu.com|www.threatcrowd.org|url.fht.im|qianxun|sublist3r的子域名收集脚本
def run_subdomainInterface(domain):
    cf = configparser.ConfigParser()
    cf.read("./iniFile/config.ini")
    # cf.read("../../../../iniFile/config.ini")     # 测试用
    virustotal_api = cf.get('virustotal api', 'VIRUSTOTAL_API')  # virustotal Api
    securitytrails_api = cf.get('securitytrails api', 'Securitytrails_API')

    subdomainInterface_context_list = run_all_api(domain, virustotal_api, securitytrails_api)
    return subdomainInterface_context_list



if __name__ == '__main__':
    domain = 'hbu.edu.cn'
    # projectInfo_context = {"virustotal_api": None,
    #                        "securitytrails_api": None}
    # subdomainInterface_context_list = run_subdomainInterface(domain, projectInfo_context)
    # print('subdomainInterface_context_list = {}'.format(subdomainInterface_context_list))
    subdomainInterface_context_list = run_subdomainInterface(domain)
    print(subdomainInterface_context_list)