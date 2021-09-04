import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import quote
import json
import math
from termcolor import cprint

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}

# www.beianbeian.com
def beianbeianApi(domain):
    cprint('Load beianbeianApi: ', 'green')
    # 获取备案ID
    beianId = ''
    url = 'http://www.beianbeian.com/s-0/{}.html'.format(domain)
    try:
        res = requests.get(url=url, headers=headers, allow_redirects=False, verify=False, timeout=10)
    except Exception as e:
        print('[error] http://www.beianbeian.com is die \n{}'.format(e.args))
        return []

    text = res.text
    # print(text)
    soup_1 = BeautifulSoup(text, 'html.parser')
    tbodys = soup_1.find_all('tbody', id='table_tr')
    for tbody in tbodys:
        a_hrefs = tbody.find_all('a')
        for a_href in a_hrefs:
            if '反查' in a_href.get_text():
                beianId = a_href['href']
    if beianId:
        beianSearchUrl = 'http://www.beianbeian.com' + beianId
        print('查询到备案号: {}'.format(beianSearchUrl))
    else:
        print('没有匹配到备案号')
        return []

    # 备案反查域名
    beianbeianNewDomains = []
    tempDict = {}
    # url = r'http://www.beianbeian.com/search-1/%E6%B5%99B2-20080224.html'
    try:
        res = requests.get(url=beianSearchUrl, headers=headers, allow_redirects=False, verify=False, timeout=10)
    except Exception as e:
        print('[error] request : {}\n{}'.format(beianSearchUrl, e.args))
        return []
    text = res.text
    # print(text)
    soup = BeautifulSoup(text, 'html.parser')
    tbodys = soup.find_all('tbody', id='table_tr')
    for tbody in tbodys:
        trs = tbody.find_all('tr')
        for tr in trs:
            tds = tr.find_all('td')
            companyName = tds[4].get_text()
            newDomain = tds[5].get_text().strip().replace('www.', '')
            time = tds[6].get_text()
            if newDomain not in tempDict:
                tempDict[newDomain] = (companyName, newDomain, time)
                beianbeianNewDomains.append((companyName, newDomain, time))
    beianbeianNewDomains = list(set(beianbeianNewDomains))
    print('beianbeianApi去重后共计{}个顶级域名'.format(len(beianbeianNewDomains)))
    # for each in beianbeianNewDomains:
    #     print(each)
    return beianbeianNewDomains

# icp.chinaz.com
def chinazApi(domain):

    # 解析chinaz返回结果的json数据
    def parse_json(json_ret):
        chinazNewDomains = []
        results = json_ret['data']
        for result in results:
            companyName = result['webName']
            newDomain = result['host']
            time = result['verifyTime']
            chinazNewDomains.append((companyName, newDomain, time))     # [('城市产业服务平台', 'cloudfoshan.com', '2020-06-09'), ('城市产业服务平台', 'cloudguangzhou.com', '2020-06-09')]
        chinazNewDomains = list(set(chinazNewDomains))
        return chinazNewDomains

    cprint('Load chinazApi: ', 'green')

    chinazNewDomains = []
    tempDict = {}
    tempList = []

    # 获取域名的公司名字
    url = r'http://icp.chinaz.com/{}'.format(domain)
    try:
        res = requests.get(url=url, headers=headers, allow_redirects=False, verify=False, timeout=10)
    except Exception as e:
        print('[error] request : {}\n{}'.format(url, e.args))
        return [], []
    text = res.text

    companyName = re.search("var kw = '([\S]*)'", text)
    if companyName:
        companyName = companyName.group(1)
        print('公司名: {}'.format(companyName))
        companyNameUrlEncode = quote(str(companyName))
    else:
        print('没有匹配到公司名')
        return [], []

    # 备案反查域名
    headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    url = 'http://icp.chinaz.com/Home/PageData'
    data = 'pageNo=1&pageSize=20&Kw=' + companyNameUrlEncode
    try:
        res = requests.post(url=url, headers=headers, data=data, allow_redirects=False, verify=False, timeout=10)
    except Exception as e:
        print('[error] request : {}\n{}'.format(url, e.args))
        return [], []

    json_ret = json.loads(res.text)
    # print(json_ret)
    if 'amount' not in json_ret.keys():
        return chinazNewDomains, []
    amount = json_ret['amount']
    pages = math.ceil(amount / 20)
    print('页数: {}'.format(pages))
    # 解析返回的json数据包，过滤出公司名，域名，时间     eg: ('城市产业服务平台', 'cloudhuizhou.com', '2020-06-09')
    tempList.extend(parse_json(json_ret))
    # for _ in chinazNewDomains:
    #     print(_)

    # 继续获取后面页数
    for page in range(2, pages+1):
        print('请求第{}页'.format(page))
        data = 'pageNo={}&pageSize=20&Kw='.format(page) + companyNameUrlEncode
        try:
            res = requests.post(url=url, headers=headers, data=data, allow_redirects=False, verify=False, timeout=10)
            json_ret = json.loads(res.text)
            tempList.extend(parse_json(json_ret))
        except Exception as e:
            print('[error] request : {}\n{}'.format(url, e.args))


    for each in tempList:
        if each[1] not in tempDict:
            tempDict[each[1]] = each
            chinazNewDomains.append(each)

    print('chinazApi去重后共计{}个顶级域名'.format(len(chinazNewDomains)))
    # for _ in chinazNewDomains:
    #     print(_)
    return chinazNewDomains, companyName


def run_beian2domain(domain):
    beianNewDomains = []
    # beianbeianNewDomains = beianbeianApi(domain)  # 失效
    chinazNewDomains, companyName = chinazApi(domain)

    tempDict = {}
    for each in chinazNewDomains:
        if each[1] not in tempDict:
            tempDict[each[1]] = each
            beianNewDomains.append(each)
    # beianNewDomains = list(set(beianbeianNewDomains + chinazNewDomains))
    # print('共计{}个顶级域名'.format(len(beianNewDomains)))
    cprint('-' * 50 + '去重后共计{}个顶级域名'.format(len(beianNewDomains)) + '-' * 50, 'green')
    for _ in beianNewDomains:
        print(_)

    cprint('去重后共计{}个顶级域名'.format(len(beianNewDomains)), 'red')
    return beianNewDomains, companyName

if __name__ == '__main__':
    domain = 'aaaaa'
    run_beian2domain(domain)