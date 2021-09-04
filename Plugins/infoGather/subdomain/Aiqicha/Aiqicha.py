import re
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
        'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
        'sec-ch-ua-mobile': '?0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'BIDUPSID=1FAA6F4D89C6311BCA477B5B766A408D; PSTM=1618319039; BAIDUID=1FAA6F4D89C6311BB29AB4FE1AEC0084:FG=1; delPer=0; PSINO=1; __yjs_duid=1_b459443288e79c76f299132c456ba4bf1630477596321; H_PS_PSSID=34437_34443_34379_34496_31254_34004_34092_34106_26350_34418_22159; Hm_lvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630490457; ZX_UNIQ_UID=235603df155283fc03e1ca707604f293; _j47_ka8_=57; log_guid=de290298a47b69cc93fdb016cc66a223; BA_HECTOR=8ha10h258l242k20rp1gj0bse0r; Hm_lpvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630547983; _fb537_=xlTM-TogKuTwvJ4X5I46%2AIuoCngLaKAfi6M%2AOS5mhcHqmd; __yjs_st=2_OTg5ZGJiYzBlZThjNWEyZTU0ZTA1NmVhNGRjZGI3NWNmMzRhYmY1YTNhODUxNzQ0OTlmMmQ2NmYzNWEwNzY3N2MzY2U5MzJkZjJhMjljYjE4MWJjZTYxMDk0YzZhZTlmZThjMzFiODJmNDUwNzU5YjBjY2Q3Y2Y4NTk4OGQ1MjkzNzI2YTAxM2FlZGVlNTY2MzY4ZTdmMmI2MmNjYzQ2YTkzYjdkODc0ZGU4YTcyZTNlYzNkMDEwZGE2ZDFmZWVhMDc5ZjgxMjJhMzIzODVmMzFhNWRlMzA2Y2M0Mjc5ZDQxY2UyMjc2ODFlMjM3MzRkYjFiMjI4OTNhYTI5YTkxM183X2RlNTJjNTZi; ab_sr=1.0.1_MWE0MzIwZjE0ZjQ2OTIzYTk5ZGMyOTQ1ZTBkYzcwM2MwOGI0ZWRjZjFmMmMxZDM0Y2Q0MzNlNzM2OWFiZmY5Y2YxM2MyOTM1ODJkZWExNDE0YzU3MmM3ODY2MzI4YWJhZWYxODBjZWJlYjhhM2FjNmE2MThjYmU0MmJiNWFhYjQ5NTEyMTE5ODA0OGQ4MGEyYTRiNDA3YTk2MjI3M2YwOQ==; _s53_d91_=2a32a31ab347483e2096871f98f0842b6ea08522c97c28c46353e56e86219e6409e838e83117a08774a8da295a5e9b0ed642b4685b780d1731e601956b4f0b82cbd45570696a8e96493db3197f88b7dd82945497dac07440c6e49d09f3e22f1452a5c00539afa2e4128ef497a792655c5b94fd56f8950542cf4f975e7426d5e73f199201a826c95d393e4afb78b199329d6e9fd6fcb87ed85a8e1e769c9ee4ff176e1f2f50250e3a86706cc09695d4d362f6ce2bba20a8c7fd13308cd1ea48f061c48546de8fa42c1ab0e9faf387a0c4; _y18_s21_=70c80ef2; RT="z=1&dm=baidu.com&si=te7c3g5s27i&ss=kt2a2egs&sl=4&tt=1d8h&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf&ld=3wfa&ul=1qdpt"'
    }

requests_proxies = None

# 网站备案的细节
icpinfo_url = "https://aiqicha.baidu.com/detail/icpinfoajax?p=1&size=20&pid=111111111111"
# 对外投资的细节
invest_url = "https://aiqicha.baidu.com/detail/investajax?p=1&size=20&pid=111111111111"
# 控股企业的细节
hold_url = "https://aiqicha.baidu.com/detail/holdajax?p=1&size=20&pid=111111111111"
# 分支机构的细节
branch_url = "https://aiqicha.baidu.com/detail/branchajax?p=1&size=20&pid=111111111111"

# 每页的条数
size = 10
# 超时
TIMEOUT = 20

invest_infos = []
holds_infos = []
branch_infos = []


# 获取基本信息:公司名、邮箱地址、联系方式
def companyDetail(pid):
    companyDetail_infos = {"emails": "", "telephone": ""}
    try:
        url = "https://aiqicha.baidu.com/company_detail_{}".format(pid)
        res = requests.get(url=url, headers=headers, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
        text = res.text
        # print(text)
        # companyName = re.findall('entName":"(.*?)"', text)[0].encode('utf-8').decode('unicode_escape')
        emails = re.findall(r'email":"(.*?)"', text)
        telephone = re.findall('telephone":"(.*?)"', text)
        # print("公司名、邮箱地址、联系方式")
        # print(companyName[0].encode('utf-8').decode('unicode_escape'), emails, telephone)
        companyDetail_infos = {"emails": emails, "telephone": telephone}
    except Exception as e:
        # print(e.args)
        pass
    # print()
    return companyDetail_infos

# 网站备案信息
def icpinfo(pid, icpinfo_page):
    icpinfo_infos = []
    for i in range(1, icpinfo_page+1):
        try:
            invest_url = "https://aiqicha.baidu.com/detail/icpinfoajax?p={}&size={}&pid={}".format(i, size, pid)
            res = requests.get(url=invest_url, headers=headers2, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
            text = res.text.encode('utf8').decode('unicode_escape')
            text = json.loads(text)
            data = text["data"]
            # print(data)
            # print("名称、备案域名、备案号")
            for each in data["list"]:
                siteName = each["siteName"]
                print("收集网站【{}】的备案信息".format(siteName))
                domain = each["domain"]
                icpNo = each["icpNo"]
                # print(siteName, domain, icpNo)
                icpinfo_infos.append({"siteName": siteName, "domain": domain, "icpNo": icpNo})
        except Exception as e:
            # print(e.args)
            pass
    # print()
    return icpinfo_infos

# 对外投资
def invest(pid, invest_page):
    print("开始查询对外投资企业:{}".format(invest_num))

    for i in range(1, invest_page+1):
        try:
            invest_url = "https://aiqicha.baidu.com/detail/investajax?p={}&size={}&pid={}".format(i, size, pid)
            res = requests.get(url=invest_url, headers=headers2, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
            text = res.text
            text = json.loads(text)
            data = text["data"]
            # print(data)
            # print("被投资企业、投资占比、被投资企业的pid")
            for each in data["list"]:
                # 对外投资企业名称
                entName = each["entName"]
                print("查询对外投资企业【{}】".format(entName))
                # 投资占比
                regRate = each["regRate"]
                # 被投资企业的pid
                invest_pid = each["pid"]
                # print(entName, regRate, invest_pid)
                icpinfo_infos = icpinfo(invest_pid, 1)
                companyDetail_infos = companyDetail(invest_pid)
                invest_infos.append({"pid": invest_pid, "invest_info": {"entName": entName, "regRate": regRate}, "icp_info": icpinfo_infos, "companyDetail_infos": companyDetail_infos})
                # invest_info.append({invest_pid: [entName, regRate]})
        except Exception as e:
            # print(e.args)
            pass
    print()

# 控股企业
def holds(pid, holds_page):
    print("开始查询控股企业: {}".format(holds_num))
    for i in range(1, holds_page+1):
        try:
            holds_url = "https://aiqicha.baidu.com/detail/holdsajax?p={}&size={}&pid={}".format(i, size, pid)
            res = requests.get(url=holds_url, headers=headers2, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
            text = res.text
            text = json.loads(text)
            data = text["data"]
            # print(data)
            # print("控股企业名称、投资占比、控股企业pid")
            for each in data["list"]:
                # print(each)
                # 控股企业名称
                entName = each["entName"]
                print("查询控股企业【{}】".format(entName))
                # 投资占比
                proportion = each["proportion"]
                # 控股企业pid
                holds_pid = each["pid"]
                # print(entName, proportion, holds_pid)
                icpinfo_infos = icpinfo(holds_pid, 1)
                companyDetail_infos = companyDetail(holds_pid)
                holds_infos.append({"pid": holds_pid, "holds_info": {"entName": entName, "proportion": proportion},  "icp_info": icpinfo_infos, "companyDetail_infos": companyDetail_infos})
        except Exception as e:
            print(e.args)
    print()

# 分支机构
def branch(pid, branch_page):
    print("开始查询分支机构:{} ".format(branch_num))
    for i in range(1, branch_page + 1):
        try:
            branch_url = "https://aiqicha.baidu.com/detail/branchajax?p={}&size={}&pid={}".format(i, size, pid)
            res = requests.get(url=branch_url, headers=headers2, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
            text = res.text
            text = json.loads(text)
            data = text["data"]
            # print(data)
            # print("分支机构名称、分支机构pid")
            for each in data["list"]:
                # print(each)
                # 分支机构名称
                entName = each["entName"]
                print("查询分支机构【{}】".format(entName))
                # 控股企业pid
                branch_pid = each["pid"]
                # print(entName, branch_pid)
                icpinfo_infos = icpinfo(branch_pid, 1)
                companyDetail_infos = companyDetail(branch_pid)
                branch_infos.append({"pid": branch_pid, "branch_info": {"entName": entName},  "icp_info": icpinfo_infos, "companyDetail_infos": companyDetail_infos})
        except Exception as e:
            print(e.args)
    print()



def start(searchContent):
    # 获取匹配度最高的pid
    url = 'https://aiqicha.baidu.com/s?q={}&t=0'.format(searchContent)

    try:
        res = requests.get(url=url, headers=headers, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
    except Exception as e:
        print(e.args)
        return [], [], [], []

    text = res.text
    # queryStr = re.findall('queryStr":"(.*?)"', text)
    # 取第一个pid，是匹配度最高的
    pids = re.findall('pid":"(.*?)"', text)
    print(pids)
    if pids == []:
        print("没有匹配到pids")
        return [], [], [], []


    pid = pids[0]
    print("获取到匹配度最高的pid:{}".format(pid))

    companyDetail(pid)



    global headers2
    # 获取网站备案、对外投资、控股企业、分支机构
    headers2 = {
        'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest',
        'sec-ch-ua-mobile': '?0',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Referer': 'https://aiqicha.baidu.com/company_detail_{}'.format(pid),
        'Zx-Open-Url': 'https://aiqicha.baidu.com/company_detail_{}'.format(pid),
        'Cookie': 'BIDUPSID=1FAA6F4D89C6311BCA477B5B766A408D; PSTM=1618319039; BAIDUID=1FAA6F4D89C6311BB29AB4FE1AEC0084:FG=1; delPer=0; PSINO=1; __yjs_duid=1_b459443288e79c76f299132c456ba4bf1630477596321; H_PS_PSSID=34437_34443_34379_34496_31254_34004_34092_34106_26350_34418_22159; Hm_lvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630490457; ZX_UNIQ_UID=235603df155283fc03e1ca707604f293; _j47_ka8_=57; log_guid=de290298a47b69cc93fdb016cc66a223; BA_HECTOR=8ha10h258l242k20rp1gj0bse0r; _s53_d91_=8a7993934c2e3aed3016469d17b932073b7b54a406de44d238e6f350d1dff19c6f4ed0cfe8dd8c73157858ec8bdf74ba70569f6014536cdd9897cbc334d0e4a457dc349592e0866ba802c2e55593df16336a09ec583cbc66c871f2a6cdd57bd252b99c7aac7dfa060e1c280a3f44131b41af584d3541e986e1f842e0a94548c08ef935673ef819b1c36bbe2257c9472c01275ae97e3a8831197fae58c859da19d779c76a4d48dcf0ac69a2e01c9983c920535b992646bb7eca4508e2aace1c9d602f8a87f140cf8a150259da45b437df; _y18_s21_=7e1a75d9; RT="z=1&dm=baidu.com&si=te7c3g5s27i&ss=kt2a2egs&sl=2&tt=wzf&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf"; Hm_lpvt_ad52b306e1ae4557f5d3534cce8f8bbf=1630547983; ab_sr=1.0.1_YzE2ZGZiZTgzNGM4OGJlYjMxOThlMWFhZjgzNGI2MzU0ZDkwY2UyYjQzMzA2YjViYTYxMmM4ODViZTVhZmY4MmVhNDZkNmRjNjY3YmQ0ZGNkYjc4Y2E5ZjEzYzc4NmZmNWJjNmFiYWViOTU1YzNmY2UzNjM4MzBkM2ViMTY2YjJmZWM3NGVmNjYwNDMyYzExN2E0NWFhMjAzZGNlYzIxMA==; _fb537_=xlTM-TogKuTwvJ4X5I46%2AIuoCngLaKAfi6M%2AOS5mhcHqmd; __yjs_st=2_OTg5ZGJiYzBlZThjNWEyZTU0ZTA1NmVhNGRjZGI3NWNmMzRhYmY1YTNhODUxNzQ0OTlmMmQ2NmYzNWEwNzY3N2MzY2U5MzJkZjJhMjljYjE4MWJjZTYxMDk0YzZhZTlmZThjMzFiODJmNDUwNzU5YjBjY2Q3Y2Y4NTk4OGQ1MjkzNzI2YTAxM2FlZGVlNTY2MzY4ZTdmMmI2MmNjYzQ2YTkzYjdkODc0ZGU4YTcyZTNlYzNkMDEwZGE2ZDFmZWVhMDc5ZjgxMjJhMzIzODVmMzFhNWRlMzA2Y2M0Mjc5ZDQxY2UyMjc2ODFlMjM3MzRkYjFiMjI4OTNhYTI5YTkxM183X2RlNTJjNTZi'
    }
    url = r"https://aiqicha.baidu.com/compdata/navigationListAjax?pid={}".format(pid)
    # print(url)
    res = requests.get(url=url, headers=headers2, proxies=requests_proxies, verify=False, timeout=TIMEOUT)
    text = res.text
    text = text.encode('utf-8').decode('unicode_escape')
    # print(text)
    text_json = json.loads(text)
    basic, certRecord = [], []
    for _ in text_json["data"]:
        if _["id"] == "basic":
            # 基本信息
            basic = _["children"]
        if _["id"] == "certRecord":
            # 知识产权
            certRecord = _["children"]
    # print(basic)
    # print(certRecord)
    global invest_num, holds_num, branch_num, webRecord_num
    invest_num, holds_num, branch_num, webRecord_num = 0, 0, 0, 0
    # 网站备案
    for each in certRecord:
        if each["name"] == "网站备案":
            webRecord_num = each["total"]

    for each in basic:
        if each["name"] == "对外投资":
            invest_num = each["total"]
        if each["name"] == "控股企业":
            holds_num = each["total"]
        if each["name"] == "分支机构":
            branch_num = each["total"]

    print("网站备案:{}\n对外投资:{}\n控股企业:{}\n分支机构:{}\n".format(webRecord_num, invest_num, holds_num, branch_num))

    if branch_num > 200:
        branch_num = 30

    # 页数
    icpinfo_page = webRecord_num // size + 1
    invest_page = invest_num // size + 1
    holds_page = holds_num // size + 1
    branch_page = branch_num // size + 1
    # print(invest_page, holds_page, branch_page)
    print()

    selfIcpinfo_infos = icpinfo(pid, icpinfo_page)
    for each in selfIcpinfo_infos:
        print(each)
    print()

    invest(pid, invest_page)
    holds(pid, holds_page)
    branch(pid, branch_page)

    for each in invest_infos:
        print(each)
    for each in holds_infos:
        print(each)
    for each in branch_infos:
        print(each)

    return selfIcpinfo_infos, invest_infos, holds_infos, branch_infos


def run_aiqicha(searchContent):
    selfIcpinfo_infos, invest_infos, holds_infos, branch_infos = start(searchContent)
    print(selfIcpinfo_infos)
    print(invest_infos)
    print(holds_infos)
    print(branch_infos)
    return selfIcpinfo_infos, invest_infos, holds_infos, branch_infos


if __name__ == '__main__':
    searchContent = "xxxx"
    run_aiqicha(searchContent)


