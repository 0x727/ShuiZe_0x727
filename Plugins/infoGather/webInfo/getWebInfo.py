from Plugins.infoGather.webInfo.Wappalyzer.Wappalyzer import Wappalyzer, WebPage
import warnings
warnings.filterwarnings('ignore')
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

wappalyzer = Wappalyzer.latest()

def run_getWebInfo(url):
    try:
        webpage = WebPage.new_from_url(url=url, verify=False)
        info = wappalyzer.analyze(webpage)
        # content = '[{}] : {}'.format(url, info)
        if len(info) > 0:
            return str(info)
            # print('\t[+]{}'.format(content))
    except Exception:
        pass
    return None

if __name__ == '__main__':
    url = r''
    info = run_getWebInfo(url)
    print(info)