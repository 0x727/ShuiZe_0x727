from Wappalyzer import Wappalyzer, WebPage
wappalyzer = Wappalyzer.latest()
webpage = WebPage.new_from_url('http://www.baidu.com')
wappalyzer.analyze(webpage)