from Plugins.infoGather.subdomain.theHarvester.runTheHarvester.lib.core import *
from Plugins.infoGather.subdomain.theHarvester.runTheHarvester.parsers import myparser

class SearchBaidu:

    def __init__(self, word, limit):
        self.word = word
        self.total_results = ""
        self.server = 'www.baidu.com'
        self.hostname = 'www.baidu.com'
        self.limit = limit
        self.proxy = False

    async def do_search(self):
        headers = {
            'Host': self.hostname,
            'User-agent': Core.get_user_agent()
        }
        base_url = f'https://{self.server}/s?wd=%40{self.word}&pn=xx&oq={self.word}'
        urls = [base_url.replace("xx", str(num)) for num in range(0, self.limit, 10) if num <= self.limit]
        responses = await AsyncFetcher.fetch_all(urls, headers=headers, proxy=self.proxy)
        for response in responses:
            self.total_results += response

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()

    async def get_emails(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.emails()

    async def get_hostnames(self):
        rawres = myparser.Parser(self.total_results, self.word)
        return await rawres.hostnames()
