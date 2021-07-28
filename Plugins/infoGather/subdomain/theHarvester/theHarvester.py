#!/usr/bin/env python3

# Note: This script runs theHarvester
from platform import python_version
import sys
import asyncio
import uvloop
# from theHarvester import __main__
from Plugins.infoGather.subdomain.theHarvester.runTheHarvester import __main__

def run_theHarvester(domain):
    uvloop.install()
    # all_ip, all_emails, all_hosts = asyncio.run(__main__.entry_point(domain))
    return asyncio.run(__main__.entry_point(domain))


if __name__ == "__main__":
    domains = ['']
    for domain in domains:
        run_theHarvester(domain)