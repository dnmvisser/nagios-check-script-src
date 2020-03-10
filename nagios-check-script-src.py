#!/usr/bin/env python3
import argparse
import sys


# pip install requests cachecontrol adblockparser bs4 lockfile
import requests
from cachecontrol import CacheControl
from cachecontrol.caches.file_cache import FileCache
from adblockparser import AdblockRules
from bs4 import BeautifulSoup


# Debug
# import logging
# logging.basicConfig(level=logging.DEBUG)

def nagios_exit(message, code):
    print(message)
    sys.exit(code)

try:
    parser = argparse.ArgumentParser(description='Check web page for unwanted script URLs')
    parser.add_argument('--url',    help='the URL to check', required=True)
    parser.add_argument('--referer', help='The referer to use when checking the URL')
    parser.add_argument('--useragent', help='The user agent to use when checking the URL',
            default='Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko')
    parser.add_argument('--blacklist', help='EasyList compatible blacklist URL. See https://easylist.to', 
            default='https://easylist-downloads.adblockplus.org/easylist_noadult.txt')
    parser.add_argument('--cachedir', help='Which directory to use for storing cached content', default='.cache')
    parser.add_argument('--verbose', help='Show found URLs', action="store_true")
    

    args = parser.parse_args()
   
    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []
    scanned_srcs = []


    # Fetch web page that we want to test
    target_sess = requests.Session()

    if(args.referer):
        target_sess.headers.update({'referer': args.referer})
    
    if(args.useragent):
        target_sess.headers.update({'user-agent': args.useragent})

    body = target_sess.get(args.url).text
    soup = BeautifulSoup(body, features='html.parser')
    scripts = soup.find_all('script')
    srcs = [link['src'] for link in scripts if 'src' in link.attrs]
    # Test with known dodgy URL 
    # srcs.append('//pushlat.com/ntfc.php?p=1273711139')



    # Set up caching
    sess = CacheControl(requests.Session(),
            FileCache(args.cachedir))

    response = sess.get(args.blacklist)
    rules = AdblockRules(
            response.text.splitlines(),
            supported_options=['third-party'],
            skip_unsupported_rules=False
            )
    options = {
            'third-party': True
            }
    for src in srcs:
        if(rules.should_block(src, options)):
            crit_msg.append(args.url + " contains dodgy 'script src' parameter: " + src)
        else:
            scanned_srcs.append(src)

    ok_msg.append("None of the " + str(len(scanned_srcs)) + " found 'script src' URLs on " + args.url + " are listed in " + args.blacklist)
    if(args.verbose):
        ok_msg.append("\n".join(scanned_srcs))

except Exception as e:
    nagios_exit("UNKNOWN: Unknown error: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + '\n'.join(ok_msg), 0)
