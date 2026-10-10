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
    parser.add_argument('--verify', help='Verify the TLS certificate on the URL',
            action='store_true',
            required=False,
            default=False)
    parser.add_argument('--referer', help='The referer to use when checking the URL')
    parser.add_argument('--useragent', help='The user agent to use when checking the URL',
            default='Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko')
    parser.add_argument('--header', help='Custom header in the format Key: Value (can be specified multiple times)',
            action='append',
            required=False)
    parser.add_argument('--blacklist', help='EasyList compatible blacklist URL. See https://easylist.to ' +
        '(default: https://easylist-downloads.adblockplus.org/easylist_noadult.txt)',
            default='https://easylist-downloads.adblockplus.org/easylist_noadult.txt')
    parser.add_argument('--cachedir', help='Which directory to use for storing cached content (default: .cache)', default='.cache')
    parser.add_argument('-v', '--verbose', help='Show found URLs (-v) or fetched body content (-vv)', action="count", default=0)


    args = parser.parse_args()

    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []
    scanned_srcs = []

    if not args.verify:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Fetch web page that we want to test
    target_sess = requests.Session()
    if(args.referer):
        target_sess.headers.update({'referer': args.referer})

    if(args.useragent):
        target_sess.headers.update({'user-agent': args.useragent})

    if(args.header):
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                target_sess.headers.update({k.strip(): v.strip()})

    response = target_sess.get(args.url, verify=args.verify)
    if response.status_code >= 400:
        crit_msg.append(f"{args.url} returned HTTP status {response.status_code}")
        body = response.text
    else:
        body = response.text
        soup = BeautifulSoup(body, features='html.parser')
        scripts = soup.find_all('script')
        srcs = [link['src'] for link in scripts if 'src' in link.attrs]
        # Test with known dodgy URL
        # srcs.append('//pushlat.com/ntfc.php?p=1273711139')

        # Set up caching
        sess = CacheControl(requests.Session(),
                FileCache(args.cachedir))

        blacklist_response = sess.get(args.blacklist)
        rules = AdblockRules(
                blacklist_response.text.splitlines(),
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

    if args.verbose >= 1 and scanned_srcs:
        ok_msg.append("\n".join(scanned_srcs))
    if args.verbose >= 2:
        ok_msg.append(body)

except Exception as e:
    nagios_exit("UNKNOWN: Unknown error: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + '\n'.join(ok_msg), 0)
