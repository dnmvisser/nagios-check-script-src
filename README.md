# nagios-check-script-src
Nagios plugin to check a webpage for malicious URLs in it's script src parameters.


Needs the following python modules:

* requests
* cachecontrol
* adblockparser
* bs4
* lockfile



```
usage: nagios-check-script-src.py [-h] --url URL [--referer REFERER]
                                  [--useragent USERAGENT]
                                  [--blacklist BLACKLIST] [--verbose]

Check web page for unwanted script URLs

optional arguments:
  -h, --help            show this help message and exit
  --url URL             the URL to check
  --referer REFERER     The referer to use when checking the URL
  --useragent USERAGENT
                        The user agent to use when checking the URL
  --blacklist BLACKLIST
                        EasyList compatible blacklist URL. See
                        https://easylist.to
  --verbose             Show found URLs
```
