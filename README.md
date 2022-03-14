# nagios-check-script-src
Nagios plugin to check a webpage for malicious URLs in it's script src parameters.


# Installation
This plugin needs the following python3 modules:

* requests
* cachecontrol
* adblockparser
* bs4
* lockfile

`adblockparser` is not commonly packaged by distros, so you'd have to use pip
for that:

```
apt-get install python3-pip
pip3 install adblockparser
```

You can now choose to install the rest with pip as well:

```
pip3 install requests cachecontrol bs4 lockfile
```


Or from apt-get - this may be easier for automagic upgrades etc:


```bash
apt-get python3-requests python3-cachecontrol python3-lockfile python3-bs4
```


# Usage 


```
usage: nagios-check-script-src.py [-h] --url URL [--referer REFERER]
                                  [--useragent USERAGENT]
                                  [--blacklist BLACKLIST]
                                  [--cachedir CACHEDIR] [--verbose]

Check web page for unwanted script URLs

optional arguments:
  -h, --help            show this help message and exit
  --url URL             the URL to check
  --referer REFERER     The referer to use when checking the URL
  --useragent USERAGENT
                        The user agent to use when checking the URL
  --blacklist BLACKLIST
                        EasyList compatible blacklist URL. See
                        https://easylist.to (default: https://easylist-
                        downloads.adblockplus.org/easylist_noadult.txt)
  --cachedir CACHEDIR   Which directory to use for storing cached content
                        (default: .cache)
  --verify              Verify TLS certificate. The default is to NOT verify
                        the TLS certificate, as this check is about something
                        else. Usually this is done with a separated/dedicated
                        service check
  --verbose             Show found URLs
```
