# nagios-check-script-src

Nagios plugin to check a webpage for malicious URLs in its `script src` parameters.

## Requirements

* Python3 with `pip`, or `uv`

## Installation

```shell
uv venv
. .venv/bin/activate
uv pip install -U -r requirements.txt
```

## Usage

```
usage: nagios-check-script-src.py [-h] --url URL [--verify]
                                  [--referer REFERER] [--useragent USERAGENT]
                                  [--header HEADER] [--blacklist BLACKLIST]
                                  [--cachedir CACHEDIR] [-v]

Check web page for unwanted script URLs

options:
  -h, --help            show this help message and exit
  --url URL             the URL to check
  --verify              Verify the TLS certificate on the URL
  --referer REFERER     The referer to use when checking the URL
  --useragent USERAGENT
                        The user agent to use when checking the URL
  --header HEADER       Custom header in the format Key: Value (can be
                        specified multiple times)
  --blacklist BLACKLIST
                        EasyList compatible blacklist URL. See
                        https://easylist.to (default: https://easylist-
                        downloads.adblockplus.org/easylist_noadult.txt)
  --cachedir CACHEDIR   Which directory to use for storing cached content
                        (default: .cache)
  -v, --verbose         Show found URLs (-v), fetched body content (-vv), or
                        request and response headers (-vvv)
```
