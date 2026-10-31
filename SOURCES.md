# Public source references

These are **upstream feeds configured in the code**, not verified or recommended proxies. Feeds can fail, publish duplicates or omit authorization details. A feed returning HTTP 200 does **not** prove any endpoint is live, safe or owned by a residential subscriber. Check each provider's terms before use. The exact configurable URLs are in [`constants.py`](constants.py) and [`community_sources.json`](community_sources.json).

## Researched community feeds

Nine protocol-specific feeds are enabled and nine are opt-in. All are publicly published upstream collections; **none is exclusive or guaranteed fresh**.

| Upstream project | Feed configuration |
|---|---|
| [free-proxy-list](https://github.com/iplocate/free-proxy-list) | 3 enabled / 3 configured |
| [awesome-free-proxy-list](https://github.com/Thordata/awesome-free-proxy-list) | 3 enabled / 3 configured |
| [ProxyGenerator](https://github.com/proxygenerator1/ProxyGenerator) | 3 enabled / 3 configured |
| [free-proxy-list](https://github.com/hproxy-com/free-proxy-list) | 0 enabled / 3 configured |
| [KangProxy](https://github.com/officialputuid/KangProxy) | 0 enabled / 3 configured |
| [free-proxy-list](https://github.com/gfpcom/free-proxy-list) | 0 enabled / 3 configured |


## Built-in GitHub repositories

These projects underpin the built-in HTTP/SOCKS lists (55 feed URLs, 22 upstream repositories as currently configured):

[proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list), [komutan234/Proxy-List-Free](https://github.com/komutan234/Proxy-List-Free), [hookzof/socks5_list](https://github.com/hookzof/socks5_list), [zevtyardt/proxy-list](https://github.com/zevtyardt/proxy-list), [hendrikbgr/Free-Proxy-Repo](https://github.com/hendrikbgr/Free-Proxy-Repo), [monosans/proxy-list](https://github.com/monosans/proxy-list), [elliottophellia/yakumo](https://github.com/elliottophellia/yakumo), [jetkai/proxy-list](https://github.com/jetkai/proxy-list), [vakhov/fresh-proxy-list](https://github.com/vakhov/fresh-proxy-list), [ErcinDedeoglu/proxies](https://github.com/ErcinDedeoglu/proxies), [TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List), [ShiftyTR/Proxy-List](https://github.com/ShiftyTR/Proxy-List), [rdavydov/proxy-list](https://github.com/rdavydov/proxy-list), [roosterkid/openproxylist](https://github.com/roosterkid/openproxylist), [mmpx12/proxy-list](https://github.com/mmpx12/proxy-list), [Zaeem20/FREE_PROXIES_LIST](https://github.com/Zaeem20/FREE_PROXIES_LIST), [prxchk/proxy-list](https://github.com/prxchk/proxy-list), [zloi-user/hideip.me](https://github.com/zloi-user/hideip.me), [clarketm/proxy-list](https://github.com/clarketm/proxy-list), [sunny9577/proxy-scraper](https://github.com/sunny9577/proxy-scraper), [almroot/proxylist](https://github.com/almroot/proxylist), [MuR2z/Proxy-List](https://github.com/MuR2z/Proxy-List).

## Other public sources

API/list hosts configured in `SOURCES_API` (23 URLs):

[api.openproxy.space](https://api.openproxy.space/), [api.proxyscrape.com](https://api.proxyscrape.com/), [openproxylist.xyz](https://openproxylist.xyz/), [proxylist.geonode.com](https://proxylist.geonode.com/), [proxyspace.pro](https://proxyspace.pro/), [spys.me](https://spys.me/), [www.proxy-list.download](https://www.proxy-list.download/).

HTML directory providers configured in `SOURCES_HTML` (seven pages):

[free-proxy-list.net/](https://free-proxy-list.net/), [www.sslproxies.org/](https://www.sslproxies.org/), [www.us-proxy.org/](https://www.us-proxy.org/), [free-proxy-list.net/uk-proxy.html](https://free-proxy-list.net/uk-proxy.html), [free-proxy-list.net/anonymous-proxy.html](https://free-proxy-list.net/anonymous-proxy.html), [www.proxy-list.download/HTTPS](https://www.proxy-list.download/HTTPS), [www.proxy-list.download/HTTP](https://www.proxy-list.download/HTTP).

Additional experimental inputs are defined in `constants.py` (Telegram, Gists, VPNGate and protocol-specific subscriptions); not every upstream returns parseable HTTP/SOCKS endpoints. Scrapoxy is an optional external aggregation service, **not** a proof of residential identity.

## How to assess the source pool

Run `py -3 run_optimal.py --list-sources` to inspect the effective community manifest without scanning. Actual hunts record per-feed fetch status, parsed candidate counts and overlap/sole-source metrics in the private run snapshot. A source being sole-source **within one run** does not mean its proxies are globally unique, live or usable. The pool is a work in progress and needs ongoing pruning, source-term review and independent verification.
