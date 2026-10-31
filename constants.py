#!/usr/bin/env python3
import re

# ИСТОЧНИКИ GITHUB / API
SOURCES_GITHUB = [
    # Tier 1 - Fresh & High Quality (Live auto-crawlers & dynamic mirrors)
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",     "socks5", 1),
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",       "http",   1),
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",     "socks4", 1),
    ("https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt",                  "socks5", 1),
    ("https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",                    "http",   1),
    ("https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks4.txt",                  "socks4", 1),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",                                "socks5", 1),
    ("https://raw.githubusercontent.com/zevtyardt/proxy-list/main/all.txt",                                   "http",   1),
    ("https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",                     "http",   1),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",                           "http", 1),
    ("https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt", "http", 1),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",         "http", 1),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",        "http", 1),
    ("https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",                                  "http", 1),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",                             "http", 1),
    ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",                         "http", 1),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",                        "socks4", 1),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",       "socks4", 1),
    ("https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",                                "socks4", 1),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",                           "socks4", 1),
    ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",                       "socks4", 1),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",                        "socks5", 1),
    ("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",       "socks5", 1),
    ("https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",                                "socks5", 1),
    ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",                           "socks5", 1),
    ("https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",                       "socks5", 1),

    # Tier 2 - Moderate Yields
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",                                "http", 2),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",                                 "http", 2),
    ("https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",                           "http", 2),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",                        "http", 2),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",                                   "http", 2),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",                                  "http", 2),
    ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",                           "http", 2),
    ("https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",                                      "http", 2),
    ("https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",                                   "http", 2),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",                              "socks4", 2),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",                               "socks4", 2),
    ("https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",                         "socks4", 2),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",                                 "socks4", 2),
    ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",                         "socks4", 2),
    ("https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",                                    "socks4", 2),
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",                              "socks5", 2),
    ("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",                               "socks5", 2),
    ("https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",                         "socks5", 2),
    ("https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",                                 "socks5", 2),
    ("https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",                         "socks5", 2),
    ("https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",                                    "socks5", 2),
    ("https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",                                 "socks5", 2),

    # Tier 3 - Experimental / Community & Volunteer Exits
    ("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",                       "http", 3),
    ("https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",                          "http", 3),
    ("https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",                                   "http", 3),
    ("https://raw.githubusercontent.com/MuR2z/Proxy-List/main/http.txt",                                       "http", 3),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",                       "socks4", 3),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",                       "socks5", 3),
    ("https://raw.githubusercontent.com/MuR2z/Proxy-List/main/socks5.txt",                                     "socks5", 3),
]

SOURCES_API = [
    # ProxyScrape v4 Live Filtered REST APIs
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&limit=2000&protocol=http&timeout=10000&country=all&simplified=true",   "http",   1),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&limit=2000&protocol=socks4&timeout=10000&country=all&simplified=true", "socks4", 1),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=displayproxies&limit=2000&protocol=socks5&timeout=10000&country=all&simplified=true", "socks5", 1),

    # Geonode Multi-Protocol Dynamic REST APIs (39%+ Residential/ISP Yield)
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&anonymityLevel=elite,anonymous", "http", 1),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5", "socks5", 1),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4", "socks4", 1),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https", "http", 1),
    ("https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&speed=fast", "http", 1),

    # Spys.me Live Checked Direct Feeds
    ("https://spys.me/proxy.txt", "http", 1),
    ("https://spys.me/socks.txt", "socks5", 1),

    # ProxySpace 15-Minute Dynamic Plaintext Feeds
    ("https://proxyspace.pro/http.txt", "http", 1),
    ("https://proxyspace.pro/https.txt", "http", 1),
    ("https://proxyspace.pro/socks4.txt", "socks4", 1),
    ("https://proxyspace.pro/socks5.txt", "socks5", 1),

    # OpenProxyList Continuous Plaintext Feeds
    ("https://openproxylist.xyz/http.txt", "http", 1),
    ("https://openproxylist.xyz/socks4.txt", "socks4", 1),
    ("https://openproxylist.xyz/socks5.txt", "socks5", 1),

    # Fallback / Tier 2 APIs
    ("https://www.proxy-list.download/api/v1/get?type=http",   "http",   2),
    ("https://www.proxy-list.download/api/v1/get?type=https",  "http",   2),
    ("https://www.proxy-list.download/api/v1/get?type=socks4", "socks4", 2),
    ("https://www.proxy-list.download/api/v1/get?type=socks5", "socks5", 2),
    ("https://api.openproxy.space/lists/http",   "http",   2),
    ("https://api.openproxy.space/lists/socks5", "socks5", 2),
]

SOURCES_VPNGATE = [
    "http://www.vpngate.net/api/iphone/",
    "http://130.158.6.81/api/iphone/",
]

TELEGRAM_CHANNELS = [
    "mtpro_xyz",
    "proxiesfree", "proxylistfree", "socks5_proxy_list", "free_socks5_proxy", "http_proxy_fresh",
    "proxylistfresh", "free_proxy_list1", "proxy_lists", "fresh_proxy_list", "socks5proxyfree",
    "shadowsockskeys", "ProxyMega", "proxyland", "ps_free_proxy_list", "proxy_list_daily",
    "proxy_socks5", "proxyme", "freeproxylist", "proxy_list", "socks5_bot", "socks_proxy_list",
    "free_proxy_socks5", "socks5_proxy", "proxies_socks5",
]

SOURCES_HTML = [
    "https://free-proxy-list.net/",
    "https://www.sslproxies.org/",
    "https://www.us-proxy.org/",
    "https://free-proxy-list.net/uk-proxy.html",
    "https://free-proxy-list.net/anonymous-proxy.html",
    "https://www.proxy-list.download/HTTPS",
    "https://www.proxy-list.download/HTTP",
]

SOURCES_TOR = [
    "http://pastebin3lrtfxnf.onion/archive",
    "http://strongbox7rqdc42p.onion/paste/",
    "http://zeronet6irsyypeq.onion/1GbG9jeHs3KMhj6FMkzUPJGBB7SnTVNRDP",
]

GIST_QUERIES = [
    "socks5 proxy list", "http proxy ip port", "proxy list socks4",
    "free proxy list ip:port", "working proxy list",
    "residential proxy list", "free residential proxy",
    "socks5 proxy drop", "leftovers proxy test", "vpngate socks5 proxy",
]

# КЛЮЧЕВЫЕ СЛОВА КЛАССИФИКАЦИИ
RESIDENTIAL_KEYWORDS = [
    "comcast","at&t","verizon","spectrum","cox","frontier","centurylink",
    "lumen","bt ","sky ","virgin","talk talk","vodafone","orange","sfr",
    "bouygues","deutsche telekom","telkom","optus","telstra","shaw",
    "bell canada","rogers","tele2","telenor","swisscom","a1 ","proximus",
    "kpn","t-home","chello","charter","cablevision","suddenlink","mediacom",
    "windstream","jio","airtel","bsnl","reliance","liberty","ziggo",
    "fastweb","infostrada","wind tre","tim brasil","oi internet","vpngate",
    "broadband",
]

MOBILE_KEYWORDS = [
    "t-mobile","tmobile","sprint","verizon wireless","at&t mobility",
    "boost mobile","cricket wireless","metro pcs","us cellular","three ",
    "o2 ","ee ","giffgaff","lebara","lyca","airtel mobile","jio mobile",
    "mobile","cellular","wireless","lte","4g","5g",
]

DC_KEYWORDS = [
    "amazon","aws","google","microsoft","azure","digitalocean","linode",
    "akamai","cloudflare","ovh","hetzner","leaseweb","rackspace","vultr",
    "contabo","scaleway","choopa","psychz","quadranet","sharktech",
    "hostwinds","server","hosting","datacenter","data center",
    "colocation","colo","vps","cloud","dedicated",
]

DC_CIDRS_FALLBACK = [
    "52.0.0.0/11","54.0.0.0/11","18.144.0.0/12","13.32.0.0/15",
    "13.35.0.0/16","3.80.0.0/12","3.96.0.0/13","15.152.0.0/13",
    "18.116.0.0/14","18.208.0.0/13","18.224.0.0/13","34.192.0.0/10",
    "34.0.0.0/9","35.184.0.0/13","35.192.0.0/11","35.224.0.0/12",
    "104.154.0.0/15","104.196.0.0/14","130.211.0.0/16",
    "13.64.0.0/11","13.104.0.0/14","23.96.0.0/13","40.64.0.0/10",
    "40.112.0.0/13","52.128.0.0/9","65.52.0.0/14","104.40.0.0/13",
    "104.131.0.0/16","104.236.0.0/16","107.170.0.0/16","138.197.0.0/16",
    "139.59.0.0/16","159.203.0.0/16","162.243.0.0/16","165.227.0.0/16",
    "167.99.0.0/16","188.166.0.0/16","198.199.0.0/16","45.55.0.0/16",
    "68.183.0.0/16","134.122.0.0/16","143.110.0.0/16","157.230.0.0/16",
    "95.216.0.0/16","116.203.0.0/16","136.243.0.0/16","138.201.0.0/16",
    "144.76.0.0/16","148.251.0.0/16","157.90.0.0/16","159.69.0.0/16",
    "167.235.0.0/16","168.119.0.0/16","176.9.0.0/16","188.40.0.0/16",
    "51.38.0.0/16","51.68.0.0/16","51.75.0.0/16","51.77.0.0/16",
    "51.89.0.0/16","51.91.0.0/16","51.195.0.0/16","51.210.0.0/16",
    "54.36.0.0/14","87.98.128.0/17","91.121.0.0/16","92.222.0.0/16",
    "45.32.0.0/20","45.63.0.0/18","45.76.0.0/15","64.237.32.0/19",
    "66.42.0.0/18","108.61.0.0/16","144.202.0.0/16","149.28.0.0/16",
    "45.33.0.0/17","45.56.0.0/21","45.79.0.0/16","50.116.0.0/20",
    "66.175.192.0/18","69.164.192.0/18","139.162.0.0/16","172.104.0.0/14",
    "51.15.0.0/16","163.172.0.0/16","104.16.0.0/12","104.24.0.0/14",
    "172.64.0.0/13","141.101.64.0/18","162.158.0.0/15","198.41.128.0/17",
    "135.181.0.0/16","142.132.0.0/14","195.201.0.0/16","192.81.128.0/17",
    "64.44.32.0/19","108.166.192.0/18","155.254.0.0/16",
    "85.17.0.0/16","37.58.0.0/16","95.211.0.0/16","192.99.0.0/16",
]

TEST_URLS = [
    "https://api.ipify.org?format=json",
    "https://checkip.amazonaws.com",
    "http://api.ipify.org?format=json",
]

XRAY_TELEGRAM_CHANNELS = [
    "NetAccount", "prrofile_orange", "VlessConfig", "TrojanV2ray", "ps_free_proxy_list",
]

SOURCES_XRAY_SUB = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub4.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all3",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
    "https://raw.githubusercontent.com/vveg26/chromego_merge/main/sub/base64_merged_proxies.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vmess",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/ss",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/all",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
]

CIDR_FETCH_URLS = [
    "https://raw.githubusercontent.com/lord-alfred/ipranges/main/all.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
]

PROXY_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
XRAY_RE = re.compile(r'(vmess|vless|trojan|ss|hysteria2?|tuic)://[A-Za-z0-9+/=@._:\-?&#%]+', re.IGNORECASE)

IP_API_FIELDS = "status,country,countryCode,city,isp,org,as,hosting,query"
IP_API_BATCH = "http://ip-api.com/batch"

# ==============================================================================
# DATACENTER ASNs (Autonomous System Numbers) for ASN vs WHOIS Mismatch Detection
# ==============================================================================
KNOWN_DC_ASNS = {
    16509, 14618, 16276, 24940, 14061, 15169, 8075, 13335, 20473, 63949,
    9009, 28753, 51167, 46606, 55081, 396982, 36352, 60068, 49505, 3214,
    31898, 209, 174, 1273, 3356, 6453, 6762, 1299, 7018, 20001,
    21859, 26347, 36024, 46562, 53667, 54290, 54801, 62240, 62567, 132203,
}

DC_ASN_NAMES = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "akamai", "cloudflare", "ovh", "hetzner", "leaseweb", "rackspace", "vultr",
    "choopa", "contabo", "scaleway", "psychz", "quadranet", "sharktech",
    "hostwinds", "m247", "datacamp", "cogent", "level3", "centurylink datacenter",
    "equinix", "interxion", "cyxtera", "fastly", "cdn77", "selectel",
]

# ==============================================================================
# BOTNET RELAYS & SDK C2 CHOKEPOINT IOCs (Kimwolf, IPIDEA, KadNap, UPnP RELAY)
# ==============================================================================
BOTNET_C2_IOCS = {
    "byteconnect": {
        "domains": ["new-endpoints.byteconnect.io", "byteconnect.io"],
        "ports": [80, 443],
        "threat_actor": "Kimwolf Botnet / ByteConnect SDK",
        "description": "Android proxy botnet monetized via ByteConnect SDK with ENS dead-drop C2",
    },
    "ipidea_castar": {
        "domains": ["ipidea.net", "api.ipidea.net", "rendezvous.castarsdk.com"],
        "protocols": ["QUIC", "TCP"],
        "threat_actor": "IPIDEA / Castar / PacketSDK Cluster",
        "description": "Two-tier C2 rendezvous using SDK injection in Radish VPN and cash-out apps",
    },
    "kadnap_peer4you": {
        "domains": ["www.c1s.su", "i.peer4you.net", "peer4you.net"],
        "threat_actor": "KadNap / Doppelganger / peer4you",
        "description": "Kademlia DHT C2 blending with BitTorrent; ASUS router residential exits",
    },
    "packetstream": {
        "domains": ["packetstream.io", "api.packetstream.io"],
        "threat_actor": "PacketStream Residential Reseller Network",
        "description": "Client SDK residential proxy network monetization node",
    },
}

UPNP_RELAY_SIGNATURES = {
    "igd_service": "urn:schemas-upnp-org:service:WANIPConnection:1",
    "action": "AddPortMapping",
    "port_mapping_description": "RELAY",
    "signature_note": "Jackskid/trees4sale malware opens external router ports labeled RELAY",
}

# ==============================================================================
# SCRAPOXY AGGREGATOR CONFIGURATION
# ==============================================================================
SCRAPOXY_DEFAULTS = {
    "api_url": "http://127.0.0.1:8890",
    "proxy_url": "http://127.0.0.1:8888",
    "username": "",
    "password": "",
    "timeout": 10,
    "target_connectors": ["proxidize", "rayobyte", "iproyal-residential", "zyte", "nimbleway"],
}

SCRAPOXY_HEADERS = {
    "header_proxy_count": "X-Scrapoxy-Proxy-Count",
    "header_proxy_latency": "X-Scrapoxy-Proxy-Latency",
    "header_proxy_mode": "X-Scrapoxy-Proxy-Mode",
    "header_connector": "X-Scrapoxy-Connector",
}

# ==============================================================================
# LANTERN UNBOUNDED / BROFLAKE P2P CONFIGURATION
# ==============================================================================
UNBOUNDED_DEFAULTS = {
    "bridge_host": "127.0.0.1",
    "bridge_port": 8000,
    "mode": "socks5",  # socks5 or http
    "signaling_url": "https://freddie.lantern.io",
    "sample_interval": 3.0,
}

