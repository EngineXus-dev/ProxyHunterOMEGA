# ProxyHunterOMEGA

**Experimental desktop proxy-source research and validation tool**  
** -- not recommended for using harvested proxies**

## Desktop GUI

![ProxyHunterOMEGA amber desktop command deck](assets/desktop_preview.png)

*Screenshot of the native desktop interface; live hunt data is shown in a separate terminal.*

ProxyHunterOMEGA is a Python/Tkinter desktop launcher for a terminal-based pipeline that collects **publicly listed proxy candidates**, checks their connectivity, and records network metadata. It is primarily a **research and testing project**, not a dependable proxy service.

> **Please read before using:** The source pool needs substantial maintenance. Some feeds fail or return nothing, many duplicate one another, and public endpoints may be stale, misconfigured, compromised or operated without their owners' consent. **Do not rely on harvested proxies for browsing, accounts, credentials, privacy, production traffic or other sensitive use.** Test only endpoints you are authorized to access.

## What it does—and doesn't do

| Can do | Cannot establish |
|---|---|
| Collect and deduplicate candidates from configured public feeds | Whether a source is trustworthy, exclusive or always current |
| Screen IP ranges and check open TCP ports | Whether an open port is a working proxy |
| Test HTTP/SOCKS requests via IP-echo services | Whether a proxy is safe, anonymous, private or authorized for use |
| Recheck previous successes in a new hunt | Whether an endpoint will remain online |
| Confirm candidates through two HTTPS exit-IP checks | 100% future reliability or all-site compatibility |
| Report ASN/ISP metadata, endpoint and distinct-exit counts | Genuine residential/mobile **devices**, consent or household access |

ISP/carrier labels are **unverified network-affiliation candidates**, never proof of a residential or mobile proxy. Multiple ports may share the same exit IP. The optional Scrapoxy and VPNGate integrations do not change these limitations.

## Install and run (Windows)

Requires Python **3.10+**, Tkinter (normally included in Windows Python), and internet access for an actual hunt.

```powershell
py -3 -m pip install -r .\requirements.txt
py -3 desktop.py
```

Or double-click `run.bat`. Select **Quiet**, **Balanced** (default) or **Turbo**, then choose **Quick Hunt** or **Full Hunt**. A separate terminal runs the pipeline; the desktop shows aggregate progress and provides latest-run exports. Press **Ctrl+C** in the terminal to cancel.

Terminal-only examples:

```powershell
py -3 run_optimal.py --list-sources
py -3 run_optimal.py --auto --profile balanced --no-scrapoxy --no-vpngate
py -3 -m unittest discover -p "test_*.py" -q
```

`--list-sources` only prints the configured researched feeds; it does not start a scan. Source configuration lives in [`constants.py`](constants.py) and [`community_sources.json`](community_sources.json). See [Sources](SOURCES.md) for the upstream provider links and caveats.

## How results are produced

`Harvest → CIDR filter → TCP probe → HTTP/SOCKS validation → network profiling → final double HTTPS confirmation`

A **completed hunt** regenerates the current confirmed-live lists from results that passed both final checks. Failed or previously verified endpoints are not automatically accepted on the next run; old successes are retested. A canceled hunt preserves the last completed export.

Output includes `all_confirmed_live.txt`, `other_live.txt`, `isp_network_candidates_live.txt`, and `carrier_network_candidates_live.txt`, plus protocol-prefixed variants when applicable. The separate ISP/carrier files are **metadata candidates, not verified residential/mobile inventories**. The project cannot verify residential-device ownership. Run results, cache, exported addresses and history are local and excluded from Git.

Even an entry in a confirmed-live file means only **successful tests at the time they ran**. The software does not certify a proxy as secure or suitable for real use.

## Project status and limitations

- **Source pool needs work:** failed, empty, stale and overlapping feeds remain; per-source counts and novelty reports help evaluate them. More harvested addresses do not mean more useful proxies.
- **Validation is imperfect:** short timeouts and high concurrency can miss slow working endpoints; a successful echo test does not cover every website or security concern.
- **Performance:** this is network-I/O-heavy, not a GPU workload. Turbo allows up to 1,000 asynchronous port probes and 64 validator threads, and may overload some networks. Balanced or Quiet is safer for development.
- **Optional integrations:** Scrapoxy and VPNGate are off by default. This public repository contains **no** bundled Scrapoxy source, credentials, Docker runtime, private history or proxy result datasets. To use Scrapoxy, configure an independently managed service; local build prerequisites are not included.
- **Testing:** the supplied unit tests are primarily offline/mocked; they do not certify live feed availability or end-to-end Windows/Docker behavior.

## Responsible use

Follow applicable law, target authorization, source terms and network policies. Publicly advertised endpoints are **not automatically available for unrestricted use**. No warranty is provided, and maintainers do not assume responsibility for misuse. See [Security](SECURITY.md). A public repository does not itself grant any license to third-party source data.
