import sys
import os
try:
    from colorama import Fore, Style, init
except ImportError:
    class _NoColors:
        def __getattr__(self, key):
            return ''
    Fore = Style = _NoColors()
    def init(**_):
        return None

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

init(autoreset=True)


P = Fore.MAGENTA
C = Fore.CYAN
G = Fore.GREEN
Y = Fore.YELLOW
R = Fore.RED
W = Fore.WHITE
DIM = Style.DIM
B = Style.BRIGHT
RST = Style.RESET_ALL

def cp(color, text):
    if os.getenv("HEADLESS") == "1":
        return str(text)
    return f"{color}{B}{text}{RST}"

def dim(text):
    if os.getenv("HEADLESS") == "1":
        return str(text)
    return f"{DIM}{text}{RST}"

def clr():
    os.system("cls" if os.name == "nt" else "clear")

def safe_input(prompt=""):
    if os.getenv("HEADLESS") == "1":
        return ""
    try:
        return input(prompt)
    except EOFError:
        return ""

BANNER = f"""{P}{B}
 ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
 ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
 ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
 ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
 ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝{RST}{C}{B}
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{RST}
 {DIM}Scrape · Filter · Validate · Profile · Score{RST}
"""

def progress_bar(filled, total, width=40, color=P):
    pct = filled / total if total > 0 else 0
    n = int(pct * width)
    return f"{color}{'█' * n}{DIM}{'░' * (width - n)}{RST}"

def type_badge(t):
    cols = {"residential": G, "mobile": C, "datacenter": R, "unknown": DIM}
    return f"{cols.get(t, DIM)}{B}[{t[:4].upper()}]{RST}"

def stars(score):
    n = 5 if score >= 80 else 4 if score >= 60 else 3 if score >= 45 else 2 if score >= 30 else 1
    col = G if score >= 60 else Y if score >= 35 else R
    return f"{col}{B}{'★' * n}{'☆' * (5 - n)}{RST}"

def lat_col(l):
    return G if l < 2 else Y if l < 4 else R
