#!/usr/bin/env python3
"""ProxyHunter Omega's native command deck. The terminal remains the hunt engine.

A local progress JSON file powers the stages and aggregate-only result tiles;
there is no HTTP service, mock network status, or embedded scanning implementation.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
PROFILES = ('quiet', 'balanced', 'laptop', 'notebook', 'server', 'turbo')
WORKERS = {'laptop': (32, 12, 8), 'notebook': (32, 16, 6),
           'server': (128, 40, 16), 'quiet': (128, 12, 6),
           'balanced': (256, 24, 12), 'turbo': (1000, 64, 24)}

BG = '#080d12'
PANEL = '#101820'
PANEL_ALT = '#17222e'
BORDER = '#65401e'
PINK = '#ff991e'  # Main amber HUD accent (legacy variable name for compatibility).
RED_DARK = '#412914'
TEXT = '#eaf2f6'
MUTED = '#93a4af'
GREEN = '#24e3be'
CYAN = '#33d9e5'
AMBER = '#ffbf58'
DANGER = '#f65371'
INNER = '#0a1118'
GLOW = '#b97324'

STAGES = (
    ('01 // INGEST', 'MULTI-HARVEST', 'Public source feeds'),
    ('02 // FILTER', 'CIDR SCREEN', 'Network exclusions'),
    ('03 // PROBE', 'TCP PORT CHECK', 'Async socket checks'),
    ('04 // VALIDATE', 'PROXY TUNNEL', 'HTTP / SOCKS traffic'),
    ('05 // PROFILE', 'PROFILE + CONFIRM', 'Final HTTPS checks'),
)


def hunt_command(*, profile='balanced', full=False, scrapoxy=False, vpngate=False,
                 recheck=True):
    if profile not in PROFILES:
        raise ValueError('Invalid resource profile')
    args = [sys.executable, str(ROOT / 'terminal_runner.py'), '--auto', '--profile', profile,
            '--desktop-status']
    if full:
        args.append('--full')
    args.append('--scrapoxy' if scrapoxy else '--no-scrapoxy')
    if not vpngate:
        args.append('--no-vpngate')
    args.append('--recheck' if recheck else '--resume')
    return args


def open_terminal(args):
    """Pass argv directly, never through a command interpreter."""
    if sys.platform == 'win32':
        return subprocess.Popen(args, cwd=ROOT, creationflags=subprocess.CREATE_NEW_CONSOLE)
    for name, prefix in (
        ('x-terminal-emulator', ['x-terminal-emulator', '-e']),
        ('gnome-terminal', ['gnome-terminal', '--']),
        ('konsole', ['konsole', '-e']),
        ('xfce4-terminal', ['xfce4-terminal', '-x']),
        ('xterm', ['xterm', '-e']),
    ):
        if shutil.which(name):
            return subprocess.Popen(prefix + args, cwd=ROOT)
    raise RuntimeError('No terminal emulator found. Use: python run_optimal.py --auto --profile turbo --no-scrapoxy --no-vpngate')


def open_data_folder(path):
    """Open local results only, without shell=True or URL handling."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == 'win32':
        os.startfile(str(path))
    elif sys.platform == 'darwin':
        subprocess.Popen(['open', str(path)])
    else:
        subprocess.Popen(['xdg-open', str(path)])


class Dashboard:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk = tk
        self.ttk = ttk
        self.root = root
        self.process = None
        self.launched_at = 0.0
        self.run_id = None
        self.last_status = None
        self.last_snapshot_mtime = None
        self.snapshot = None
        self.live = False

        root.title('PROXYHUNTER // OMEGA  ·  Desktop Command Deck')
        root.geometry('1500x900')
        root.minsize(1130, 700)
        root.configure(bg=BG)
        root.option_add('*Font', ('Consolas', 10))
        style = ttk.Style(root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('Omega.TCombobox', fieldbackground=PANEL_ALT, background=PANEL_ALT,
                        foreground=TEXT, bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER, arrowcolor=PINK, padding=8)
        style.map('Omega.TCombobox', fieldbackground=[('readonly', PANEL_ALT)],
                  foreground=[('readonly', TEXT)], selectbackground=[('readonly', PANEL_ALT)],
                  selectforeground=[('readonly', TEXT)])

        # Vertical structure: title, telemetry, five steps, dashboard, footer.
        # A scrollable command deck keeps all controls reachable on smaller laptops.
        viewport = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0)
        viewport.pack(side='left', fill='both', expand=True)
        scrollbar = tk.Scrollbar(root, orient='vertical', command=viewport.yview,
                                 width=10, troughcolor=BG, bg=BORDER,
                                 activebackground=AMBER)
        scrollbar.pack(side='right', fill='y')
        viewport.configure(yscrollcommand=scrollbar.set)
        shell = tk.Frame(viewport, bg=BG, padx=18, pady=12)
        panel_id = viewport.create_window((0, 0), window=shell, anchor='nw')
        def relayout(_=None):
            viewport.itemconfigure(panel_id, width=viewport.winfo_width())
            desired = max(shell.winfo_reqheight(), viewport.winfo_height())
            viewport.itemconfigure(panel_id, height=desired)
            viewport.configure(scrollregion=(0, 0, viewport.winfo_width(), desired))
        shell.bind('<Configure>', relayout)
        viewport.bind('<Configure>', relayout)
        def wheel(event):
            if event.num == 4:
                viewport.yview_scroll(-3, 'units')
            elif event.num == 5:
                viewport.yview_scroll(3, 'units')
            elif getattr(event, 'delta', 0):
                viewport.yview_scroll(int(-event.delta / 120) * 3, 'units')
        root.bind_all('<MouseWheel>', wheel)
        root.bind_all('<Button-4>', wheel)
        root.bind_all('<Button-5>', wheel)
        self._header(shell)
        self._telemetry(shell)
        self._pipeline(shell)
        self._body(shell)
        self._footer(shell)
        self.refresh()

    def txt(self, parent, value, *, size=10, color=TEXT, bold=False, bg=None,
            wrap=None, anchor='w', **kw):
        return self.tk.Label(parent, **({'textvariable': value} if isinstance(value, self.tk.Variable) else {'text': value}),
                             bg=bg or parent.cget('bg'), fg=color,
                             font=('Consolas', size, 'bold' if bold else 'normal'),
                             anchor=anchor, justify='left', wraplength=wrap or 0, **kw)

    def panel(self, parent, *, bg=PANEL, border=BORDER, padx=15, pady=14):
        edge = self.tk.Frame(parent, bg=border, padx=1, pady=1)
        inside = self.tk.Frame(edge, bg=bg, padx=padx, pady=pady)
        inside.pack(fill='both', expand=True)
        return edge, inside

    def btn(self, parent, text, cmd, *, primary=False, color=None, pady=11):
        back = PINK if primary else PANEL_ALT
        b = self.tk.Button(parent, text=text, command=cmd, cursor='hand2',
                           bg=back, fg='#17120c' if primary else (color or TEXT),
                           activebackground='#ffc15f' if primary else '#24323d',
                           activeforeground='#17120c' if primary else 'white', relief='flat', bd=0,
                           highlightthickness=1, highlightbackground=PINK if primary else BORDER,
                           font=('Consolas', 10, 'bold'), pady=pady)
        return b

    def _header(self, shell):
        tk = self.tk
        header = tk.Frame(shell, bg=BG)
        header.pack(fill='x', pady=(0, 10))
        brand = tk.Frame(header, bg=BG)
        brand.pack(side='left', fill='y')
        logo = tk.Canvas(brand, width=58, height=62, bg=BG, highlightthickness=0)
        logo.create_rectangle(3, 7, 53, 57, fill=INNER, outline=GLOW, width=2)
        logo.create_rectangle(9, 13, 47, 51, fill='#332010', outline=PINK, width=1)
        logo.create_text(28, 32, text='Ω', font=('Consolas', 29, 'bold'), fill=AMBER)
        logo.pack(side='left', padx=(0, 11))
        names = tk.Frame(brand, bg=BG)
        names.pack(side='left', anchor='w')
        self.txt(names, 'PROXYHUNTER  //  OMEGA', size=24, bold=True).pack(anchor='w')
        self.txt(names, 'DESKTOP COMMAND DECK   /   TERMINAL-DRIVEN ENGINE',
                 size=9, color=MUTED).pack(anchor='w', pady=(4, 0))
        badge_edge, badges = self.panel(header, bg=INNER, padx=17, pady=9)
        badge_edge.pack(side='right', padx=(8, 0))
        self.txt(badges, '●  EXPERIMENTAL / WIP', size=9, color=AMBER,
                 bold=True).pack(anchor='e', pady=(0, 6))
        self.engine_var = tk.StringVar(value='●  ENGINE STANDBY')
        self.txt(badges, self.engine_var, size=10, color=GREEN,
                 bold=True).pack(anchor='e')
        tk.Frame(shell, height=2, bg=GLOW).pack(fill='x', pady=(0, 13))

    def _telemetry(self, shell):
        tk = self.tk
        row = tk.Frame(shell, bg=BG)
        row.pack(fill='x', pady=(0, 12))
        self.chips = {}
        chips = [('▣', 'ENGINE', 'TERMINAL-DRIVEN'),
                 ('▤', 'SCRAPOXY', 'DISABLED'),
                 ('◇', 'VPNGATE', 'DISABLED'),
                 ('◴', 'PERFORMANCE', 'TURBO / 1,000 · 64')]
        for col, (glyph, label, value) in enumerate(chips):
            row.grid_columnconfigure(col, weight=1, uniform='status')
            edge, content = self.panel(row, bg=PANEL, padx=11, pady=10)
            edge.grid(row=0, column=col, sticky='ew', padx=(0 if col == 0 else 5, 5 if col < 3 else 0))
            icon = tk.Label(content, text=glyph, font=('Consolas', 20, 'bold'),
                            bg=INNER, fg=AMBER, width=3, height=2)
            icon.pack(side='left', padx=(0, 11))
            column = tk.Frame(content, bg=PANEL)
            column.pack(side='left', fill='both', expand=True)
            self.txt(column, label, size=8, color=MUTED, bold=True).pack(anchor='w', pady=(2, 0))
            variable = tk.StringVar(value=value)
            self.txt(column, variable, size=10, color=AMBER if col in (0, 3) else TEXT,
                     bold=True).pack(anchor='w', pady=(5, 0))
            self.chips[label] = variable
            tk.Frame(column, height=2, bg=GLOW if col in (0, 3) else BORDER).pack(
                fill='x', pady=(7, 0))

    def _pipeline(self, shell):
        tk = self.tk
        title = tk.Frame(shell, bg=BG)
        title.pack(fill='x', pady=(0, 8))
        self.txt(title, '▸  PIPELINE  /  FIVE STAGES', size=11, bold=True).pack(side='left')
        self.txt(title, 'LIVE FROM TERMINAL  ·  NO WEB SERVER', size=8, color=MUTED).pack(side='right')
        row = tk.Frame(shell, bg=BG)
        row.pack(fill='x', pady=(0, 13))
        self.steps = []
        glyphs = ('▤', '▼', '◎', '✓', '▣')
        for col, (code, label, detail) in enumerate(STAGES):
            row.grid_columnconfigure(col, weight=1, uniform='stages')
            edge, content = self.panel(row, bg=PANEL, padx=10, pady=10)
            edge.grid(row=0, column=col, sticky='nsew', padx=(0 if col == 0 else 5, 5 if col < 4 else 0))
            heading = tk.Frame(content, bg=PANEL)
            heading.pack(fill='x')
            self.txt(heading, glyphs[col] + '  ' + code, size=9, color=AMBER,
                     bold=True).pack(side='left')
            stage_value = tk.StringVar(value='—')
            self.txt(heading, stage_value, size=8, color=MUTED).pack(side='right')
            self.txt(content, label, size=11, bold=True).pack(anchor='w', pady=(12, 4))
            self.txt(content, detail, size=8, color=MUTED).pack(anchor='w')
            tk.Frame(content, height=2, bg=GLOW).pack(fill='x', pady=(12, 0))
            self.steps.append((edge, stage_value))

    def _body(self, shell):
        tk = self.tk
        body = tk.Frame(shell, bg=BG)
        body.pack(fill='both', expand=True)
        body.grid_columnconfigure(0, weight=0, minsize=315)
        body.grid_columnconfigure(1, weight=1, minsize=335)
        body.grid_columnconfigure(2, weight=0, minsize=365)
        body.grid_rowconfigure(0, weight=1)
        left_edge, left = self.panel(body, bg=PANEL, padx=15, pady=15)
        left_edge.grid(row=0, column=0, sticky='nsew', padx=(0, 9))
        self._control(left)
        self._hub(body)
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=2, sticky='nsew', padx=(9, 0))
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)
        self._matrix(right)
        self._operation(right)

    def _hub(self, body):
        tk = self.tk
        edge, content = self.panel(body, bg=INNER, padx=6, pady=8)
        edge.grid(row=0, column=1, sticky='nsew')
        self.txt(content, '◈  LOCAL SCAN CORE   /   OMEGA HUD', size=10,
                 color=AMBER, bold=True).pack(anchor='center', pady=(5, 5))
        canvas = tk.Canvas(content, bg=INNER, highlightthickness=0, width=350, height=310)
        canvas.pack(fill='both', expand=True)
        self.hub_canvas = canvas
        self.hub_image = None
        self.hub_size = None
        canvas.bind('<Configure>', self._draw_hub)
        self.hub_title = tk.StringVar(value='STANDBY   //   AWAITING HUNT')
        self.txt(content, self.hub_title, size=11, color=AMBER, bold=True,
                 anchor='center').pack(fill='x', pady=(0, 6))
        progress = tk.Frame(content, bg='#32302c', height=10)
        progress.pack(fill='x', padx=12, pady=(0, 7))
        progress.pack_propagate(False)
        self.hub_meter = tk.Frame(progress, bg=PINK)
        self.hub_meter.place(x=0, y=0, relheight=1, relwidth=0)
        self.hub_status = tk.StringVar(value='PORTS OPEN  —     VERIFIED  —')
        self.txt(content, self.hub_status, size=8, color=CYAN,
                 anchor='center').pack(fill='x', pady=(0, 7))
        self.txt(content, 'DECORATIVE HUD  ·  DATA FROM LOCAL RUN STATUS',
                 size=7, color=MUTED, anchor='center').pack(fill='x', pady=(0, 6))

    def _draw_hub(self, event=None):
        from pathlib import Path
        c = self.hub_canvas
        w, h = c.winfo_width(), c.winfo_height()
        if w < 50 or h < 50:
            return
        side = max(150, min(w - 12, h - 12, 490))
        # Rebuild only on actual layout-size changes; Pillow is used only by the UI.
        if self.hub_size != side:
            self.hub_size = side
            from PIL import Image, ImageTk
            asset = Image.open(ROOT / 'assets' / 'omega_hud_core.png').convert('RGBA')
            asset = asset.resize((side, side), Image.Resampling.LANCZOS)
            self.hub_image = ImageTk.PhotoImage(asset, master=self.root)
        c.delete('all')
        center_x, center_y = w / 2, h / 2
        c.create_image(center_x, center_y, image=self.hub_image)
        r = side * 0.475
        c.create_oval(center_x-r, center_y-r, center_x+r, center_y+r,
                      outline=GLOW, width=1)
        c.create_line(center_x-22, center_y, center_x+22, center_y, fill=AMBER)
        c.create_line(center_x, center_y-22, center_x, center_y+22, fill=AMBER)
        c.create_oval(center_x-4, center_y-4, center_x+4, center_y+4,
                      fill=AMBER, outline='')

    def _control(self, parent):
        h = self.tk.Frame(parent, bg=PANEL)
        h.pack(fill='x', pady=(0, 13))
        self.txt(h, '▸  TACTICAL CONTROL', size=12, bold=True).pack(side='left')
        self.txt(h, 'READY', size=9, color=GREEN, bold=True).pack(side='right')
        self.tk.Frame(parent, height=1, bg=BORDER).pack(fill='x', pady=(0, 13))
        hunt_actions = self.tk.Frame(parent, bg=PANEL)
        hunt_actions.pack(fill='x', pady=(0, 8))
        self.quick_button = self.btn(hunt_actions, '⚡ QUICK HUNT', lambda: self.launch(False), primary=True, pady=9)
        self.quick_button.pack(side='left', fill='x', expand=True, padx=(0, 4))
        self.full_button = self.btn(hunt_actions, '☠ FULL HUNT', lambda: self.launch(True), pady=9)
        self.full_button.pack(side='left', fill='x', expand=True, padx=(4, 0))
        self.cancel_button = self.btn(parent, '■  CANCEL ACTIVE HUNT', self.cancel, color=AMBER, pady=8)
        self.cancel_button.pack(fill='x', pady=(0, 7))
        self.cancel_button.config(state='disabled')
        self.export_button = self.btn(parent, '▣  EXPORT LATEST RESULTS', self.save, pady=9)
        self.export_button.pack(fill='x', pady=(0, 7))
        self.btn(parent, '▤  OPEN LOCAL DATA FOLDER', self.open_folder, pady=7).pack(fill='x', pady=(0, 10))

        self.tk.Frame(parent, height=1, bg=BORDER).pack(fill='x', pady=(0, 8))
        self.txt(parent, 'PERFORMANCE PROFILE', size=9, color=AMBER, bold=True).pack(anchor='w')
        self.profile = self.tk.StringVar(value='balanced')
        combo = self.ttk.Combobox(parent, style='Omega.TCombobox', state='readonly',
                                  textvariable=self.profile, values=PROFILES)
        combo.pack(fill='x', pady=(6, 5))
        combo.bind('<<ComboboxSelected>>', lambda _: self.show_profile())
        self.workers_var = self.tk.StringVar()
        self.txt(parent, self.workers_var, size=9, color=CYAN).pack(anchor='w', pady=(0, 8))

        self.scrapoxy = self.tk.BooleanVar(value=False)
        self.vpngate = self.tk.BooleanVar(value=False)
        self.recheck = self.tk.BooleanVar(value=True)
        for text, variable in (
            ('Enable existing Scrapoxy service', self.scrapoxy),
            ('Enable VPNGate / Docker adapter', self.vpngate),
            ('Fresh recheck every hunt (recommended)', self.recheck),
        ):
            cb = self.tk.Checkbutton(parent, text=text, variable=variable, command=self.show_profile,
                                     bg=PANEL, fg=TEXT, selectcolor=PANEL_ALT, activebackground=PANEL,
                                     activeforeground=TEXT, highlightthickness=0,
                                     font=('Consolas', 9), anchor='w')
            cb.pack(fill='x', pady=1)
        self.show_profile()
        self.txt(parent, 'Optional adapters are not pre-verified.', color=MUTED, size=8,
                 wrap=280).pack(anchor='w', pady=(9, 0))

    def _matrix(self, parent):
        tk = self.tk
        edge, content = self.panel(parent, bg=PANEL, padx=12, pady=12)
        edge.grid(row=0, column=0, sticky='ew', pady=(0, 9))
        head = tk.Frame(content, bg=PANEL)
        head.pack(fill='x', pady=(0, 10))
        self.txt(head, '▸  LAST HUNT / INTEL MATRIX', size=11, bold=True).pack(side='left')
        self.latest_var = tk.StringVar(value='NO SNAPSHOT')
        self.txt(head, self.latest_var, size=8, color=MUTED).pack(side='right')
        metrics = tk.Frame(content, bg=PANEL)
        metrics.pack(fill='x')
        self.metrics = {}
        colors = (('isp','ISP / ACCESS UNKNOWN',GREEN,'⌂'),
                  ('carrier','CARRIER / ACCESS UNKNOWN',CYAN,'▯'),
                  ('datacenter','DATACENTER TAG',DANGER,'▤'),
                  ('risk','RISK-TAGGED',AMBER,'⚠'))
        for idx, (key, label, tint, symbol) in enumerate(colors):
            col, row = idx % 2, idx // 2
            metrics.grid_columnconfigure(col, weight=1, uniform='classifications')
            card_edge, inner = self.panel(metrics, bg=INNER, padx=10, pady=8)
            card_edge.grid(row=row, column=col, sticky='nsew', padx=(0 if col == 0 else 4, 4 if col == 0 else 0), pady=(0, 5))
            upper = tk.Frame(inner, bg=INNER)
            upper.pack(fill='x')
            tk.Label(upper, text=symbol, font=('Consolas', 19, 'bold'),
                     fg=tint, bg=INNER).pack(side='left', padx=(0, 7))
            self.txt(upper, label, size=8, color=MUTED, wrap=110).pack(side='left', fill='x')
            count = tk.StringVar(value='—')
            self.txt(inner, count, size=23, color=tint, bold=True).pack(anchor='w', pady=(2, 0))
            self.metrics[key] = count
        self.metrics_note = tk.StringVar(value='No completed hunt snapshot. Start a scan to populate these counts.')
        self.txt(content, self.metrics_note, size=8, color=MUTED,
                 wrap=340).pack(anchor='w', pady=(5, 0))

    def _operation(self, parent):
        tk = self.tk
        edge, content = self.panel(parent, bg=PANEL, padx=12, pady=12)
        edge.grid(row=1, column=0, sticky='nsew')
        heading = tk.Frame(content, bg=PANEL)
        heading.pack(fill='x', pady=(0, 9))
        self.txt(heading, '▸  LIVE HUNT TELEMETRY', size=11, bold=True).pack(side='left')
        self.event_state = tk.StringVar(value='STANDBY')
        self.txt(heading, self.event_state, size=9, color=CYAN, bold=True).pack(side='right')
        self.operation_title = tk.StringVar(value='READY  //  AWAITING HUNT')
        self.txt(content, self.operation_title, size=11, bold=True,
                 wrap=340).pack(anchor='w', fill='x', pady=(0, 8))
        self.operation_detail = tk.StringVar(value='Terminal handles the scan; this panel tracks its live progress.')
        self.txt(content, self.operation_detail, color=MUTED, size=9,
                 wrap=340).pack(anchor='w', fill='x')
        track = tk.Frame(content, height=11, bg='#322b26')
        track.pack(fill='x', pady=(12, 5))
        track.pack_propagate(False)
        self.meter = tk.Frame(track, bg=PINK)
        self.meter.place(x=0, y=0, relheight=1, relwidth=0)
        self.percent_var = tk.StringVar(value='0%')
        self.txt(content, self.percent_var, color=AMBER, size=11, bold=True).pack(anchor='e')
        self.telemetry_var = tk.StringVar(value='SOURCES  —     PORTS OPEN  —     VERIFIED  —')
        self.txt(content, self.telemetry_var, color=CYAN, size=9,
                 wrap=335).pack(anchor='w', fill='x', pady=(7, 0))
        self.footer_status = tk.StringVar(value='Terminal output contains the detailed logs and errors.')
        self.txt(content, self.footer_status, color=MUTED, size=8,
                 wrap=335).pack(anchor='w', fill='x', pady=(10, 0))

    def _radar(self, canvas):
        # Decorative geometric indicator only; NOT a fabricated threat scan.
        x, y = 113, 105
        for rad, color in ((85, '#382033'), (61, '#542039'), (36, '#71253e')):
            canvas.create_oval(x-rad, y-rad, x+rad, y+rad, outline=color, width=1)
        canvas.create_line(20, y, 206, y, fill='#332036')
        canvas.create_line(x, 13, x, 198, fill='#332036')
        canvas.create_arc(x-84, y-84, x+84, y+84, start=24, extent=55,
                          outline=PINK, style='arc', width=3)
        canvas.create_line(x, y, x+49, y-48, fill=PINK, width=2)
        canvas.create_oval(x-5, y-5, x+5, y+5, fill=PINK, outline='')
        canvas.create_text(x, 209, text='LOCAL PROGRESS DISPLAY',
                           font=('Consolas', 8), fill=MUTED)

    def _footer(self, shell):
        footer = self.tk.Frame(shell, bg=BG)
        footer.pack(fill='x', pady=(11, 0))
        self.txt(footer, 'RESEARCH TOOL  ·  PORT OPEN ≠ WORKING PROXY ≠ AUTHORIZED OR RESIDENTIAL',
                 size=8, color=MUTED).pack(side='left')
        self.txt(footer, 'OMEGA / WIP', size=8, color=AMBER).pack(side='right')

    def show_profile(self):
        p, v, s = WORKERS[self.profile.get()]
        self.workers_var.set(f'{p:,} port probes   /   {v} validators   /   {s} sources')
        self.chips['SCRAPOXY'].set('SELECTED / UNVERIFIED' if self.scrapoxy.get() else 'DISABLED')
        self.chips['VPNGATE'].set('SELECTED / UNVERIFIED' if self.vpngate.get() else 'DISABLED')
        self.chips['PERFORMANCE'].set(f'{self.profile.get().upper()} / {p:,} · {v}')

    def launch(self, full):
        from tkinter import messagebox
        if self.live:
            messagebox.showinfo('Hunt already active', 'Finish or cancel the current hunt first.')
            return
        try:
            self.launched_at = time.time()
            self.run_id = None
            self.process = open_terminal(hunt_command(profile=self.profile.get(), full=full,
                                scrapoxy=self.scrapoxy.get(), vpngate=self.vpngate.get(),
                                recheck=self.recheck.get()))
            # Don't let the old scan status briefly appear as the new one.
            self.last_status = None
            self.live = True
            self.operation_title.set('OPENING TERMINAL  //  ' + ('FULL' if full else 'QUICK') + ' HUNT')
            self.operation_detail.set('Starting the independent terminal engine…')
            self.event_state.set('STARTING')
            self.hub_title.set('STARTING  //  TERMINAL OPENING')
            self.engine_var.set('●  HUNT STARTING')
            self._busy_buttons()
        except (OSError, RuntimeError, ValueError) as exc:
            self.live = False
            messagebox.showerror('Unable to launch', str(exc))

    def _busy_buttons(self):
        self.quick_button.config(state='disabled' if self.live else 'normal')
        self.full_button.config(state='disabled' if self.live else 'normal')
        self.cancel_button.config(state='normal' if self.live and self.run_id else 'disabled')

    def cancel(self):
        from tkinter import messagebox
        from run_control import request_cancel
        if not self.live or self.last_status is None:
            messagebox.showinfo('No active hunt', 'No active operation has registered yet.')
            return
        try:
            pid = int(self.last_status['pid'])
            if pid < 1 or not self.run_id:
                raise ValueError('No registered hunt')
            count = request_cancel(pid)
            if count:
                self.footer_status.set('Cancellation requested. The terminal completes in-flight checks safely.')
            else:
                messagebox.showinfo('No active hunt', 'The hunt may have already finished.')
        except (OSError, ValueError, KeyError) as exc:
            messagebox.showerror('Cancellation failed', str(exc))

    def save(self):
        from tkinter import filedialog, messagebox
        from recent_results import export_latest, RESULTS_FILE
        from run_control import data_dir
        if not (data_dir() / RESULTS_FILE).is_file():
            messagebox.showinfo('No recent results', 'Run a hunt first. There is no last-run snapshot.')
            return
        destination = filedialog.asksaveasfilename(title='Export most recent hunt',
            defaultextension='.txt', initialfile='proxyhunter_latest.txt',
            filetypes=[('Endpoint text list', '*.txt'), ('CSV records', '*.csv'), ('JSON snapshot', '*.json')])
        if not destination:
            return
        try:
            count = export_latest(destination)
            messagebox.showinfo('Exported latest run',
                f'{count} confirmed-live records exported.\n\n{destination}\n\n'
                'ISP/carrier hints are NOT proof of residential or mobile access; endpoints may be unsafe, expired, '
                'unauthorized, or contain credentials. Do not publish raw results.')
            self.footer_status.set(f'Exported {count} latest-run records in selected format.')
        except (OSError, KeyError, ValueError) as exc:
            messagebox.showerror('Export failed', str(exc))

    def open_folder(self):
        from tkinter import messagebox
        from run_control import data_dir
        try:
            open_data_folder(data_dir())
        except OSError as exc:
            messagebox.showerror('Unable to open folder', str(exc))

    def _update_status(self, status):
        from desktop_status import FINAL_RESULTS
        if not status:
            return
        if self.live and status.get('updated_at', 0) < self.launched_at - 0.5:
            return
        self.last_status = status
        self.run_id = status.get('run_id')
        stage = status.get('stage', 0)
        try:
            stage = int(stage)
            percent = max(0, min(100, int(status.get('percent', 0))))
        except (ValueError, TypeError):
            stage, percent = 0, 0
        name = str(status.get('name') or 'STANDBY')
        result = str(status.get('result') or 'running')
        for idx, (edge, variable) in enumerate(self.steps, start=1):
            if 1 <= idx < stage or (result in FINAL_RESULTS and result not in ('error', 'cancelled') and stage >= idx):
                edge.config(bg=GREEN)
                variable.set('✓ DONE')
            elif idx == stage and result == 'running':
                edge.config(bg=PINK)
                variable.set('● LIVE')
            else:
                edge.config(bg=BORDER)
                variable.set('—')
        self.meter.place_configure(relwidth=percent / 100)
        self.hub_meter.place_configure(relwidth=percent / 100)
        self.hub_title.set(f'{name.upper()}  /  {percent}%')
        self.percent_var.set(f'{percent}%')
        self.event_state.set(result.upper() if result in FINAL_RESULTS else f'STAGE {stage:02d} / 05')
        self.operation_title.set(name.upper() + '  //  ' + ('RUNNING' if result == 'running' else result.upper()))
        self.operation_detail.set(str(status.get('message') or 'See terminal for details.'))
        counters = status.get('counters') or {}
        def count(key):
            try:
                return f'{int(counters[key]):,}'
            except (KeyError, ValueError, TypeError):
                return '—'
        self.telemetry_var.set(f'SOURCES  {count("scraped")}     PORTS OPEN  {count("ports_alive")}     VERIFIED  {count("valid")}')
        self.hub_status.set(f'PORTS OPEN  {count("ports_alive")}   /   VERIFIED  {count("valid")}')
        self.live = result not in FINAL_RESULTS and result != 'status_unavailable'
        self.engine_var.set('●  ENGINE ACTIVE' if self.live else '●  ' + result.upper())
        self._busy_buttons()

    def _update_snapshot(self):
        from desktop_status import snapshot_summary
        from recent_results import RESULTS_FILE
        from run_control import data_dir
        path = data_dir() / RESULTS_FILE
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            mtime = None
        if mtime == self.last_snapshot_mtime:
            return
        self.last_snapshot_mtime = mtime
        self.snapshot = snapshot_summary(path) if mtime else None
        if not self.snapshot:
            self.latest_var.set('NO SNAPSHOT')
            return
        if 'error' in self.snapshot:
            self.latest_var.set('SNAPSHOT ERROR')
            self.metrics_note.set(self.snapshot['error'])
            return
        s = self.snapshot
        for key, variable in self.metrics.items():
            variable.set(str(s['counters'][key]))
        self.latest_var.set(s['result'].upper().replace('_', ' '))
        self.metrics_note.set(f'{s["total"]:,} confirmed endpoints / {s.get("distinct_exits", 0):,} distinct observed exit IPs • '
                              f'{s["counters"]["other"]:,} other • '
                              'ISP/carrier affiliation does NOT prove residential/mobile device access.')

    def refresh(self):
        from desktop_status import read_status
        try:
            self._update_snapshot()
            current = read_status()
            if current:
                # A missing run registration with a stale progress file could mean
                # telemetry failed, even if the terminal completed successfully.
                # Don't falsely label the hunt a pipeline ERROR.
                if (current.get('result') == 'running' and
                        current.get('updated_at', 0) < time.time() - 2):
                    from run_control import data_dir
                    pid = current.get('pid')
                    registration = data_dir() / 'runs' / f'{pid}.json'
                    if not registration.is_file():
                        current = dict(current, result='status_unavailable', name='STATUS STALE',
                                       message='No fresh dashboard telemetry; check the terminal for the actual outcome.')
                self._update_status(current)
            elif self.live and self.process and self.process.poll() is not None:
                self.live = False
                self.engine_var.set('●  TERMINAL CLOSED')
                self.event_state.set('NO STATUS')
                self.operation_detail.set('Terminal exited before providing status; check its output.')
                self._busy_buttons()
        except Exception as exc:
            # A disappearing/partial progress file must not crash the GUI.
            self.footer_status.set(f'Local status unavailable ({type(exc).__name__}); see terminal.')
        self.root.after(850, self.refresh)


def main():
    try:
        import tkinter as tk
    except ImportError as exc:
        raise SystemExit('Tkinter unavailable. Use python run_optimal.py --auto --profile turbo --no-scrapoxy --no-vpngate') from exc
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()


if __name__ == '__main__':
    main()
