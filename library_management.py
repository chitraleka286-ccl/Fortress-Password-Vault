import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import ttkbootstrap as tbs
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledFrame
import json, os, time, threading, random, string, math, base64, hashlib, secrets
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip

# ─── Constants ────────────────────────────────────────────────────────────────
APP_TITLE   = "FORTRESS — Password Vault"
VAULT_FILE  = os.path.join(os.path.expanduser("~"), ".fortress_vault.enc")
LOCK_AFTER  = 300          # seconds of inactivity → auto-lock
CLIP_CLEAR  = 30           # seconds before clipboard wipe
PBKDF2_ITER = 480_000      # OWASP 2024 recommendation

CATEGORIES = ["🌐 Web", "📧 Email", "💳 Finance", "🏢 Work",
              "🎮 Gaming", "🛒 Shopping", "🔒 SSH/Keys", "📱 Mobile", "⚙️ Other"]

PALETTES = {
    "dark":  {"bg": "#0d1117", "panel": "#161b22", "card": "#21262d",
              "border": "#30363d", "accent": "#58a6ff", "accent2": "#3fb950",
              "warn": "#d29922", "danger": "#f85149", "text": "#e6edf3",
              "subtext": "#8b949e", "input": "#0d1117"},
    "light": {"bg": "#f0f2f5", "panel": "#ffffff", "card": "#f6f8fa",
              "border": "#d0d7de", "accent": "#0969da", "accent2": "#1a7f37",
              "warn": "#9a6700", "danger": "#d1242f", "text": "#1f2328",
              "subtext": "#656d76", "input": "#ffffff"},
}

# ─── Crypto Layer ─────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITER)
    return kdf.derive(password.encode())

def encrypt_vault(data: dict, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    return nonce + ct

def decrypt_vault(raw: bytes, key: bytes) -> dict:
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return json.loads(aesgcm.decrypt(nonce, ct, None))

# ─── Password Utilities ───────────────────────────────────────────────────────
def generate_password(length=16, upper=True, lower=True, digits=True,
                      symbols=True, ambiguous=False, custom_chars="") -> str:
    pool = custom_chars
    if not pool:
        if lower:   pool += string.ascii_lowercase
        if upper:   pool += string.ascii_uppercase
        if digits:  pool += string.digits
        if symbols: pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if not ambiguous:
        pool = pool.translate(str.maketrans('', '', 'Il1O0'))
    if not pool:
        pool = string.ascii_letters + string.digits
    return ''.join(secrets.choice(pool) for _ in range(length))

def password_entropy(pwd: str) -> float:
    pool = 0
    if any(c in string.ascii_lowercase for c in pwd): pool += 26
    if any(c in string.ascii_uppercase for c in pwd): pool += 26
    if any(c in string.digits for c in pwd):          pool += 10
    if any(c in string.punctuation for c in pwd):     pool += 32
    pool = max(pool, len(set(pwd)))
    return len(pwd) * math.log2(pool) if pool > 0 else 0

def strength_label(entropy: float):
    if entropy < 28:  return "Very Weak",  "#f85149", 0.15
    if entropy < 36:  return "Weak",        "#ffa657", 0.35
    if entropy < 60:  return "Fair",        "#d29922", 0.55
    if entropy < 80:  return "Strong",      "#3fb950", 0.78
    return               "Very Strong", "#58a6ff", 1.0

def password_age_days(created_iso: str) -> int:
    try:
        dt = datetime.fromisoformat(created_iso)
        return (datetime.now() - dt).days
    except Exception:
        return 0

# ─── Tooltip Helper ───────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x, y = self.widget.winfo_rootx() + 20, self.widget.winfo_rooty() + 28
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, background="#21262d",
                       foreground="#e6edf3", relief="solid", borderwidth=1,
                       font=("Consolas", 9), padx=8, pady=4)
        lbl.pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None

# ─── Main Application ─────────────────────────────────────────────────────────
class FortressApp:
    def __init__(self):
        self.root = tbs.Window(themename="darkly")
        self.root.title(APP_TITLE)
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)

        self.theme_name = "dark"
        self.C = PALETTES["dark"]

        self.vault_key   = None
        self.vault_salt  = None
        self.vault_data  = {"entries": [], "settings": {}}
        self.last_active = time.time()
        self.locked      = True
        self.clip_timer  = None
        self.lock_timer  = None
        self.search_var  = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_vault())
        self.selected_id = None
        self.sort_col    = "site"
        self.sort_rev    = False

        self._build_ui()
        self._show_login()
        self._start_lock_watch()
        self.root.mainloop()

    # ── Activity tracker ──────────────────────────────────────────────────────
    def _touch(self, _=None):
        self.last_active = time.time()

    def _start_lock_watch(self):
        def _watch():
            while True:
                time.sleep(10)
                if not self.locked and (time.time() - self.last_active > LOCK_AFTER):
                    self.root.after(0, self._auto_lock)
        t = threading.Thread(target=_watch, daemon=True)
        t.start()
        self.root.bind_all("<Any-KeyPress>", self._touch)
        self.root.bind_all("<Any-Button>",   self._touch)

    def _auto_lock(self):
        messagebox.showinfo("Auto-Locked", "Fortress locked due to inactivity.")
        self._do_lock()

    # ── Build UI skeleton ─────────────────────────────────────────────────────
    def _build_ui(self):
        C = self.C
        self.root.configure(bg=C["bg"])

        # ── Top bar ──────────────────────────────────────────────────────────
        self.topbar = tk.Frame(self.root, bg=C["panel"], height=56)
        self.topbar.pack(fill=X, side=TOP)
        self.topbar.pack_propagate(False)

        logo_lbl = tk.Label(self.topbar, text="🔐 FORTRESS",
                            font=("Courier New", 17, "bold"),
                            bg=C["panel"], fg=C["accent"])
        logo_lbl.pack(side=LEFT, padx=20)

        sub = tk.Label(self.topbar, text="Password Vault  •  Professional Edition",
                       font=("Consolas", 9), bg=C["panel"], fg=C["subtext"])
        sub.pack(side=LEFT, padx=0, pady=18)

        # right buttons
        self.btn_lock   = self._topbtn("🔒 Lock",      self._do_lock)
        self.btn_theme  = self._topbtn("🌙 Theme",     self._toggle_theme)
        self.btn_export = self._topbtn("📤 Export",    self._export_vault)
        self.btn_import = self._topbtn("📥 Import",    self._import_vault)
        self.btn_gen    = self._topbtn("⚡ Generator",  self._open_generator)

        # separator
        sep = tk.Frame(self.root, bg=C["border"], height=1)
        sep.pack(fill=X)

        # ── Main content ──────────────────────────────────────────────────────
        self.content = tk.Frame(self.root, bg=C["bg"])
        self.content.pack(fill=BOTH, expand=True)

        self._build_sidebar()
        self._build_vault_panel()
        self._build_detail_panel()

    def _topbtn(self, text, cmd):
        C = self.C
        btn = tk.Button(self.topbar, text=text, command=cmd,
                        bg=C["card"], fg=C["text"], relief="flat",
                        font=("Consolas", 9, "bold"), cursor="hand2",
                        padx=12, pady=6, bd=0,
                        activebackground=C["accent"], activeforeground="#fff")
        btn.pack(side=RIGHT, padx=6, pady=10)
        return btn

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        C = self.C
        self.sidebar = tk.Frame(self.content, bg=C["panel"], width=200)
        self.sidebar.pack(side=LEFT, fill=Y)
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="CATEGORIES", font=("Consolas", 8, "bold"),
                 bg=C["panel"], fg=C["subtext"]).pack(anchor=W, padx=14, pady=(16,4))

        self.cat_var = tk.StringVar(value="All")
        cats = ["All"] + CATEGORIES
        self.cat_buttons = []
        for cat in cats:
            btn = tk.Button(self.sidebar, text=cat, anchor=W,
                            font=("Consolas", 10), relief="flat", bd=0,
                            bg=C["panel"], fg=C["text"], cursor="hand2",
                            padx=14, pady=5,
                            command=lambda c=cat: self._filter_cat(c))
            btn.pack(fill=X)
            self.cat_buttons.append(btn)

        # stats
        sep = tk.Frame(self.sidebar, bg=C["border"], height=1)
        sep.pack(fill=X, pady=12)
        self.stat_lbl = tk.Label(self.sidebar, text="", font=("Consolas", 8),
                                 bg=C["panel"], fg=C["subtext"], justify=LEFT)
        self.stat_lbl.pack(anchor=W, padx=14)

    def _filter_cat(self, cat):
        self.cat_var.set(cat)
        self.refresh_vault()
        C = self.C
        for btn in self.cat_buttons:
            chosen = btn.cget("text") == cat
            btn.config(bg=C["accent"] if chosen else C["panel"],
                       fg="#fff" if chosen else C["text"])

    # ── Vault panel ───────────────────────────────────────────────────────────
    def _build_vault_panel(self):
        C = self.C
        mid = tk.Frame(self.content, bg=C["bg"])
        mid.pack(side=LEFT, fill=BOTH, expand=True)

        # search bar
        sbar = tk.Frame(mid, bg=C["bg"])
        sbar.pack(fill=X, padx=14, pady=10)

        tk.Label(sbar, text="🔍", bg=C["bg"], fg=C["subtext"],
                 font=("Segoe UI Emoji", 12)).pack(side=LEFT, padx=(0,4))
        self.search_entry = tk.Entry(sbar, textvariable=self.search_var,
                                     bg=C["card"], fg=C["text"], relief="flat",
                                     font=("Consolas", 11), insertbackground=C["accent"],
                                     bd=0)
        self.search_entry.pack(side=LEFT, fill=X, expand=True, ipady=7, ipadx=8)
        self.search_entry.insert(0, "Search vault…")
        self.search_entry.bind("<FocusIn>",  lambda e: self._clr_ph(e))
        self.search_entry.bind("<FocusOut>", lambda e: self._add_ph(e))

        add_btn = tk.Button(sbar, text="+ Add Entry", command=self._add_entry,
                            bg=C["accent"], fg="#fff", relief="flat",
                            font=("Consolas", 9, "bold"), cursor="hand2",
                            padx=14, pady=6)
        add_btn.pack(side=RIGHT, padx=(8,0))

        # column headers
        hdr = tk.Frame(mid, bg=C["panel"])
        hdr.pack(fill=X, padx=14)
        for col, lbl, w in [("site","SITE/SERVICE",200), ("username","USERNAME",160),
                              ("category","CATEGORY",110), ("strength","STRENGTH",90),
                              ("updated","UPDATED",100)]:
            b = tk.Button(hdr, text=lbl, font=("Consolas", 8, "bold"),
                          bg=C["panel"], fg=C["subtext"], relief="flat",
                          anchor=W, width=w//8, cursor="hand2",
                          command=lambda c=col: self._sort_by(c))
            b.pack(side=LEFT, padx=4, pady=6)

        # scrolled list
        self.vault_scroll = ScrolledFrame(mid, autohide=True)
        self.vault_scroll.pack(fill=BOTH, expand=True, padx=14, pady=(0,10))
        self.vault_list_frame = self.vault_scroll

    def _clr_ph(self, e):
        if self.search_entry.get() == "Search vault…":
            self.search_entry.delete(0, END)
            self.search_entry.config(fg=self.C["text"])

    def _add_ph(self, e):
        if not self.search_entry.get():
            self.search_entry.insert(0, "Search vault…")
            self.search_entry.config(fg=self.C["subtext"])

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col = col
            self.sort_rev = False
        self.refresh_vault()

    # ── Detail panel ──────────────────────────────────────────────────────────
    def _build_detail_panel(self):
        C = self.C
        self.detail = tk.Frame(self.content, bg=C["panel"], width=340)
        self.detail.pack(side=RIGHT, fill=Y)
        self.detail.pack_propagate(False)

        sep = tk.Frame(self.detail, bg=C["border"], width=1)
        sep.place(x=0, y=0, relheight=1)

        self.detail_inner = tk.Frame(self.detail, bg=C["panel"])
        self.detail_inner.pack(fill=BOTH, expand=True, padx=20, pady=20)
        self._show_empty_detail()

    def _show_empty_detail(self):
        for w in self.detail_inner.winfo_children():
            w.destroy()
        C = self.C
        tk.Label(self.detail_inner, text="🔐", font=("Segoe UI Emoji", 48),
                 bg=C["panel"], fg=C["border"]).pack(pady=(80,10))
        tk.Label(self.detail_inner, text="Select an entry\nto view details",
                 font=("Consolas", 12), bg=C["panel"], fg=C["subtext"],
                 justify=CENTER).pack()

    # ── Login / Master Password ───────────────────────────────────────────────
    def _show_login(self):
        self.locked = True
        self.login_win = tk.Toplevel(self.root)
        self.login_win.title("FORTRESS — Unlock")
        self.login_win.geometry("420x520")
        self.login_win.resizable(False, False)
        self.login_win.grab_set()
        self.login_win.protocol("WM_DELETE_WINDOW", self.root.destroy)
        C = self.C
        self.login_win.configure(bg=C["bg"])

        is_new = not os.path.exists(VAULT_FILE)

        tk.Label(self.login_win, text="🔐", font=("Segoe UI Emoji", 56),
                 bg=C["bg"]).pack(pady=(40,0))
        tk.Label(self.login_win, text="FORTRESS",
                 font=("Courier New", 24, "bold"), bg=C["bg"], fg=C["accent"]).pack()
        tk.Label(self.login_win, text="Password Vault",
                 font=("Consolas", 11), bg=C["bg"], fg=C["subtext"]).pack(pady=(0,30))

        if is_new:
            tk.Label(self.login_win, text="Create Master Password",
                     font=("Consolas", 10, "bold"), bg=C["bg"], fg=C["text"]).pack()
        else:
            tk.Label(self.login_win, text="Enter Master Password",
                     font=("Consolas", 10, "bold"), bg=C["bg"], fg=C["text"]).pack()

        self.mp_var  = tk.StringVar()
        self.mp2_var = tk.StringVar()

        mp_frame = tk.Frame(self.login_win, bg=C["bg"])
        mp_frame.pack(pady=8, padx=40, fill=X)
        self.mp_entry = tk.Entry(mp_frame, textvariable=self.mp_var, show="●",
                                 bg=C["card"], fg=C["text"], relief="flat",
                                 font=("Consolas", 13), insertbackground=C["accent"],
                                 bd=0)
        self.mp_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, ipadx=10)
        show_btn = tk.Button(mp_frame, text="👁", bg=C["card"], fg=C["subtext"],
                             relief="flat", bd=0, cursor="hand2",
                             command=lambda: self._toggle_show(self.mp_entry))
        show_btn.pack(side=RIGHT)

        if is_new:
            tk.Label(self.login_win, text="Confirm Password",
                     font=("Consolas", 9), bg=C["bg"], fg=C["subtext"]).pack(pady=(6,0))
            mp2_frame = tk.Frame(self.login_win, bg=C["bg"])
            mp2_frame.pack(pady=4, padx=40, fill=X)
            self.mp2_entry = tk.Entry(mp2_frame, textvariable=self.mp2_var, show="●",
                                      bg=C["card"], fg=C["text"], relief="flat",
                                      font=("Consolas", 13), insertbackground=C["accent"],
                                      bd=0)
            self.mp2_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, ipadx=10)

        # strength bar for master pwd
        self.mp_strength_bar = tk.Canvas(self.login_win, height=6, bg=C["card"],
                                          highlightthickness=0)
        self.mp_strength_bar.pack(fill=X, padx=40, pady=4)
        self.mp_var.trace_add("write", self._update_mp_strength)

        self.mp_lbl = tk.Label(self.login_win, text="", font=("Consolas", 9),
                                bg=C["bg"], fg=C["subtext"])
        self.mp_lbl.pack()

        action = "Create Vault" if is_new else "Unlock Vault"
        cmd    = self._create_vault if is_new else self._unlock_vault
        unlock_btn = tk.Button(self.login_win, text=action, command=cmd,
                               bg=C["accent"], fg="#fff", relief="flat",
                               font=("Consolas", 12, "bold"), cursor="hand2",
                               padx=20, pady=10)
        unlock_btn.pack(pady=20)
        self.mp_entry.bind("<Return>", lambda e: cmd())
        self.mp_entry.focus_set()

    def _update_mp_strength(self, *_):
        pwd = self.mp_var.get()
        if not pwd:
            self.mp_strength_bar.delete("all")
            self.mp_lbl.config(text="")
            return
        ent = password_entropy(pwd)
        lbl, color, ratio = strength_label(ent)
        w = self.mp_strength_bar.winfo_width() or 300
        self.mp_strength_bar.delete("all")
        self.mp_strength_bar.create_rectangle(0, 0, w, 6, fill=self.C["card"], outline="")
        self.mp_strength_bar.create_rectangle(0, 0, int(w*ratio), 6, fill=color, outline="")
        self.mp_lbl.config(text=f"{lbl}  •  {ent:.0f} bits", fg=color)

    def _toggle_show(self, entry):
        entry.config(show="" if entry.cget("show") == "●" else "●")

    def _create_vault(self):
        pwd  = self.mp_var.get()
        pwd2 = self.mp2_var.get()
        if len(pwd) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters.")
            return
        if pwd != pwd2:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        self.vault_salt = os.urandom(32)
        self.vault_key  = derive_key(pwd, self.vault_salt)
        self.vault_data = {"entries": [], "settings": {"created": datetime.now().isoformat()}}
        self._save_vault()
        self.login_win.destroy()
        self.locked = False
        self.refresh_vault()
        self._show_welcome()

    def _unlock_vault(self):
        pwd = self.mp_var.get()
        try:
            with open(VAULT_FILE, "rb") as f:
                raw = f.read()
            salt = raw[:32]
            key  = derive_key(pwd, salt)
            self.vault_data = decrypt_vault(raw[32:], key)
            self.vault_key  = key
            self.vault_salt = salt
            self.login_win.destroy()
            self.locked = False
            self.refresh_vault()
        except Exception:
            messagebox.showerror("Error", "Wrong master password or corrupted vault.")

    def _save_vault(self):
        if self.vault_key is None: return
        enc = encrypt_vault(self.vault_data, self.vault_key)
        with open(VAULT_FILE, "wb") as f:
            f.write(self.vault_salt + enc)

    def _do_lock(self):
        self.vault_key  = None
        self.vault_salt = None
        self.locked 
