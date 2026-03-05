import os
import json
import base64
import secrets
import string
import getpass
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path
import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ──────────────────────────────────────────────
#  Encryption helpers
# ──────────────────────────────────────────────

DATA_FILE = Path.home() / ".pm_vault.json"
SALT_FILE = Path.home() / ".pm_salt.bin"


def _load_salt():
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt


def _derive_key(master: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_load_salt(),
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))


def _get_fernet(master: str) -> Fernet:
    return Fernet(_derive_key(master))


def load_vault(master: str):
    f = _get_fernet(master)
    if not DATA_FILE.exists():
        return f, {}
    try:
        raw = DATA_FILE.read_bytes()
        return f, json.loads(f.decrypt(raw))
    except (InvalidToken, Exception):
        return None, None


def save_vault(vault: dict, f: Fernet):
    DATA_FILE.write_bytes(f.encrypt(json.dumps(vault).encode()))


def generate_password(length=18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*()-_=+" for c in pwd)):
            return pwd


# ──────────────────────────────────────────────
#  Login window
# ──────────────────────────────────────────────

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.resizable(False, False)
        self.configure(bg="#0f1117")
        self._center(400, 480)

        self.vault = None
        self.fernet = None

        self._build_ui()

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        # ── logo area ──
        logo_frame = tk.Frame(self, bg="#0f1117")
        logo_frame.pack(pady=(50, 10))

        tk.Label(logo_frame, text="🔐", font=("Segoe UI Emoji", 52),
                 bg="#0f1117").pack()
        tk.Label(logo_frame, text="Password Manager",
                 font=("Georgia", 22, "bold"),
                 fg="#e8d5b7", bg="#0f1117").pack()
        tk.Label(logo_frame, text="Your vault, your rules.",
                 font=("Georgia", 11, "italic"),
                 fg="#7a6a55", bg="#0f1117").pack(pady=(4, 0))

        # ── card ──
        card = tk.Frame(self, bg="#1a1d27", bd=0, relief="flat")
        card.pack(padx=40, pady=30, fill="x")

        tk.Label(card, text="Master Password",
                 font=("Consolas", 10), fg="#7a6a55",
                 bg="#1a1d27").pack(anchor="w", padx=24, pady=(20, 4))

        self.pw_var = tk.StringVar()
        pw_entry = tk.Entry(card, textvariable=self.pw_var, show="●",
                            font=("Consolas", 13), bg="#252836",
                            fg="#e8d5b7", insertbackground="#e8d5b7",
                            relief="flat", bd=0)
        pw_entry.pack(fill="x", padx=24, ipady=10)
        pw_entry.bind("<Return>", lambda e: self._login())

        tk.Frame(card, bg="#2e3148", height=1).pack(fill="x", padx=24)

        btn = tk.Button(card, text="Unlock Vault",
                        font=("Georgia", 12, "bold"),
                        bg="#c9a96e", fg="#0f1117",
                        activebackground="#e8c87a", activeforeground="#0f1117",
                        relief="flat", bd=0, cursor="hand2",
                        command=self._login)
        btn.pack(fill="x", padx=24, pady=20, ipady=10)

        self.status = tk.Label(self, text="", font=("Consolas", 10),
                               fg="#c0392b", bg="#0f1117")
        self.status.pack()

    def _login(self):
        master = self.pw_var.get()
        if not master:
            self.status.config(text="Enter your master password.")
            return
        self.status.config(text="Unlocking…", fg="#7a6a55")
        self.update()
        f, vault = load_vault(master)
        if vault is None:
            self.status.config(text="Wrong password or corrupted vault.", fg="#c0392b")
            return
        self.fernet = f
        self.vault = vault
        self.destroy()


# ──────────────────────────────────────────────
#  Main application
# ──────────────────────────────────────────────

class App(tk.Tk):
    COLS = ("Site", "Username", "Password")

    def __init__(self, vault: dict, fernet: Fernet):
        super().__init__()
        self.vault = vault
        self.fernet = fernet

        self.title("Password Manager")
        self.configure(bg="#0f1117")
        self.minsize(860, 560)
        self._center(960, 620)

        self._build_styles()
        self._build_ui()
        self._populate_table()

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── styles ──────────────────────────────────
    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("Treeview",
                        background="#1a1d27",
                        foreground="#e8d5b7",
                        rowheight=34,
                        fieldbackground="#1a1d27",
                        borderwidth=0,
                        font=("Consolas", 11))
        style.configure("Treeview.Heading",
                        background="#252836",
                        foreground="#c9a96e",
                        relief="flat",
                        font=("Georgia", 11, "bold"))
        style.map("Treeview",
                  background=[("selected", "#2e3148")],
                  foreground=[("selected", "#e8d5b7")])
        style.configure("Vertical.TScrollbar",
                        background="#252836", troughcolor="#1a1d27",
                        arrowcolor="#c9a96e", bordercolor="#1a1d27")

    # ── layout ──────────────────────────────────
    def _build_ui(self):
        # top bar
        topbar = tk.Frame(self, bg="#0f1117")
        topbar.pack(fill="x", padx=20, pady=(16, 4))

        tk.Label(topbar, text="🔐  Password Manager",
                 font=("Georgia", 18, "bold"),
                 fg="#e8d5b7", bg="#0f1117").pack(side="left")

        # search
        search_frame = tk.Frame(topbar, bg="#252836")
        search_frame.pack(side="right")
        tk.Label(search_frame, text="🔍", bg="#252836",
                 fg="#7a6a55", font=("Segoe UI Emoji", 11)).pack(side="left", padx=(8, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *_: self._populate_table())
        tk.Entry(search_frame, textvariable=self.search_var,
                 font=("Consolas", 11), bg="#252836",
                 fg="#e8d5b7", insertbackground="#e8d5b7",
                 relief="flat", bd=0, width=22).pack(side="left", ipady=6, padx=(0, 8))

        tk.Frame(self, bg="#2e3148", height=1).pack(fill="x", padx=20)

        # table
        table_frame = tk.Frame(self, bg="#0f1117")
        table_frame.pack(fill="both", expand=True, padx=20, pady=12)

        self.tree = ttk.Treeview(table_frame, columns=self.COLS,
                                 show="headings", selectmode="browse")
        for col in self.COLS:
            self.tree.heading(col, text=col)
        self.tree.column("Site",     width=220, anchor="w")
        self.tree.column("Username", width=240, anchor="w")
        self.tree.column("Password", width=300, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<Double-1>", lambda e: self._copy_password())

        # action buttons
        btn_frame = tk.Frame(self, bg="#0f1117")
        btn_frame.pack(fill="x", padx=20, pady=(0, 18))

        actions = [
            ("＋  Add",      "#c9a96e", "#0f1117", self._open_add),
            ("✎  Edit",      "#2e3148", "#e8d5b7", self._open_edit),
            ("⧉  Copy PW",   "#2e3148", "#e8d5b7", self._copy_password),
            ("⚙  Generate",  "#2e3148", "#e8d5b7", self._open_generate),
            ("✕  Delete",    "#3d1a1a", "#e07070", self._delete_entry),
        ]
        for label, bg, fg, cmd in actions:
            tk.Button(btn_frame, text=label,
                      font=("Georgia", 11),
                      bg=bg, fg=fg,
                      activebackground="#3a3d52", activeforeground="#e8d5b7",
                      relief="flat", bd=0, cursor="hand2",
                      command=cmd).pack(side="left", padx=(0, 8), ipady=8, ipadx=14)

        self.status_bar = tk.Label(self, text="",
                                   font=("Consolas", 10),
                                   fg="#7a6a55", bg="#0f1117", anchor="w")
        self.status_bar.pack(fill="x", padx=22, pady=(0, 8))

    # ── table helpers ────────────────────────────
    def _populate_table(self):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for site, data in sorted(self.vault.items()):
            if query and query not in site.lower() and query not in data["username"].lower():
                continue
            masked = "●" * len(data["password"])
            self.tree.insert("", "end", iid=site,
                             values=(site, data["username"], masked))

    def _selected_site(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _flash(self, msg, color="#c9a96e"):
        self.status_bar.config(text=msg, fg=color)
        self.after(3000, lambda: self.status_bar.config(text=""))

    # ── actions ─────────────────────────────────
    def _copy_password(self):
        site = self._selected_site()
        if not site:
            messagebox.showinfo("No selection", "Select an entry first.")
            return
        pyperclip.copy(self.vault[site]["password"])
        self._flash(f"Password for '{site}' copied to clipboard ✓")

    def _delete_entry(self):
        site = self._selected_site()
        if not site:
            messagebox.showinfo("No selection", "Select an entry first.")
            return
        if messagebox.askyesno("Delete", f"Delete entry for '{site}'?"):
            del self.vault[site]
            save_vault(self.vault, self.fernet)
            self._populate_table()
            self._flash(f"'{site}' deleted.", "#e07070")

    def _open_add(self):
        EntryDialog(self, title="Add Entry")

    def _open_edit(self):
        site = self._selected_site()
        if not site:
            messagebox.showinfo("No selection", "Select an entry first.")
            return
        EntryDialog(self, title="Edit Entry", site=site)

    def _open_generate(self):
        GenerateDialog(self)


# ──────────────────────────────────────────────
#  Add / Edit dialog
# ──────────────────────────────────────────────

class EntryDialog(tk.Toplevel):
    def __init__(self, app: App, title="Entry", site=None):
        super().__init__(app)
        self.app = app
        self.editing = site
        self.title(title)
        self.configure(bg="#0f1117")
        self.resizable(False, False)
        self._center(440, 400)
        self.grab_set()
        self._build(site)

    def _center(self, w, h):
        self.update_idletasks()
        px = self.master.winfo_x() + (self.master.winfo_width()  - w) // 2
        py = self.master.winfo_y() + (self.master.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

    def _field(self, parent, label, show=None):
        tk.Label(parent, text=label, font=("Consolas", 10),
                 fg="#7a6a55", bg="#1a1d27").pack(anchor="w", padx=24, pady=(14, 2))
        var = tk.StringVar()
        kw = dict(textvariable=var, font=("Consolas", 12),
                  bg="#252836", fg="#e8d5b7", insertbackground="#e8d5b7",
                  relief="flat", bd=0)
        if show:
            kw["show"] = show
        tk.Entry(parent, **kw).pack(fill="x", padx=24, ipady=8)
        tk.Frame(parent, bg="#2e3148", height=1).pack(fill="x", padx=24)
        return var

    def _build(self, site):
        card = tk.Frame(self, bg="#1a1d27")
        card.pack(fill="both", expand=True, padx=16, pady=16)

        self.site_var = self._field(card, "Site / App")
        self.user_var = self._field(card, "Username / Email")
        self.pw_var   = self._field(card, "Password", show="●")

        if site:
            data = self.app.vault[site]
            self.site_var.set(site)
            self.user_var.set(data["username"])
            self.pw_var.set(data["password"])

        # generate button
        gen_row = tk.Frame(card, bg="#1a1d27")
        gen_row.pack(fill="x", padx=24, pady=(10, 0))
        tk.Button(gen_row, text="⚙ Generate strong password",
                  font=("Consolas", 10), bg="#2e3148", fg="#c9a96e",
                  activebackground="#3a3d52", relief="flat", bd=0,
                  cursor="hand2",
                  command=self._gen).pack(side="left")

        # save
        tk.Button(card, text="Save Entry",
                  font=("Georgia", 12, "bold"),
                  bg="#c9a96e", fg="#0f1117",
                  activebackground="#e8c87a", relief="flat", bd=0,
                  cursor="hand2", command=self._save
                  ).pack(fill="x", padx=24, pady=20, ipady=10)

    def _gen(self):
        self.pw_var.set(generate_password(18))

    def _save(self):
        site = self.site_var.get().strip()
        user = self.user_var.get().strip()
        pw   = self.pw_var.get()

        if not site or not user or not pw:
            messagebox.showwarning("Missing fields", "All fields are required.", parent=self)
            return

        if self.editing and self.editing != site and self.editing in self.app.vault:
            del self.app.vault[self.editing]

        self.app.vault[site] = {"username": user, "password": pw}
        save_vault(self.app.vault, self.app.fernet)
        self.app._populate_table()
        self.app._flash(f"'{site}' saved ✓")
        self.destroy()


# ──────────────────────────────────────────────
#  Password generator dialog
# ──────────────────────────────────────────────

class GenerateDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.title("Generate Password")
        self.configure(bg="#0f1117")
        self.resizable(False, False)
        self._center(420, 280)
        self.grab_set()
        self._build()

    def _center(self, w, h):
        self.update_idletasks()
        px = self.master.winfo_x() + (self.master.winfo_width()  - w) // 2
        py = self.master.winfo_y() + (self.master.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

    def _build(self):
        card = tk.Frame(self, bg="#1a1d27")
        card.pack(fill="both", expand=True, padx=16, pady=16)

        tk.Label(card, text="Password Length",
                 font=("Consolas", 10), fg="#7a6a55",
                 bg="#1a1d27").pack(anchor="w", padx=24, pady=(16, 4))

        self.length_var = tk.IntVar(value=18)
        row = tk.Frame(card, bg="#1a1d27")
        row.pack(fill="x", padx=24)
        tk.Scale(row, from_=8, to=40, orient="horizontal",
                 variable=self.length_var,
                 bg="#1a1d27", fg="#e8d5b7", troughcolor="#252836",
                 highlightthickness=0, bd=0,
                 command=lambda _: self._refresh()).pack(side="left", fill="x", expand=True)
        self.len_lbl = tk.Label(row, text="18", width=3,
                                font=("Consolas", 12, "bold"),
                                fg="#c9a96e", bg="#1a1d27")
        self.len_lbl.pack(side="left", padx=8)

        self.pw_var = tk.StringVar(value=generate_password(18))
        pw_entry = tk.Entry(card, textvariable=self.pw_var,
                            font=("Consolas", 13), bg="#252836",
                            fg="#e8d5b7", relief="flat", bd=0,
                            state="readonly", readonlybackground="#252836")
        pw_entry.pack(fill="x", padx=24, pady=(16, 0), ipady=10)

        btn_row = tk.Frame(card, bg="#1a1d27")
        btn_row.pack(fill="x", padx=24, pady=16)

        tk.Button(btn_row, text="↺  Regenerate",
                  font=("Consolas", 11), bg="#2e3148", fg="#e8d5b7",
                  activebackground="#3a3d52", relief="flat", bd=0,
                  cursor="hand2", command=self._refresh
                  ).pack(side="left", ipady=8, ipadx=12)

        tk.Button(btn_row, text="⧉  Copy",
                  font=("Georgia", 11, "bold"), bg="#c9a96e", fg="#0f1117",
                  activebackground="#e8c87a", relief="flat", bd=0,
                  cursor="hand2", command=self._copy
                  ).pack(side="right", ipady=8, ipadx=16)

    def _refresh(self):
        length = self.length_var.get()
        self.len_lbl.config(text=str(length))
        self.pw_var.set(generate_password(length))

    def _copy(self):
        pyperclip.copy(self.pw_var.get())
        self.app._flash("Generated password copied to clipboard ✓")
        self.destroy()


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def main():
    login = LoginWindow()
    login.mainloop()

    if login.vault is None:
        return   # user closed without logging in

    app = App(login.vault, login.fernet)
    app.mainloop()


if __name__ == "__main__":
    main()