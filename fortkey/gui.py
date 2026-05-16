"""
Tkinter front-end: vault dashboard, generator, breach checks, settings, backups.

Security notes:
- Passwords live in memory only while unlocked; Treeview shows masked values.
- Clipboard clears on a timer after copying secrets (see `_schedule_clipboard_clear`).
- Auto-lock arms on activity; when it fires, the derived key is dropped until you re-enter the master password.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

import auth
import database as db
from breach_checker import analyze_password
from encryption import decrypt_backup_blob, decrypt_entry_payload, encrypt_backup_blob, encrypt_entry_payload
from password_generator import GeneratorOptions, generate_password, password_strength
from utils import APP_NAME, clear_clipboard


class Theme:
    def __init__(self, dark: bool) -> None:
        self.dark = dark
        if dark:
            self.bg = "#1e1e2e"
            self.fg = "#e8e8ef"
            self.accent = "#7aa2f7"
            self.card = "#242436"
            self.muted = "#a9b1d6"
            self.danger = "#f7768e"
            self.ok = "#9ece6a"
        else:
            self.bg = "#f6f7fb"
            self.fg = "#1a1b26"
            self.accent = "#2563eb"
            self.card = "#ffffff"
            self.muted = "#4b5563"
            self.danger = "#dc2626"
            self.ok = "#16a34a"


class FortKeyApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.minsize(980, 620)
        self.session: auth.Session | None = None
        self._clipboard_after: str | None = None
        self._lock_after: str | None = None
        self._locked_overlay: tk.Toplevel | None = None
        self.settings: dict[str, Any] = {"dark_mode": True, "auto_lock_minutes": 5}
        self.theme = Theme(self.settings["dark_mode"])
        self._entries_cache: list[dict[str, Any]] = []
        self._build_shell()
        self._show_auth_frame()

    # --- lifecycle ---
    def _build_shell(self) -> None:
        self._apply_theme()
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.container = ttk.Frame(self, padding=12)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.columnconfigure(0, weight=1)
        self.container.rowconfigure(0, weight=1)

    def _apply_theme(self) -> None:
        t = self.theme
        self.configure(bg=t.bg)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=t.bg, foreground=t.fg, fieldbackground=t.card)
        style.configure("TFrame", background=t.bg)
        style.configure("Card.TFrame", background=t.card)
        style.configure("TLabel", background=t.bg, foreground=t.fg)
        style.configure("TLabelframe", background=t.bg, foreground=t.fg)
        style.configure("TLabelframe.Label", background=t.bg, foreground=t.fg)
        style.configure("TButton", padding=6)
        style.configure("Accent.TButton", foreground=t.fg)
        style.map("TEntry", fieldbackground=[("readonly", t.card)])

    def _clear_container(self) -> None:
        for child in self.container.winfo_children():
            child.destroy()

    def _show_auth_frame(self) -> None:
        self._cancel_lock_timer()
        self.session = None
        self._clear_container()
        frame = ttk.Frame(self.container)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        title = ttk.Label(frame, text=APP_NAME, font=("Segoe UI", 22, "bold"))
        title.grid(row=0, column=0, pady=(40, 8))
        subtitle = ttk.Label(
            frame,
            text="Local-first vault. Master password is never stored in plaintext.",
            font=("Segoe UI", 10),
            foreground=self.theme.muted,
        )
        subtitle.grid(row=1, column=0, pady=(0, 24))
        card = ttk.Frame(frame, style="Card.TFrame", padding=20)
        card.grid(row=2, column=0, sticky="ew", padx=80)
        card.columnconfigure(0, weight=1)

        first = auth.is_first_run()
        if first:
            ttk.Label(card, text="Create your master password").grid(row=0, column=0, sticky="w")
            pw1 = ttk.Entry(card, show="*")
            pw1.grid(row=1, column=0, sticky="ew", pady=(6, 10))
            ttk.Label(card, text="Confirm master password").grid(row=2, column=0, sticky="w")
            pw2 = ttk.Entry(card, show="*")
            pw2.grid(row=3, column=0, sticky="ew", pady=(6, 10))

            def do_setup() -> None:
                a, b = pw1.get(), pw2.get()
                if len(a) < 10:
                    messagebox.showerror("Weak master password", "Use at least 10 characters.")
                    return
                if a != b:
                    messagebox.showerror("Mismatch", "Passwords do not match.")
                    return
                try:
                    self.session = auth.setup_master_password(a)
                    self._load_settings_from_db()
                    self._show_vault()
                except Exception as exc:  # noqa: BLE001
                    messagebox.showerror("Setup failed", str(exc))

            ttk.Button(card, text="Create vault", command=do_setup).grid(row=4, column=0, pady=(8, 0))
        else:
            ttk.Label(card, text="Master password").grid(row=0, column=0, sticky="w")
            pw = ttk.Entry(card, show="*")
            pw.grid(row=1, column=0, sticky="ew", pady=(6, 10))
            pw.bind("<Return>", lambda _e: do_login())

            def do_login() -> None:
                s = auth.unlock(pw.get())
                if s is None:
                    messagebox.showerror("Unlock failed", "Incorrect master password.")
                    return
                self.session = s
                self._load_settings_from_db()
                self._show_vault()

            ttk.Button(card, text="Unlock", command=do_login).grid(row=2, column=0, pady=(8, 0))

    def _load_settings_from_db(self) -> None:
        assert self.session is not None
        merged = db.load_settings(self.session.user_id)
        self.settings.update(merged)
        self.theme = Theme(bool(self.settings.get("dark_mode", True)))
        self._apply_theme()

    def _save_settings_to_db(self) -> None:
        if self.session:
            db.save_settings(self.session.user_id, self.settings)

    def _show_vault(self) -> None:
        assert self.session is not None
        self._clear_container()
        self._build_menu()
        outer = ttk.Frame(self.container)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        top = ttk.Frame(outer, padding=(0, 0, 0, 10))
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Vault", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())
        search = ttk.Entry(top, textvariable=self.search_var)
        search.grid(row=0, column=1, sticky="ew", padx=(16, 16))
        ttk.Label(top, text="Category").grid(row=0, column=2, sticky="e")
        self.filter_cat = tk.StringVar(value="All")
        cats = ["All"] + [n for _i, n in db.list_categories(self.session.user_id)]
        self.cat_combo = ttk.Combobox(top, textvariable=self.filter_cat, values=cats, state="readonly", width=18)
        self.cat_combo.grid(row=0, column=3, sticky="e")
        self.cat_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_table())

        table_frame = ttk.Frame(outer, style="Card.TFrame", padding=8)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("website", "username", "category", "updated", "password")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=18)
        headings = {
            "website": "Website / App",
            "username": "Username",
            "category": "Category",
            "updated": "Updated",
            "password": "Password",
        }
        widths = {"website": 220, "username": 200, "category": 120, "updated": 140, "password": 160}
        for c in columns:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        actions = ttk.Frame(outer, padding=(0, 10, 0, 0))
        actions.grid(row=2, column=0, sticky="ew")
        for i in range(8):
            actions.columnconfigure(i, weight=1)
        ttk.Button(actions, text="Add entry", command=self._dialog_add_entry).grid(row=0, column=0, padx=4)
        ttk.Button(actions, text="Edit entry", command=self._edit_selected).grid(row=0, column=1, padx=4)
        ttk.Button(actions, text="Delete entry", command=self._delete_selected).grid(row=0, column=2, padx=4)
        ttk.Button(actions, text="Copy username", command=self._copy_username).grid(row=0, column=3, padx=4)
        ttk.Button(actions, text="Copy password", command=self._copy_password).grid(row=0, column=4, padx=4)
        ttk.Button(actions, text="Reveal password…", command=self._reveal_password).grid(row=0, column=5, padx=4)
        ttk.Button(actions, text="Generator", command=self._open_generator).grid(row=0, column=6, padx=4)
        ttk.Button(actions, text="Breach check", command=self._open_breach).grid(row=0, column=7, padx=4)

        self._bind_activity()
        self._schedule_lock_timer()
        self._refresh_table()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_m = tk.Menu(menubar, tearoff=0)
        file_m.add_command(label="Lock vault", command=self._logout)
        file_m.add_separator()
        file_m.add_command(label="Export encrypted backup…", command=self._export_backup)
        file_m.add_command(label="Import encrypted backup…", command=self._import_backup)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="Vault", menu=file_m)

        tools_m = tk.Menu(menubar, tearoff=0)
        tools_m.add_command(label="Password generator", command=self._open_generator)
        tools_m.add_command(label="Offline breach checker", command=self._open_breach)
        menubar.add_cascade(label="Tools", menu=tools_m)

        settings_m = tk.Menu(menubar, tearoff=0)
        settings_m.add_command(label="Preferences…", command=self._open_settings)
        menubar.add_cascade(label="Settings", menu=settings_m)

        help_m = tk.Menu(menubar, tearoff=0)
        help_m.add_command(
            label="Security notes",
            command=lambda: messagebox.showinfo(
                "Security",
                "Passwords are encrypted with Fernet (AES + HMAC).\n"
                "Master password is verified via an encrypted challenge, not stored.\n"
                "Clipboard clears automatically after copying secrets.",
            ),
        )
        menubar.add_cascade(label="Help", menu=help_m)
        self.config(menu=menubar)

    # --- data ---
    def _decrypt_entries(self) -> list[dict[str, Any]]:
        assert self.session is not None
        rows = db.list_entries_for_user(self.session.user_id)
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                payload = decrypt_entry_payload(self.session.cipher, r["payload_enc"])
            except Exception:
                continue
            out.append(
                {
                    "id": r["id"],
                    "website": payload.get("website", ""),
                    "username": payload.get("username", ""),
                    "password": payload.get("password", ""),
                    "notes": payload.get("notes", ""),
                    "category_id": r["category_id"],
                    "category_name": r["category_name"] or "",
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return out

    def _refresh_table(self) -> None:
        assert self.session is not None
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._entries_cache = self._decrypt_entries()
        q = self.search_var.get().lower().strip()
        cat = self.filter_cat.get()
        for e in self._entries_cache:
            if cat != "All" and (e["category_name"] or "") != cat:
                continue
            if q and q not in (e["website"] + e["username"] + e["notes"]).lower():
                continue
            self.tree.insert(
                "",
                "end",
                iid=str(e["id"]),
                values=(
                    e["website"],
                    e["username"],
                    e["category_name"],
                    e["updated_at"],
                    "••••••••",
                ),
            )

    def _selected_entry(self) -> dict[str, Any] | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select an entry", "Choose a row first.")
            return None
        eid = int(sel[0])
        for e in self._entries_cache:
            if e["id"] == eid:
                return e
        return None

    def _copy_text(self, text: str, secret: bool = False) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        if secret:
            self._schedule_clipboard_clear()
        messagebox.showinfo("Clipboard", "Copied.")

    def _schedule_clipboard_clear(self) -> None:
        if self._clipboard_after:
            self.after_cancel(self._clipboard_after)
        self._clipboard_after = self.after(30_000, self._clear_secret_clipboard)

    def _clear_secret_clipboard(self) -> None:
        clear_clipboard()
        self._clipboard_after = None

    # --- actions ---
    def _copy_username(self) -> None:
        e = self._selected_entry()
        if e:
            self._copy_text(e["username"], secret=False)

    def _copy_password(self) -> None:
        e = self._selected_entry()
        if e:
            self._copy_text(e["password"], secret=True)

    def _reveal_password(self) -> None:
        e = self._selected_entry()
        if not e:
            return
        if not messagebox.askyesno(
            "Reveal password",
            "Anyone shoulder-surfing could read this value.\nReveal now?",
        ):
            return
        messagebox.showinfo("Password", e["password"])

    def _delete_selected(self) -> None:
        e = self._selected_entry()
        if not e:
            return
        if not messagebox.askyesno("Delete", "Permanently delete this entry?"):
            return
        assert self.session is not None
        db.delete_entry(self.session.user_id, e["id"])
        db.append_audit(self.session.user_id, "entry_deleted", str(e["id"]))
        self._refresh_table()

    def _edit_selected(self) -> None:
        e = self._selected_entry()
        if e:
            self._dialog_entry_editor(e)

    def _dialog_add_entry(self) -> None:
        self._dialog_entry_editor(None)

    def _dialog_entry_editor(self, existing: dict[str, Any] | None) -> None:
        assert self.session is not None
        win = tk.Toplevel(self)
        win.title("Edit entry" if existing else "New entry")
        win.transient(self)
        win.grab_set()
        frm = ttk.Frame(win, padding=12)
        frm.grid(sticky="nsew")
        fields: dict[str, tk.Variable] = {}
        row = 0

        def add_row(label: str, key: str, show: str | None = None) -> ttk.Entry:
            nonlocal row
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w")
            var = tk.StringVar(value=existing.get(key, "") if existing else "")
            ent = ttk.Entry(frm, textvariable=var, width=48, show=show)
            ent.grid(row=row, column=1, pady=4, sticky="ew")
            fields[key] = var
            row += 1
            return ent

        add_row("Website / app", "website")
        add_row("Username / email", "username")
        add_row("Password", "password", show="*")
        add_row("Notes", "notes")
        if existing:
            ttk.Label(frm, text=f"Created: {existing.get('created_at', '')}").grid(
                row=row, column=1, sticky="w", pady=(0, 2)
            )
            row += 1
            ttk.Label(frm, text=f"Updated: {existing.get('updated_at', '')}").grid(
                row=row, column=1, sticky="w", pady=(0, 6)
            )
            row += 1

        ttk.Label(frm, text="Category").grid(row=row, column=0, sticky="w")
        cat_names = [n for _i, n in db.list_categories(self.session.user_id)]
        cat_var = tk.StringVar(value=(existing or {}).get("category_name") or (cat_names[0] if cat_names else "General"))
        cat_combo = ttk.Combobox(frm, textvariable=cat_var, values=cat_names, state="readonly")
        cat_combo.grid(row=row, column=1, sticky="ew", pady=4)
        row += 1

        gen_opts = GeneratorOptions()

        def autogen() -> None:
            fields["password"].set(generate_password(gen_opts))

        ttk.Button(frm, text="Generate password", command=autogen).grid(row=row, column=1, sticky="e")
        row += 1

        def save() -> None:
            website = fields["website"].get().strip()
            username = fields["username"].get().strip()
            password = fields["password"].get()
            notes = fields["notes"].get()
            if not website:
                messagebox.showerror("Validation", "Website is required.")
                return
            cat_name = cat_var.get().strip()
            cat_id = None
            for cid, name in db.list_categories(self.session.user_id):
                if name == cat_name:
                    cat_id = cid
                    break
            if cat_id is None:
                cat_id = db.add_category(self.session.user_id, cat_name or "General")
            payload = {"website": website, "username": username, "password": password, "notes": notes}
            blob = encrypt_entry_payload(self.session.cipher, payload)
            if existing:
                db.update_entry(self.session.user_id, int(existing["id"]), cat_id, blob)
                db.append_audit(self.session.user_id, "entry_updated", str(existing["id"]))
            else:
                new_id = db.insert_entry(self.session.user_id, cat_id, blob)
                db.append_audit(self.session.user_id, "entry_created", str(new_id))
            self._refresh_filter_values()
            self._refresh_table()
            win.destroy()

        ttk.Button(frm, text="Save", command=save).grid(row=row, column=1, sticky="e", pady=(10, 0))
        frm.columnconfigure(1, weight=1)

    def _refresh_filter_values(self) -> None:
        assert self.session is not None
        cats = ["All"] + [n for _i, n in db.list_categories(self.session.user_id)]
        self.cat_combo.configure(values=cats)

    def _open_generator(self) -> None:
        win = tk.Toplevel(self)
        win.title("Password generator")
        win.transient(self)
        frm = ttk.Frame(win, padding=12)
        frm.grid(sticky="nsew")
        opts = GeneratorOptions()
        length_var = tk.IntVar(value=opts.length)
        vars_map = {
            "use_upper": tk.BooleanVar(value=True),
            "use_lower": tk.BooleanVar(value=True),
            "use_digits": tk.BooleanVar(value=True),
            "use_symbols": tk.BooleanVar(value=True),
            "exclude_confusing": tk.BooleanVar(value=True),
        }

        def read_opts() -> GeneratorOptions:
            return GeneratorOptions(
                length=int(length_var.get()),
                use_upper=vars_map["use_upper"].get(),
                use_lower=vars_map["use_lower"].get(),
                use_digits=vars_map["use_digits"].get(),
                use_symbols=vars_map["use_symbols"].get(),
                exclude_confusing=vars_map["exclude_confusing"].get(),
            )

        ttk.Label(frm, text="Length").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(frm, from_=8, to=64, textvariable=length_var, width=6).grid(row=0, column=1, sticky="w")
        r = 1
        for label, key in [
            ("Uppercase A–Z", "use_upper"),
            ("Lowercase a–z", "use_lower"),
            ("Digits 0–9", "use_digits"),
            ("Symbols", "use_symbols"),
            ("Exclude confusing (0/O/1/l…)", "exclude_confusing"),
        ]:
            ttk.Checkbutton(frm, text=label, variable=vars_map[key]).grid(row=r, column=0, columnspan=2, sticky="w")
            r += 1
        out_var = tk.StringVar()
        strength_var = tk.StringVar()

        def do_gen() -> None:
            o = read_opts()
            pwd = generate_password(o)
            out_var.set(pwd)
            strength_var.set(password_strength(pwd))

        ttk.Button(frm, text="Generate", command=do_gen).grid(row=r, column=0, pady=8, sticky="w")
        r += 1
        ttk.Label(frm, text="Output").grid(row=r, column=0, sticky="w")
        ttk.Entry(frm, textvariable=out_var, width=44).grid(row=r, column=1, sticky="ew")
        r += 1
        ttk.Label(frm, textvariable=strength_var, foreground=self.theme.accent).grid(row=r, column=1, sticky="w")
        r += 1

        def copy_out() -> None:
            if out_var.get():
                self._copy_text(out_var.get(), secret=True)

        ttk.Button(frm, text="Copy", command=copy_out).grid(row=r, column=1, sticky="e")

    def _open_breach(self) -> None:
        win = tk.Toplevel(self)
        win.title("Offline breach checker")
        win.transient(self)
        frm = ttk.Frame(win, padding=12)
        frm.grid(sticky="nsew")
        pwd_var = tk.StringVar()
        ttk.Label(frm, text="Password to evaluate").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=pwd_var, show="*", width=40).grid(row=1, column=0, sticky="ew", pady=6)
        result = tk.Text(frm, height=12, width=70, wrap="word")
        result.grid(row=2, column=0, pady=8)

        def run_check() -> None:
            assert self.session is not None
            all_pw = [e["password"] for e in self._decrypt_entries()]
            issues = analyze_password(pwd_var.get(), all_vault_passwords=all_pw)
            result.delete("1.0", "end")
            if not issues:
                result.insert("end", "No local rule violations detected.\n")
                result.insert("end", "This does not prove the password was never leaked online.\n")
            else:
                for line in issues:
                    result.insert("end", f"• {line}\n")

        ttk.Button(frm, text="Analyze", command=run_check).grid(row=3, column=0, sticky="e")

    def _open_settings(self) -> None:
        assert self.session is not None
        win = tk.Toplevel(self)
        win.title("Settings")
        win.transient(self)
        frm = ttk.Frame(win, padding=12)
        frm.grid(sticky="nsew")

        dark_var = tk.BooleanVar(value=bool(self.settings.get("dark_mode", True)))
        lock_var = tk.IntVar(value=int(self.settings.get("auto_lock_minutes", 5)))

        ttk.Checkbutton(frm, text="Dark mode", variable=dark_var).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text="Auto-lock after minutes of inactivity").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Spinbox(frm, from_=1, to=120, textvariable=lock_var, width=6).grid(row=2, column=0, sticky="w")

        ttk.Separator(frm).grid(row=3, column=0, sticky="ew", pady=12)
        ttk.Label(frm, text="Change master password", font=("Segoe UI", 11, "bold")).grid(row=4, column=0, sticky="w")
        old_pw = tk.StringVar()
        new_pw = tk.StringVar()
        ttk.Label(frm, text="Current master password").grid(row=5, column=0, sticky="w")
        ttk.Entry(frm, textvariable=old_pw, show="*", width=36).grid(row=6, column=0, sticky="ew", pady=4)
        ttk.Label(frm, text="New master password").grid(row=7, column=0, sticky="w")
        ttk.Entry(frm, textvariable=new_pw, show="*", width=36).grid(row=8, column=0, sticky="ew", pady=4)

        def apply_change_master() -> None:
            if len(new_pw.get()) < 10:
                messagebox.showerror("Policy", "New master password must be at least 10 characters.")
                return
            ok = auth.change_master_password(self.session, old_pw.get(), new_pw.get())  # type: ignore[arg-type]
            if not ok:
                messagebox.showerror("Failed", "Current master password incorrect.")
                return
            messagebox.showinfo("Updated", "Master password and all entries re-encrypted.")
            win.destroy()

        ttk.Button(frm, text="Update master password", command=apply_change_master).grid(row=9, column=0, sticky="e", pady=8)

        ttk.Separator(frm).grid(row=10, column=0, sticky="ew", pady=12)
        ttk.Label(frm, text="Audit log (recent)", font=("Segoe UI", 11, "bold")).grid(row=11, column=0, sticky="w")
        log = tk.Text(frm, height=8, width=72, wrap="none")
        log.grid(row=12, column=0, pady=6)
        for ev, det, ts in db.list_audit(self.session.user_id, limit=50):
            log.insert("end", f"{ts}  {ev}  {det or ''}\n")

        ttk.Separator(frm).grid(row=13, column=0, sticky="ew", pady=12)
        ttk.Label(frm, text="Optional integrations (placeholders)", font=("Segoe UI", 11, "bold")).grid(
            row=14, column=0, sticky="w"
        )
        ttk.Label(
            frm,
            text="Biometric unlock: hook OS APIs here (Windows Hello / Touch ID). Not wired in this build.",
            wraplength=520,
            foreground=self.theme.muted,
        ).grid(row=15, column=0, sticky="w")
        ttk.Label(
            frm,
            text="Cloud backup structure (future): encrypted blob + remote object key in user_settings JSON.",
            wraplength=520,
            foreground=self.theme.muted,
        ).grid(row=16, column=0, sticky="w")

        def save_prefs() -> None:
            self.settings["dark_mode"] = bool(dark_var.get())
            self.settings["auto_lock_minutes"] = int(lock_var.get())
            self.theme = Theme(self.settings["dark_mode"])
            self._apply_theme()
            self._save_settings_to_db()
            messagebox.showinfo("Saved", "Preferences saved.")
            win.destroy()

        ttk.Button(frm, text="Save preferences", command=save_prefs).grid(row=17, column=0, sticky="e", pady=10)

    def _export_backup(self) -> None:
        assert self.session is not None
        export_pw = simpledialog.askstring(
            "Export password",
            "Choose a strong export passphrase (different from your master password is recommended):",
            show="*",
            parent=self,
        )
        if not export_pw:
            return
        entries = self._decrypt_entries()
        inner = {
            "version": 1,
            "entries": [
                {
                    "category": e["category_name"] or "General",
                    "payload": {
                        "website": e["website"],
                        "username": e["username"],
                        "password": e["password"],
                        "notes": e["notes"],
                    },
                    "created_at": e["created_at"],
                    "updated_at": e["updated_at"],
                }
                for e in entries
            ],
            "settings": self.settings,
        }
        data = encrypt_backup_blob(export_pw, inner)
        path = filedialog.asksaveasfilename(
            defaultextension=".svv",
            filetypes=[("FortKey backup", "*.svv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "wb") as f:
            f.write(data)
        db.append_audit(self.session.user_id, "backup_exported", path)
        messagebox.showinfo("Export", "Encrypted backup written.")

    def _import_backup(self) -> None:
        assert self.session is not None
        path = filedialog.askopenfilename(filetypes=[("FortKey backup", "*.svv"), ("All files", "*.*")])
        if not path:
            return
        export_pw = simpledialog.askstring("Import", "Export passphrase:", show="*", parent=self)
        if not export_pw:
            return
        try:
            raw = open(path, "rb").read()
            inner = decrypt_backup_blob(export_pw, raw)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Import failed", str(exc))
            return
        added = 0
        for item in inner.get("entries", []):
            cat_name = (item.get("category") or "General").strip()
            cat_id = None
            for cid, name in db.list_categories(self.session.user_id):
                if name == cat_name:
                    cat_id = cid
                    break
            if cat_id is None:
                cat_id = db.add_category(self.session.user_id, cat_name)
            p = item.get("payload", {})
            blob = encrypt_entry_payload(
                self.session.cipher,
                {
                    "website": p.get("website", ""),
                    "username": p.get("username", ""),
                    "password": p.get("password", ""),
                    "notes": p.get("notes", ""),
                },
            )
            db.insert_entry(self.session.user_id, cat_id, blob)
            added += 1
        db.append_audit(self.session.user_id, "backup_imported", f"{path} ({added} entries)")
        self._refresh_filter_values()
        self._refresh_table()
        messagebox.showinfo("Import", f"Imported {added} entries.")

    # --- lock / activity ---
    def _bind_activity(self) -> None:
        def ping(_event=None) -> None:
            self._schedule_lock_timer()

        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(seq, ping, add="+")

    def _schedule_lock_timer(self) -> None:
        if self.session is None:
            return
        if self._locked_overlay is not None and self._locked_overlay.winfo_exists():
            return
        if self._lock_after:
            self.after_cancel(self._lock_after)
            self._lock_after = None
        minutes = int(self.settings.get("auto_lock_minutes", 5))
        ms = max(1, minutes) * 60 * 1000
        self._lock_after = self.after(ms, self._idle_lock_overlay)

    def _cancel_lock_timer(self) -> None:
        if self._lock_after:
            self.after_cancel(self._lock_after)
            self._lock_after = None

    def _idle_lock_overlay(self) -> None:
        """Drop derived keys from memory and require the master password again."""
        if self.session is None:
            return
        if self._locked_overlay is not None and self._locked_overlay.winfo_exists():
            return
        user_id = self.session.user_id
        self.session = None
        self._entries_cache.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._cancel_lock_timer()
        overlay = tk.Toplevel(self)
        overlay.title("Locked")
        overlay.transient(self)
        overlay.attributes("-topmost", True)
        overlay.grab_set()
        frm = ttk.Frame(overlay, padding=20)
        frm.pack()
        ttk.Label(frm, text="Vault locked due to inactivity.").pack()
        pw = ttk.Entry(frm, show="*")
        pw.pack(pady=8, fill="x")
        db.append_audit(user_id, "auto_lock", None)

        def unlock() -> None:
            s = auth.unlock(pw.get())
            if s is None or s.user_id != user_id:
                messagebox.showerror("Unlock failed", "Incorrect master password.")
                return
            self.session = s
            overlay.destroy()
            self._locked_overlay = None
            self._refresh_table()
            self._schedule_lock_timer()

        ttk.Button(frm, text="Unlock", command=unlock).pack()
        self._locked_overlay = overlay

    def _logout(self) -> None:
        """User chose Lock from menu: return to login."""
        if self.session:
            db.append_audit(self.session.user_id, "manual_lock", None)
        self._cancel_lock_timer()
        if self._locked_overlay is not None and self._locked_overlay.winfo_exists():
            self._locked_overlay.destroy()
        self._locked_overlay = None
        self._show_auth_frame()
