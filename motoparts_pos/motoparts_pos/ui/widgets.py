"""
Reusable CustomTkinter widgets shared across every module:
 - StatCard: dashboard KPI card
 - Table: a themed ttk.Treeview with scrollbar, sorting, and row selection
 - SearchBar: search entry + button
 - FormDialog: generic modal add/edit form built from a field spec list
 - ConfirmDialog: Yes/No confirmation modal
 - toast helpers wrapping tkinter.messagebox
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk

PRIMARY = "#1F6FEB"
PRIMARY_DARK = "#164B9E"
SUCCESS = "#2EA043"
DANGER = "#DA3633"
WARNING = "#D29922"
MUTED = "#8B949E"
CARD_BG_LIGHT = "#FFFFFF"
CARD_BG_DARK = "#2B2B2B"


def style_treeview():
    """Configures a ttk theme so the Treeview matches CustomTkinter's look."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    mode = ctk.get_appearance_mode()
    if mode == "Dark":
        bg, fg, field_bg, sel = "#2B2B2B", "#E6E6E6", "#242424", PRIMARY
        heading_bg = "#333333"
    else:
        bg, fg, field_bg, sel = "#FFFFFF", "#1A1A1A", "#FFFFFF", PRIMARY
        heading_bg = "#EAEAEA"

    style.configure("Custom.Treeview",
                     background=field_bg, foreground=fg, fieldbackground=field_bg,
                     rowheight=28, borderwidth=0, font=("Segoe UI", 11))
    style.configure("Custom.Treeview.Heading",
                     background=heading_bg, foreground=fg, font=("Segoe UI", 11, "bold"),
                     relief="flat")
    style.map("Custom.Treeview", background=[("selected", sel)],
              foreground=[("selected", "#FFFFFF")])
    style.map("Custom.Treeview.Heading", background=[("active", heading_bg)])


class StatCard(ctk.CTkFrame):
    def __init__(self, parent, title, value="0", subtitle="", accent=PRIMARY, **kwargs):
        super().__init__(parent, corner_radius=12, fg_color=("gray90", "gray17"), **kwargs)
        self.accent_bar = ctk.CTkFrame(self, width=6, corner_radius=3, fg_color=accent)
        self.accent_bar.pack(side="left", fill="y", padx=(10, 0), pady=10)

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=12)

        self.title_label = ctk.CTkLabel(inner, text=title, font=("Segoe UI", 13),
                                         text_color=MUTED, anchor="w")
        self.title_label.pack(anchor="w")
        self.value_label = ctk.CTkLabel(inner, text=value, font=("Segoe UI", 24, "bold"), anchor="w")
        self.value_label.pack(anchor="w", pady=(2, 0))
        if subtitle:
            self.subtitle_label = ctk.CTkLabel(inner, text=subtitle, font=("Segoe UI", 11),
                                                text_color=MUTED, anchor="w")
            self.subtitle_label.pack(anchor="w")
        else:
            self.subtitle_label = None

    def set_value(self, value):
        self.value_label.configure(text=value)

    def set_subtitle(self, text):
        if self.subtitle_label:
            self.subtitle_label.configure(text=text)


class Table(ctk.CTkFrame):
    """A themed, sortable Treeview table with a vertical scrollbar."""

    def __init__(self, parent, columns, widths=None, on_select=None, on_double_click=None, height=15, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        style_treeview()
        self.columns = columns
        self.on_select = on_select
        self.on_double_click = on_double_click
        self._sort_reverse = {}

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(container, columns=columns, show="headings",
                                  style="Custom.Treeview", height=height, selectmode="browse")
        for i, col in enumerate(columns):
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            width = widths[i] if widths and i < len(widths) else 120
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        if on_select:
            self.tree.bind("<<TreeviewSelect>>", lambda e: on_select(self.get_selected()))
        if on_double_click:
            self.tree.bind("<Double-1>", lambda e: on_double_click(self.get_selected()))

    def _sort_by(self, col):
        idx = self.columns.index(col)
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]

        def try_num(v):
            try:
                return float(str(v).replace(",", "").replace("PHP", "").strip())
            except ValueError:
                return str(v).lower()

        reverse = self._sort_reverse.get(col, False)
        data.sort(key=lambda t: try_num(t[0]), reverse=reverse)
        for i, (_, k) in enumerate(data):
            self.tree.move(k, "", i)
        self._sort_reverse[col] = not reverse

    def set_rows(self, rows, row_ids=None):
        """rows: list of tuples matching self.columns. row_ids: optional list of
        underlying record ids stored as the Treeview item iid (as string)."""
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(rows):
            iid = str(row_ids[i]) if row_ids else str(i)
            self.tree.insert("", "end", iid=iid, values=row)

    def get_selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return sel[0]

    def get_selected_values(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.item(sel[0], "values")

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def tag_row(self, iid, tag, background):
        self.tree.tag_configure(tag, background=background)
        self.tree.item(iid, tags=(tag,))
        
class SearchBar(ctk.CTkFrame):
    def __init__(self, parent, placeholder="Search...", on_search=None, width=200, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.on_search = on_search
        self.entry = ctk.CTkEntry(self, placeholder_text=placeholder, width=width)
        self.entry.pack(side="left", padx=(0, 6))
        self.entry.bind("<Return>", lambda e: self._fire())
        btn = ctk.CTkButton(self, text="Search", width=80, command=self._fire)
        btn.pack(side="left", padx=(0, 6))
        clear_btn = ctk.CTkButton(self, text="Clear", width=70, fg_color=MUTED,
                                   hover_color="#6e7681", command=self._clear)
        clear_btn.pack(side="left")

    def _fire(self):
        if self.on_search:
            self.on_search(self.entry.get().strip())

    def _clear(self):
        self.entry.delete(0, "end")
        if self.on_search:
            self.on_search("")

    def get(self):
        return self.entry.get().strip()


class ConfirmDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Confirm", message="Are you sure?", danger=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("380x160")
        self.resizable(False, False)
        self.grab_set()
        self.result = False

        ctk.CTkLabel(self, text=message, wraplength=340, font=("Segoe UI", 13),
                     justify="center").pack(expand=True, padx=20, pady=(24, 10))
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 16))
        ctk.CTkButton(btn_frame, text="Cancel", width=110, fg_color=MUTED,
                      hover_color="#6e7681", command=self._cancel).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Yes, Continue", width=140,
                      fg_color=DANGER if danger else SUCCESS,
                      hover_color="#a82b26" if danger else "#238636",
                      command=self._confirm).pack(side="left", padx=6)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _confirm(self):
        self.result = True
        self.destroy()

    def _cancel(self):
        self.result = False
        self.destroy()

    @staticmethod
    def ask(parent, title="Confirm", message="Are you sure?", danger=False):
        dlg = ConfirmDialog(parent, title, message, danger)
        parent.wait_window(dlg)
        return dlg.result


class FormDialog(ctk.CTkToplevel):
    """Generic modal form.

    fields: list of dicts, each with:
        key, label, type ('entry'|'number'|'password'|'combobox'|'textarea'),
        options (for combobox: list of (value, label) tuples),
        initial (default value), required (bool)
    """

    def __init__(self, parent, title, fields, submit_text="Save", width=460):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.grab_set()
        self.fields = fields
        self.result = None
        self._vars = {}
        self._widgets = {}

        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.pack(fill="both", expand=True, padx=20, pady=20)

        for f in fields:
            row = ctk.CTkFrame(wrapper, fg_color="transparent")
            row.pack(fill="x", pady=6)
            label_text = f["label"] + (" *" if f.get("required") else "")
            ctk.CTkLabel(row, text=label_text, width=150, anchor="w").pack(side="left")

            ftype = f.get("type", "entry")
            initial = f.get("initial", "")

            if ftype == "combobox":
                labels = [opt[1] for opt in f["options"]]
                var = tk.StringVar(value=initial if initial else (labels[0] if labels else ""))
                widget = ctk.CTkOptionMenu(row, values=labels or [""], variable=var, width=240)
                widget.pack(side="left", fill="x", expand=True)
                self._vars[f["key"]] = var
                self._widgets[f["key"]] = widget
            elif ftype == "textarea":
                widget = ctk.CTkTextbox(row, height=70, width=240)
                widget.pack(side="left", fill="x", expand=True)
                if initial:
                    widget.insert("1.0", str(initial))
                self._widgets[f["key"]] = widget
            else:
                show = "*" if ftype == "password" else None
                widget = ctk.CTkEntry(row, width=240, show=show)
                if initial not in (None, ""):
                    widget.insert(0, str(initial))
                widget.pack(side="left", fill="x", expand=True)
                self._widgets[f["key"]] = widget

        btn_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(16, 0))
        ctk.CTkButton(btn_frame, text="Cancel", width=110, fg_color=MUTED,
                      hover_color="#6e7681", command=self._cancel).pack(side="right", padx=(6, 0))
        ctk.CTkButton(btn_frame, text=submit_text, width=140,
                      command=self._submit).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _submit(self):
        values = {}
        for f in self.fields:
            key = f["key"]
            ftype = f.get("type", "entry")
            if ftype == "combobox":
                display_val = self._vars[key].get()
                match = next((opt[0] for opt in f["options"] if opt[1] == display_val), display_val)
                values[key] = match
            elif ftype == "textarea":
                values[key] = self._widgets[key].get("1.0", "end").strip()
            else:
                values[key] = self._widgets[key].get().strip()

            if f.get("required") and not values[key]:
                messagebox.showerror("Missing Information", f"'{f['label']}' is required.", parent=self)
                return
            if ftype == "number" and values[key]:
                try:
                    float(values[key])
                except ValueError:
                    messagebox.showerror("Invalid Value", f"'{f['label']}' must be a number.", parent=self)
                    return
        self.result = values
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

    @staticmethod
    def ask(parent, title, fields, submit_text="Save"):
        dlg = FormDialog(parent, title, fields, submit_text)
        parent.wait_window(dlg)
        return dlg.result


def info(parent, title, message):
    messagebox.showinfo(title, message, parent=parent)


def error(parent, title, message):
    messagebox.showerror(title, message, parent=parent)


def warn(parent, title, message):
    messagebox.showwarning(title, message, parent=parent)
