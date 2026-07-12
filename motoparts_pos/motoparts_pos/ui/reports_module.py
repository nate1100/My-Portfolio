import os
import datetime
import customtkinter as ctk
from tkinter import filedialog
from ui import widgets
from core import export_utils

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")


class ReportsModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        os.makedirs(EXPORTS_DIR, exist_ok=True)
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Reports & Analytics", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkLabel(toolbar, text="Period:").pack(side="left", padx=(0, 6))
        self.period_menu = ctk.CTkOptionMenu(toolbar, values=["Daily", "Weekly", "Monthly", "Yearly",
                                                                "Custom Range"],
                                              command=lambda v: self._on_period_change())
        self.period_menu.pack(side="left")

        self.date_from_entry = ctk.CTkEntry(toolbar, placeholder_text="YYYY-MM-DD", width=110)
        self.date_to_entry = ctk.CTkEntry(toolbar, placeholder_text="YYYY-MM-DD", width=110)
        self.date_from_entry.pack(side="left", padx=(12, 4))
        ctk.CTkLabel(toolbar, text="to").pack(side="left")
        self.date_to_entry.pack(side="left", padx=4)
        self.date_from_entry.configure(state="disabled")
        self.date_to_entry.configure(state="disabled")

        ctk.CTkButton(toolbar, text="Generate", command=self.refresh).pack(side="left", padx=10)

        export_btns = ctk.CTkFrame(toolbar, fg_color="transparent")
        export_btns.pack(side="right")
        ctk.CTkButton(export_btns, text="Export CSV", width=100, command=lambda: self.export("csv")).pack(side="left", padx=3)
        ctk.CTkButton(export_btns, text="Export Excel", width=100, command=lambda: self.export("xlsx")).pack(side="left", padx=3)
        ctk.CTkButton(export_btns, text="Export PDF", width=100, command=lambda: self.export("pdf")).pack(side="left", padx=3)

        # summary cards
        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.pack(fill="x", padx=20, pady=10)
        for i in range(4):
            self.cards_frame.grid_columnconfigure(i, weight=1)
        self.card_revenue = widgets.StatCard(self.cards_frame, "Total Revenue", "PHP 0.00", accent=widgets.SUCCESS)
        self.card_transactions = widgets.StatCard(self.cards_frame, "Transactions", "0", accent=widgets.PRIMARY)
        self.card_discounts = widgets.StatCard(self.cards_frame, "Total Discounts", "PHP 0.00", accent=widgets.WARNING)
        self.card_tax = widgets.StatCard(self.cards_frame, "Total Tax Collected", "PHP 0.00", accent="#8957E5")
        self.card_revenue.grid(row=0, column=0, padx=8, pady=4, sticky="ew")
        self.card_transactions.grid(row=0, column=1, padx=8, pady=4, sticky="ew")
        self.card_discounts.grid(row=0, column=2, padx=8, pady=4, sticky="ew")
        self.card_tax.grid(row=0, column=3, padx=8, pady=4, sticky="ew")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        daily_panel = ctk.CTkFrame(body, corner_radius=12, fg_color=("gray92", "gray15"))
        daily_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(daily_panel, text="Sales by Day", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.daily_table = widgets.Table(daily_panel, columns=("Date", "Transactions", "Revenue"),
                                          widths=(120, 100, 120), height=12)
        self.daily_table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        top_panel = ctk.CTkFrame(body, corner_radius=12, fg_color=("gray92", "gray15"))
        top_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(top_panel, text="Top Selling Products", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.top_table = widgets.Table(top_panel, columns=("Product", "Qty Sold", "Revenue"),
                                        widths=(180, 90, 110), height=12)
        self.top_table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def _on_period_change(self):
        custom = self.period_menu.get() == "Custom Range"
        state = "normal" if custom else "disabled"
        self.date_from_entry.configure(state=state)
        self.date_to_entry.configure(state=state)
        self.refresh()

    def _get_range(self):
        today = datetime.date.today()
        period = self.period_menu.get()
        if period == "Daily":
            return today, today
        if period == "Weekly":
            start = today - datetime.timedelta(days=today.weekday())
            return start, today
        if period == "Monthly":
            return today.replace(day=1), today
        if period == "Yearly":
            return today.replace(month=1, day=1), today
        # Custom range
        try:
            start = datetime.date.fromisoformat(self.date_from_entry.get().strip())
        except ValueError:
            start = today
        try:
            end = datetime.date.fromisoformat(self.date_to_entry.get().strip())
        except ValueError:
            end = today
        return start, end

    def refresh(self):
        date_from, date_to = self._get_range()
        currency = self.db.get_setting("currency_symbol", "PHP ")
        summary = self.db.sales_summary(date_from.isoformat(), date_to.isoformat())
        self.card_revenue.set_value(f"{currency}{summary['revenue']:.2f}")
        self.card_transactions.set_value(str(summary["n"]))
        self.card_discounts.set_value(f"{currency}{summary['discounts']:.2f}")
        self.card_tax.set_value(f"{currency}{summary['tax']:.2f}")

        self._daily_rows = self.db.sales_by_day(date_from.isoformat(), date_to.isoformat())
        rows = [(d["d"], d["n"], f"{currency}{d['revenue']:.2f}") for d in self._daily_rows]
        self.daily_table.set_rows(rows)

        self._top_rows = self.db.top_selling_products(date_from.isoformat(), date_to.isoformat(), limit=20)
        rows = [(t["product_name"], t["qty"], f"{currency}{t['revenue']:.2f}") for t in self._top_rows]
        self.top_table.set_rows(rows)

        self._current_range = (date_from, date_to)

    def export(self, fmt):
        date_from, date_to = getattr(self, "_current_range", self._get_range())
        headers = ["Date", "Transactions", "Revenue"]
        rows = [[d["d"], d["n"], round(d["revenue"], 2)] for d in self._daily_rows]
        default_name = f"sales_report_{date_from}_{date_to}.{fmt}"

        path = filedialog.asksaveasfilename(
            initialdir=EXPORTS_DIR, initialfile=default_name,
            defaultextension=f".{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not path:
            return
        try:
            if fmt == "csv":
                export_utils.export_to_csv(path, headers, rows)
            elif fmt == "xlsx":
                export_utils.export_to_excel(path, headers, rows, title="Sales Report")
            elif fmt == "pdf":
                export_utils.export_to_pdf(path, "Sales Report", headers, rows,
                                            subtitle=f"Period: {date_from} to {date_to}")
            widgets.info(self, "Export Complete", f"Report exported to:\n{path}")
        except Exception as e:
            widgets.error(self, "Export Failed", str(e))
