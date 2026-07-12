import datetime
import customtkinter as ctk
from ui import widgets
from core import print_utils


class SalesModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Sales History", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))
        self.search_bar = widgets.SearchBar(toolbar, placeholder="Search invoice # or customer...",
                                             on_search=self.refresh)
        self.search_bar.pack(side="left")

        self.range_menu = ctk.CTkOptionMenu(toolbar, values=["All Time", "Today", "This Week",
                                                               "This Month", "This Year"],
                                             command=lambda v: self.refresh())
        self.range_menu.pack(side="left", padx=8)

        btns = ctk.CTkFrame(toolbar, fg_color="transparent")
        btns.pack(side="right")
        ctk.CTkButton(btns, text="View Invoice", command=self.view_invoice).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Reprint", fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self.reprint_invoice).pack(side="left", padx=4)

        table_frame = ctk.CTkFrame(self, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        columns = ("Invoice #", "Date", "Customer", "Cashier", "Payment", "Total", "Status")
        widths = (150, 150, 150, 130, 90, 90, 90)
        self.table = widgets.Table(table_frame, columns=columns, widths=widths,
                                    on_double_click=lambda i: self.view_invoice(), height=18)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)
        self._sale_ids = []

    def _date_range(self):
        today = datetime.date.today()
        choice = self.range_menu.get()
        if choice == "Today":
            return today.isoformat(), today.isoformat()
        if choice == "This Week":
            start = today - datetime.timedelta(days=today.weekday())
            return start.isoformat(), today.isoformat()
        if choice == "This Month":
            start = today.replace(day=1)
            return start.isoformat(), today.isoformat()
        if choice == "This Year":
            start = today.replace(month=1, day=1)
            return start.isoformat(), today.isoformat()
        return None, None

    def refresh(self, *_):
        date_from, date_to = self._date_range()
        search = self.search_bar.get()
        user_id = None
        if self.app.current_user["role"] == "cashier":
            user_id = self.app.current_user["id"]
        sales = self.db.list_sales(date_from=date_from, date_to=date_to, search=search, user_id=user_id)
        currency = self.db.get_setting("currency_symbol", "PHP ")
        rows, ids = [], []
        for s in sales:
            rows.append((s["invoice_number"], s["created_at"], s["customer_name"] or "Walk-in",
                        s["cashier_name"], s["payment_method"], f"{currency}{s['total']:.2f}", s["status"]))
            ids.append(s["id"])
        self.table.set_rows(rows, row_ids=ids)

    def _get_selected_id(self):
        iid = self.table.get_selected()
        return int(iid) if iid else None

    def view_invoice(self):
        sid = self._get_selected_id()
        if not sid:
            widgets.warn(self, "No Selection", "Please select a sale to view.")
            return
        sale = self.db.get_sale(sid)
        items = self.db.get_sale_items(sid)
        currency = self.db.get_setting("currency_symbol", "PHP ")

        dlg = ctk.CTkToplevel(self)
        dlg.title(f"Invoice {sale['invoice_number']}")
        dlg.geometry("480x560")
        dlg.grab_set()

        ctk.CTkLabel(dlg, text=f"Invoice {sale['invoice_number']}", font=("Segoe UI", 18, "bold")).pack(pady=(16, 4))
        ctk.CTkLabel(dlg, text=sale["created_at"], text_color=widgets.MUTED).pack()
        info = ctk.CTkFrame(dlg, fg_color="transparent")
        info.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(info, text=f"Customer: {sale['customer_name'] or 'Walk-in'}", anchor="w").pack(fill="x")
        ctk.CTkLabel(info, text=f"Cashier: {sale['cashier_name']}", anchor="w").pack(fill="x")
        ctk.CTkLabel(info, text=f"Payment Method: {sale['payment_method']}", anchor="w").pack(fill="x")

        table_frame = ctk.CTkFrame(dlg, fg_color=("gray92", "gray15"), corner_radius=10)
        table_frame.pack(fill="both", expand=True, padx=20, pady=8)
        item_table = widgets.Table(table_frame, columns=("Item", "Qty", "Price", "Total"),
                                    widths=(180, 40, 70, 80), height=8)
        item_table.pack(fill="both", expand=True, padx=8, pady=8)
        rows = [(it["product_name"], it["quantity"], f"{currency}{it['unit_price']:.2f}",
                f"{currency}{it['line_total']:.2f}") for it in items]
        item_table.set_rows(rows)

        totals = ctk.CTkFrame(dlg, fg_color="transparent")
        totals.pack(fill="x", padx=20, pady=(0, 10))
        for label, value in [
            ("Subtotal", sale["subtotal"]), ("Discount", -sale["discount_amount"]),
            (f"Tax ({sale['tax_rate']}%)", sale["tax_amount"]), ("TOTAL", sale["total"]),
            ("Amount Paid", sale["amount_paid"]), ("Change", sale["change_due"]),
        ]:
            row = ctk.CTkFrame(totals, fg_color="transparent")
            row.pack(fill="x")
            bold = label == "TOTAL"
            ctk.CTkLabel(row, text=f"{label}:", font=("Segoe UI", 13, "bold" if bold else "normal")).pack(side="left")
            ctk.CTkLabel(row, text=f"{currency}{value:.2f}",
                         font=("Segoe UI", 13, "bold" if bold else "normal")).pack(side="right")

        ctk.CTkButton(dlg, text="Reprint / Print PDF", command=lambda: self._print(sid)).pack(pady=(0, 16))

    def reprint_invoice(self):
        sid = self._get_selected_id()
        if not sid:
            widgets.warn(self, "No Selection", "Please select a sale to reprint.")
            return
        self._print(sid)

    def _print(self, sale_id):
        sale = self.db.get_sale(sale_id)
        items = self.db.get_sale_items(sale_id)
        store_info = self.db.get_all_settings()
        currency = store_info.get("currency_symbol", "PHP ")
        try:
            path, kind = print_utils.generate_and_get_invoice_file(store_info, sale, items, currency)
            ok, msg = print_utils.print_file(path)
            widgets.info(self, "Print", msg)
        except Exception as e:
            widgets.error(self, "Print Error", f"Could not print invoice.\n{e}")
