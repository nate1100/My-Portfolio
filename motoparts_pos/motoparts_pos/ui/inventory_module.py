import customtkinter as ctk
from ui import widgets


class InventoryModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Inventory Management", font=("Segoe UI", 22, "bold")).pack(side="left")

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.tabs.add("Stock Levels")
        self.tabs.add("Adjustment History")

        self._build_stock_tab(self.tabs.tab("Stock Levels"))
        self._build_history_tab(self.tabs.tab("Adjustment History"))

    def _build_stock_tab(self, tab):
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", pady=(10, 10))
        self.search_bar = widgets.SearchBar(toolbar, placeholder="Search product...",
                                             on_search=self.refresh)
        self.search_bar.pack(side="left")
        self.low_stock_only = ctk.CTkCheckBox(toolbar, text="Low stock only", command=self.refresh)
        self.low_stock_only.pack(side="left", padx=10)
        ctk.CTkButton(toolbar, text="Adjust Stock", command=self.adjust_stock).pack(side="right", padx=4)

        table_frame = ctk.CTkFrame(tab, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True)
        columns = ("SKU", "Product", "Category", "Current Qty", "Reorder Level", "Status")
        widths = (90, 220, 120, 90, 100, 100)
        self.stock_table = widgets.Table(table_frame, columns=columns, widths=widths, height=16)
        self.stock_table.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_history_tab(self, tab):
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", pady=(10, 10))
        self.hist_search = widgets.SearchBar(toolbar, placeholder="Search product...",
                                              on_search=self.refresh_history)
        self.hist_search.pack(side="left")

        table_frame = ctk.CTkFrame(tab, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True)
        columns = ("Date", "Product", "Type", "Qty", "Reason", "By")
        widths = (140, 200, 100, 60, 220, 130)
        self.history_table = widgets.Table(table_frame, columns=columns, widths=widths, height=16)
        self.history_table.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self, *_):
        search = self.search_bar.get()
        only_low = bool(self.low_stock_only.get())
        products = self.db.list_products(search=search, only_low_stock=only_low)
        rows, ids = [], []
        for p in products:
            status = "LOW STOCK" if p["quantity"] <= p["reorder_level"] else "OK"
            rows.append((p["sku"], p["name"], p["category_name"] or "-", p["quantity"],
                        p["reorder_level"], status))
            ids.append(p["id"])
        self.stock_table.set_rows(rows, row_ids=ids)
        self.refresh_history()

    def refresh_history(self, *_):
        search = self.hist_search.get() if hasattr(self, "hist_search") else ""
        adjustments = self.db.list_adjustments(search=search)
        rows = [(a["created_at"], a["product_name"], a["adj_type"], a["quantity"],
                 a["reason"] or "-", a["user_name"]) for a in adjustments]
        self.history_table.set_rows(rows)

    def adjust_stock(self):
        iid = self.stock_table.get_selected()
        if not iid:
            widgets.warn(self, "No Selection", "Please select a product from the Stock Levels tab.")
            return
        pid = int(iid)
        p = self.db.get_product(pid)
        fields = [
            {"key": "adj_type", "label": "Adjustment Type", "type": "combobox",
             "options": [("Stock In", "Stock In (add)"), ("Stock Out", "Stock Out (remove)"),
                         ("Correction", "Correction (set exact qty)"),
                         ("Damaged", "Damaged / Lost"), ("Returned", "Returned by customer")]},
            {"key": "quantity", "label": "Quantity", "type": "number", "required": True},
            {"key": "reason", "label": "Reason / Notes", "type": "textarea"},
        ]
        result = widgets.FormDialog.ask(self, f"Adjust Stock - {p['name']} (Current: {p['quantity']})",
                                         fields, submit_text="Apply Adjustment")
        if not result:
            return
        try:
            qty = int(float(result["quantity"]))
            if qty < 0:
                raise ValueError("Quantity cannot be negative.")
            self.db.add_inventory_adjustment(pid, self.app.current_user["id"],
                                              result["adj_type"], qty, result["reason"])
            widgets.info(self, "Success", "Stock adjusted successfully.")
        except Exception as e:
            widgets.error(self, "Error", f"Could not adjust stock.\n{e}")
        self.refresh()
