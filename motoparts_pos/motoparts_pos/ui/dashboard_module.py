import datetime
import customtkinter as ctk
from ui import widgets


class DashboardModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Dashboard", font=("Segoe UI", 22, "bold")).pack(side="left")
        ctk.CTkLabel(header, text=datetime.date.today().strftime("%A, %B %d, %Y"),
                     font=("Segoe UI", 13), text_color=widgets.MUTED).pack(side="right")

        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.pack(fill="x", padx=20, pady=10)
        for i in range(4):
            self.cards_frame.grid_columnconfigure(i, weight=1)

        self.card_sales_today = widgets.StatCard(self.cards_frame, "Today's Sales", "PHP 0.00",
                                                   accent=widgets.SUCCESS)
        self.card_transactions = widgets.StatCard(self.cards_frame, "Transactions Today", "0",
                                                    accent=widgets.PRIMARY)
        self.card_products = widgets.StatCard(self.cards_frame, "Active Products", "0",
                                               accent="#8957E5")
        self.card_low_stock = widgets.StatCard(self.cards_frame, "Low Stock Alerts", "0",
                                                accent=widgets.WARNING)

        self.card_sales_today.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        self.card_transactions.grid(row=0, column=1, padx=8, pady=8, sticky="ew")
        self.card_products.grid(row=0, column=2, padx=8, pady=8, sticky="ew")
        self.card_low_stock.grid(row=0, column=3, padx=8, pady=8, sticky="ew")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=10)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Low stock panel
        low_panel = ctk.CTkFrame(body, corner_radius=12, fg_color=("gray92", "gray15"))
        low_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(low_panel, text="\u26A0 Low Stock Products", font=("Segoe UI", 15, "bold"),
                     text_color=widgets.WARNING).pack(anchor="w", padx=14, pady=(12, 4))
        self.low_stock_table = widgets.Table(low_panel, columns=("Product", "SKU", "Qty", "Reorder"),
                                              widths=(160, 90, 60, 70), height=8)
        self.low_stock_table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Top products panel
        top_panel = ctk.CTkFrame(body, corner_radius=12, fg_color=("gray92", "gray15"))
        top_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(top_panel, text="\U0001F525 Top Selling Products (Last 30 Days)",
                     font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.top_products_table = widgets.Table(top_panel, columns=("Product", "Qty Sold", "Revenue"),
                                                  widths=(180, 80, 100), height=8)
        self.top_products_table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        refresh_btn = ctk.CTkButton(self, text="Refresh", width=100, command=self.refresh)
        refresh_btn.pack(anchor="e", padx=24, pady=(0, 10))

    def refresh(self):
        currency = self.db.get_setting("currency_symbol", "PHP ")
        today = self.db.sales_total_for_today()
        self.card_sales_today.set_value(f"{currency}{today['v']:.2f}")
        self.card_transactions.set_value(str(today["n"]))
        self.card_products.set_value(str(self.db.count_products()))
        low_count = self.db.count_low_stock()
        self.card_low_stock.set_value(str(low_count))

        low_products = self.db.list_products(only_low_stock=True)
        rows = [(p["name"], p["sku"], p["quantity"], p["reorder_level"]) for p in low_products]
        self.low_stock_table.set_rows(rows)

        date_to = datetime.date.today()
        date_from = date_to - datetime.timedelta(days=30)
        top = self.db.top_selling_products(date_from.isoformat(), date_to.isoformat(), limit=10)
        rows = [(t["product_name"], t["qty"], f"{currency}{t['revenue']:.2f}") for t in top]
        self.top_products_table.set_rows(rows)
