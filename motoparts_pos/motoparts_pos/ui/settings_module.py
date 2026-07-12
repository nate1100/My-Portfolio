import os
import customtkinter as ctk
from tkinter import filedialog
from ui import widgets
from core import backup as backup_utils
from core import export_utils

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")


class SettingsModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        os.makedirs(EXPORTS_DIR, exist_ok=True)
        self._build()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Settings", font=("Segoe UI", 22, "bold")).pack(side="left")

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.tabs.add("Store Info")
        self.tabs.add("Categories")
        self.tabs.add("Backup & Restore")
        self.tabs.add("Export Data")

        self._build_store_tab(self.tabs.tab("Store Info"))
        self._build_categories_tab(self.tabs.tab("Categories"))
        self._build_backup_tab(self.tabs.tab("Backup & Restore"))
        self._build_export_tab(self.tabs.tab("Export Data"))

    # -------------------- Store Info --------------------
    def _build_store_tab(self, tab):
        wrapper = ctk.CTkFrame(tab, fg_color="transparent")
        wrapper.pack(fill="x", pady=20, padx=10)

        settings = self.db.get_all_settings()
        self._store_vars = {}
        fields = [
            ("store_name", "Store Name"),
            ("store_address", "Store Address"),
            ("store_phone", "Store Phone"),
            ("store_email", "Store Email"),
            ("currency_symbol", "Currency Symbol (e.g. 'PHP ')"),
            ("tax_rate", "Tax Rate (%)"),
            ("invoice_prefix", "Invoice Number Prefix"),
            ("low_stock_threshold", "Default Low Stock Threshold"),
            ("receipt_footer", "Receipt Footer Message"),
        ]
        for key, label in fields:
            row = ctk.CTkFrame(wrapper, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=label, width=240, anchor="w").pack(side="left")
            entry = ctk.CTkEntry(row, width=320)
            entry.insert(0, settings.get(key, ""))
            entry.pack(side="left", fill="x", expand=True)
            self._store_vars[key] = entry

        ctk.CTkButton(wrapper, text="Save Settings", command=self.save_store_settings).pack(
            anchor="w", pady=(16, 0))

    def save_store_settings(self):
        for key, entry in self._store_vars.items():
            self.db.set_setting(key, entry.get().strip())
        widgets.info(self, "Saved", "Store settings updated successfully.")

    # -------------------- Categories --------------------
    def _build_categories_tab(self, tab):
        toolbar = ctk.CTkFrame(tab, fg_color="transparent")
        toolbar.pack(fill="x", pady=(10, 10))
        self.new_cat_entry = ctk.CTkEntry(toolbar, placeholder_text="New category name", width=220)
        self.new_cat_entry.pack(side="left", padx=(0, 6))
        ctk.CTkButton(toolbar, text="Add Category", command=self.add_category).pack(side="left")
        ctk.CTkButton(toolbar, text="Delete Selected", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.delete_category).pack(side="left", padx=6)

        table_frame = ctk.CTkFrame(tab, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True)
        self.cat_table = widgets.Table(table_frame, columns=("Category Name",), widths=(300,), height=14)
        self.cat_table.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_categories()

    def refresh_categories(self):
        cats = self.db.list_categories()
        rows = [(c["name"],) for c in cats]
        ids = [c["id"] for c in cats]
        self.cat_table.set_rows(rows, row_ids=ids)

    def add_category(self):
        name = self.new_cat_entry.get().strip()
        if not name:
            return
        self.db.add_category(name)
        self.new_cat_entry.delete(0, "end")
        self.refresh_categories()

    def delete_category(self):
        iid = self.cat_table.get_selected()
        if not iid:
            widgets.warn(self, "No Selection", "Please select a category to delete.")
            return
        if widgets.ConfirmDialog.ask(self, "Delete Category", "Delete this category?", danger=True):
            self.db.delete_category(int(iid))
            self.refresh_categories()

    # -------------------- Backup & Restore --------------------
    def _build_backup_tab(self, tab):
        wrapper = ctk.CTkFrame(tab, fg_color="transparent")
        wrapper.pack(fill="both", expand=True, pady=20, padx=10)

        ctk.CTkLabel(wrapper, text="Create a backup copy of the database, or restore from a "
                                    "previous backup. Restoring will replace all current data.",
                     wraplength=600, justify="left").pack(anchor="w", pady=(0, 16))

        btn_row = ctk.CTkFrame(wrapper, fg_color="transparent")
        btn_row.pack(anchor="w", pady=(0, 16))
        ctk.CTkButton(btn_row, text="Backup Now", command=self.backup_now).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Restore From Backup", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.restore_backup).pack(side="left")

        ctk.CTkLabel(wrapper, text="Recent Backups:", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        table_frame = ctk.CTkFrame(wrapper, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.backup_table = widgets.Table(table_frame, columns=("Backup File",), widths=(500,), height=10)
        self.backup_table.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_backups()

    def refresh_backups(self):
        backups = backup_utils.list_backups()
        rows = [(os.path.basename(b),) for b in backups]
        self.backup_table.set_rows(rows, row_ids=backups)

    def backup_now(self):
        try:
            path = backup_utils.backup_database(self.db.db_path)
            self.db.set_setting("last_backup", path)
            widgets.info(self, "Backup Complete", f"Database backed up to:\n{path}")
        except Exception as e:
            widgets.error(self, "Backup Failed", str(e))
        self.refresh_backups()

    def restore_backup(self):
        path = filedialog.askopenfilename(
            initialdir=backup_utils.BACKUPS_DIR,
            filetypes=[("Database files", "*.db")])
        if not path:
            return
        if not widgets.ConfirmDialog.ask(
                self, "Restore Database",
                "This will REPLACE all current data with the selected backup. "
                "The application must be restarted afterward. Continue?", danger=True):
            return
        try:
            backup_utils.restore_database(path, self.db.db_path)
            widgets.info(self, "Restore Complete",
                         "Database restored successfully. Please restart the application now.")
        except Exception as e:
            widgets.error(self, "Restore Failed", str(e))

    # -------------------- Export Data --------------------
    def _build_export_tab(self, tab):
        wrapper = ctk.CTkFrame(tab, fg_color="transparent")
        wrapper.pack(fill="both", expand=True, pady=20, padx=10)
        ctk.CTkLabel(wrapper, text="Export the full product/inventory list to a file.",
                     wraplength=600, justify="left").pack(anchor="w", pady=(0, 16))
        btn_row = ctk.CTkFrame(wrapper, fg_color="transparent")
        btn_row.pack(anchor="w")
        ctk.CTkButton(btn_row, text="Export CSV", command=lambda: self.export_inventory("csv")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Export Excel", command=lambda: self.export_inventory("xlsx")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Export PDF", command=lambda: self.export_inventory("pdf")).pack(side="left")

    def export_inventory(self, fmt):
        products = self.db.list_products(only_active=False)
        headers = ["SKU", "Barcode", "Name", "Category", "Supplier", "Cost Price",
                   "Selling Price", "Qty", "Reorder Level", "Unit"]
        rows = [[p["sku"], p["barcode"] or "", p["name"], p["category_name"] or "",
                p["supplier_name"] or "", p["cost_price"], p["selling_price"], p["quantity"],
                p["reorder_level"], p["unit"]] for p in products]

        default_name = f"inventory_export.{fmt}"
        path = filedialog.asksaveasfilename(initialdir=EXPORTS_DIR, initialfile=default_name,
                                             defaultextension=f".{fmt}", filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not path:
            return
        try:
            if fmt == "csv":
                export_utils.export_to_csv(path, headers, rows)
            elif fmt == "xlsx":
                export_utils.export_to_excel(path, headers, rows, title="Inventory")
            elif fmt == "pdf":
                export_utils.export_to_pdf(path, "Inventory Report", headers, rows)
            widgets.info(self, "Export Complete", f"Inventory exported to:\n{path}")
        except Exception as e:
            widgets.error(self, "Export Failed", str(e))
