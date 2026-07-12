import customtkinter as ctk
from ui import widgets


class ProductsModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self.selected_id = None
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Products", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))

        self.search_bar = widgets.SearchBar(toolbar, placeholder="Search name, SKU or barcode...",
                                             on_search=self.refresh)
        self.search_bar.pack(side="left")

        self.category_filter = ctk.CTkOptionMenu(toolbar, values=["All Categories"],
                                                   command=lambda v: self.refresh())
        self.category_filter.pack(side="left", padx=8)

        self.low_stock_only = ctk.CTkCheckBox(toolbar, text="Low stock only", command=self.refresh)
        self.low_stock_only.pack(side="left", padx=8)

        btns = ctk.CTkFrame(toolbar, fg_color="transparent")
        btns.pack(side="right")
        ctk.CTkButton(btns, text="+ Add Product", command=self.add_product).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Edit", fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self.edit_product).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Deactivate", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.deactivate_product).pack(side="left", padx=4)

        table_frame = ctk.CTkFrame(self, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        columns = ("SKU", "Barcode", "Name", "Category", "Cost", "Price", "Qty", "Reorder", "Supplier")
        widths = (80, 100, 200, 110, 70, 70, 50, 60, 130)
        self.table = widgets.Table(table_frame, columns=columns, widths=widths,
                                    on_double_click=self._on_row_double_click, height=18)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)
        self._row_id_map = {}

    def refresh(self, *_):
        cats = self.db.list_categories()
        self._cat_lookup = {c["name"]: c["id"] for c in cats}
        self.category_filter.configure(values=["All Categories"] + [c["name"] for c in cats])

        search = self.search_bar.get()
        cat_name = self.category_filter.get()
        cat_id = self._cat_lookup.get(cat_name) if cat_name != "All Categories" else None
        only_low = bool(self.low_stock_only.get())

        products = self.db.list_products(search=search, category_id=cat_id, only_low_stock=only_low)
        currency = self.db.get_setting("currency_symbol", "PHP ")
        rows, ids = [], []
        for p in products:
            rows.append((p["sku"], p["barcode"] or "-", p["name"], p["category_name"] or "-",
                         f"{currency}{p['cost_price']:.2f}", f"{currency}{p['selling_price']:.2f}",
                         p["quantity"], p["reorder_level"], p["supplier_name"] or "-"))
            ids.append(p["id"])
        self.table.set_rows(rows, row_ids=ids)
        self._row_id_map = {str(i): i for i in ids}

    def _on_row_double_click(self, iid):
        if iid:
            self.selected_id = int(iid)
            self.edit_product()

    def _get_selected_id(self):
        iid = self.table.get_selected()
        return int(iid) if iid else None

    def _category_options(self):
        cats = self.db.list_categories()
        return [(c["id"], c["name"]) for c in cats]

    def _supplier_options(self):
        sups = self.db.list_suppliers()
        return [(s["id"], s["name"]) for s in sups]

    def add_product(self):
        cat_opts = self._category_options()
        sup_opts = [(None, "-- None --")] + self._supplier_options()
        fields = [
            {"key": "sku", "label": "SKU", "required": True},
            {"key": "barcode", "label": "Barcode"},
            {"key": "name", "label": "Product Name", "required": True},
            {"key": "category_id", "label": "Category", "type": "combobox", "options": cat_opts},
            {"key": "supplier_id", "label": "Supplier", "type": "combobox", "options": sup_opts},
            {"key": "cost_price", "label": "Cost Price", "type": "number", "initial": "0"},
            {"key": "selling_price", "label": "Selling Price", "type": "number", "required": True},
            {"key": "quantity", "label": "Initial Stock Qty", "type": "number", "initial": "0"},
            {"key": "reorder_level", "label": "Reorder Level", "type": "number", "initial": "5"},
            {"key": "unit", "label": "Unit (pc, set, liter...)", "initial": "pc"},
            {"key": "description", "label": "Description", "type": "textarea"},
        ]
        result = widgets.FormDialog.ask(self, "Add Product", fields, submit_text="Add Product")
        if not result:
            return
        try:
            self.db.add_product(
                sku=result["sku"], barcode=result["barcode"], name=result["name"],
                category_id=result["category_id"] or None, supplier_id=result["supplier_id"] or None,
                cost_price=float(result["cost_price"] or 0), selling_price=float(result["selling_price"]),
                quantity=int(float(result["quantity"] or 0)), reorder_level=int(float(result["reorder_level"] or 5)),
                unit=result["unit"] or "pc", description=result["description"])
            widgets.info(self, "Success", f"Product '{result['name']}' added.")
        except Exception as e:
            widgets.error(self, "Error", f"Could not add product.\n{e}")
        self.refresh()

    def edit_product(self):
        pid = self.selected_id or self._get_selected_id()
        if not pid:
            widgets.warn(self, "No Selection", "Please select a product to edit.")
            return
        p = self.db.get_product(pid)
        if not p:
            return
        cat_opts = self._category_options()
        sup_opts = [(None, "-- None --")] + self._supplier_options()
        cat_label = next((n for i, n in cat_opts if i == p["category_id"]), "")
        sup_label = next((n for i, n in sup_opts if i == p["supplier_id"]), "-- None --")

        fields = [
            {"key": "sku", "label": "SKU", "required": True, "initial": p["sku"]},
            {"key": "barcode", "label": "Barcode", "initial": p["barcode"] or ""},
            {"key": "name", "label": "Product Name", "required": True, "initial": p["name"]},
            {"key": "category_id", "label": "Category", "type": "combobox", "options": cat_opts, "initial": cat_label},
            {"key": "supplier_id", "label": "Supplier", "type": "combobox", "options": sup_opts, "initial": sup_label},
            {"key": "cost_price", "label": "Cost Price", "type": "number", "initial": p["cost_price"]},
            {"key": "selling_price", "label": "Selling Price", "type": "number", "required": True, "initial": p["selling_price"]},
            {"key": "reorder_level", "label": "Reorder Level", "type": "number", "initial": p["reorder_level"]},
            {"key": "unit", "label": "Unit", "initial": p["unit"]},
            {"key": "description", "label": "Description", "type": "textarea", "initial": p["description"] or ""},
        ]
        result = widgets.FormDialog.ask(self, f"Edit Product - {p['name']}", fields, submit_text="Save Changes")
        if not result:
            return
        try:
            self.db.update_product(
                pid, sku=result["sku"], barcode=result["barcode"], name=result["name"],
                category_id=result["category_id"] or None, supplier_id=result["supplier_id"] or None,
                cost_price=float(result["cost_price"] or 0), selling_price=float(result["selling_price"]),
                reorder_level=int(float(result["reorder_level"] or 5)), unit=result["unit"] or "pc",
                description=result["description"])
            widgets.info(self, "Success", "Product updated.")
        except Exception as e:
            widgets.error(self, "Error", f"Could not update product.\n{e}")
        self.selected_id = None
        self.refresh()

    def deactivate_product(self):
        pid = self._get_selected_id()
        if not pid:
            widgets.warn(self, "No Selection", "Please select a product to deactivate.")
            return
        p = self.db.get_product(pid)
        if widgets.ConfirmDialog.ask(self, "Deactivate Product",
                                      f"Deactivate '{p['name']}'? It will no longer appear in POS "
                                      f"but its sales history will be kept.", danger=True):
            self.db.set_product_active(pid, False)
            self.refresh()
