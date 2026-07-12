import customtkinter as ctk
from ui import widgets


class SuppliersModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Suppliers", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))
        self.search_bar = widgets.SearchBar(toolbar, placeholder="Search supplier...",
                                             on_search=self.refresh)
        self.search_bar.pack(side="left")

        btns = ctk.CTkFrame(toolbar, fg_color="transparent")
        btns.pack(side="right")
        ctk.CTkButton(btns, text="+ Add Supplier", command=self.add_supplier).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Edit", fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self.edit_supplier).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Delete", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.delete_supplier).pack(side="left", padx=4)

        table_frame = ctk.CTkFrame(self, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        columns = ("Name", "Contact Person", "Phone", "Email", "Address")
        widths = (180, 150, 110, 170, 220)
        self.table = widgets.Table(table_frame, columns=columns, widths=widths,
                                    on_double_click=lambda i: self.edit_supplier(), height=18)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self, *_):
        search = self.search_bar.get()
        suppliers = self.db.list_suppliers(search=search)
        rows = [(s["name"], s["contact_person"] or "-", s["phone"] or "-",
                s["email"] or "-", s["address"] or "-") for s in suppliers]
        ids = [s["id"] for s in suppliers]
        self.table.set_rows(rows, row_ids=ids)

    def _get_selected_id(self):
        iid = self.table.get_selected()
        return int(iid) if iid else None

    def add_supplier(self):
        fields = [
            {"key": "name", "label": "Supplier Name", "required": True},
            {"key": "contact_person", "label": "Contact Person"},
            {"key": "phone", "label": "Phone"},
            {"key": "email", "label": "Email"},
            {"key": "address", "label": "Address", "type": "textarea"},
        ]
        result = widgets.FormDialog.ask(self, "Add Supplier", fields, submit_text="Add Supplier")
        if not result:
            return
        self.db.add_supplier(result["name"], result["contact_person"], result["phone"],
                              result["email"], result["address"])
        self.refresh()

    def edit_supplier(self):
        sid = self._get_selected_id()
        if not sid:
            widgets.warn(self, "No Selection", "Please select a supplier to edit.")
            return
        s = self.db.get_supplier(sid)
        fields = [
            {"key": "name", "label": "Supplier Name", "required": True, "initial": s["name"]},
            {"key": "contact_person", "label": "Contact Person", "initial": s["contact_person"] or ""},
            {"key": "phone", "label": "Phone", "initial": s["phone"] or ""},
            {"key": "email", "label": "Email", "initial": s["email"] or ""},
            {"key": "address", "label": "Address", "type": "textarea", "initial": s["address"] or ""},
        ]
        result = widgets.FormDialog.ask(self, f"Edit Supplier - {s['name']}", fields, submit_text="Save Changes")
        if not result:
            return
        self.db.update_supplier(sid, result["name"], result["contact_person"], result["phone"],
                                 result["email"], result["address"])
        self.refresh()

    def delete_supplier(self):
        sid = self._get_selected_id()
        if not sid:
            widgets.warn(self, "No Selection", "Please select a supplier to delete.")
            return
        s = self.db.get_supplier(sid)
        if widgets.ConfirmDialog.ask(self, "Delete Supplier", f"Delete supplier '{s['name']}'?", danger=True):
            try:
                self.db.delete_supplier(sid)
            except Exception as e:
                widgets.error(self, "Error", f"Could not delete supplier (it may be linked to products).\n{e}")
            self.refresh()
