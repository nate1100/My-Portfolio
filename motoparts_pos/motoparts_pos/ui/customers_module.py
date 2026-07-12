import customtkinter as ctk
from ui import widgets


class CustomersModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="Customers", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))
        self.search_bar = widgets.SearchBar(toolbar, placeholder="Search customer...",
                                             on_search=self.refresh)
        self.search_bar.pack(side="left")

        btns = ctk.CTkFrame(toolbar, fg_color="transparent")
        btns.pack(side="right")
        ctk.CTkButton(btns, text="+ Add Customer", command=self.add_customer).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Edit", fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self.edit_customer).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Delete", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.delete_customer).pack(side="left", padx=4)

        table_frame = ctk.CTkFrame(self, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        columns = ("Name", "Phone", "Email", "Address", "Customer Since")
        widths = (180, 120, 170, 220, 140)
        self.table = widgets.Table(table_frame, columns=columns, widths=widths,
                                    on_double_click=lambda i: self.edit_customer(), height=18)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self, *_):
        search = self.search_bar.get()
        customers = self.db.list_customers(search=search)
        rows = [(c["name"], c["phone"] or "-", c["email"] or "-", c["address"] or "-",
                c["created_at"][:10]) for c in customers]
        ids = [c["id"] for c in customers]
        self.table.set_rows(rows, row_ids=ids)

    def _get_selected_id(self):
        iid = self.table.get_selected()
        return int(iid) if iid else None

    def add_customer(self):
        fields = [
            {"key": "name", "label": "Customer Name", "required": True},
            {"key": "phone", "label": "Phone"},
            {"key": "email", "label": "Email"},
            {"key": "address", "label": "Address", "type": "textarea"},
        ]
        result = widgets.FormDialog.ask(self, "Add Customer", fields, submit_text="Add Customer")
        if not result:
            return
        self.db.add_customer(result["name"], result["phone"], result["email"], result["address"])
        self.refresh()

    def edit_customer(self):
        cid = self._get_selected_id()
        if not cid:
            widgets.warn(self, "No Selection", "Please select a customer to edit.")
            return
        c = self.db.get_customer(cid)
        fields = [
            {"key": "name", "label": "Customer Name", "required": True, "initial": c["name"]},
            {"key": "phone", "label": "Phone", "initial": c["phone"] or ""},
            {"key": "email", "label": "Email", "initial": c["email"] or ""},
            {"key": "address", "label": "Address", "type": "textarea", "initial": c["address"] or ""},
        ]
        result = widgets.FormDialog.ask(self, f"Edit Customer - {c['name']}", fields, submit_text="Save Changes")
        if not result:
            return
        self.db.update_customer(cid, result["name"], result["phone"], result["email"], result["address"])
        self.refresh()

    def delete_customer(self):
        cid = self._get_selected_id()
        if not cid:
            widgets.warn(self, "No Selection", "Please select a customer to delete.")
            return
        c = self.db.get_customer(cid)
        if widgets.ConfirmDialog.ask(self, "Delete Customer", f"Delete customer '{c['name']}'?", danger=True):
            try:
                self.db.delete_customer(cid)
            except Exception as e:
                widgets.error(self, "Error", f"Could not delete customer.\n{e}")
            self.refresh()
