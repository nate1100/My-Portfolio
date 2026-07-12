import customtkinter as ctk
from ui import widgets


class UsersModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self._build()
        self.refresh()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="User Management", font=("Segoe UI", 22, "bold")).pack(side="left")

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkButton(toolbar, text="+ Add User", command=self.add_user).pack(side="left", padx=4)
        ctk.CTkButton(toolbar, text="Edit", fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self.edit_user).pack(side="left", padx=4)
        ctk.CTkButton(toolbar, text="Reset Password", fg_color=widgets.WARNING, hover_color="#9e7415",
                      command=self.reset_password).pack(side="left", padx=4)
        ctk.CTkButton(toolbar, text="Enable/Disable", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.toggle_active).pack(side="left", padx=4)

        table_frame = ctk.CTkFrame(self, fg_color=("gray92", "gray15"), corner_radius=12)
        table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        columns = ("Username", "Full Name", "Role", "Status", "Created")
        widths = (140, 200, 100, 90, 150)
        self.table = widgets.Table(table_frame, columns=columns, widths=widths,
                                    on_double_click=lambda i: self.edit_user(), height=18)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self, *_):
        users = self.db.list_users()
        rows = [(u["username"], u["full_name"], u["role"].capitalize(),
                "Active" if u["active"] else "Disabled", u["created_at"][:10]) for u in users]
        ids = [u["id"] for u in users]
        self.table.set_rows(rows, row_ids=ids)

    def _get_selected_id(self):
        iid = self.table.get_selected()
        return int(iid) if iid else None

    def add_user(self):
        fields = [
            {"key": "username", "label": "Username", "required": True},
            {"key": "password", "label": "Password", "type": "password", "required": True},
            {"key": "full_name", "label": "Full Name", "required": True},
            {"key": "role", "label": "Role", "type": "combobox",
             "options": [("cashier", "Cashier"), ("admin", "Administrator")]},
        ]
        result = widgets.FormDialog.ask(self, "Add User", fields, submit_text="Create User")
        if not result:
            return
        if self.db.get_user_by_username(result["username"]):
            widgets.error(self, "Error", "That username is already taken.")
            return
        try:
            self.db.create_user(result["username"], result["password"], result["full_name"], result["role"])
            widgets.info(self, "Success", f"User '{result['username']}' created.")
        except Exception as e:
            widgets.error(self, "Error", str(e))
        self.refresh()

    def edit_user(self):
        uid = self._get_selected_id()
        if not uid:
            widgets.warn(self, "No Selection", "Please select a user to edit.")
            return
        users = {u["id"]: u for u in self.db.list_users()}
        u = users.get(uid)
        if not u:
            return
        fields = [
            {"key": "full_name", "label": "Full Name", "required": True, "initial": u["full_name"]},
            {"key": "role", "label": "Role", "type": "combobox",
             "options": [("cashier", "Cashier"), ("admin", "Administrator")],
             "initial": "Cashier" if u["role"] == "cashier" else "Administrator"},
        ]
        result = widgets.FormDialog.ask(self, f"Edit User - {u['username']}", fields, submit_text="Save Changes")
        if not result:
            return
        self.db.update_user(uid, full_name=result["full_name"], role=result["role"])
        self.refresh()

    def reset_password(self):
        uid = self._get_selected_id()
        if not uid:
            widgets.warn(self, "No Selection", "Please select a user to reset password for.")
            return
        fields = [{"key": "password", "label": "New Password", "type": "password", "required": True}]
        result = widgets.FormDialog.ask(self, "Reset Password", fields, submit_text="Reset")
        if not result:
            return
        self.db.reset_password(uid, result["password"])
        widgets.info(self, "Success", "Password has been reset.")

    def toggle_active(self):
        uid = self._get_selected_id()
        if not uid:
            widgets.warn(self, "No Selection", "Please select a user.")
            return
        if uid == self.app.current_user["id"]:
            widgets.warn(self, "Not Allowed", "You cannot disable your own account.")
            return
        users = {u["id"]: u for u in self.db.list_users()}
        u = users.get(uid)
        new_state = not bool(u["active"])
        action = "enable" if new_state else "disable"
        if widgets.ConfirmDialog.ask(self, "Confirm", f"Are you sure you want to {action} '{u['username']}'?"):
            self.db.update_user(uid, active=new_state)
            self.refresh()
