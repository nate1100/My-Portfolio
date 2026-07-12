"""
Edrik Motorcycle Parts & Accessories - Offline POS and Inventory Management System
Run with:  python main.py
"""

import sys
import customtkinter as ctk
from database.db import Database
from ui.login_window import LoginFrame
from ui.dashboard_module import DashboardModule
from ui.pos_module import POSModule
from ui.products_module import ProductsModule
from ui.inventory_module import InventoryModule
from ui.suppliers_module import SuppliersModule
from ui.customers_module import CustomersModule
from ui.sales_module import SalesModule
from ui.reports_module import ReportsModule
from ui.settings_module import SettingsModule
from ui.users_module import UsersModule
from ui import widgets

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# (label, module class, roles allowed, icon)
NAV_ITEMS = [
    ("Dashboard", DashboardModule, ("admin", "cashier"), "\U0001F4CA"),
    ("Point of Sale", POSModule, ("admin", "cashier"), "\U0001F6D2"),
    ("Sales History", SalesModule, ("admin", "cashier"), "\U0001F9FE"),
    ("Products", ProductsModule, ("admin"), "\U0001F527"),
    ("Inventory", InventoryModule, ("admin",), "\U0001F4E6"),
    ("Suppliers", SuppliersModule, ("admin",), "\U0001F69A"),
    ("Customers", CustomersModule, ("admin", "cashier"), "\U0001F465"),
    ("Reports", ReportsModule, ("admin",), "\U0001F4C8"),
    ("User Management", UsersModule, ("admin",), "\U0001F464"),
    ("Settings", SettingsModule, ("admin",), "\U00002699"),
]


class POSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Edrik Motorshop POS & Inventory Management System")
        self.geometry("1500x900")
        self.minsize(1200,750)
        self.state("zoomed")
        try:
            
            self.db = Database()
        except Exception as e:
            widgets.error(self, "Database Error", f"Could not initialize the database.\n{e}")
            sys.exit(1)

        self.current_user = None
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        self.sidebar = None
        self.content_frame = None
        self.nav_buttons = {}
        self.current_module_name = None

        self.show_login()

    # ---------------------------------------------------------------- login
    def show_login(self):
        for widget in self.container.winfo_children():
            widget.destroy()
        self.current_user = None
        login = LoginFrame(self.container, self)
        login.pack(fill="both", expand=True)

    def on_login_success(self, user):
        self.current_user = user
        self.build_shell()

    def logout(self):
        if widgets.ConfirmDialog.ask(self, "Log Out", "Are you sure you want to log out?"):
            self.show_login()

    # ---------------------------------------------------------------- shell
    def build_shell(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        self.container.grid_columnconfigure(0, weight=0)
        self.container.grid_columnconfigure(1, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self.container, width=230, corner_radius=0,
                                     fg_color=("gray88", "gray13"))
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(20, 10))
        ctk.CTkLabel(brand, text="\U0001F3CD Edrik Motorshop", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ctk.CTkLabel(brand, text="POS & Inventory", font=("Segoe UI", 11),
                     text_color=widgets.MUTED).pack(anchor="w")

        user_card = ctk.CTkFrame(self.sidebar, corner_radius=10, fg_color=("gray80", "gray20"))
        user_card.pack(fill="x", padx=16, pady=(10, 16))
        ctk.CTkLabel(user_card, text=self.current_user["full_name"], font=("Segoe UI", 13, "bold")).pack(
            anchor="w", padx=10, pady=(8, 0))
        ctk.CTkLabel(user_card, text=self.current_user["role"].capitalize(), font=("Segoe UI", 11),
                     text_color=widgets.MUTED).pack(anchor="w", padx=10, pady=(0, 8))

        nav_scroll = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        nav_scroll.pack(fill="both", expand=True, padx=8)

        self.nav_buttons = {}
        role = self.current_user["role"]
        for label, module_cls, allowed_roles, icon in NAV_ITEMS:
            if role not in allowed_roles:
                continue
            btn = ctk.CTkButton(
                nav_scroll, text=f"  {icon}   {label}", anchor="w", height=40,
                fg_color="transparent", text_color=("gray10", "gray90"),
                hover_color=("gray75", "gray25"), font=("Segoe UI", 13),
                command=lambda l=label, m=module_cls: self.show_module(l, m))
            btn.pack(fill="x", pady=2)
            self.nav_buttons[label] = btn

        bottom = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bottom.pack(fill="x", side="bottom", padx=16, pady=16)
        ctk.CTkButton(bottom, text="Log Out", fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self.logout).pack(fill="x")

        self.content_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew")

        # default landing module
        default_label, default_cls = NAV_ITEMS[0][0], NAV_ITEMS[0][1]
        self.show_module(default_label, default_cls)

    def show_module(self, label, module_cls):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        for name, btn in self.nav_buttons.items():
            if name == label:
                btn.configure(fg_color=("gray70", "gray30"))
            else:
                btn.configure(fg_color="transparent")
        module = module_cls(self.content_frame, self)
        module.pack(fill="both", expand=True)
        self.current_module_name = label

    def on_sale_completed(self):
        """Hook so other modules (e.g. Dashboard) could refresh after a sale."""
        pass


def main():
    app = POSApp()
    app.protocol("WM_DELETE_WINDOW", lambda: (app.db.close(), app.destroy()))
    app.mainloop()


if __name__ == "__main__":
    main()

