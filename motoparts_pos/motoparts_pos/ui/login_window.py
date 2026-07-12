import customtkinter as ctk
from database.db import verify_password
from ui import widgets


class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=("gray95", "gray10"))
        self.app = app
        self.db = app.db

        card = ctk.CTkFrame(self, width=400, corner_radius=16, fg_color=("white", "gray17"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=40, pady=40)

        ctk.CTkLabel(inner, text="\U0001F3CD  Edrik Motorshop POS", font=("Segoe UI", 24, "bold")).pack(pady=(0, 4))
        ctk.CTkLabel(inner, text="Point of Sale & Inventory Management", font=("Segoe UI", 12),
                     text_color=widgets.MUTED).pack(pady=(0, 24))

        self.username_entry = ctk.CTkEntry(inner, placeholder_text="Username", width=280, height=38)
        self.username_entry.pack(pady=6)
        self.password_entry = ctk.CTkEntry(inner, placeholder_text="Password", show="*", width=280, height=38)
        self.password_entry.pack(pady=6)
        self.password_entry.bind("<Return>", lambda e: self.attempt_login())
        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())

        self.error_label = ctk.CTkLabel(inner, text="", text_color=widgets.DANGER, font=("Segoe UI", 11))
        self.error_label.pack(pady=(4, 0))

        ctk.CTkButton(inner, text="Log In", width=280, height=40, font=("Segoe UI", 13, "bold"),
                      command=self.attempt_login).pack(pady=(14, 4))

        ctk.CTkLabel(inner, text="Please contact the administrator if you have trouble logging in.",
                     font=("Segoe UI", 10), text_color=widgets.MUTED).pack(pady=(16, 0))

        self.username_entry.focus()

    def attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.error_label.configure(text="Please enter both username and password.")
            return

        user = self.db.get_user_by_username(username)
        if user is None or not user["active"]:
            self.error_label.configure(text="Invalid username or account is disabled.")
            return
        if not verify_password(password, user["salt"], user["password_hash"]):
            self.error_label.configure(text="Incorrect password.")
            return

        self.error_label.configure(text="")
        self.app.on_login_success(user)
