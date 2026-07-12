import customtkinter as ctk
from tkinter import messagebox
from ui import widgets
from core import print_utils


class POSModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.db = app.db
        self.cart = []  # list of dicts: product_id, name, sku, unit_price, quantity, stock, discount
        self.customer_map = {}
        self._build()
        self.refresh_customers()
        self.refresh_products("")

    # ---------------------------------------------------------- layout
    def _build(self):
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(fill="both", expand=True, padx=20, pady=20)
        outer.grid_columnconfigure(0, weight=3)
        outer.grid_columnconfigure(1, weight=2)
        outer.grid_rowconfigure(0, weight=1)

        # -------- LEFT: product search / scan --------
        left = ctk.CTkFrame(outer, corner_radius=12, fg_color=("gray92", "gray15"))
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(left, text="Point of Sale", font=("Segoe UI", 20, "bold")).pack(
            anchor="w", padx=16, pady=(16, 4))

        scan_frame = ctk.CTkFrame(left, fg_color="transparent")
        scan_frame.pack(fill="x", padx=16, pady=(4, 8))
        self.scan_entry = ctk.CTkEntry(scan_frame, placeholder_text="Scan barcode or type name/SKU, then press Enter",
                                        height=42, font=("Segoe UI", 14))
        self.scan_entry.pack(fill="x")
        self.scan_entry.bind("<Return>", self._on_scan_enter)
        self.scan_entry.bind("<KeyRelease>", self._on_type)
        self.scan_entry.focus()

        table_frame = ctk.CTkFrame(left, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        columns = ("Name", "SKU", "Category", "Price", "Stock")
        widths = (220, 90, 110, 80, 60)
        self.results_table = widgets.Table(table_frame, columns=columns, widths=widths,
                                            on_double_click=self._add_selected_to_cart, height=16)
        self.results_table.pack(fill="both", expand=True)
        self._results_products = {}

        hint = ctk.CTkLabel(left, text="Tip: double-click a product to add it to the cart.",
                             font=("Segoe UI", 11), text_color=widgets.MUTED)
        hint.pack(anchor="w", padx=16, pady=(0, 12))

        # -------- RIGHT: cart & checkout --------
        right = ctk.CTkFrame(outer, corner_radius=12, fg_color=("gray92", "gray15"))
        right.grid(row=0, column=1, sticky="nsew")

        ctk.CTkLabel(right, text="Current Sale", font=("Segoe UI", 18, "bold")).pack(
            anchor="w", padx=16, pady=(16, 4))

        cust_frame = ctk.CTkFrame(right, fg_color="transparent")
        cust_frame.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(cust_frame, text="Customer:", width=80, anchor="w").pack(side="left")
        self.customer_menu = ctk.CTkOptionMenu(cust_frame, values=["Walk-in Customer"], width=180)
        self.customer_menu.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkButton(cust_frame, text="+", width=32, command=self._quick_add_customer).pack(side="left")

        cart_frame = ctk.CTkFrame(right, fg_color="transparent")
        cart_frame.pack(fill="both", expand=True, padx=16, pady=4)
        columns = ("Item", "Qty", "Price", "Total")
        widths = (100, 20, 50, 60)
        self.cart_table = widgets.Table(cart_frame, columns=columns, widths=widths, height=6)
        self.cart_table.pack(fill="both", expand=True)

        cart_btns = ctk.CTkFrame(right, fg_color="transparent")
        cart_btns.pack(fill="x", padx=16, pady=(4, 8))
        ctk.CTkButton(cart_btns, text="+ Qty", width=60, command=lambda: self._change_qty(1)).pack(side="left", padx=2)
        ctk.CTkButton(cart_btns, text="- Qty", width=60, command=lambda: self._change_qty(-1)).pack(side="left", padx=2)
        ctk.CTkButton(cart_btns, text="Remove", width=70, fg_color=widgets.DANGER, hover_color="#a82b26",
                      command=self._remove_item).pack(side="left", padx=2)
        ctk.CTkButton(cart_btns, text="Clear Cart", width=80, fg_color=widgets.MUTED, hover_color="#6e7681",
                      command=self._clear_cart).pack(side="right", padx=2)

        # discount / payment section
        calc_frame = ctk.CTkFrame(right, fg_color="transparent")
        calc_frame.pack(fill="x", padx=12, pady=(4, 4))

        row1 = ctk.CTkFrame(calc_frame, fg_color="transparent")
        row1.pack(fill="x", pady=2)
        ctk.CTkLabel(row1, text="Discount:", width=80, anchor="w").pack(side="left")
        self.discount_entry = ctk.CTkEntry(row1, width=80, placeholder_text="0")
        self.discount_entry.pack(side="left")
        self.discount_type = ctk.CTkOptionMenu(row1, values=["Amount (PHP)", "Percent (%)"], width=130,
                                                command=lambda v: self._recalculate())
        self.discount_type.pack(side="left", padx=4)
        self.discount_entry.bind("<KeyRelease>", lambda e: self._recalculate())

        row2 = ctk.CTkFrame(calc_frame, fg_color="transparent")
        row2.pack(fill="x", pady=2)
        ctk.CTkLabel(row2, text="Payment:", width=80, anchor="w").pack(side="left")
        self.payment_method = ctk.CTkOptionMenu(row2, values=["Cash", "GCash", "Card", "Bank Transfer"])
        self.payment_method.pack(side="left", fill="x", expand=True)

        row3 = ctk.CTkFrame(calc_frame, fg_color="transparent")
        row3.pack(fill="x", pady=2)
        ctk.CTkLabel(row3, text="Amount Paid:", width=80, anchor="w").pack(side="left")
        self.amount_paid_entry = ctk.CTkEntry(row3, width=80, placeholder_text="0.00")
        self.amount_paid_entry.pack(side="left")
        self.amount_paid_entry.bind("<KeyRelease>", lambda e: self._recalculate())

        # totals
        totals_frame = ctk.CTkFrame(right, fg_color=("gray85", "gray20"), corner_radius=5)
        totals_frame.pack(fill="x", padx=5, pady=(3, 3))
        self.subtotal_label = self._totals_row(totals_frame, "Subtotal:")
        self.discount_label = self._totals_row(totals_frame, "Discount:")
        self.total_label = self._totals_row(totals_frame, "TOTAL:", bold=True, size=14)
        self.change_label = self._totals_row(totals_frame, "Change:")

        ctk.CTkButton(right, text="Complete Sale", height=30, font=("Segoe UI", 12, "bold"),
                      fg_color=widgets.SUCCESS, hover_color="#238636",
                      command=self.checkout).pack(fill="x", padx=12, pady=(3,9))

    def _totals_row(self, parent, label, bold=False, size=13):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(row, text=label, font=("Segoe UI", size, "bold" if bold else "normal")).pack(side="left")
        val = ctk.CTkLabel(row, text="PHP 0.00", font=("Segoe UI", size, "bold" if bold else "normal"))
        val.pack(side="right")
        return val

    # ---------------------------------------------------------- product search
    def _on_type(self, event):
        if event.keysym in ("Return",):
            return
        text = self.scan_entry.get().strip()
        self.refresh_products(text)

    def refresh_products(self, search):
        products = self.db.list_products(search=search)
        rows, ids = [], []
        currency = self.db.get_setting("currency_symbol", "PHP ")
        self._results_products = {}
        for p in products:
            rows.append((p["name"], p["sku"], p["category_name"] or "-",
                        f"{currency}{p['selling_price']:.2f}", p["quantity"]))
            ids.append(p["id"])
            self._results_products[p["id"]] = p
        self.results_table.set_rows(rows, row_ids=ids)

    def _on_scan_enter(self, event):
        code = self.scan_entry.get().strip()
        if not code:
            return
        product = self.db.get_product_by_barcode_or_sku(code)
        if product:
            self._add_to_cart(product)
            self.scan_entry.delete(0, "end")
            self.refresh_products("")
        else:
            # fall back to filtering the results list by typed text
            self.refresh_products(code)

    def _add_selected_to_cart(self, iid):
        if not iid:
            return
        pid = int(iid)
        product = self._results_products.get(pid) or self.db.get_product(pid)
        if product:
            self._add_to_cart(product)

    # ---------------------------------------------------------- cart logic
    def _add_to_cart(self, product):
        if product["quantity"] <= 0:
            widgets.warn(self, "Out of Stock", f"'{product['name']}' has no available stock.")
            return
        for item in self.cart:
            if item["product_id"] == product["id"]:
                if item["quantity"] + 1 > product["quantity"]:
                    widgets.warn(self, "Insufficient Stock",
                                 f"Only {product['quantity']} unit(s) of '{product['name']}' available.")
                    return
                item["quantity"] += 1
                self._render_cart()
                return
        self.cart.append({
            "product_id": product["id"], "name": product["name"], "sku": product["sku"],
            "unit_price": product["selling_price"], "quantity": 1, "stock": product["quantity"],
        })
        self._render_cart()

    def _change_qty(self, delta):
        iid = self.cart_table.get_selected()
        if iid is None:
            return
        idx = int(iid)
        item = self.cart[idx]
        new_qty = item["quantity"] + delta
        if new_qty <= 0:
            self.cart.pop(idx)
        elif new_qty > item["stock"]:
            widgets.warn(self, "Insufficient Stock", f"Only {item['stock']} unit(s) available.")
            return
        else:
            item["quantity"] = new_qty
        self._render_cart()

    def _remove_item(self):
        iid = self.cart_table.get_selected()
        if iid is None:
            return
        idx = int(iid)
        self.cart.pop(idx)
        self._render_cart()

    def _clear_cart(self):
        if not self.cart:
            return
        if widgets.ConfirmDialog.ask(self, "Clear Cart", "Remove all items from the current sale?"):
            self.cart = []
            self._render_cart()

    def _render_cart(self):
        rows = []
        currency = self.db.get_setting("currency_symbol", "PHP ")
        for item in self.cart:
            line_total = item["unit_price"] * item["quantity"]
            rows.append((item["name"], item["quantity"], f"{currency}{item['unit_price']:.2f}",
                        f"{currency}{line_total:.2f}"))
        self.cart_table.set_rows(rows, row_ids=list(range(len(self.cart))))
        self._recalculate()

    # ---------------------------------------------------------- calculations
    def _compute_totals(self):
        subtotal = sum(item["unit_price"] * item["quantity"] for item in self.cart)
        try:
            discount_input = float(self.discount_entry.get() or 0)
        except ValueError:
            discount_input = 0.0
        if self.discount_type.get().startswith("Percent"):
            discount_amount = subtotal * (discount_input / 100.0)
        else:
            discount_amount = discount_input
        discount_amount = max(0.0, min(discount_amount, subtotal))

        tax_rate = float(self.db.get_setting("tax_rate", "12") or 0)
        taxable = subtotal - discount_amount
        tax_amount = taxable * (tax_rate / 100.0)
        total = taxable + tax_amount

        try:
            amount_paid = float(self.amount_paid_entry.get() or 0)
        except ValueError:
            amount_paid = 0.0
        change = amount_paid - total
        return {
            "subtotal": subtotal, "discount_amount": discount_amount, "tax_rate": tax_rate,
            "tax_amount": tax_amount, "total": total, "amount_paid": amount_paid,
            "change": change,
        }

    def _recalculate(self):
        currency = self.db.get_setting("currency_symbol", "PHP ")
        t = self._compute_totals()
        self.subtotal_label.configure(text=f"{currency}{t['subtotal']:.2f}")
        self.discount_label.configure(text=f"-{currency}{t['discount_amount']:.2f}")
        self.total_label.configure(text=f"{currency}{t['total']:.2f}")
        change_text = f"{currency}{t['change']:.2f}" if t["change"] >= 0 else f"-{currency}{abs(t['change']):.2f}"
        self.change_label.configure(text=change_text,
                                     text_color=widgets.DANGER if t["change"] < 0 else None)

    # ---------------------------------------------------------- customers
    def refresh_customers(self):
        customers = self.db.list_customers()
        self.customer_map = {"Walk-in Customer": None}
        for c in customers:
            self.customer_map[c["name"]] = c["id"]
        self.customer_menu.configure(values=list(self.customer_map.keys()))
        self.customer_menu.set("Walk-in Customer")

    def _quick_add_customer(self):
        fields = [
            {"key": "name", "label": "Customer Name", "required": True},
            {"key": "phone", "label": "Phone"},
            {"key": "email", "label": "Email"},
            {"key": "address", "label": "Address", "type": "textarea"},
        ]
        result = widgets.FormDialog.ask(self, "Add Customer", fields, submit_text="Add")
        if not result:
            return
        self.db.add_customer(result["name"], result["phone"], result["email"], result["address"])
        self.refresh_customers()
        self.customer_menu.set(result["name"])

    # ---------------------------------------------------------- checkout
    def checkout(self):
        if not self.cart:
            widgets.warn(self, "Empty Cart", "Add at least one product before checking out.")
            return

        t = self._compute_totals()
        if self.payment_method.get() == "Cash" and t["amount_paid"] < t["total"] - 0.001:
            widgets.warn(self, "Insufficient Payment",
                         "Amount paid is less than the total due. Please collect full payment "
                         "(or a valid amount tendered) before completing the sale.")
            return

        amount_paid = t["amount_paid"] if t["amount_paid"] > 0 else t["total"]
        change = max(0.0, amount_paid - t["total"])

        items = [{
            "product_id": item["product_id"], "product_name": item["name"], "sku": item["sku"],
            "quantity": item["quantity"], "unit_price": item["unit_price"], "discount": 0,
            "line_total": item["unit_price"] * item["quantity"],
        } for item in self.cart]

        customer_name = self.customer_menu.get()
        customer_id = self.customer_map.get(customer_name)

        try:
            sale_id, invoice_number = self.db.create_sale(
                customer_id=customer_id, user_id=self.app.current_user["id"], items=items,
                subtotal=t["subtotal"], discount_amount=t["discount_amount"], tax_rate=t["tax_rate"],
                tax_amount=t["tax_amount"], total=t["total"], payment_method=self.payment_method.get(),
                amount_paid=amount_paid, change_due=change)
        except Exception as e:
            widgets.error(self, "Checkout Failed", f"Could not complete the sale.\n{e}")
            return

        widgets.info(self, "Sale Completed",
                     f"Invoice {invoice_number} completed successfully.\nChange due: "
                     f"{self.db.get_setting('currency_symbol', 'PHP ')}{change:.2f}")

        if widgets.ConfirmDialog.ask(self, "Print Receipt", "Print the receipt/invoice now?"):
            self._print_invoice(sale_id)

        self.cart = []
        self.discount_entry.delete(0, "end")
        self.amount_paid_entry.delete(0, "end")
        self.payment_method.set("Cash")
        self.customer_menu.set("Walk-in Customer")
        self._render_cart()
        self.refresh_products("")
        self.scan_entry.focus()
        if hasattr(self.app, "on_sale_completed"):
            self.app.on_sale_completed()

    def _print_invoice(self, sale_id):
        sale = self.db.get_sale(sale_id)
        items = self.db.get_sale_items(sale_id)
        store_info = self.db.get_all_settings()
        currency = store_info.get("currency_symbol", "PHP ")
        try:
            path, kind = print_utils.generate_and_get_invoice_file(store_info, sale, items, currency)
            ok, msg = print_utils.print_file(path)
            widgets.info(self, "Print", msg)
        except Exception as e:
            widgets.error(self, "Print Error", f"Could not generate/print invoice.\n{e}")
