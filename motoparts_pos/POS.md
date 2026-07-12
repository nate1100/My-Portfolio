# Edrik Motorshop — POS & Inventory Management System <br />
## Project Overview
A desktop Point of Sale (POS) and Inventory Management System built for our motorcycle parts & accessories business. Fully offline, single-file SQLite backend, role-based access for admins and cashiers, and a modern dark-themed UI built with customtkinter. <br />
![](motorparts_pos/images/login.png)
![](images/login.png)
![](images/dashbboard.png)
![](images/POS.png)
![](images/userm.png)
![](images/reports.png)

## 📖 Overview
Edrik Motorshop POS is a fully offline desktop application designed to replace manual, paper-based sales and stock tracking with a fast, reliable, and modern digital system — no internet connection or cloud subscription required.

It handles the full daily workflow of a small retail shop: logging cashiers in, ringing up sales at the counter, tracking stock levels in real time, managing suppliers and customers, and giving the owner/admin visibility into performance through dashboards and exportable reports.

📌 Portfolio note: This project was built to demonstrate desktop application architecture, database design, role-based access control, and building a real, business-usable tool from scratch — not just a UI mockup. <br />

##✨ Key Features

#🔐 Authentication & Roles


Secure login screen with salted/hashed password verification
Two roles — Admin and Cashier — each with a different set of accessible modules
Accounts can be disabled without deleting sales history tied to them


#📊 Dashboard


Live "Today's Sales" and "Transactions Today" stat cards
Active product count and low-stock alert count at a glance
Low-stock product table with reorder levels
Top-selling products for the last 30 days
One-click refresh


#🛒 Point of Sale (POS)


Barcode scanner and manual SKU/name search with live filtering
Add items to cart via barcode scan or double-click
Adjustable quantity per line item with stock-level validation (can't oversell)
Walk-in or registered customer selection, with a quick "add customer" shortcut mid-sale
Discounts by fixed amount or percentage
Automatic tax calculation based on configurable tax rate
Multiple payment methods: Cash, GCash, Card, Bank Transfer
Real-time subtotal / discount / tax / total / change computation
Change-due validation (blocks checkout if cash tendered is insufficient)
Auto-generated invoice numbers
Optional receipt/invoice printing (PDF generation + print) immediately after checkout


🧾 Sales History


Full transaction log, filterable by date range (Today / Week / Month / Year / All-time) and searchable by invoice number or customer
Cashiers only see their own transactions; admins see all
Detailed invoice viewer showing line items, totals, payment method, and cashier
Reprint any past invoice on demand


#🔧 Products Management (Admin)


Full CRUD for products: SKU, barcode, name, category, supplier, cost price, selling price, stock quantity, reorder level, unit of measure, description
Search by name/SKU/barcode, filter by category, filter to low-stock items only
Soft-deactivate products (removes from POS while preserving historical sales data)


#📦 Inventory Management (Admin)


Stock Levels tab: live view of current quantity vs. reorder level with OK/LOW STOCK status
Adjustment History tab: full audit trail of every stock change
Manual stock adjustments with typed reasons: Stock In, Stock Out, Correction, Damaged/Lost, Returned by Customer
Every adjustment is attributed to the logged-in user and timestamped


#🚚 Suppliers & 👥 Customers


Full CRUD directories for suppliers (contact person, phone, email, address) and customers
Searchable tables, inline add/edit/delete
Customers can also be added on-the-fly directly from the POS screen


#📈 Reports & Analytics (Admin)


Configurable reporting periods: Daily, Weekly, Monthly, Yearly, or a Custom Range
Summary cards: Total Revenue, Transactions, Total Discounts, Total Tax Collected
Sales-by-day breakdown table
Top-selling products table
Export reports to CSV, Excel (.xlsx), or PDF


#⚙️ Settings (Admin)


Store Info: store name, address, phone, email, currency symbol, tax rate, invoice number prefix, low-stock threshold, receipt footer message
Categories: add/delete product categories
Backup & Restore: one-click database backup, restore from a previous .db backup file, with a visible backup history list
Export Data: export the entire product/inventory list to CSV, Excel, or PDF


#👤 User Management (Admin)

Create cashier/admin accounts
Edit full name and role
Reset a user's password
Enable/disable accounts (self-disable is blocked as a safety guard)

#🏗️ Tech Stack

LayerTechnologyLanguagePython 3GUI FrameworkCustomTkinter (built on Tkinter)DatabaseSQLite (local, file-based, zero-config)Reporting/ExportCSV, Excel (.xlsx), and PDF export utilitiesPrintingPDF invoice generation with print dispatchArchitectureModular MVC-style structure — one module per feature, shared Database service layer, shared reusable widget library
