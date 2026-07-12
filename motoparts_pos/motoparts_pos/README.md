# Moto Parts POS & Inventory Management System

A simple, modern, **fully offline** Point of Sale and Inventory Management System
built for motorcycle parts & accessories retail stores. Built with **Python**,
**CustomTkinter**, and **SQLite** — no internet connection required, ever.

## Features

- **Secure login** with Administrator and Cashier roles
- **Dashboard** with today's sales, transaction count, low-stock alerts, and top products
- **Point of Sale (POS)**: barcode/SKU scanning, live search, cart management,
  discounts (amount or %), automatic tax computation, multiple payment methods,
  automatic stock deduction, automatic invoice numbering
- **Invoice & receipt printing**: generates a PDF invoice (or plain-text receipt
  fallback) and sends it straight to your default printer; reprint any past invoice
- **Products**: full CRUD, categories, suppliers, barcode/SKU, cost & selling price,
  reorder levels, search & filter
- **Inventory management**: stock in/out, corrections, damaged/returned tracking,
  full adjustment history, low-stock indicator
- **Suppliers & Customers**: full CRUD with search
- **Sales History**: search/filter by date range, view full invoice detail, reprint
- **Reports & Analytics**: Daily / Weekly / Monthly / Yearly / Custom range, revenue,
  discounts, tax collected, sales-by-day, top-selling products
- **Export**: sales & inventory data to **CSV**, **Excel (.xlsx)**, and **PDF**
- **Backup & Restore**: one-click local database backup/restore
- **User Management**: add/edit/disable users, reset passwords, assign roles
- **Settings**: store info, tax rate, currency symbol, invoice prefix, receipt
  footer, low-stock threshold, category management

## Requirements

- Windows 10/11 (also runs on macOS/Linux for development/testing)
- Python 3.10+

## Installation

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py
```

On first run the app automatically creates `motoparts_pos.db` (SQLite database)
in the project folder and seeds it with:

- Default administrator account: **username `admin` / password `admin123`**
  (change this immediately from **Settings → User Management**)
- A starter set of product categories

## Project Structure

```
motoparts_pos/
├── main.py                    # Application entry point, navigation shell
├── requirements.txt
├── database/
│   ├── db.py                  # SQLite access layer (all queries live here)
│   └── schema.sql             # Database schema
├── core/
│   ├── export_utils.py        # CSV / Excel / PDF export helpers
│   ├── print_utils.py         # Receipt & invoice generation + printing
│   └── backup.py              # Backup / restore helpers
├── ui/
│   ├── widgets.py             # Reusable UI components (tables, dialogs, forms)
│   ├── login_window.py        # Login screen
│   ├── dashboard_module.py    # Dashboard
│   ├── pos_module.py          # Point of Sale
│   ├── products_module.py     # Product management
│   ├── inventory_module.py    # Stock adjustments & levels
│   ├── suppliers_module.py    # Supplier records
│   ├── customers_module.py    # Customer records
│   ├── sales_module.py        # Sales history / reprint
│   ├── reports_module.py      # Analytics & exports
│   ├── settings_module.py     # Store settings, categories, backup, export
│   └── users_module.py        # User/role management (admin only)
├── receipts/                  # Generated invoices/receipts are saved here
├── exports/                   # Default folder for CSV/Excel/PDF exports
└── backups/                   # Database backup files
```

## Printing Notes

The system always generates a proper invoice file (PDF if `reportlab` is
installed, otherwise a formatted plain-text receipt) and saves a permanent
copy under `receipts/<invoice_number>.pdf`. On Windows it is then sent to your
**default printer** automatically. If no printer is configured, the file is
simply opened for preview so you can print manually or export it. Every past
invoice can be reprinted at any time from **Sales History**.

## Roles

| Feature                | Admin | Cashier |
|-------------------------|:-----:|:-------:|
| Dashboard               |  ✔    |  ✔ (own)|
| Point of Sale            |  ✔    |  ✔      |
| Sales History            |  ✔    |  ✔ (own)|
| Customers                |  ✔    |  ✔      |
| Products / Inventory     |  ✔    |         |
| Suppliers                |  ✔    |         |
| Reports                  |  ✔    |         |
| User Management          |  ✔    |         |
| Settings                 |  ✔    |         |

## Backing Up Your Data

Go to **Settings → Backup & Restore** to create a timestamped copy of the
database, or restore from a previous backup. It's recommended to back up
regularly (e.g., at the end of each business day) and store copies on a USB
drive or external location, since this is a fully offline, local-only system.

## Optional Dependencies

- `openpyxl` — required only for Excel (.xlsx) export
- `reportlab` — required only for PDF invoices/reports
- `pywin32` — improves silent printing on Windows

If any of these aren't installed, the relevant feature shows a clear message
telling you which package to install — the rest of the app keeps working.
