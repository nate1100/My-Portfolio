"""
Receipt / invoice generation and printing.

Printing strategy (works fully offline):
 - Always generate a proper PDF invoice/receipt (via reportlab, if installed).
 - On Windows, send the PDF straight to the default printer using the
   `os.startfile(path, "print")` verb (uses whatever printer driver Windows has
   configured - no internet required).
 - If reportlab isn't installed, or we're not on Windows, fall back to a plain
   text receipt file that can be opened / printed manually, and we still try
   os.startfile(path, "print") for .txt on Windows.
 - Everything is saved under /receipts so invoices can always be reprinted later.
"""

import os
import sys
import platform
import textwrap

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIPTS_DIR = os.path.join(BASE_DIR, "receipts")
os.makedirs(RECEIPTS_DIR, exist_ok=True)

LINE_WIDTH = 42  # characters, typical for 80mm thermal receipt paper


def _center(text, width=LINE_WIDTH):
    return text.center(width)


def _line(char="-", width=LINE_WIDTH):
    return char * width


def _kv_line(label, value, width=LINE_WIDTH):
    value = str(value)
    space = width - len(label) - len(value)
    if space < 1:
        space = 1
    return f"{label}{' ' * space}{value}"


def build_receipt_text(store_info, sale, items, currency="PHP "):
    """sale and items are sqlite3.Row / dict-like objects."""
    w = LINE_WIDTH
    lines = []
    lines.append(_center(store_info.get("store_name", "Store")))
    if store_info.get("store_address"):
        for chunk in textwrap.wrap(store_info["store_address"], w):
            lines.append(_center(chunk))
    if store_info.get("store_phone"):
        lines.append(_center(f"Tel: {store_info['store_phone']}"))
    lines.append(_line("="))
    lines.append(_kv_line("Invoice #:", sale["invoice_number"]))
    lines.append(_kv_line("Date:", sale["created_at"]))
    lines.append(_kv_line("Cashier:", sale["cashier_name"]))
    lines.append(_kv_line("Customer:", sale["customer_name"] or "Walk-in"))
    lines.append(_line("-"))
    lines.append(f"{'Item':<20}{'Qty':>4}{'Price':>8}{'Total':>10}")
    lines.append(_line("-"))
    for it in items:
        name = it["product_name"]
        for i, chunk in enumerate(textwrap.wrap(name, 20) or [""]):
            if i == 0:
                lines.append(f"{chunk:<20}{it['quantity']:>4}"
                              f"{it['unit_price']:>8.2f}{it['line_total']:>10.2f}")
            else:
                lines.append(f"{chunk:<20}")
    lines.append(_line("-"))
    lines.append(_kv_line("Subtotal:", f"{currency}{sale['subtotal']:.2f}"))
    if sale["discount_amount"]:
        lines.append(_kv_line("Discount:", f"-{currency}{sale['discount_amount']:.2f}"))
    lines.append(_kv_line(f"Tax ({sale['tax_rate']:.1f}%):", f"{currency}{sale['tax_amount']:.2f}"))
    lines.append(_line("="))
    lines.append(_kv_line("TOTAL:", f"{currency}{sale['total']:.2f}"))
    lines.append(_kv_line("Payment:", sale["payment_method"]))
    lines.append(_kv_line("Amount Paid:", f"{currency}{sale['amount_paid']:.2f}"))
    lines.append(_kv_line("Change:", f"{currency}{sale['change_due']:.2f}"))
    lines.append(_line("="))
    footer = store_info.get("receipt_footer", "")
    for chunk in textwrap.wrap(footer, w):
        lines.append(_center(chunk))
    lines.append("")
    return "\n".join(lines)


def save_receipt_text(sale, text):
    path = os.path.join(RECEIPTS_DIR, f"{sale['invoice_number']}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def build_invoice_pdf(store_info, sale, items, currency="PHP "):
    """Generates a full-page PDF invoice (nicer than the thermal receipt) and
    returns the file path. Requires reportlab."""
    from reportlab.lib.pagesizes import A5
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                     Paragraph, Spacer)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT

    path = os.path.join(RECEIPTS_DIR, f"{sale['invoice_number']}.pdf")
    doc = SimpleDocTemplate(path, pagesize=A5, topMargin=10 * mm, bottomMargin=10 * mm,
                             leftMargin=10 * mm, rightMargin=10 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=14, alignment=TA_CENTER)
    normal_center = ParagraphStyle("nc", parent=styles["Normal"], alignment=TA_CENTER)

    elements = [Paragraph(store_info.get("store_name", "Store"), title_style)]
    if store_info.get("store_address"):
        elements.append(Paragraph(store_info["store_address"], normal_center))
    if store_info.get("store_phone"):
        elements.append(Paragraph(f"Tel: {store_info['store_phone']}", normal_center))
    elements.append(Spacer(1, 8))

    info_data = [
        ["Invoice #:", sale["invoice_number"], "Date:", sale["created_at"]],
        ["Cashier:", sale["cashier_name"], "Customer:", sale["customer_name"] or "Walk-in"],
    ]
    info_table = Table(info_data, colWidths=[55, 100, 45, 100])
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 8))

    item_rows = [["Item", "Qty", "Unit Price", "Total"]]
    for it in items:
        item_rows.append([it["product_name"], str(it["quantity"]),
                           f"{currency}{it['unit_price']:.2f}", f"{currency}{it['line_total']:.2f}"])
    item_table = Table(item_rows, colWidths=[150, 30, 60, 60])
    item_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
    ]))
    elements.append(item_table)
    elements.append(Spacer(1, 8))

    totals_data = [
        ["Subtotal:", f"{currency}{sale['subtotal']:.2f}"],
        ["Discount:", f"-{currency}{sale['discount_amount']:.2f}"],
        [f"Tax ({sale['tax_rate']:.1f}%):", f"{currency}{sale['tax_amount']:.2f}"],
        ["TOTAL:", f"{currency}{sale['total']:.2f}"],
        ["Payment Method:", sale["payment_method"]],
        ["Amount Paid:", f"{currency}{sale['amount_paid']:.2f}"],
        ["Change:", f"{currency}{sale['change_due']:.2f}"],
    ]
    totals_table = Table(totals_data, colWidths=[300, 100])
    totals_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTNAME", (0, 3), (-1, 3), "Helvetica-Bold"),
        ("LINEABOVE", (0, 3), (-1, 3), 0.5, colors.black),
    ]))
    elements.append(totals_table)
    elements.append(Spacer(1, 10))

    if store_info.get("receipt_footer"):
        elements.append(Paragraph(store_info["receipt_footer"], normal_center))

    doc.build(elements)
    return path


def print_file(filepath):
    """Send a file to the default printer if possible, otherwise open it for
    manual printing/preview. Always safe to call on any OS."""
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(filepath, "print")  # noqa: type: ignore
            return True, "Sent to default printer."
        elif system == "Darwin":
            os.system(f'lp "{filepath}" >/dev/null 2>&1 || open "{filepath}"')
            return True, "Sent to printer (or opened for preview)."
        else:
            # Linux - try lp/lpr, fall back to opening the file
            ret = os.system(f'lp "{filepath}" >/dev/null 2>&1')
            if ret != 0:
                os.system(f'xdg-open "{filepath}" >/dev/null 2>&1')
            return True, "Sent to printer (or opened for preview)."
    except Exception as e:
        return False, f"Could not print automatically ({e}). File saved at: {filepath}"


def open_file(filepath):
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(filepath)  # noqa
        elif system == "Darwin":
            os.system(f'open "{filepath}"')
        else:
            os.system(f'xdg-open "{filepath}" >/dev/null 2>&1')
        return True
    except Exception:
        return False


def generate_and_get_invoice_file(store_info, sale, items, currency="PHP "):
    """Tries to build a PDF invoice; falls back to a text receipt file.
    Returns (filepath, kind) where kind is 'pdf' or 'txt'."""
    try:
        path = build_invoice_pdf(store_info, sale, items, currency)
        return path, "pdf"
    except Exception:
        text = build_receipt_text(store_info, sale, items, currency)
        path = save_receipt_text(sale, text)
        return path, "txt"
