import os
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import simpledialog
import sqlite3
from datetime import datetime
from urllib.parse import quote
import qrcode
from PIL import ImageTk
import security
from case_logic import (
    calculate_risk,
    classify_scam,
    initialize_case_support,
)


# =========================================================
# CECMS - CYBERCRIME EARLY-WARNING MANAGEMENT SYSTEM
# =========================================================

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cecms.db"
)


def request_totp_enrollment_code(parent, username, secret):

    account_name = quote(f"CECMS:{username}")
    issuer = quote("CECMS")
    provisioning_uri = (
        f"otpauth://totp/{account_name}?secret={secret}&issuer={issuer}"
        "&algorithm=SHA1&digits=6&period=30"
    )
    qr = qrcode.QRCode(box_size=6, border=3)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_photo = ImageTk.PhotoImage(qr_image)

    dialog = tk.Toplevel(parent)
    dialog.title("Set Up Authenticator")
    dialog.transient(parent)
    dialog.resizable(False, False)
    dialog.grab_set()

    tk.Label(
        dialog,
        text="Scan this QR code with your authenticator app",
        font=("Arial", 11, "bold")
    ).pack(padx=18, pady=(16, 8))

    qr_label = tk.Label(dialog, image=qr_photo)
    qr_label.image = qr_photo
    qr_label.pack(padx=12, pady=4)

    tk.Label(
        dialog,
        text="If scanning is unavailable, enter this setup key manually:",
        wraplength=340,
        justify="left"
    ).pack(anchor="w", padx=18, pady=(10, 4))

    key_label = tk.Label(
        dialog,
        text=secret,
        font=("Consolas", 11, "bold"),
        wraplength=340
    )
    key_label.pack(anchor="w", padx=18, pady=4)

    def copy_setup_key():

        dialog.clipboard_clear()
        dialog.clipboard_append(secret)
        messagebox.showinfo(
            "Authenticator Setup",
            "Setup key copied. Paste it into your authenticator app.",
            parent=dialog
        )

    ttk.Button(
        dialog,
        text="COPY SETUP KEY",
        command=copy_setup_key
    ).pack(anchor="w", padx=18, pady=4)

    tk.Label(
        dialog,
        text="Keep the key private. Enter the current 6-digit code below.",
        wraplength=340,
        justify="left"
    ).pack(anchor="w", padx=18, pady=(8, 4))

    code_entry = tk.Entry(dialog, width=12, justify="center")
    code_entry.pack(pady=8)
    result = {"code": None}

    def finish():

        result["code"] = code_entry.get().strip()
        dialog.destroy()

    buttons = tk.Frame(dialog)
    buttons.pack(fill="x", padx=18, pady=(4, 16))
    ttk.Button(buttons, text="CANCEL", command=dialog.destroy).pack(side="right")
    ttk.Button(buttons, text="VERIFY", command=finish).pack(side="right", padx=8)
    dialog.bind("<Return>", lambda event: finish())
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    code_entry.focus_set()
    parent.wait_window(dialog)
    return result["code"]


# =========================================================
# DATABASE
# =========================================================

def connect_database():
    return sqlite3.connect(DATABASE, timeout=15)


def create_database():
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim_name TEXT NOT NULL,
            platform TEXT NOT NULL,
            business_name TEXT,
            contact TEXT,
            product TEXT NOT NULL,
            description TEXT NOT NULL,
            amount_lost REAL DEFAULT 0,
            risk_level TEXT,
            status TEXT,
            created_at TEXT,
            scam_type TEXT NOT NULL DEFAULT 'Other or unclassified',
            banking_involved INTEGER NOT NULL DEFAULT 0,
            account_compromised INTEGER NOT NULL DEFAULT 0,
            personal_info_exposed INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT 'legacy'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS contact_alert_reviews (
            contact TEXT PRIMARY KEY,
            decision TEXT NOT NULL DEFAULT 'PENDING',
            reviewer TEXT,
            reviewed_at TEXT
        )
    """)

    columns = {
        column[1]
        for column in cursor.execute(
            "PRAGMA table_info(reports)"
        )
    }

    if "contact" not in columns:

        cursor.execute(
            "ALTER TABLE reports ADD COLUMN contact TEXT"
        )

        if "whatsapp_number" in columns:

            cursor.execute("""
                UPDATE reports
                SET contact = whatsapp_number
                WHERE whatsapp_number IS NOT NULL
            """)

    if "scam_type" not in columns:

        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN scam_type TEXT NOT NULL DEFAULT 'Unclassified'
        """)

    for column in (
        "banking_involved",
        "account_compromised",
        "personal_info_exposed",
        "created_by"
    ):

        if column not in columns:

            definition = (
                "TEXT NOT NULL DEFAULT 'legacy'" if column == "created_by"
                else "INTEGER NOT NULL DEFAULT 0"
            )
            cursor.execute(
                f"ALTER TABLE reports ADD COLUMN {column} {definition}"
            )

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_contact ON reports(contact)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_risk ON reports(risk_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(scam_type)")

    cursor.execute("""
        UPDATE reports
        SET status = 'SUBMITTED'
        WHERE status = 'NEW'
    """)

    initialize_case_support(connection)

    connection.commit()
    connection.close()


# =========================================================
# MAIN APPLICATION
# =========================================================

class CECMSApp:

    def __init__(self, root, current_user):

        self.root = root
        self.current_user = current_user

        self.root.title(
            "CECMS - Cybercrime Early-Warning Management System"
        )

        self.root.geometry("1100x700")

        self.root.minsize(900, 600)

        self.create_styles()

        self.create_layout()

        if self.current_user.get("system_locked"):

            self.show_security_center()

        else:

            self.show_dashboard()


    # =====================================================
    # STYLES
    # =====================================================

    def create_styles(self):

        style = ttk.Style()

        style.theme_use("clam")

        style.configure(
            "Title.TLabel",
            font=("Arial", 22, "bold")
        )

        style.configure(
            "Heading.TLabel",
            font=("Arial", 16, "bold")
        )

        style.configure(
            "Menu.TButton",
            font=("Arial", 11),
            padding=10
        )

        style.configure(
            "Action.TButton",
            font=("Arial", 11, "bold"),
            padding=10
        )


    # =====================================================
    # MAIN LAYOUT
    # =====================================================

    def create_layout(self):

        # -----------------------------
        # TOP HEADER
        # -----------------------------

        header = tk.Frame(
            self.root,
            height=70
        )

        header.pack(
            side="top",
            fill="x"
        )

        title = tk.Label(
            header,
            text="CECMS",
            font=("Arial", 24, "bold")
        )

        title.pack(
            side="left",
            padx=25,
            pady=15
        )

        subtitle = tk.Label(
            header,
            text="Cybercrime Early-Warning Management System",
            font=("Arial", 11)
        )

        subtitle.pack(
            side="left",
            pady=20
        )

        tk.Label(
            header,
            text=f"{self.current_user['username']} | {self.current_user['role']}"
        ).pack(
            side="right",
            padx=16
        )

        ttk.Button(
            header,
            text="SIGN OUT",
            command=self.root.destroy
        ).pack(
            side="right",
            padx=8
        )


        # -----------------------------
        # LEFT MENU
        # -----------------------------

        self.sidebar = tk.Frame(
            self.root,
            width=220
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        self.sidebar.pack_propagate(False)


        tk.Label(
            self.sidebar,
            text="MENU",
            font=("Arial", 12, "bold")
        ).pack(
            pady=(25, 15)
        )


        system_locked = security.system_lock_status(DATABASE)[0]

        if system_locked:

            tk.Label(
                self.sidebar,
                text="APPLICATION LOCKED",
                font=("Arial", 10, "bold")
            ).pack(pady=8)

            self.menu_button("Privacy and Access Use", self.show_privacy)

            if security.is_administrator(self.current_user):

                self.menu_button("Security Center", self.show_security_center)
                self.menu_button("Audit Log", self.show_audit_log)
                self.menu_button("Database Maintenance", self.show_database_maintenance)

        else:

            self.menu_button("Dashboard", self.show_dashboard)
            self.menu_button("Report Cybercrime", self.show_report_form)
            self.menu_button("View Reports", self.show_reports)

            if security.is_reviewer(self.current_user):

                self.menu_button("Search Contact", self.show_search)

            self.menu_button("Early-Warning Alerts", self.show_alerts)
            self.menu_button("Privacy and Access Use", self.show_privacy)

            if security.is_administrator(self.current_user):

                self.menu_button("Create Staff Account", self.create_staff_account)
                self.menu_button("Security Center", self.show_security_center)
                self.menu_button("Audit Log", self.show_audit_log)
                self.menu_button("Database Maintenance", self.show_database_maintenance)



        # -----------------------------
        # CONTENT AREA
        # -----------------------------

        self.content = tk.Frame(
            self.root
        )

        self.content.pack(
            side="right",
            fill="both",
            expand=True
        )


    # =====================================================
    # MENU BUTTON
    # =====================================================

    def menu_button(self, text, command):

        button = ttk.Button(
            self.sidebar,
            text=text,
            style="Menu.TButton",
            command=command
        )

        button.pack(
            fill="x",
            padx=15,
            pady=5
        )


    def create_staff_account(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        username = simpledialog.askstring(
            "Create Staff Account",
            "New username:",
            parent=self.root
        )

        if username is None:

            return

        role = choose_role_gui(self.root, "Create Staff Account")

        if role is None:

            return

        password = simpledialog.askstring(
            "Create Staff Account",
            "Password (12+ characters):",
            show="*",
            parent=self.root
        )

        if password is None:

            return

        confirmation = simpledialog.askstring(
            "Create Staff Account",
            "Confirm password:",
            show="*",
            parent=self.root
        )

        if password != confirmation:

            messagebox.showerror("Account", "Passwords do not match.")
            return

        secret = security.generate_totp_secret()
        code = request_totp_enrollment_code(
            self.root,
            username,
            secret
        )

        if code is None:

            return

        while True:

            try:

                security.create_user(
                    DATABASE,
                    username,
                    password,
                    role,
                    secret,
                    code.strip()
                )
                messagebox.showinfo("Account", "Staff account created.")
                return

            except ValueError as error:

                messagebox.showerror("Account", str(error))

                if "username" not in str(error).casefold():

                    return

                username = simpledialog.askstring(
                    "Create Staff Account",
                    "Choose a different username:",
                    parent=self.root
                )

                if username is None:

                    return

            except sqlite3.IntegrityError as error:

                messagebox.showerror("Account", str(error))
                return


    def show_security_center(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        self.clear_content()
        tk.Label(
            self.content,
            text="Locked Accounts",
            font=("Arial", 20, "bold")
        ).pack(anchor="w", padx=25, pady=20)

        system_locked, locked_by, locked_at, lock_reason = security.system_lock_status(DATABASE)
        system_status = (
            f"Application locked by {locked_by} at {locked_at}: {lock_reason}"
            if system_locked else "Application is unlocked"
        )
        tk.Label(
            self.content,
            text=system_status,
            wraplength=800,
            justify="left"
        ).pack(anchor="w", padx=25, pady=6)

        ttk.Button(
            self.content,
            text="UNLOCK APPLICATION" if system_locked else "LOCK APPLICATION",
            command=self.toggle_application_lock
        ).pack(anchor="w", padx=25, pady=6)

        columns = ("Username", "Attempts", "Last Failure", "IP", "Device", "Locked Until")
        self.locked_users_table = ttk.Treeview(
            self.content,
            columns=columns,
            show="headings",
            height=12
        )

        for column in columns:

            self.locked_users_table.heading(column, text=column)
            self.locked_users_table.column(column, width=125)

        self.locked_users_table.pack(fill="both", expand=True, padx=25, pady=10)

        for user in security.list_locked_users(DATABASE, self.current_user):

            self.locked_users_table.insert("", "end", values=user)

        ttk.Button(
            self.content,
            text="UNLOCK SELECTED ACCOUNT",
            command=self.unlock_selected_account
        ).pack(pady=12)


    def toggle_application_lock(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        currently_locked = security.system_lock_status(DATABASE)[0]

        if currently_locked:

            confirmed = messagebox.askyesno(
                "Unlock Application",
                "Unlock case access for signed-in users?",
                parent=self.root
            )

            if not confirmed:

                return

            security.set_system_lock(DATABASE, self.current_user, False)
            message = "Application unlocked. Restart and sign in to resume case access."

        else:

            reason = simpledialog.askstring(
                "Lock Application",
                "Reason for locking case access:",
                parent=self.root
            )

            if reason is None:

                return

            security.set_system_lock(DATABASE, self.current_user, True, reason)
            message = "Application locked. Case access is suspended; restart to enter the Administrator security view."

        messagebox.showinfo("Application Lock", message, parent=self.root)
        self.root.after(250, self.root.destroy)


    def require_unlocked_system(self):

        if not security.system_lock_status(DATABASE)[0]:

            return True

        messagebox.showerror(
            "Application Locked",
            "An Administrator has suspended case access."
        )
        return False


    def unlock_selected_account(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        selected = self.locked_users_table.selection()

        if not selected:

            messagebox.showwarning("Unlock Account", "Select a locked account first.")
            return

        username = self.locked_users_table.item(selected[0], "values")[0]

        try:

            security.unlock_user(DATABASE, username, self.current_user)
            messagebox.showinfo("Unlock Account", f"{username} was unlocked.")
            self.show_security_center()

        except (PermissionError, sqlite3.Error) as error:

            messagebox.showerror("Unlock Account", str(error))


    def show_audit_log(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        self.clear_content()
        tk.Label(
            self.content,
            text="Audit Log",
            font=("Arial", 20, "bold")
        ).pack(anchor="w", padx=25, pady=20)

        output = tk.Text(self.content, height=24, width=110, state="normal")
        output.pack(fill="both", expand=True, padx=25, pady=10)

        for username, action, event_time, ip, hostname, details in security.recent_audit_events(
            DATABASE,
            self.current_user
        ):

            output.insert(
                tk.END,
                f"{event_time} | {username} | {action} | {ip} | {hostname} | {details}\n"
            )

        output.configure(state="disabled")


    def show_database_maintenance(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        self.clear_content()
        tk.Label(
            self.content,
            text="Database Maintenance",
            font=("Arial", 20, "bold")
        ).pack(anchor="w", padx=25, pady=20)

        ttk.Button(
            self.content,
            text="CREATE DATABASE BACKUP",
            command=self.create_database_backup
        ).pack(anchor="w", padx=25, pady=8)

        ttk.Button(
            self.content,
            text="CHECK DATABASE INTEGRITY",
            command=self.run_integrity_check
        ).pack(anchor="w", padx=25, pady=8)


    def create_database_backup(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        try:

            backup_path = security.backup_database(DATABASE, self.current_user)
            messagebox.showinfo("Database Backup", f"Backup created:\n{backup_path}")

        except (OSError, sqlite3.Error, PermissionError) as error:

            messagebox.showerror("Database Backup", str(error))


    def run_integrity_check(self):

        if not security.is_administrator(self.current_user):

            messagebox.showerror("Access denied", "Administrator access required.")
            return

        try:

            result = security.check_database_integrity(DATABASE, self.current_user)
            messagebox.showinfo("Database Integrity", result)

        except (sqlite3.Error, PermissionError) as error:

            messagebox.showerror("Database Integrity", str(error))

    # =====================================================
    # CLEAR CONTENT
    # =====================================================

    def clear_content(self):

        pending_submit = getattr(
            self,
            "auto_submit_after_id",
            None
        )

        if pending_submit is not None:

            self.root.after_cancel(pending_submit)
            self.auto_submit_after_id = None

        for widget in self.content.winfo_children():

            widget.destroy()


    # =====================================================
    # DASHBOARD
    # =====================================================

    def show_dashboard(self):

        if not self.require_unlocked_system():

            return

        self.clear_content()

        tk.Label(
            self.content,
            text="Dashboard",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 20)
        )


        connection = connect_database()
        cursor = connection.cursor()


        cursor.execute(
            "SELECT COUNT(*) FROM reports"
        )

        total_reports = cursor.fetchone()[0]


        cursor.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE risk_level = 'HIGH'
        """)

        high_risk = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE risk_level = 'MEDIUM'
        """)
        medium_risk = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE risk_level = 'LOW'
        """)
        low_risk = cursor.fetchone()[0]


        cursor.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE status != 'CLOSED'
        """)

        open_reports = cursor.fetchone()[0]


        if security.is_reviewer(self.current_user):

            cursor.execute("""
                SELECT COALESCE(SUM(amount_lost), 0)
                FROM reports
            """)

            total_loss = cursor.fetchone()[0]


        connection.close()


        # -----------------------------
        # STATISTICS
        # -----------------------------

        cards = tk.Frame(
            self.content
        )

        cards.pack(
            fill="x",
            padx=30
        )


        self.dashboard_card(
            cards,
            "TOTAL REPORTS",
            str(total_reports)
        )


        self.dashboard_card(
            cards,
            "HIGH-RISK CASES",
            str(high_risk)
        )

        self.dashboard_card(
            cards,
            "MEDIUM-RISK CASES",
            str(medium_risk)
        )

        self.dashboard_card(
            cards,
            "LOW-RISK CASES",
            str(low_risk)
        )


        self.dashboard_card(
            cards,
            "OPEN REPORTS",
            str(open_reports)
        )


        if security.is_reviewer(self.current_user):

            self.dashboard_card(
                cards,
                "REPORTED LOSS",
                f"R{total_loss:,.2f}"
            )


        # -----------------------------
        # INFORMATION
        # -----------------------------

        information = tk.Frame(
            self.content
        )

        information.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=30
        )


        tk.Label(
            information,
            text="About CECMS",
            font=("Arial", 16, "bold")
        ).pack(
            anchor="w"
        )


        text = (
            "Potential scam classifications and repeated-contact alerts "
            "are investigation leads, not proof of guilt. An Investigator must "
            "verify alerts before case action."
        )


        tk.Label(
            information,
            text=text,
            font=("Arial", 11),
            justify="left",
            wraplength=750
        ).pack(
            anchor="w",
            pady=15
        )


    def show_privacy(self):

        self.clear_content()

        tk.Label(
            self.content,
            text="Privacy and Access Use",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(30, 20)
        )

        principles = (
            "No automatic criminal label: indicators are leads for investigation, not proof of guilt.",
            "Controlled access: Authorized users see limited report fields; Investigators can access full details.",
            "Minimize exposure: personal contact and victim details are restricted to Investigators.",
            "Human verification: Investigators confirm or dismiss repeated-contact alerts before case action.",
            "Assist: the system connects information and supports cybersecurity investigations; it does not determine guilt.",
        )

        for principle in principles:

            tk.Label(
                self.content,
                text=principle,
                font=("Arial", 12),
                justify="left",
                wraplength=760
            ).pack(
                anchor="w",
                padx=30,
                pady=8
            )


    # =====================================================
    # DASHBOARD CARD
    # =====================================================

    def dashboard_card(
        self,
        parent,
        title,
        value
    ):

        card = tk.Frame(
            parent,
            width=190,
            height=120,
            relief="solid",
            borderwidth=1
        )

        card.pack(
            side="left",
            padx=8,
            fill="both",
            expand=True
        )

        card.pack_propagate(False)


        tk.Label(
            card,
            text=title,
            font=("Arial", 10, "bold")
        ).pack(
            pady=(20, 5)
        )


        tk.Label(
            card,
            text=value,
            font=("Arial", 22, "bold")
        ).pack()


    # =====================================================
    # REPORT FORM
    # =====================================================

    def show_report_form(self):

        if not self.require_unlocked_system():

            return

        self.clear_content()
        self.auto_submit_after_id = None


        tk.Label(
            self.content,
            text="Report Cybercrime",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=(25, 20)
        )


        form = tk.Frame(
            self.content
        )

        form.pack(
            padx=30,
            fill="both",
            expand=True
        )


        # Victim name

        tk.Label(
            form,
            text="Reporter Name (optional)"
        ).grid(
            row=0,
            column=0,
            sticky="w",
            pady=7
        )


        self.victim_entry = tk.Entry(
            form,
            width=55
        )

        self.victim_entry.grid(
            row=0,
            column=1,
            pady=7
        )


        # Incident location

        tk.Label(
            form,
            text="Where did the incident happen?",
            wraplength=220,
            justify="left"
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=7
        )


        self.platform_combo = tk.Entry(
            form,
            width=55
        )

        self.platform_combo.grid(
            row=1,
            column=1,
            pady=7
        )

        # Business

        tk.Label(
            form,
            text="Organization or Person Involved (optional)",
            wraplength=220,
            justify="left"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            pady=7
        )


        self.business_entry = tk.Entry(
            form,
            width=55
        )

        self.business_entry.grid(
            row=2,
            column=1,
            pady=7
        )


        # Contact

        tk.Label(
            form,
            text="Related Contact or Indicator (optional)",
            wraplength=220,
            justify="left"
        ).grid(
            row=3,
            column=0,
            sticky="w",
            pady=7
        )


        self.contact_entry = tk.Entry(
            form,
            width=55
        )

        self.contact_entry.grid(
            row=3,
            column=1,
            pady=7
        )


        # Message details

        tk.Label(
            form,
            text="What happened? Include any message, call, request, or activity.",
            wraplength=220,
            justify="left"
        ).grid(
            row=4,
            column=0,
            sticky="nw",
            pady=7
        )

        self.description_text = tk.Text(
            form,
            width=42,
            height=5
        )

        self.description_text.grid(
            row=4,
            column=1,
            pady=7
        )

        self.scam_type_value = tk.StringVar(
            value="Enter message details to classify"
        )

        tk.Label(
            form,
            text="Detected Classification"
        ).grid(
            row=5,
            column=0,
            sticky="w",
            pady=7
        )

        ttk.Label(
            form,
            textvariable=self.scam_type_value
        ).grid(
            row=5,
            column=1,
            sticky="w",
            pady=7
        )

        tk.Label(
            form,
            text="Evidence note or reference (optional)",
            wraplength=220,
            justify="left"
        ).grid(
            row=9,
            column=0,
            sticky="nw",
            pady=7
        )

        self.evidence_text = tk.Text(
            form,
            width=42,
            height=3
        )
        self.evidence_text.grid(row=9, column=1, pady=7)

        self.evidence_text.bind(
            "<KeyRelease>",
            self.schedule_auto_submit
        )

        self.banking_var = tk.BooleanVar(value=False)
        self.account_compromised_var = tk.BooleanVar(value=False)
        self.personal_info_var = tk.BooleanVar(value=False)

        impact_frame = tk.Frame(form)
        impact_frame.grid(
            row=6,
            column=1,
            sticky="w",
            pady=4
        )

        tk.Label(
            form,
            text="Impact (select all that apply)"
        ).grid(
            row=6,
            column=0,
            sticky="nw",
            pady=7
        )

        for text, variable in (
            ("Bank or payment account involved", self.banking_var),
            ("Account accessed or taken over", self.account_compromised_var),
            ("Personal information exposed", self.personal_info_var)
        ):

            ttk.Checkbutton(
                impact_frame,
                text=text,
                variable=variable,
                command=self.schedule_auto_submit
            ).pack(anchor="w")


        # Product

        tk.Label(
            form,
            text="Product or Service (optional)"
        ).grid(
            row=7,
            column=0,
            sticky="w",
            pady=7
        )


        self.product_entry = tk.Entry(
            form,
            width=55
        )

        self.product_entry.grid(
            row=7,
            column=1,
            pady=7
        )


        # Amount

        tk.Label(
            form,
            text="Financial Loss (R; 0 if none/unknown)"
        ).grid(
            row=10,
            column=0,
            sticky="w",
            pady=7
        )


        self.amount_entry = tk.Entry(
            form,
            width=55
        )

        self.amount_entry.grid(
            row=10,
            column=1,
            pady=7
        )

        for entry in (
            self.victim_entry,
            self.platform_combo,
            self.business_entry,
            self.contact_entry,
            self.product_entry,
            self.amount_entry
        ):

            entry.bind(
                "<KeyRelease>",
                self.schedule_auto_submit
            )
            entry.bind(
                "<FocusOut>",
                self.schedule_auto_submit
            )

        self.description_text.bind(
            "<KeyRelease>",
            self.update_detected_classification
        )
        self.description_text.bind(
            "<FocusOut>",
            self.update_detected_classification
        )


        # Submit

        ttk.Button(
            form,
            text="SUBMIT REPORT",
            style="Action.TButton",
            command=self.submit_report
        ).grid(
            row=11,
            column=1,
            pady=20,
            sticky="w"
        )


    # =====================================================
    # SUBMIT REPORT
    # =====================================================

    def schedule_auto_submit(self, _event=None):

        del _event

        if self.auto_submit_after_id is not None:

            self.root.after_cancel(
                self.auto_submit_after_id
            )

        self.auto_submit_after_id = self.root.after(
            2000,
            self.submit_if_complete
        )


    def update_detected_classification(self, event=None):

        message = self.description_text.get("1.0", tk.END).strip()

        if message:

            self.scam_type_value.set(
                classify_scam(message)
            )

        else:

            self.scam_type_value.set(
                "Enter message details to classify"
            )

        self.schedule_auto_submit(event)


    def submit_if_complete(self):

        self.auto_submit_after_id = None

        if not all((
            self.platform_combo.get().strip(),
            self.description_text.get("1.0", tk.END).strip()
        )):

            return

        amount_text = self.amount_entry.get().strip()

        try:

            amount = float(amount_text if amount_text else 0)

            if amount < 0:

                messagebox.showerror(
                    "Error",
                    "Please enter a valid amount."
                )

                return

        except ValueError:

            messagebox.showerror(
                "Error",
                "Please enter a valid amount."
            )

            return

        self.submit_report()

    def submit_report(self):

        if not self.require_unlocked_system():

            return

        if self.auto_submit_after_id is not None:

            self.root.after_cancel(
                self.auto_submit_after_id
            )
            self.auto_submit_after_id = None

        victim = self.victim_entry.get().strip() or "Not provided"

        platform = self.platform_combo.get()

        business = self.business_entry.get().strip()

        contact = self.contact_entry.get().strip()

        product = self.product_entry.get().strip()

        description = (
            self.description_text
            .get("1.0", tk.END)
            .strip()
        )

        evidence_note = self.evidence_text.get("1.0", tk.END).strip()

        scam_type = classify_scam(description, platform)

        amount_text = (
            self.amount_entry
            .get()
            .strip()
        )


        # Validation

        if not victim:

            messagebox.showerror(
                "Error",
                "Please enter the victim name."
            )

            return


        if not description:

            messagebox.showerror(
                "Error",
                "Please describe what happened."
            )

            return

        if not platform:

            messagebox.showerror(
                "Error",
                "Please enter where the incident happened."
            )

            return


        try:

            amount = float(
                amount_text
                if amount_text
                else 0
            )

            if amount < 0:

                raise ValueError

        except ValueError:

            messagebox.showerror(
                "Error",
                "Please enter a valid amount."
            )

            return


        connection = connect_database()
        cursor = connection.cursor()


        # Check repeated contact

        cursor.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE contact = ?
            AND contact != ''
        """, (contact,))


        repeated_contact = (
            cursor.fetchone()[0] > 0
        )


        risk = calculate_risk(
            amount,
            repeated_contact,
            self.banking_var.get(),
            self.account_compromised_var.get(),
            self.personal_info_var.get(),
            any(word in description.casefold() for word in ("link", "url", "click"))
        )


        # Save report

        cursor.execute("""
            INSERT INTO reports (
                victim_name,
                platform,
                business_name,
                contact,
                product,
                description,
                amount_lost,
                risk_level,
                status,
                created_at,
                scam_type,
                banking_involved,
                account_compromised,
                personal_info_exposed,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            victim,
            platform,
            business,
            contact,
            product,
            description,
            amount,
            risk,
            "SUBMITTED",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            scam_type,
            int(self.banking_var.get()),
            int(self.account_compromised_var.get()),
            int(self.personal_info_var.get()),
            self.current_user["username"]
        ))


        report_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO cases (
                title, organization, category, description, priority, status,
                investigator, created_by, created_at, report_id
            ) VALUES (?, ?, ?, ?, ?, 'SUBMITTED', NULL, ?, ?, ?)
        """, (
            scam_type,
            business or "Not provided",
            scam_type,
            description,
            risk,
            self.current_user["username"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id
        ))
        case_id = cursor.lastrowid

        if contact:

            cursor.execute("""
                INSERT INTO indicators (case_id, indicator_type, indicator_value)
                VALUES (?, 'contact or URL', ?)
            """, (case_id, contact))

        if evidence_note:

            cursor.execute("""
                INSERT INTO evidence (case_id, evidence_type, description)
                VALUES (?, 'Reporter note or reference', ?)
            """, (case_id, evidence_note[:2000]))

        cursor.execute("""
            INSERT INTO access_log (username, action, case_id, log_time)
            VALUES (?, 'CASE CREATED', ?, ?)
        """, (
            self.current_user["username"],
            case_id,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        if repeated_contact:

            cursor.execute("""
                INSERT INTO contact_alert_reviews (contact, decision)
                VALUES (?, 'PENDING')
                ON CONFLICT(contact) DO UPDATE SET
                    decision = 'PENDING',
                    reviewer = NULL,
                    reviewed_at = NULL
            """, (contact,))


        connection.commit()
        connection.close()

        security.audit_event(
            DATABASE,
            self.current_user["username"],
            "CASE CREATED",
            f"Report ID {report_id}; category {scam_type}; risk {risk}"
        )

        if contact:

            security.audit_event(
                DATABASE,
                self.current_user["username"],
                "INDICATOR ADDED",
                f"Case {case_id}"
            )

        if evidence_note:

            security.audit_event(
                DATABASE,
                self.current_user["username"],
                "EVIDENCE ADDED",
                f"Case {case_id}; reporter note/reference"
            )


        message = (
            f"Report submitted successfully!\n\n"
            f"Report ID: {report_id}\n"
            f"Submission Status: SUBMITTED\n"
            f"Unverified Scam Lead: {scam_type}\n"
            f"Risk Indicator: {risk}"
        )


        if repeated_contact:

            message += (
                "\n\nWARNING:\n"
                "This phone number / email has "
                "appeared in another report."
            )


        messagebox.showinfo(
            "CECMS",
            message
        )


        self.show_dashboard()


    # =====================================================
    # VIEW REPORTS
    # =====================================================

    def show_reports(self):

        if not self.require_unlocked_system():

            return

        self.clear_content()


        tk.Label(
            self.content,
            text="Cybercrime Reports",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=25,
            pady=20
        )

        filter_bar = tk.Frame(self.content)
        filter_bar.pack(fill="x", padx=25, pady=(0, 4))

        category_connection = connect_database()
        categories = [
            row[0]
            for row in category_connection.execute("""
                SELECT DISTINCT scam_type
                FROM reports
                WHERE scam_type IS NOT NULL AND scam_type != ''
                ORDER BY scam_type
            """)
        ]
        category_connection.close()

        self.category_filter = tk.StringVar(value="All categories")
        ttk.Label(filter_bar, text="Category").pack(side="left", padx=(0, 5))
        self.category_filter_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.category_filter,
            values=["All categories", *categories],
            state="readonly",
            width=30
        )
        self.category_filter_combo.pack(side="left", padx=(0, 14))
        self.category_filter_combo.bind(
            "<<ComboboxSelected>>",
            self.apply_report_filters
        )

        self.risk_filter = tk.StringVar(value="All risks")
        ttk.Label(filter_bar, text="Risk").pack(side="left", padx=(0, 5))
        self.risk_filter_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.risk_filter,
            values=("All risks", "HIGH", "MEDIUM", "LOW"),
            state="readonly",
            width=12
        )
        self.risk_filter_combo.pack(side="left")
        self.risk_filter_combo.bind(
            "<<ComboboxSelected>>",
            self.apply_report_filters
        )


        # Table

        frame = tk.Frame(
            self.content
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10
        )


        if security.is_reviewer(self.current_user):

            columns = (
                "ID",
                "Victim",
                "Incident Location",
                "Lead (unverified)",
                "Contact",
                "Product",
                "Amount",
                "Risk",
                "Status"
            )

        else:

            columns = (
                "ID",
                "Incident Location",
                "Product",
                "Lead (unverified)",
                "Risk",
                "Status"
            )


        self.report_table = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )


        for column in columns:

            self.report_table.heading(
                column,
                text=column
            )


        self.report_table.column(
            "ID",
            width=50
        )

        for column, width in (
            ("Incident Location", 160),
            ("Product", 120),
            ("Lead (unverified)", 190),
            ("Risk", 80),
            ("Status", 140)
        ):

            self.report_table.column(column, width=width)

        if security.is_reviewer(self.current_user):

            self.report_table.column("Victim", width=120)
            self.report_table.column("Contact", width=170)
            self.report_table.column("Amount", width=90)


        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.report_table.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=self.report_table.xview
        )


        self.report_table.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )


        self.report_table.pack(
            side="left",
            fill="both",
            expand=True
        )


        scrollbar.pack(
            side="right",
            fill="y"
        )

        horizontal_scrollbar.pack(
            side="bottom",
            fill="x"
        )


        self.report_page_size = 50
        self.report_page = 0

        paging = tk.Frame(self.content)
        paging.pack(fill="x", padx=25, pady=(0, 8))

        self.report_page_label = ttk.Label(paging, text="")
        self.report_page_label.pack(side="left", padx=8)

        ttk.Button(
            paging,
            text="PREVIOUS",
            command=lambda: self.change_report_page(-1)
        ).pack(side="right", padx=4)

        ttk.Button(
            paging,
            text="NEXT",
            command=lambda: self.change_report_page(1)
        ).pack(side="right", padx=4)


        # Load reports

        self.load_reports()


        ttk.Button(
            self.content,
            text="VIEW SELECTED REPORT",
            command=self.view_selected_report
        ).pack(
            pady=15
        )


    # =====================================================
    # LOAD REPORTS
    # =====================================================

    def load_reports(self):

        if not self.require_unlocked_system():

            return

        connection = connect_database()
        cursor = connection.cursor()

        where_clauses = []
        parameters = []

        if not security.is_reviewer(self.current_user):

            where_clauses.append("created_by = ?")
            parameters.append(self.current_user["username"])

        if self.category_filter.get() != "All categories":

            where_clauses.append("scam_type = ?")
            parameters.append(self.category_filter.get())

        if self.risk_filter.get() != "All risks":

            where_clauses.append("risk_level = ?")
            parameters.append(self.risk_filter.get())

        where_sql = (
            " WHERE " + " AND ".join(where_clauses)
            if where_clauses else ""
        )

        total_reports = cursor.execute(
            "SELECT COUNT(*) FROM reports" + where_sql,
            parameters
        ).fetchone()[0]
        page_count = max(1, (total_reports + self.report_page_size - 1) // self.report_page_size)
        self.report_page = max(0, min(self.report_page, page_count - 1))
        offset = self.report_page * self.report_page_size


        if security.is_reviewer(self.current_user):

            cursor.execute("""
                SELECT
                    id, victim_name, platform, scam_type, contact,
                    product, amount_lost, risk_level, status
                FROM reports
            """ + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?", (
                *parameters,
                self.report_page_size,
                offset
            ))

        else:

            cursor.execute("""
                SELECT id, platform, product, scam_type, risk_level, status
                FROM reports
            """ + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?", (
                *parameters,
                self.report_page_size,
                offset
            ))


        reports = cursor.fetchall()

        connection.close()

        start = offset + 1 if total_reports else 0
        end = offset + len(reports)
        self.report_page_label.configure(
            text=f"Cases {start}-{end} of {total_reports}"
        )

        for item in self.report_table.get_children():

            self.report_table.delete(item)


        for report in reports:

            if security.is_reviewer(self.current_user):

                values = (
                    report[0], report[1], report[2], report[3],
                    report[4], report[5], f"R{report[6]:.2f}",
                    report[7], report[8]
                )

            else:

                values = (
                    report[0], report[1], report[2], report[3],
                    report[4], report[5]
                )

            self.report_table.insert("", "end", values=values)


    def change_report_page(self, direction):

        self.report_page += direction
        self.load_reports()


    def apply_report_filters(self, _event=None):

        del _event

        self.report_page = 0
        self.load_reports()


    # =====================================================
    # VIEW SELECTED REPORT
    # =====================================================

    def view_selected_report(self):

        if not self.require_unlocked_system():

            return

        selected = (
            self.report_table
            .selection()
        )


        if not selected:

            messagebox.showwarning(
                "CECMS",
                "Please select a report."
            )

            return


        values = (
            self.report_table
            .item(selected[0])
            ["values"]
        )


        report_id = values[0]


        connection = connect_database()
        cursor = connection.cursor()


        if security.is_reviewer(self.current_user):

            cursor.execute("""
                SELECT
                    id, victim_name, platform, business_name, contact,
                    product, description, amount_lost, risk_level, status,
                    created_at, scam_type
                FROM reports
                WHERE id = ?
            """, (report_id,))

        else:

            cursor.execute("""
                SELECT id, platform, product, risk_level, status, scam_type
                FROM reports
                WHERE id = ? AND created_by = ?
            """, (report_id, self.current_user["username"]))


        report = cursor.fetchone()

        connection.close()


        if not report:

            return

        security.audit_event(
            DATABASE,
            self.current_user["username"],
            "REPORT VIEWED",
            f"Report ID {report_id}"
        )

        if not security.is_reviewer(self.current_user):

            details = (
                f"Report ID: {report[0]}\n"
                f"Incident Location: {report[1]}\n"
                f"Product or Service: {report[2] or 'Not provided'}\n"
                f"Risk Indicator: {report[3]}\n"
                f"Case Status: {report[4]}\n"
                f"Unverified Scam Lead: {report[5]}"
            )
            messagebox.showinfo("My Report Summary", details)
            return


        details = (
            f"Report ID: {report[0]}\n\n"
            f"Victim Name: {report[1]}\n"
            f"Incident Location: {report[2]}\n"
            f"Original Business: {report[3]}\n"
            f"Phone Number / Email: {report[4]}\n"
            f"Unverified Scam Lead: {report[11]}\n"
            f"Product: {report[5]}\n\n"
            f"Description:\n{report[6]}\n\n"
            f"Amount Lost: R{report[7]:.2f}\n"
            f"Risk Indicator: {report[8]}\n"
            f"Status: {report[9]}\n"
            f"Created: {report[10]}"
        )


        messagebox.showinfo(
            "Report Details",
            details
        )


    # =====================================================
    # SEARCH
    # =====================================================

    def show_search(self):

        if not self.require_unlocked_system():

            return

        if not security.is_reviewer(self.current_user):

            messagebox.showerror("Access denied", "Investigator access required.")
            return

        self.clear_content()


        tk.Label(
            self.content,
            text="Search Phone Number / Email",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=25
        )


        search_frame = tk.Frame(
            self.content
        )

        search_frame.pack(
            padx=30,
            anchor="w"
        )


        self.search_entry = tk.Entry(
            search_frame,
            width=50
        )

        self.search_entry.pack(
            side="left",
            padx=(0, 10)
        )


        ttk.Button(
            search_frame,
            text="SEARCH",
            command=self.search_contact
        ).pack(
            side="left"
        )


        self.search_results = tk.Text(
            self.content,
            height=20,
            width=90
        )

        self.search_results.pack(
            padx=30,
            pady=20,
            fill="both",
            expand=True
        )


    # =====================================================
    # SEARCH CONTACT
    # =====================================================

    def search_contact(self):

        if not self.require_unlocked_system():

            return

        if not security.is_reviewer(self.current_user):

            messagebox.showerror("Access denied", "Investigator access required.")
            return

        contact = (
            self.search_entry
            .get()
            .strip()
        )


        if not contact:

            messagebox.showwarning(
                "Search",
                "Enter a phone number or email."
            )

            return


        connection = connect_database()
        cursor = connection.cursor()


        cursor.execute("""
            SELECT
                id,
                victim_name,
                platform,
                business_name,
                product,
                risk_level,
                status,
                scam_type
            FROM reports
            WHERE contact = ?
        """, (contact,))


        results = cursor.fetchall()

        connection.close()

        security.audit_event(
            DATABASE,
            self.current_user["username"],
            "CONTACT SEARCH"
        )


        self.search_results.delete(
            "1.0",
            tk.END
        )


        if not results:

            self.search_results.insert(
                tk.END,
                "No reports found for this contact."
            )

            return


        self.search_results.insert(
            tk.END,
            f"Found {len(results)} report(s).\n\n"
        )


        for report in results:

            self.search_results.insert(
                tk.END,
                "--------------------------------------\n"
            )

            self.search_results.insert(
                tk.END,
                f"Report ID: {report[0]}\n"
                f"Victim: {report[1]}\n"
                f"Incident Location: {report[2]}\n"
                f"Business: {report[3]}\n"
                f"Product: {report[4]}\n"
                f"Risk Indicator: {report[5]}\n"
                f"Status: {report[6]}\n"
                f"Unverified Scam Lead: {report[7]}\n\n"
            )


    # =====================================================
    # ALERTS
    # =====================================================

    def show_alerts(self):

        if not self.require_unlocked_system():

            return

        self.clear_content()


        tk.Label(
            self.content,
            text="Early-Warning Alerts",
            font=("Arial", 22, "bold")
        ).pack(
            anchor="w",
            padx=30,
            pady=25
        )


        connection = connect_database()
        cursor = connection.cursor()


        if security.is_reviewer(self.current_user):

            cursor.execute("""
                SELECT
                    reports.contact,
                    COUNT(*),
                    COALESCE(contact_alert_reviews.decision, 'PENDING'),
                    contact_alert_reviews.reviewer
                FROM reports
                LEFT JOIN contact_alert_reviews
                    ON contact_alert_reviews.contact = reports.contact
                WHERE reports.contact != ''
                GROUP BY reports.contact
                HAVING COUNT(*) > 1
                ORDER BY COUNT(*) DESC
            """)
            alerts = cursor.fetchall()

        else:

            cursor.execute("""
                SELECT decision, COUNT(*)
                FROM (
                    SELECT
                        COALESCE(contact_alert_reviews.decision, 'PENDING') AS decision
                    FROM reports
                    LEFT JOIN contact_alert_reviews
                        ON contact_alert_reviews.contact = reports.contact
                    WHERE reports.contact != ''
                    GROUP BY reports.contact
                    HAVING COUNT(*) > 1
                )
                GROUP BY decision
            """)
            review_counts = dict(cursor.fetchall())
            connection.close()

            tk.Label(
                self.content,
                text=(
                    "Repeated-contact alerts: "
                    f"{sum(review_counts.values())}\n"
                    f"Pending Investigator review: {review_counts.get('PENDING', 0)}"
                ),
                font=("Arial", 12),
                justify="left"
            ).pack(
                anchor="w",
                padx=30,
                pady=10
            )
            return

        connection.close()

        if not alerts:

            tk.Label(
                self.content,
                text="No repeated-contact alerts require review.",
                font=("Arial", 12)
            ).pack(
                padx=30,
                anchor="w"
            )
            return

        tk.Label(
            self.content,
            text="Repeated-contact indicators require human review; they do not establish guilt.",
            font=("Arial", 12),
            wraplength=760
        ).pack(
            padx=30,
            anchor="w"
        )

        for contact, count, decision, reviewer in alerts:

            alert_frame = tk.Frame(
                self.content,
                relief="solid",
                borderwidth=1
            )
            alert_frame.pack(fill="x", padx=30, pady=8)

            tk.Label(
                alert_frame,
                text=f"{contact}\nAppears in {count} reports\nReview: {decision}",
                justify="left"
            ).pack(side="left", padx=12, pady=10)

            if reviewer:

                tk.Label(
                    alert_frame,
                    text=f"Reviewed by Investigator {reviewer}"
                ).pack(side="left", padx=8)

            ttk.Button(
                alert_frame,
                text="CONFIRM LEAD",
                command=lambda value=contact: self.set_alert_review(
                    value,
                    "CONFIRMED"
                )
            ).pack(side="right", padx=6)

            ttk.Button(
                alert_frame,
                text="DISMISS",
                command=lambda value=contact: self.set_alert_review(
                    value,
                    "DISMISSED"
                )
            ).pack(side="right", padx=6)


    def set_alert_review(self, contact, decision):

        if not self.require_unlocked_system():

            return

        if not security.is_reviewer(self.current_user):

            messagebox.showerror("Access denied", "Investigator access required.")
            return

        if decision not in ("CONFIRMED", "DISMISSED"):

            return

        connection = connect_database()
        matching_reports = connection.execute("""
            SELECT COUNT(*)
            FROM reports
            WHERE contact = ?
        """, (contact,)).fetchone()[0]

        if matching_reports < 2:

            connection.close()
            messagebox.showerror(
                "Alert review",
                "A repeated-contact alert must exist before it can be reviewed."
            )
            return

        connection.execute("""
            INSERT INTO contact_alert_reviews (
                contact,
                decision,
                reviewer,
                reviewed_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(contact) DO UPDATE SET
                decision = excluded.decision,
                reviewer = excluded.reviewer,
                reviewed_at = excluded.reviewed_at
        """, (
            contact,
            decision,
            self.current_user["username"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        connection.commit()
        connection.close()
        security.audit_event(
            DATABASE,
            self.current_user["username"],
            "INDICATOR REVIEWED",
            f"Repeated-contact alert {decision.lower()}"
        )
        self.show_alerts()


def choose_role_gui(parent, title):

    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.resizable(False, False)

    selected_role = tk.StringVar(value="Authorized user")
    result = {"role": None}

    tk.Label(
        dialog,
        text="Choose your role"
    ).pack(anchor="w", padx=20, pady=(18, 8))

    for role in ("Investigator", "Authorized user"):

        ttk.Radiobutton(
            dialog,
            text=role,
            value=role,
            variable=selected_role
        ).pack(anchor="w", padx=20, pady=4)

    buttons = tk.Frame(dialog)
    buttons.pack(fill="x", padx=20, pady=16)

    def choose():

        result["role"] = selected_role.get()
        dialog.destroy()

    ttk.Button(
        buttons,
        text="CONTINUE",
        command=choose
    ).pack(side="right", padx=(8, 0))

    ttk.Button(
        buttons,
        text="CANCEL",
        command=dialog.destroy
    ).pack(side="right")

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    parent.wait_window(dialog)

    return result["role"]


def notify_administrator_gui(root, account):

    if security.is_administrator(account):

        try:

            backup_path = security.daily_backup_if_due(DATABASE, account)

            if backup_path:

                messagebox.showinfo(
                    "Daily Backup",
                    f"A daily database backup was created:\n{backup_path}",
                    parent=root
                )

        except (OSError, sqlite3.Error, PermissionError) as error:

            messagebox.showwarning(
                "Daily Backup",
                f"The daily database backup could not be created:\n{error}",
                parent=root
            )

    alerts = security.pending_security_alerts(DATABASE, account)

    if not alerts:

        return

    details = "\n".join(
        f"{username}: {attempts} failed attempts at {created_at}; "
        f"IP {ip}; device {hostname}; locked until {locked_until}"
        for _, username, attempts, created_at, ip, hostname, locked_until in alerts
    )

    messagebox.showwarning(
        "Security Warning",
        "SECURITY ALERT: account locked after three failed attempts.\n\n" + details,
        parent=root
    )

    security.acknowledge_security_alerts(
        DATABASE,
        [alert[0] for alert in alerts],
        account
    )


def startup_choice_gui(root, first_setup):

    dialog = tk.Toplevel(root)
    dialog.title("CYBER CRIME EARLY-WARNING SYSTEM")
    dialog.transient(root)
    dialog.resizable(False, False)
    result = {"choice": "exit"}

    tk.Label(
        dialog,
        text="CYBER CRIME EARLY-WARNING SYSTEM",
        font=("Arial", 16, "bold")
    ).pack(padx=22, pady=(20, 14))

    if first_setup:

        tk.Label(dialog, text="First-time secure setup").pack(pady=4)
        primary_label = "CREATE AUTHORISED ADMINISTRATOR ACCOUNT"
    else:

        primary_label = "LOGIN"

    buttons = tk.Frame(dialog)
    buttons.pack(fill="x", padx=20, pady=18)

    def select(choice):

        result["choice"] = choice
        dialog.destroy()

    ttk.Button(
        buttons,
        text=primary_label,
        command=lambda: select("setup" if first_setup else "login")
    ).pack(fill="x", pady=5)

    ttk.Button(
        buttons,
        text="EXIT",
        command=lambda: select("exit")
    ).pack(fill="x", pady=5)

    dialog.protocol("WM_DELETE_WINDOW", lambda: select("exit"))
    dialog.grab_set()
    root.wait_window(dialog)
    return result["choice"]


def create_administrator_gui(root):

    username = simpledialog.askstring(
        "Administrator Setup", "Administrator username:", parent=root
    )
    if username is None:
        return None

    password = simpledialog.askstring(
        "Administrator Setup", "Password (12+ characters):",
        show="*", parent=root
    )
    if password is None:
        return None

    confirmation = simpledialog.askstring(
        "Administrator Setup", "Confirm password:", show="*", parent=root
    )
    if password != confirmation:
        messagebox.showerror("Administrator Setup", "Passwords do not match.", parent=root)
        return None

    secret = security.generate_totp_secret()
    code = request_totp_enrollment_code(
        root,
        username,
        secret
    )
    if code is None:
        return None

    try:
        security.create_user(
            DATABASE,
            username,
            password,
            "Administrator",
            secret,
            code.strip()
        )
    except (ValueError, sqlite3.IntegrityError) as error:
        messagebox.showerror("Administrator Setup", str(error), parent=root)
        return None

    security.audit_event(DATABASE, username, "FIRST ADMIN CREATED")
    account = {"username": username, "role": "Administrator"}
    messagebox.showinfo(
        "Administrator Setup",
        "Administrator created. Setup is now permanently disabled.\n"
        "Successfully logged in.",
        parent=root
    )
    notify_administrator_gui(root, account)
    return account


def enroll_existing_user_gui(root, username, password):

    secret = security.generate_totp_secret()
    security.set_totp_secret(DATABASE, username, secret)
    code = request_totp_enrollment_code(
        root,
        username,
        secret
    )
    if code is None:
        return None
    if not security.complete_totp_enrollment(DATABASE, username, code.strip()):
        security.record_failed_login(DATABASE, username, "invalid MFA enrollment code")
        messagebox.showerror("Authenticator Setup", "Invalid code.", parent=root)
        return None
    return security.authenticate_user(DATABASE, username, password, code.strip())


def authenticate_gui(root):

    account_count = security.initialize_authentication(DATABASE)

    if account_count == 0:

        if startup_choice_gui(root, True) != "setup":
            return None
        return create_administrator_gui(root)

    while startup_choice_gui(root, False) == "login":

        username = simpledialog.askstring("Login", "Username:", parent=root)
        if username is None:
            continue
        password = simpledialog.askstring(
            "Login", "Password:", show="*", parent=root
        )
        if password is None:
            continue

        account = security.authenticate_user(DATABASE, username, password)

        if account and account.get("mfa_enrollment_required"):
            account = enroll_existing_user_gui(root, username, password)

        elif account and account.get("mfa_challenge_required"):
            code = simpledialog.askstring(
                "Two-Factor Verification",
                "Authenticator 6-digit code:",
                parent=root
            )
            if code is None:
                continue
            account = security.authenticate_user(
                DATABASE, username, password, code.strip()
            )

        if account and not account.get("mfa_enrollment_required") and not account.get("mfa_challenge_required"):

            if account.get("system_locked") and not security.is_administrator(account):

                messagebox.showerror(
                    "Application Locked",
                    "An Administrator has suspended application access.",
                    parent=root
                )
                continue

            messagebox.showinfo("Login", "Successfully logged in.", parent=root)
            notify_administrator_gui(root, account)
            return account

        attempts, locked_until = security.lockout_status(DATABASE, username)
        if locked_until:
            messagebox.showerror(
                "Account Locked",
                f"Account locked until {locked_until}. An Administrator alert was created.",
                parent=root
            )
        else:
            messagebox.showerror(
                "Login Failed",
                f"Invalid login ({attempts}/{security.LOGIN_FAILURE_LIMIT}).",
                parent=root
            )

    return None


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    root = tk.Tk()
    root.withdraw()

    def report_callback_exception(exception_type, exception, _traceback_object):

        del _traceback_object

        if issubclass(exception_type, sqlite3.Error):

            messagebox.showerror(
                "Database Error",
                "Database connection error. Please contact the system administrator.",
                parent=root
            )

        else:

            messagebox.showerror(
                "Application Error",
                f"The operation could not be completed: {exception}",
                parent=root
            )

    root.report_callback_exception = report_callback_exception

    try:

        create_database()
        current_user = authenticate_gui(root)

    except sqlite3.Error:

        messagebox.showerror(
            "Database Error",
            "Database connection error. Please contact the system administrator.",
            parent=root
        )
        current_user = None

    if current_user:

        root.deiconify()
        app = CECMSApp(root, current_user)
        root.mainloop()

    else:

        root.destroy()