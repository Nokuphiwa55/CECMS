import os
import sqlite3
import getpass
from datetime import datetime
import security
from case_logic import calculate_risk, classify_scam, initialize_case_support

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cecms.db"
)
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
            amount_lost REAL,
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


# ==========================================
# SUBMIT REPORT
# ==========================================

def ask_yes_no(prompt):

    while True:

        answer = input(f"{prompt} (y/n): ").strip().casefold()

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please answer y or n.")


def submit_report(account=None):

    print("\n========================================")
    print("        SUBMIT CYBERCRIME REPORT")
    print("========================================")

    victim_name = input("Reporter name (optional): ").strip() or "Not provided"

    platform = input(
        "Where did it happen (website, app, phone, email, in person, etc.)? "
    ).strip()

    business_name = input(
        "Organization or person involved (optional): "
    ).strip()

    contact = input(
        "Related phone, email, account, URL, or other indicator (optional): "
    ).strip()

    product = input(
        "Product or service involved (optional): "
    ).strip()

    evidence_note = input(
        "Evidence note or link (optional; do not paste passwords): "
    ).strip()

    description = input(
        "What happened? Include any message, call, request, or activity: "
    ).strip()

    banking_involved = ask_yes_no("Did this involve a bank or payment account?")
    account_compromised = ask_yes_no("Was an account accessed or taken over?")
    personal_info_exposed = ask_yes_no("Was personal information exposed?")
    scam_type = classify_scam(description, platform)

    print("Automatically classified as an unverified lead:", scam_type)

    # Get amount lost
    while True:

        try:

            amount_lost = float(
                input("Financial loss amount (R; enter 0 if none or unknown): ")
            )

            if amount_lost < 0:
                print("Amount cannot be negative.")
                continue

            break

        except ValueError:

            print(
                "Please enter a valid amount."
            )

    connection = connect_database()
    cursor = connection.cursor()

    # ==========================================
    # CHECK FOR REPEATED CONTACT
    # ==========================================

    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE contact = ?
        AND contact != ''
    """, (contact,))

    repeated_contact = cursor.fetchone()[0] > 0

    # ==========================================
    # CALCULATE RISK
    # ==========================================

    risk_level = calculate_risk(
        amount_lost,
        repeated_contact,
        banking_involved,
        account_compromised,
        personal_info_exposed,
        any(word in description.casefold() for word in ("link", "url", "click"))
    )

    # ==========================================
    # SAVE REPORT
    # ==========================================

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
        victim_name,
        platform,
        business_name,
        contact,
        product,
        description,
        amount_lost,
        risk_level,
        "SUBMITTED",
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        scam_type,
        int(banking_involved),
        int(account_compromised),
        int(personal_info_exposed),
        account["username"] if account else victim_name
    ))

    report_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO cases (
            title, organization, category, description, priority, status,
            investigator, created_by, created_at, report_id
        ) VALUES (?, ?, ?, ?, ?, 'SUBMITTED', NULL, ?, ?, ?)
    """, (
        scam_type,
        business_name or "Not provided",
        scam_type,
        description,
        risk_level,
        account["username"] if account else victim_name,
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
        account["username"] if account else victim_name,
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

    if account:

        security.audit_event(
            DATABASE,
            account["username"],
            "CASE CREATED",
            f"Report ID {report_id}; category {scam_type}; risk {risk_level}"
        )

        if contact:

            security.audit_event(
                DATABASE,
                account["username"],
                "INDICATOR ADDED",
                f"Case {case_id}"
            )

        if evidence_note:

            security.audit_event(
                DATABASE,
                account["username"],
                "EVIDENCE ADDED",
                f"Case {case_id}; reporter note/reference"
            )

    # ==========================================
    # REPORT RESULT
    # ==========================================

    print("\n========================================")
    print("       REPORT SUBMITTED SUCCESSFULLY")
    print("========================================")

    print("Report ID:", report_id)
    print("Unverified Scam Lead:", scam_type)
    print("Risk Indicator:", risk_level)

    if repeated_contact:

        print(
            "\nWARNING:"
        )

        print(
            "This phone number / email "
            "appears in another report."
        )

    else:

        print(
            "\nNo previous report was found "
            "using this contact."
        )


# ==========================================
# VIEW ALL REPORTS
# ==========================================

def view_reports(account):

    page = 0

    while True:

        page, page_count = display_report_page(account, page)

        if page_count <= 1:

            return

        choice = input("N next page, P previous page, Enter to return: ").strip().casefold()

        if choice == "n" and page + 1 < page_count:

            page += 1

        elif choice == "p" and page > 0:

            page -= 1

        else:

            return


def display_report_page(account, page):

    print("\n========================================")
    print("             ALL REPORTS")
    print("========================================")

    connection = connect_database()
    cursor = connection.cursor()
    if security.is_reviewer(account):

        total_reports = cursor.execute(
            "SELECT COUNT(*) FROM reports"
        ).fetchone()[0]

    else:

        total_reports = cursor.execute(
            "SELECT COUNT(*) FROM reports WHERE created_by = ?",
            (account["username"],)
        ).fetchone()[0]
    page_size = 50
    page_count = max(1, (total_reports + page_size - 1) // page_size)
    page = max(0, min(page, page_count - 1))
    offset = page * page_size

    print(f"Cases {offset + 1 if total_reports else 0}-"
          f"{min(offset + page_size, total_reports)} of {total_reports}")

    if security.is_reviewer(account):

        cursor.execute("""
            SELECT
                id, victim_name, platform, business_name, contact,
                product, description, amount_lost, risk_level, status,
                created_at, scam_type
            FROM reports
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (page_size, offset))

    else:

        cursor.execute("""
            SELECT id, platform, product, risk_level, status, scam_type
            FROM reports
            WHERE created_by = ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (account["username"], page_size, offset))

    reports = cursor.fetchall()

    connection.close()

    if len(reports) == 0:

        print("No reports found.")

        return page, page_count

    for report in reports:

        print("\n----------------------------------------")

        if not security.is_reviewer(account):

            print("Report ID:", report[0])
            print("Incident Location:", report[1])
            print("Product:", report[2])
            print("Risk Indicator:", report[3])
            print("Case Status:", report[4])
            print("Unverified Scam Lead:", report[5])
            continue

        print("Report ID:", report[0])

        print(
            "Victim Name:",
            report[1]
        )

        print(
            "Incident Location:",
            report[2]
        )

        print(
            "Original Business:",
            report[3]
        )

        print(
            "Phone Number / Email:",
            report[4]
        )

        print(
            "Product:",
            report[5]
        )

        print(
            "Description:",
            report[6]
        )

        print(
            "Amount Lost: R",
            report[7]
        )

        print(
            "Risk Indicator:",
            report[8]
        )

        print(
            "Status:",
            report[9]
        )

        print(
            "Date:",
            report[10]
        )

        print(
            "Unverified Scam Lead:",
            report[11]
        )

    return page, page_count


# ==========================================
# SEARCH PHONE NUMBER / EMAIL
# ==========================================

def search_contact(account):

    if not security.is_reviewer(account):

        print("Investigator access required.")
        return

    print("\n========================================")
    print("        SEARCH PHONE NUMBER / EMAIL")
    print("========================================")

    contact = input(
        "Enter phone number / email to search: "
    )

    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
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
            scam_type
        FROM reports
        WHERE contact = ?
    """, (contact,))

    results = cursor.fetchall()

    connection.close()

    security.audit_event(DATABASE, account["username"], "CONTACT SEARCH")

    if len(results) == 0:

        print(
            "\nNo reports found for this "
            "phone number / email."
        )

    else:

        print(
            "\nContact found in",
            len(results),
            "report(s)."
        )

        for report in results:

            print(
                "\nReport ID:",
                report[0]
            )

            print(
                "Victim:",
                report[1]
            )

            print(
                "Incident Location:",
                report[2]
            )

            print(
                "Business:",
                report[3]
            )

            print(
                "Risk:",
                report[8]
            )

            print(
                "Status:",
                report[9]
            )

            print(
                "Unverified Scam Lead:",
                report[11]
            )


# ==========================================
# VIEW SINGLE REPORT
# ==========================================

def view_single_report(account):

    print("\n========================================")
    print("             VIEW REPORT")
    print("========================================")

    try:

        report_id = int(
            input("Enter report ID: ")
        )

    except ValueError:

        print("Please enter a valid report ID.")

        return

    connection = connect_database()
    cursor = connection.cursor()

    if security.is_reviewer(account):

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
        """, (report_id, account["username"]))

    report = cursor.fetchone()

    connection.close()

    if report is None:

        print("Report not found.")

        return

    security.audit_event(
        DATABASE,
        account["username"],
        "REPORT VIEWED",
        f"Report ID {report_id}"
    )

    print("\n========================================")
    print("             REPORT DETAILS")
    print("========================================")

    if not security.is_reviewer(account):

        print("Report ID:", report[0])
        print("Incident Location:", report[1])
        print("Product:", report[2])
        print("Risk Indicator:", report[3])
        print("Case Status:", report[4])
        print("Unverified Scam Lead:", report[5])
        return

    print("Report ID:", report[0])

    print(
        "Victim Name:",
        report[1]
    )

    print(
        "Incident Location:",
        report[2]
    )

    print(
        "Original Business:",
        report[3]
    )

    print(
        "Phone Number / Email:",
        report[4]
    )

    print(
        "Product:",
        report[5]
    )

    print(
        "Description:",
        report[6]
    )

    print(
        "Amount Lost: R",
        report[7]
    )

    print(
        "Risk Indicator:",
        report[8]
    )

    print(
        "Status:",
        report[9]
    )

    print(
        "Created:",
        report[10]
    )

    print(
        "Unverified Scam Lead:",
        report[11]
    )


# ==========================================
# UPDATE REPORT STATUS
# ==========================================

def update_status(account):

    if not security.is_reviewer(account):

        print("Investigator access required.")
        return

    print("\n========================================")
    print("          UPDATE REPORT STATUS")
    print("========================================")

    try:

        report_id = int(
            input("Enter report ID: ")
        )

    except ValueError:

        print("Please enter a valid report ID.")

        return

    print("\nChoose new status:")

    print("1. NEW")
    print("2. UNDER INVESTIGATION")
    print("3. RESOLVED")
    print("4. CLOSED")

    choice = input(
        "Enter your choice: "
    )

    if choice == "1":

        status = "NEW"

    elif choice == "2":

        status = "UNDER INVESTIGATION"

    elif choice == "3":

        status = "RESOLVED"

    elif choice == "4":

        status = "CLOSED"

    else:

        print("Invalid choice.")

        return

    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            reports.contact,
            (
                SELECT COUNT(*)
                FROM reports AS matching_reports
                WHERE matching_reports.contact = reports.contact
            )
        FROM reports
        WHERE reports.id = ?
    """, (report_id,))
    contact_row = cursor.fetchone()

    if contact_row and contact_row[1] > 1:

        cursor.execute("""
            SELECT decision
            FROM contact_alert_reviews
            WHERE contact = ?
        """, (contact_row[0],))
        alert_review = cursor.fetchone()

        if not alert_review or alert_review[0] != "CONFIRMED":

            connection.close()
            print("Confirm this contact alert before changing case status.")
            return

    cursor.execute("""
        UPDATE reports
        SET status = ?
        WHERE id = ?
    """, (status, report_id))

    cursor.execute("""
        UPDATE cases
        SET status = ?
        WHERE report_id = ?
    """, (status, report_id))

    if cursor.rowcount == 0:

        print("Report not found.")

    else:

        print(
            "Report status updated successfully."
        )

    connection.commit()
    connection.close()

    if cursor.rowcount:

        security.audit_event(
            DATABASE,
            account["username"],
            "CASE STATUS UPDATED",
            f"Report ID {report_id}; status {status}"
        )


# ==========================================
# DASHBOARD
# ==========================================

def dashboard(account):

    print("\n========================================")
    print("             CECMS DASHBOARD")
    print("========================================")

    connection = connect_database()
    cursor = connection.cursor()

    # Total reports
    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
    """)

    total_reports = cursor.fetchone()[0]

    # High-risk reports
    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE risk_level = 'HIGH'
    """)

    high_risk = cursor.fetchone()[0]

    # Medium-risk reports
    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE risk_level = 'MEDIUM'
    """)

    medium_risk = cursor.fetchone()[0]

    # Low-risk reports
    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE risk_level = 'LOW'
    """)

    low_risk = cursor.fetchone()[0]

    if security.is_reviewer(account):

        cursor.execute("""
            SELECT COALESCE(SUM(amount_lost), 0)
            FROM reports
        """)

        total_loss = cursor.fetchone()[0]

    # Open cases
    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE status != 'CLOSED'
    """)

    open_reports = cursor.fetchone()[0]

    connection.close()

    print(
        "Total Reports:",
        total_reports
    )

    print(
        "High-Risk Indicators:",
        high_risk
    )

    print(
        "Medium-Risk Indicators:",
        medium_risk
    )

    print(
        "Low-Risk Indicators:",
        low_risk
    )

    print(
        "Open Reports:",
        open_reports
    )

    if security.is_reviewer(account):

        print("Total Reported Loss: R", total_loss)


def authenticate_cli():

    security.initialize_authentication(DATABASE)
    account_count = security.initialize_authentication(DATABASE)

    if account_count == 0:

        print("\nCYBER CRIME EARLY-WARNING SYSTEM")
        print("1. Create authorised administrator account")
        print("2. Exit")

        if input("Choose an option: ").strip() != "1":

            return None

        account = create_administrator_cli()

        if account:

            return account

        return None

    while True:

        print("\nCYBER CRIME EARLY-WARNING SYSTEM")
        print("1. Login")
        print("2. Exit")
        choice = input("Choose an option: ").strip()

        if choice != "1":

            return None

        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        account = security.authenticate_user(
            DATABASE,
            username,
            password
        )

        if account and account.get("mfa_enrollment_required"):

            account = enroll_existing_user_cli(username, password)

        elif account and account.get("mfa_challenge_required"):

            code = input("Authenticator verification code: ").strip()
            account = security.authenticate_user(
                DATABASE,
                username,
                password,
                code
            )

        if account and not account.get("mfa_enrollment_required") and not account.get("mfa_challenge_required"):

            if account.get("system_locked") and not security.is_administrator(account):

                print("Application is locked by an Administrator. Case access is unavailable.")
                continue

            notify_administrator_cli(account)
            print("Successfully logged in.")
            return account

        attempts, locked_until = security.lockout_status(DATABASE, username)

        if locked_until:

            print(
                f"Account temporarily locked until {locked_until}. "
                "An Administrator security alert was created."
            )

        else:

            print(f"Login failed ({attempts}/{security.LOGIN_FAILURE_LIMIT}).")


def create_administrator_cli():

    username = input("Administrator username: ").strip()
    password = getpass.getpass("Password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")

    if password != confirmation:

        print("Passwords do not match.")
        return None

    secret = security.generate_totp_secret()
    print("Add this secret to an authenticator app:", secret)
    code = input("Enter the authenticator's current 6-digit code: ").strip()

    try:

        security.create_user(
            DATABASE,
            username,
            password,
            "Administrator",
            secret,
            code
        )

    except (ValueError, sqlite3.IntegrityError) as error:

        print(error)
        return None

    account = {"username": username, "role": "Administrator"}
    security.audit_event(DATABASE, username, "FIRST ADMIN CREATED")
    notify_administrator_cli(account)
    print("Administrator account created and MFA verified.")
    print("Successfully logged in.")
    return account


def enroll_existing_user_cli(username, password):

    print("MFA setup required for this existing account.")
    secret = security.generate_totp_secret()
    print("Add this secret to an authenticator app:", secret)
    security.set_totp_secret(DATABASE, username, secret)
    code = input("Enter the authenticator's current 6-digit code: ").strip()

    if not security.complete_totp_enrollment(DATABASE, username, code):

        security.record_failed_login(DATABASE, username, "invalid MFA enrollment code")
        print("Authenticator code was invalid.")
        return None

    return security.authenticate_user(DATABASE, username, password, code)


def notify_administrator_cli(account):

    if security.is_administrator(account):

        try:

            backup_path = security.daily_backup_if_due(DATABASE, account)

            if backup_path:

                print("Daily database backup created:", backup_path)

        except (OSError, sqlite3.Error, PermissionError) as error:

            print("Daily database backup failed:", error)

    alerts = security.pending_security_alerts(DATABASE, account)

    if not alerts:

        return

    print("\nSECURITY ALERTS")

    for _, username, attempts, created_at, ip, hostname, locked_until in alerts:

        print(
            f"{username}: {attempts} failed attempts at {created_at}; "
            f"IP {ip}; device {hostname}; locked until {locked_until}."
        )

    security.acknowledge_security_alerts(
        DATABASE,
        [alert[0] for alert in alerts],
        account
    )


def create_staff_account(account):

    if not security.is_administrator(account):

        print("Administrator access required.")
        return

    username = input("New username: ").strip()
    print("1. Investigator\n2. Authorized user")
    role_choice = input("Role: ")
    role = {"1": "Investigator", "2": "Authorized user"}.get(role_choice)

    if role is None:

        print("Invalid role.")
        return

    password = getpass.getpass("Temporary password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")

    if password != confirmation:

        print("Passwords do not match.")
        return

    while True:

        try:

            secret = security.generate_totp_secret()
            print("Give this authenticator secret to the user:", secret)
            code = input("Enter its current 6-digit code to verify setup: ").strip()
            security.create_user(DATABASE, username, password, role, secret, code)
            print(f"{role} account created.")
            return

        except ValueError as error:

            print(error)

            if "username" not in str(error).casefold():

                return

            username = input("Choose a different username: ").strip()

        except sqlite3.IntegrityError as error:

            print(error)
            return


def privacy_and_access():

    print("\nPRIVACY AND ACCESS USE")
    print("Scam classifications are unverified investigation leads, not proof of guilt.")
    print("First setup creates one Administrator; later account creation requires that Administrator.")
    print("Login requires a password and authenticator code; three failed attempts lock the account for 15 minutes.")
    print("Investigators and Authorized users receive role-limited access.")
    print("Repeated-contact alerts require human review before case action.")
    print("The system supports investigations; it does not determine guilt or automate enforcement.")


def review_contact_alerts(account):

    if not security.is_reviewer(account):

        print("Investigator access required.")
        return

    connection = connect_database()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT
            reports.contact,
            COUNT(*),
            COALESCE(contact_alert_reviews.decision, 'PENDING'),
            contact_alert_reviews.reviewer,
            contact_alert_reviews.reviewed_at
        FROM reports
        LEFT JOIN contact_alert_reviews
            ON contact_alert_reviews.contact = reports.contact
        WHERE reports.contact != ''
        GROUP BY reports.contact
        HAVING COUNT(*) > 1
        ORDER BY COUNT(*) DESC
    """)
    alerts = cursor.fetchall()
    connection.close()

    if not alerts:

        print("No repeated-contact alerts.")
        return

    for contact, count, decision, reviewer, reviewed_at in alerts:

        print(f"{contact}: {count} reports; {decision}")

        if reviewer:

            print(f"Reviewed by Investigator {reviewer} at {reviewed_at}")

    contact = input("Contact to review (blank to cancel): ").strip()

    if not contact:

        return

    if not any(alert[0] == contact for alert in alerts):

        print("No matching repeated-contact alert.")
        return

    print("1. Confirm as an investigation lead\n2. Dismiss alert")
    decision = {"1": "CONFIRMED", "2": "DISMISSED"}.get(
        input("Decision: ")
    )

    if decision is None:

        print("No change made.")
        return

    connection = connect_database()
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
        account["username"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    connection.commit()
    connection.close()
    print(f"Alert marked {decision.lower()} by an Investigator.")
    security.audit_event(
        DATABASE,
        account["username"],
        "INDICATOR REVIEWED",
        f"Repeated-contact alert {decision.lower()}"
    )


def administrator_security_center(account):

    if not security.is_administrator(account):

        print("Administrator access required.")
        return

    system_locked, locked_by, locked_at, lock_reason = security.system_lock_status(DATABASE)
    print("1. Unlock a user account")
    print("2. Lock the entire application")
    print("3. Unlock the application")
    print("4. Return")
    action = input("Choose a security action: ").strip()

    if action == "2":

        reason = input("Reason for system lock: ").strip()

        try:

            security.set_system_lock(DATABASE, account, True, reason)
            print("Application locked for all non-Administrator users.")

        except (PermissionError, sqlite3.Error) as error:

            print(error)

        return

    if action == "3":

        if not system_locked:

            print("The application is not locked.")
            return

        security.set_system_lock(DATABASE, account, False)
        print("Application unlocked.")
        return

    if action != "1":

        if system_locked:

            print(f"Application locked by {locked_by} at {locked_at}: {lock_reason}")

        return

    locked_users = security.list_locked_users(DATABASE, account)

    if not locked_users:

        print("No accounts are currently locked.")

    for username, attempts, last_failed, ip, hostname, locked_until in locked_users:

        print(
            f"{username}: {attempts} failures; last {last_failed}; "
            f"IP {ip}; device {hostname}; unlocks {locked_until}"
        )

    username = input("Username to unlock (blank to cancel): ").strip()

    if username:

        try:

            security.unlock_user(DATABASE, username, account)
            print("Account unlocked.")

        except (PermissionError, sqlite3.Error) as error:

            print(error)


def view_audit_log_cli(account):

    if not security.is_administrator(account):

        print("Administrator access required.")
        return

    events = security.recent_audit_events(DATABASE, account)

    if not events:

        print("No audit events recorded.")
        return

    for username, action, event_time, ip, hostname, details in events:

        print(f"{event_time} | {username} | {action} | {ip} | {hostname} | {details}")


def database_maintenance_cli(account):

    if not security.is_administrator(account):

        print("Administrator access required.")
        return

    print("1. Create backup\n2. Check database integrity")
    choice = input("Choose maintenance action: ").strip()

    try:

        if choice == "1":

            print("Backup created:", security.backup_database(DATABASE, account))

        elif choice == "2":

            print("Database integrity:", security.check_database_integrity(DATABASE, account))

        else:

            print("No action taken.")

    except (OSError, sqlite3.Error, PermissionError) as error:

        print("Database maintenance failed:", error)


# ==========================================
# MAIN MENU
# ==========================================

def main():

    create_database()

    account = authenticate_cli()

    if account is None:

        return

    print("Successfully logged in.")

    while True:

        print("\n")
        print("========================================")
        print("       CECMS CYBERCRIME SYSTEM")
        print("========================================")

        print(f"Signed in: {account['username']} ({account['role']})")
        system_locked = security.system_lock_status(DATABASE)[0]

        if system_locked:

            print("APPLICATION LOCKED: case access is suspended.")

            if security.is_administrator(account):

                print("10. Security Center / Unlock Application")
                print("11. View Audit Log")
                print("12. Database Maintenance")

        else:

            print("1. Submit Cybercrime Report")
            print("2. View Reports")
            print("3. View One Report")
            print("4. View Dashboard")
            print("5. Privacy and Access Use")

            if security.is_reviewer(account):

                print("6. Search Phone Number / Email")
                print("7. Update Report Status")
                print("8. Review Contact Alerts")

            if security.is_administrator(account):

                print("9. Create User Account")
                print("10. Security Center / Lock Application")
                print("11. View Audit Log")
                print("12. Database Maintenance")

        print("0. Exit")

        print(
            "========================================"
        )

        choice = input(
            "Choose an option: "
        )

        if (system_locked and not security.is_administrator(account)
                and choice != "0"):

            print("Application locked by an Administrator.")
            continue

        if (system_locked and security.is_administrator(account)
                and choice not in ("10", "11", "12", "0")):

            print("Only Administrator security and maintenance options are available.")
            continue

        if choice == "1":

            submit_report(account)

        elif choice == "2":

            view_reports(account)

        elif choice == "3":

            view_single_report(account)

        elif choice == "4":

            dashboard(account)

        elif choice == "5":

            privacy_and_access()

        elif choice == "6":

            if security.is_reviewer(account):

                search_contact(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "7":

            if security.is_reviewer(account):

                update_status(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "8":

            if security.is_reviewer(account):

                review_contact_alerts(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "9":

            if security.is_administrator(account):

                create_staff_account(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "10":

            if security.is_administrator(account):

                administrator_security_center(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "11":

            if security.is_administrator(account):

                view_audit_log_cli(account)

            else:

                print("Option unavailable for your role.")

        elif choice == "12":

            database_maintenance_cli(account)

        elif choice == "0":

            print(
                "\nThank you for using CECMS."
            )

            break

        else:

            print(
                "\nInvalid option. Please try again."
            )


# ==========================================
# START SYSTEM
# ==========================================

if __name__ == "__main__":

    try:

        main()

    except sqlite3.Error:

        print("Database connection error. Please contact the system administrator.")
