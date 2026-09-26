import os
import ipaddress
import math
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import quote

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import security
from app import DATABASE, create_database
from case_logic import calculate_risk, classify_indicator, classify_scam


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("CECMS_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("CECMS_COOKIE_SECURE") == "1",
)

_setup_secrets = {}
_staff_setup_secrets = {}
REPORT_PROVINCES = (
    "Eastern Cape",
    "Free State",
    "Gauteng",
    "KwaZulu-Natal",
    "Limpopo",
    "Mpumalanga",
    "Northern Cape",
    "North West",
    "Western Cape",
    "Outside South Africa",
    "Unknown",
)


def connect_database():
    connection = sqlite3.connect(DATABASE, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def current_user():
    return session.get("user")


def reviewer_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        if not security.is_reviewer(current_user()):
            abort(403)
        if security.system_lock_status(DATABASE)[0]:
            flash("The system is locked. Case access is temporarily unavailable.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def administrator_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        if not security.is_administrator(current_user()):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def unlocked_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        if security.system_lock_status(DATABASE)[0] and not security.is_administrator(current_user()):
            flash("The system is locked. Case access is temporarily unavailable.", "error")
            return redirect(url_for("privacy"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def protect_posts():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            abort(400, "Your session token is invalid. Refresh the page and try again.")


@app.context_processor
def template_context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {
        "current_user": current_user(),
        "is_reviewer": security.is_reviewer(current_user()),
        "is_admin": security.is_administrator(current_user()),
        "system_locked": security.system_lock_status(DATABASE)[0],
        "csrf_token": session["csrf_token"],
        "report_provinces": REPORT_PROVINCES,
    }


@app.template_filter("money")
def money(value):
    return f"R {float(value or 0):,.2f}"


@app.template_filter("date_short")
def date_short(value):
    if not value:
        return "—"
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y")
    except ValueError:
        return value


def finish_login(account):
    if account.get("system_locked") and not security.is_administrator(account):
        flash("The application is locked by an Administrator. Please try again later.", "error")
        return redirect(url_for("login"))
    session.clear()
    session["user"] = {"username": account["username"], "role": account["role"]}
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("dashboard"))


def get_or_create_enrollment_secret(username):
    connection = connect_database()
    try:
        row = connection.execute(
            "SELECT totp_secret FROM app_users WHERE username = ? COLLATE NOCASE",
            (username.strip(),)
        ).fetchone()
    finally:
        connection.close()
    if not row:
        return None
    if not row["totp_secret"]:
        secret = security.generate_totp_secret()
        security.set_totp_secret(DATABASE, username, secret)
        return secret
    return row["totp_secret"]


@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user() else "login"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if current_user():
        return redirect(url_for("dashboard"))
    if security.initialize_authentication(DATABASE) > 0:
        return redirect(url_for("login"))

    token = session.setdefault("setup_token", secrets.token_urlsafe(24))
    if request.method == "GET":
        _setup_secrets[token] = security.generate_totp_secret()
    secret = _setup_secrets.get(token)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirmation", "")
        code = request.form.get("verification_code", "").strip()
        secret = _setup_secrets.get(token)
        if not secret:
            flash("Setup expired. Reload this page to generate a new authenticator key.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            try:
                security.create_user(
                    DATABASE, username, password, "Administrator", secret, code
                )
                security.audit_event(DATABASE, username, "FIRST ADMIN CREATED")
                _setup_secrets.pop(token, None)
                return finish_login({"username": username, "role": "Administrator"})
            except (ValueError, sqlite3.IntegrityError) as error:
                flash(str(error), "error")

    provisioning_uri = ""
    if secret:
        label = quote(f"CECMS:{request.form.get('username', 'administrator')}")
        provisioning_uri = (
            f"otpauth://totp/{label}?secret={secret}&issuer=CECMS"
            "&algorithm=SHA1&digits=6&period=30"
        )
    return render_template(
        "setup.html", authenticator_secret=secret, provisioning_uri=provisioning_uri
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if security.initialize_authentication(DATABASE) == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("verification_code", "").strip()
        enrollment = session.get("mfa_enrollment_username") == username.casefold()

        if enrollment:
            account = security.authenticate_user(DATABASE, username, password)
            if account and account.get("mfa_enrollment_required"):
                get_or_create_enrollment_secret(username)
                if not code:
                    flash(
                        "Add the setup key to your authenticator app, then enter the current six-digit code.",
                        "error",
                    )
                elif security.complete_totp_enrollment(DATABASE, username, code):
                    account = security.authenticate_user(
                        DATABASE, username, password, code
                    )
                else:
                    security.record_failed_login(
                        DATABASE, username, "invalid MFA enrollment code"
                    )
                    account = None
                    _attempts, locked_until = security.lockout_status(
                        DATABASE, username
                    )
                    if locked_until:
                        flash(
                            f"Account temporarily locked until {locked_until}.",
                            "error",
                        )
                    else:
                        flash(
                            "That code did not match. Enter the current six-digit code from the authenticator app, not the setup key. If needed, check your phone's date and time settings.",
                            "error",
                        )
            elif account and account.get("mfa_challenge_required") and code:
                account = security.authenticate_user(
                    DATABASE, username, password, code
                )
            if account and not account.get("mfa_enrollment_required") and not account.get("mfa_challenge_required"):
                session.pop("mfa_enrollment_username", None)
                return finish_login(account)
            if account and account.get("mfa_challenge_required"):
                flash("Enter the six-digit code from your authenticator app.", "error")
            elif not account and not session.get("_flashes"):
                attempts, locked_until = security.lockout_status(DATABASE, username)
                if locked_until:
                    flash(f"Account temporarily locked until {locked_until}.", "error")
                else:
                    flash(f"Login failed. Check your credentials and authenticator code. ({attempts}/{security.LOGIN_FAILURE_LIMIT})", "error")
        else:
            account = security.authenticate_user(
                DATABASE, username, password, code or None
            )
            if account and account.get("mfa_enrollment_required"):
                secret = security.generate_totp_secret()
                security.set_totp_secret(DATABASE, username, secret)
                session["mfa_enrollment_username"] = username.casefold()
                flash("Set up an authenticator app, then enter its six-digit code.", "success")
                return render_template(
                    "login.html",
                    enrollment_secret=secret,
                    provisioning_uri=(
                        f"otpauth://totp/{quote('CECMS:' + username)}?secret={secret}"
                        "&issuer=CECMS&algorithm=SHA1&digits=6&period=30"
                    ),
                    username=username,
                )
            if account and account.get("mfa_challenge_required"):
                session["mfa_challenge_username"] = username.casefold()
                flash("Enter the six-digit code from your authenticator app.", "success")
            elif account:
                return finish_login(account)
            else:
                attempts, locked_until = security.lockout_status(DATABASE, username)
                if locked_until:
                    flash(f"Account temporarily locked until {locked_until}.", "error")
                else:
                    flash(f"Login failed. Check your credentials and authenticator code. ({attempts}/{security.LOGIN_FAILURE_LIMIT})", "error")

    enrollment_secret = None
    provisioning_uri = ""
    submitted_username = request.form.get("username", "").strip()
    if (
        session.get("mfa_enrollment_username")
        and session["mfa_enrollment_username"] == submitted_username.casefold()
    ):
        enrollment_secret = get_or_create_enrollment_secret(submitted_username)
        if enrollment_secret:
            provisioning_uri = (
                f"otpauth://totp/{quote('CECMS:' + submitted_username)}"
                f"?secret={enrollment_secret}&issuer=CECMS&algorithm=SHA1&digits=6&period=30"
            )
    mfa_challenge_required = (
        session.get("mfa_challenge_username") == submitted_username.casefold()
    )
    return render_template(
        "login.html",
        enrollment_secret=enrollment_secret,
        provisioning_uri=provisioning_uri,
        mfa_challenge_required=mfa_challenge_required,
        username=submitted_username,
    )


@app.post("/logout")
def logout():
    if current_user():
        security.audit_event(DATABASE, current_user()["username"], "USER LOGOUT")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


def dashboard_data():
    connection = connect_database()
    try:
        total = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        counts = {
            row["risk_level"]: row["total"]
            for row in connection.execute(
                "SELECT risk_level, COUNT(*) AS total FROM reports GROUP BY risk_level"
            )
        }
        open_cases = connection.execute(
            "SELECT COUNT(*) FROM reports WHERE status != 'CLOSED'"
        ).fetchone()[0]
        recent = connection.execute("""
            SELECT id, platform, product, province, scam_type, risk_level, status, created_at
            FROM reports ORDER BY id DESC LIMIT 6
        """).fetchall()
        categories = connection.execute("""
            SELECT scam_type, COUNT(*) AS total FROM reports
            GROUP BY scam_type ORDER BY total DESC LIMIT 5
        """).fetchall()
        provinces = connection.execute("""
            SELECT COALESCE(NULLIF(province, ''), 'Unknown') AS province,
                COUNT(*) AS total
            FROM reports
            GROUP BY COALESCE(NULLIF(province, ''), 'Unknown')
            ORDER BY total DESC, province
        """).fetchall()
        loss = 0
        if security.is_reviewer(current_user()):
            loss = connection.execute(
                "SELECT COALESCE(SUM(amount_lost), 0) FROM reports"
            ).fetchone()[0]
    finally:
        connection.close()
    return {
        "total": total,
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "open_cases": open_cases,
        "loss": loss,
        "recent": recent,
        "categories": categories,
        "province_counts": provinces,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


@app.route("/dashboard")
@unlocked_required
def dashboard():
    return render_template("dashboard.html", **dashboard_data())


@app.get("/dashboard/live")
@unlocked_required
def dashboard_live():
    data = dashboard_data()
    data["categories"] = [dict(item) for item in data["categories"]]
    data["province_counts"] = [dict(item) for item in data["province_counts"]]
    data["recent"] = [
        {
            "id": report["id"],
            "url": url_for("report_detail", report_id=report["id"]),
            "created_at": date_short(report["created_at"]),
            "province": report["province"] or "Unknown",
            "platform": report["platform"],
            "scam_type": report["scam_type"] or "Unclassified",
            "risk_level": report["risk_level"] or "LOW",
            "status": report["status"],
        }
        for report in data["recent"]
    ]
    response = jsonify(data)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/reports")
@unlocked_required
def reports():
    connection = connect_database()
    clauses = []
    values = []
    if not security.is_reviewer(current_user()):
        clauses.append("created_by = ?")
        values.append(current_user()["username"])
    risk = request.args.get("risk", "").upper()
    if risk in ("HIGH", "MEDIUM", "LOW"):
        clauses.append("risk_level = ?")
        values.append(risk)
    search = request.args.get("q", "").strip()
    if search:
        searchable_fields = [
            "platform LIKE ?", "product LIKE ?", "scam_type LIKE ?",
            "province LIKE ?",
        ]
        if security.is_reviewer(current_user()):
            searchable_fields.extend(("contact LIKE ?", "suspect_ip LIKE ?"))
        clauses.append("(" + " OR ".join(searchable_fields) + ")")
        values.extend([f"%{search}%"] * len(searchable_fields))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    page = max(1, request.args.get("page", 1, type=int))
    page_size = 20
    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM reports" + where, values
        ).fetchone()[0]
        page_count = max(1, (total + page_size - 1) // page_size)
        page = min(page, page_count)
        rows = connection.execute("""
            SELECT id, victim_name, platform, business_name, contact, suspect_ip,
                province, product,
                description, amount_lost, risk_level, status, created_at,
                scam_type, created_by
            FROM reports
        """ + where + " ORDER BY id DESC LIMIT ? OFFSET ?", (
            *values, page_size, (page - 1) * page_size
        )).fetchall()
    finally:
        connection.close()
    return render_template(
        "reports.html", reports=rows, page=page, page_count=page_count,
        total=total, risk=risk, search=search
    )


@app.route("/reports/new", methods=["GET", "POST"])
@unlocked_required
def new_report():
    if request.method == "POST":
        victim = request.form.get("victim_name", "").strip() or "Not provided"
        platform = request.form.get("platform", "").strip()
        business = request.form.get("business_name", "").strip()
        contact = request.form.get("contact", "").strip()
        suspect_ip = request.form.get("suspect_ip", "").strip()
        province = request.form.get("province", "").strip()
        product = request.form.get("product", "").strip()
        description = request.form.get("description", "").strip()
        evidence = request.form.get("evidence", "").strip()
        try:
            amount = float(request.form.get("amount_lost", "0") or 0)
            if not math.isfinite(amount) or amount < 0:
                raise ValueError
        except ValueError:
            flash("Enter a valid loss amount of zero or more.", "error")
            return render_template("report_form.html", form=request.form)
        if not platform or not description:
            flash("Incident location and incident description are required.", "error")
            return render_template("report_form.html", form=request.form)
        if province not in REPORT_PROVINCES:
            flash("Choose a province, Outside South Africa, or Unknown.", "error")
            return render_template("report_form.html", form=request.form)
        if (
            len(victim) > 250
            or len(platform) > 250
            or len(business) > 250
            or len(contact) > 500
            or len(suspect_ip) > 45
            or len(product) > 250
            or len(description) > 10000
        ):
            flash("One or more report fields exceed their allowed length.", "error")
            return render_template("report_form.html", form=request.form)

        if suspect_ip:
            try:
                suspect_ip = str(ipaddress.ip_address(suspect_ip))
            except ValueError:
                flash("Enter a valid IPv4 or IPv6 address found in the evidence.", "error")
                return render_template("report_form.html", form=request.form)

        banking = "banking_involved" in request.form
        compromised = "account_compromised" in request.form
        exposed = "personal_info_exposed" in request.form
        scam_type = classify_scam(description, platform)
        connection = connect_database()
        try:
            repeated_contact = bool(contact and connection.execute(
                "SELECT 1 FROM reports WHERE contact = ? LIMIT 1", (contact,)
            ).fetchone())
            repeated_ip = bool(suspect_ip and connection.execute(
                "SELECT 1 FROM reports WHERE suspect_ip = ? LIMIT 1", (suspect_ip,)
            ).fetchone())
            repeated = repeated_contact or repeated_ip
            risk_level = calculate_risk(
                amount, repeated, banking, compromised, exposed,
                any(word in description.casefold() for word in ("link", "url", "click"))
            )
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor = connection.execute("""
                INSERT INTO reports (
                    victim_name, platform, business_name, contact, product,
                    description, amount_lost, risk_level, status, created_at,
                    scam_type, banking_involved, account_compromised,
                    personal_info_exposed, created_by, suspect_ip, province
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                victim, platform, business, contact, product, description,
                amount, risk_level, created_at, scam_type, int(banking),
                int(compromised), int(exposed), current_user()["username"],
                suspect_ip, province
            ))
            report_id = cursor.lastrowid
            case_cursor = connection.execute("""
                INSERT INTO cases (
                    title, organization, category, description, priority, status,
                    investigator, created_by, created_at, report_id
                ) VALUES (?, ?, ?, ?, ?, 'SUBMITTED', NULL, ?, ?, ?)
            """, (
                scam_type, business or "Not provided", scam_type, description,
                risk_level, current_user()["username"], created_at, report_id
            ))
            case_id = case_cursor.lastrowid
            if contact:
                indicator_type = classify_indicator(contact)
                connection.execute("""
                    INSERT INTO indicators (case_id, indicator_type, indicator_value)
                    VALUES (?, ?, ?)
                """, (case_id, indicator_type, contact))
            if suspect_ip:
                connection.execute("""
                    INSERT INTO indicators (case_id, indicator_type, indicator_value)
                    VALUES (?, 'IP address', ?)
                """, (case_id, suspect_ip))
            if evidence:
                connection.execute("""
                    INSERT INTO evidence (case_id, evidence_type, description)
                    VALUES (?, 'Reporter note or reference', ?)
                """, (case_id, evidence[:2000]))
            connection.execute("""
                INSERT INTO access_log (username, action, case_id, log_time)
                VALUES (?, 'CASE CREATED', ?, ?)
            """, (current_user()["username"], case_id, created_at))
            if repeated_contact:
                connection.execute("""
                    INSERT INTO contact_alert_reviews (contact, decision)
                    VALUES (?, 'PENDING')
                    ON CONFLICT(contact) DO UPDATE SET
                        decision = 'PENDING', reviewer = NULL, reviewed_at = NULL
                """, (contact,))
            if repeated_ip:
                connection.execute("""
                    INSERT INTO ip_alert_reviews (ip_address, decision)
                    VALUES (?, 'PENDING')
                    ON CONFLICT(ip_address) DO UPDATE SET
                        decision = 'PENDING', reviewer = NULL, reviewed_at = NULL
                """, (suspect_ip,))
            connection.commit()
        finally:
            connection.close()
        security.audit_event(
            DATABASE, current_user()["username"], "CASE CREATED",
            f"Report ID {report_id}; category {scam_type}; risk {risk_level}"
        )
        if contact or suspect_ip:
            security.audit_event(
                DATABASE, current_user()["username"], "INDICATOR ADDED",
                f"Case {case_id}"
            )
        if evidence:
            security.audit_event(
                DATABASE, current_user()["username"], "EVIDENCE ADDED",
                f"Case {case_id}; reporter note/reference"
            )
        flash(
            f"Report #{report_id} submitted. {scam_type} is an unverified lead; "
            "it is not a determination of guilt.",
            "success",
        )
        return redirect(url_for("report_detail", report_id=report_id))
    return render_template("report_form.html", form={})


@app.route("/reports/<int:report_id>", methods=["GET", "POST"])
@unlocked_required
def report_detail(report_id):
    connection = connect_database()
    if request.method == "POST":
        if not security.is_reviewer(current_user()):
            connection.close()
            abort(403)
        status = request.form.get("status", "")
        if status not in ("UNDER INVESTIGATION", "RESOLVED", "CLOSED"):
            connection.close()
            abort(400, "Choose a valid case status.")
        row = connection.execute(
            "SELECT contact, suspect_ip FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        if not row:
            connection.close()
            abort(404)
        if row["contact"]:
            repeated_count = connection.execute(
                "SELECT COUNT(*) FROM reports WHERE contact = ?", (row["contact"],)
            ).fetchone()[0]
            review = connection.execute(
                "SELECT decision FROM contact_alert_reviews WHERE contact = ?",
                (row["contact"],)
            ).fetchone()
            if repeated_count > 1 and (not review or review["decision"] != "CONFIRMED"):
                connection.close()
                flash("Confirm the repeated-contact alert before changing this case status.", "error")
                return redirect(url_for("alerts"))
        if row["suspect_ip"]:
            repeated_ip_count = connection.execute(
                "SELECT COUNT(*) FROM reports WHERE suspect_ip = ?",
                (row["suspect_ip"],)
            ).fetchone()[0]
            ip_review = connection.execute(
                "SELECT decision FROM ip_alert_reviews WHERE ip_address = ?",
                (row["suspect_ip"],)
            ).fetchone()
            if repeated_ip_count > 1 and (
                not ip_review or ip_review["decision"] != "CONFIRMED"
            ):
                connection.close()
                flash("Confirm the repeated-IP alert before changing this case status.", "error")
                return redirect(url_for("alerts"))
        connection.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))
        connection.execute(
            "UPDATE cases SET status = ? WHERE report_id = ?", (status, report_id)
        )
        connection.commit()
        connection.close()
        security.audit_event(
            DATABASE, current_user()["username"], "CASE STATUS UPDATED",
            f"Report ID {report_id}; status {status}"
        )
        flash("Case status updated.", "success")
        return redirect(url_for("report_detail", report_id=report_id))

    report = connection.execute("""
        SELECT id, victim_name, platform, business_name, contact, suspect_ip,
            province, product,
            description, amount_lost, risk_level, status, created_at,
            scam_type, created_by, banking_involved, account_compromised,
            personal_info_exposed
        FROM reports WHERE id = ?
    """, (report_id,)).fetchone()
    if not report or (
        not security.is_reviewer(current_user())
        and report["created_by"] != current_user()["username"]
    ):
        connection.close()
        abort(404)
    evidence = []
    if security.is_reviewer(current_user()):
        case = connection.execute(
            "SELECT case_id FROM cases WHERE report_id = ?", (report_id,)
        ).fetchone()
        if case:
            evidence = connection.execute("""
                SELECT evidence_type, description FROM evidence
                WHERE case_id = ? ORDER BY evidence_id
            """, (case["case_id"],)).fetchall()
        security.audit_event(
            DATABASE, current_user()["username"], "REPORT VIEWED",
            f"Report ID {report_id}"
        )
    connection.close()
    return render_template("report_detail.html", report=report, evidence=evidence)


@app.route("/alerts")
@unlocked_required
def alerts():
    connection = connect_database()
    rows = connection.execute("""
        SELECT reports.contact, COUNT(*) AS total,
            COALESCE(contact_alert_reviews.decision, 'PENDING') AS decision,
            contact_alert_reviews.reviewer, MAX(reports.created_at) AS latest
        FROM reports
        LEFT JOIN contact_alert_reviews
            ON contact_alert_reviews.contact = reports.contact
        WHERE reports.contact != ''
        GROUP BY reports.contact HAVING COUNT(*) > 1
        ORDER BY total DESC
    """).fetchall()
    alerts = [
        {**dict(row), "indicator_type": classify_indicator(row["contact"])}
        for row in rows
    ]
    ip_alerts = connection.execute("""
        SELECT reports.suspect_ip AS ip_address, COUNT(*) AS total,
            COALESCE(ip_alert_reviews.decision, 'PENDING') AS decision,
            ip_alert_reviews.reviewer, MAX(reports.created_at) AS latest
        FROM reports
        LEFT JOIN ip_alert_reviews
            ON ip_alert_reviews.ip_address = reports.suspect_ip
        WHERE reports.suspect_ip != ''
        GROUP BY reports.suspect_ip
        ORDER BY total DESC, reports.suspect_ip
    """).fetchall()
    connection.close()
    return render_template("alerts.html", alerts=alerts, ip_alerts=ip_alerts)


@app.post("/alerts/review")
@reviewer_required
def review_alert():
    contact = request.form.get("contact", "").strip()
    decision = request.form.get("decision", "")
    if not contact or decision not in ("CONFIRMED", "DISMISSED"):
        abort(400, "Invalid alert review.")
    connection = connect_database()
    matching = connection.execute(
        "SELECT COUNT(*) FROM reports WHERE contact = ?", (contact,)
    ).fetchone()[0]
    if matching < 2:
        connection.close()
        abort(400, "This repeated-contact alert no longer exists.")
    connection.execute("""
        INSERT INTO contact_alert_reviews (contact, decision, reviewer, reviewed_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(contact) DO UPDATE SET decision = excluded.decision,
            reviewer = excluded.reviewer, reviewed_at = excluded.reviewed_at
    """, (
        contact, decision, current_user()["username"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    connection.commit()
    connection.close()
    security.audit_event(
        DATABASE, current_user()["username"], "INDICATOR REVIEWED",
        f"Repeated-contact alert {decision.lower()}"
    )
    flash("Repeated-contact alert review saved.", "success")
    return redirect(url_for("alerts"))


@app.post("/alerts/review-ip")
@reviewer_required
def review_ip_alert():
    ip_address = request.form.get("ip_address", "").strip()
    decision = request.form.get("decision", "")
    if decision not in ("CONFIRMED", "DISMISSED"):
        abort(400, "Invalid IP indicator review.")
    try:
        ip_address = str(ipaddress.ip_address(ip_address))
    except ValueError:
        abort(400, "Invalid IP indicator.")

    connection = connect_database()
    matching = connection.execute(
        "SELECT COUNT(*) FROM reports WHERE suspect_ip = ?", (ip_address,)
    ).fetchone()[0]
    if not matching:
        connection.close()
        abort(400, "This reported IP indicator no longer exists.")
    connection.execute("""
        INSERT INTO ip_alert_reviews (ip_address, decision, reviewer, reviewed_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET decision = excluded.decision,
            reviewer = excluded.reviewer, reviewed_at = excluded.reviewed_at
    """, (
        ip_address, decision, current_user()["username"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    connection.commit()
    connection.close()
    security.audit_event(
        DATABASE, current_user()["username"], "IP INDICATOR REVIEWED",
        f"Reported IP indicator {decision.lower()}"
    )
    flash("Reported IP indicator review saved.", "success")
    return redirect(url_for("alerts"))


@app.route("/audit")
@unlocked_required
def audit_log():
    if not security.is_administrator(current_user()):
        abort(403)
    events = security.recent_audit_events(DATABASE, current_user(), 100)
    return render_template("audit.html", events=events)


@app.route("/admin/users", methods=["GET", "POST"])
@administrator_required
def staff_accounts():
    token = session.setdefault("staff_setup_token", secrets.token_urlsafe(24))
    if request.method == "GET" and token not in _staff_setup_secrets:
        _staff_setup_secrets[token] = security.generate_totp_secret()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("password_confirmation", "")
        role = request.form.get("role", "")
        code = request.form.get("verification_code", "").strip()
        secret = _staff_setup_secrets.get(token)
        if not secret:
            flash("Account setup expired. Reload this page to generate a new authenticator key.", "error")
        elif role not in ("Investigator", "Authorized user"):
            flash("Choose an Investigator or Authorized user role.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            try:
                security.create_user(DATABASE, username, password, role, secret, code)
                security.audit_event(
                    DATABASE, current_user()["username"], "STAFF ACCOUNT CREATED",
                    f"Username {username}; role {role}"
                )
                _staff_setup_secrets.pop(token, None)
                session.pop("staff_setup_token", None)
                flash(f"{role} account created successfully.", "success")
                return redirect(url_for("staff_accounts"))
            except (ValueError, sqlite3.IntegrityError) as error:
                flash(str(error), "error")

    secret = _staff_setup_secrets.get(token)
    provisioning_uri = ""
    if secret:
        label = quote(f"CECMS:{request.form.get('username', 'staff')}")
        provisioning_uri = (
            f"otpauth://totp/{label}?secret={secret}&issuer=CECMS"
            "&algorithm=SHA1&digits=6&period=30"
        )
    connection = connect_database()
    try:
        accounts = connection.execute("""
            SELECT username, role, created_at, mfa_enabled
            FROM app_users ORDER BY username COLLATE NOCASE
        """).fetchall()
    finally:
        connection.close()
    return render_template(
        "staff_accounts.html", accounts=accounts, authenticator_secret=secret,
        provisioning_uri=provisioning_uri, form=request.form
    )


@app.route("/admin/security", methods=["GET", "POST"])
@administrator_required
def admin_security():
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "lock":
            reason = request.form.get("reason", "").strip()
            if not reason:
                flash("Enter a reason before locking case access.", "error")
            else:
                security.set_system_lock(DATABASE, current_user(), True, reason)
                flash("Case access has been locked. Administrator security tools remain available.", "success")
        elif action == "unlock":
            security.set_system_lock(DATABASE, current_user(), False)
            flash("Case access has been unlocked.", "success")
        elif action == "unlock-user":
            username = request.form.get("username", "").strip()
            if not username:
                abort(400, "Choose an account to unlock.")
            security.unlock_user(DATABASE, username, current_user())
            flash(f"Sign-in lockout cleared for {username}.", "success")
        elif action == "acknowledge-alerts":
            try:
                alert_ids = [int(value) for value in request.form.getlist("alert_ids")]
            except ValueError:
                abort(400, "Invalid security alert selection.")
            if not alert_ids:
                flash("Select at least one alert to acknowledge.", "error")
            else:
                security.acknowledge_security_alerts(DATABASE, alert_ids, current_user())
                flash("Selected security alerts acknowledged.", "success")
        elif action == "backup":
            path = security.backup_database(DATABASE, current_user())
            flash(f"Database backup created: {os.path.basename(path)}", "success")
        elif action == "integrity":
            result = security.check_database_integrity(DATABASE, current_user())
            flash(f"Database integrity check: {result}", "success" if result == "ok" else "error")
        else:
            abort(400, "Unknown security action.")
        return redirect(url_for("admin_security"))

    lock_status = security.system_lock_status(DATABASE)
    locked_users = security.list_locked_users(DATABASE, current_user())
    security_alerts = security.pending_security_alerts(DATABASE, current_user())
    return render_template(
        "admin_security.html",
        lock_status=lock_status,
        locked_users=locked_users,
        security_alerts=security_alerts,
    )


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page or report could not be found."), 404


create_database()
security.initialize_authentication(DATABASE)


if __name__ == "__main__":
    host = os.environ.get("CECMS_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    production = os.environ.get("CECMS_ENV", "local").casefold() == "production"
    local_hosts = {"127.0.0.1", "localhost", "::1"}

    if host not in local_hosts and not production:
        raise RuntimeError("Non-local CECMS_HOST requires CECMS_ENV=production.")
    if production and (
        not os.environ.get("CECMS_SECRET_KEY")
        or os.environ.get("CECMS_COOKIE_SECURE") != "1"
    ):
        raise RuntimeError(
            "Production requires a persistent CECMS_SECRET_KEY and CECMS_COOKIE_SECURE=1."
        )

    from waitress import serve

    serve(app, host=host, port=port)
