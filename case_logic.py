import ipaddress
import re
from urllib.parse import urlsplit


EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
PHONE_PATTERN = re.compile(r"\+?[0-9().\s-]+")


def classify_indicator(value):
    value = value.strip()
    if not value:
        return "Other indicator"

    try:
        ipaddress.ip_address(value)
        return "IP address"
    except ValueError:
        pass

    if EMAIL_PATTERN.fullmatch(value):
        return "Email address"

    if PHONE_PATTERN.fullmatch(value) and sum(character.isdigit() for character in value) >= 7:
        return "Phone number"

    if value.casefold().startswith(("http://", "https://", "www.")):
        return "Website or URL"

    try:
        parsed = urlsplit(f"//{value}")
    except ValueError:
        parsed = None
    if parsed and parsed.hostname and "." in parsed.hostname:
        return "Website or URL"

    return "Other indicator"


SCAM_RULES = (
    ("Malware or malicious software", (
        "malware", "ransomware", "spyware", "virus", "remote access",
        "screen sharing app", "downloaded an app", "installed software",
        "encrypted my files", "encrypted my computer files", "files encrypted",
        "computer files locked"
    )),
    ("Extortion or blackmail", (
        "blackmail", "extortion", "threatened to share", "demanded money",
        "threatened to publish", "private files unless paid", "sextortion",
        "pay or else", "ransom demand"
    )),
    ("Banking or payment fraud", (
        "bank transfer", "credit card", "debit card", "card details",
        "payment app", "mobile money", "wire transfer", "unauthorized payment",
        "unauthorised payment", "bank account", "my bank", "banking", "cash app",
        "paypal", "money stolen", "money taken"
    )),
    ("Account compromise", (
        "account taken over", "account takeover", "account hacked",
        "hacked account", "locked out", "password changed", "email account",
        "social account", "stolen password", "unauthorized access",
        "unauthorised access"
    )),
    ("Phishing or social engineering", (
        "phishing", "otp", "one-time pin", "one-time code", "verification code", "security code",
        "verify your account", "click this link", "suspicious link", "password",
        "login details", "fake login", "account suspended", "reset password",
        "bank details", "text message", "sms", "email link"
    )),
    ("Investment scam", (
        "investment", "invest", "crypto", "bitcoin", "forex", "trading",
        "guaranteed profit", "investment returns", "double your money"
    )),
    ("Romance scam", (
        "romance", "dating", "lover", "boyfriend", "girlfriend",
        "relationship", "met online", "love interest"
    )),
    ("Employment scam", (
        "job offer", "job application", "vacancy", "recruiter", "recruitment",
        "work from home", "employment", "salary", "hiring", "job scam"
    )),
    ("Impersonation scam", (
        "impersonat", "pretending to be", "posing as", "fake official",
        "police officer", "government official", "support agent", "family member",
        "relative", "fake bank representative", "executive impersonation"
    )),
    ("Advance-fee scam", (
        "advance fee", "upfront fee", "processing fee", "release fee",
        "customs fee", "clearance fee", "inheritance", "claim fee",
        "tax payment", "prize fee", "pay a fee first"
    )),
    ("Online shopping or marketplace scam", (
        "online shop", "online store", "marketplace", "seller", "product",
        "order", "purchase", "parcel", "not delivered", "never arrived",
        "fake shop", "paid for goods", "item never arrived"
    )),
    ("Identity theft or personal-data misuse", (
        "identity theft", "identity stolen", "personal information",
        "personal data", "identity document", "id number", "stolen identity",
        "used my details", "data breach"
    )),
)


def classify_scam(description, incident_location=""):

    text = f"{description} {incident_location}".casefold()

    for category, keywords in SCAM_RULES:

        if any(keyword in text for keyword in keywords):

            return category

    return "Other or unclassified"


def calculate_risk(
    amount_lost,
    repeated_indicator=False,
    banking_involved=False,
    account_compromised=False,
    personal_info_exposed=False,
    suspicious_link=False,
):

    if amount_lost > 0 or banking_involved or account_compromised:

        return "HIGH"

    if repeated_indicator or personal_info_exposed or suspicious_link:

        return "MEDIUM"

    return "LOW"


def initialize_case_support(connection):

    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            organization TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            investigator TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            report_id INTEGER UNIQUE
        )
    """)
    case_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(cases)")
    }
    if "report_id" not in case_columns:
        cursor.execute("ALTER TABLE cases ADD COLUMN report_id INTEGER")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            case_id INTEGER,
            log_time TEXT NOT NULL
        )
    """)
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_report ON cases(report_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_status_created ON cases(status, created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_category ON cases(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_case ON indicators(case_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_log_time ON access_log(log_time)")

    cursor.execute("""
        INSERT OR IGNORE INTO cases (
            title, organization, category, description, priority, status,
            investigator, created_by, created_at, report_id
        )
        SELECT
            COALESCE(NULLIF(scam_type, ''), 'Other or unclassified'),
            COALESCE(NULLIF(business_name, ''), 'Not provided'),
            COALESCE(NULLIF(scam_type, ''), 'Other or unclassified'),
            COALESCE(description, ''),
            COALESCE(risk_level, 'LOW'),
            COALESCE(status, 'SUBMITTED'),
            NULL,
            'Legacy report import',
            COALESCE(created_at, CURRENT_TIMESTAMP),
            id
        FROM reports
    """)
