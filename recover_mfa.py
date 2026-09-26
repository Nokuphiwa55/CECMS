import hmac
import os

import security


DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "cecms.db"
)


def main():
    if not os.path.isfile(DATABASE):
        raise SystemExit(
            f"CECMS database was not found: {DATABASE}\n"
            "Run this command from your existing CECMS installation."
        )

    security.initialize_authentication(DATABASE)
    print("CECMS local Administrator MFA recovery")
    print("This resets MFA only. It does not display the old authenticator secret")
    print("or change the account password. The next login requires MFA setup again.")
    print("Only run this command in a local terminal on the computer hosting CECMS.\n")

    username = input("Administrator username: ").strip()
    if not username:
        raise SystemExit("No username entered; MFA was not changed.")

    confirmation = f"RESET MFA FOR {username}"
    print(f"\nTo confirm this recovery, type exactly: {confirmation}")
    if not hmac.compare_digest(input("> "), confirmation):
        raise SystemExit("Confirmation did not match; MFA was not changed.")

    try:
        canonical_username = security.reset_administrator_mfa(
            DATABASE, username
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error

    print(f"\nMFA reset for Administrator {canonical_username}.")
    print("Your password has not been changed.")
    print("Return to the CECMS sign-in page and sign in to enroll a new authenticator.")
    print("The sign-in page will display a new setup key. Do not share that key.")
    print("Close any old CECMS tabs or use a new private browser window for enrollment.")


if __name__ == "__main__":
    main()
