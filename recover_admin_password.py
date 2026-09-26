import getpass
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
    print("CECMS local Administrator password recovery")
    print("This changes only the Administrator password.")
    print("It does not display or change the authenticator setup key.")
    print("Only run this command in a local terminal on the computer hosting CECMS.\n")

    username = input("Administrator username [nokuphiwa]: ").strip() or "nokuphiwa"
    confirmation = f"RESET PASSWORD FOR {username}"
    print(f"\nTo confirm this recovery, type exactly: {confirmation}")
    if not hmac.compare_digest(input("> "), confirmation):
        raise SystemExit("Confirmation did not match; the password was not changed.")

    password = getpass.getpass(
        f"\nNew password (at least {security.MIN_PASSWORD_LENGTH} characters): "
    )
    password_confirmation = getpass.getpass("Re-enter the new password: ")
    if not hmac.compare_digest(password, password_confirmation):
        raise SystemExit("Passwords did not match; the password was not changed.")

    try:
        canonical_username = security.reset_administrator_password(
            DATABASE, username, password
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error

    print(f"\nPassword updated for Administrator {canonical_username}.")
    print("MFA enrollment is unchanged. Sign in at http://127.0.0.1:5000/login.")


if __name__ == "__main__":
    main()
