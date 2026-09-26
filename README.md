# CECMS

CECMS is a browser-based cybercrime early-warning and case-management system. It uses the existing SQLite database, authentication, multi-factor verification, role permissions, and case workflows.

## Run locally

1. Open PowerShell in this folder.
2. Install the project dependencies:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Start the application:

   ```powershell
   .\.venv\Scripts\python.exe webapp.py
   ```

4. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

On first launch, create the Administrator account and enroll an authenticator app using the setup key shown on screen. For an existing CECMS database, sign in with an existing account; accounts without MFA are prompted to enroll.

The application listens on the local computer only by default. Do not expose it to a network without configuring HTTPS, a persistent `CECMS_SECRET_KEY`, setting `CECMS_COOKIE_SECURE=1`, and using an appropriately secured deployment environment.

### Recover Administrator authenticator access

If the Administrator loses access to their authenticator, run this recovery command in a local PowerShell terminal on the computer hosting CECMS:

```powershell
.\.venv\Scripts\python.exe .\recover_mfa.py
```

Enter the Administrator username, then type the exact confirmation phrase displayed by the command. Recovery clears that Administrator's authenticator enrollment and any sign-in lockout for that account; it does not change the password or reveal the old authenticator secret. After recovery, close existing CECMS browser tabs (or use a new private window), sign in with the existing password, and follow the sign-in page's instructions to enroll a replacement authenticator. Anyone who has seen the old setup key should treat it as exposed. This recovery command is intended only for an operator with direct local access to the CECMS computer. The recovery action is recorded in the audit log.

### Recover Administrator password access

CECMS does not use a default password and cannot display an existing password. If the Administrator password is forgotten, run this command in a local PowerShell terminal and choose a new password when prompted:

```powershell
.\.venv\Scripts\python.exe .\recover_admin_password.py
```

The password is entered without being displayed and must be at least 12 characters long. Confirm the reset by typing the exact phrase shown by the command. For this installation the default username prompt is `nokuphiwa`; this is an account name, not a password. Password recovery does not change the account's MFA enrollment. Both recovery commands require direct local access and record the recovery in the security audit log.

## Included workflows

- Secure sign-in with authenticator MFA and existing account lockouts.
- Role-aware dashboards and report visibility.
- Cybercrime report submission, risk indicators, and case status tracking.
- Repeated-contact early-warning alerts with investigator review.
- Administrator tools for staff accounts, access lockout, backups, integrity checks, and the security audit trail.

Automated classifications, risk ratings, and matching indicators are investigative leads, not proof of wrongdoing.
