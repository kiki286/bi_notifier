# Better Impact Notifier & Workflow Dashboard

A complete automated notification system and public-facing (but encrypted) workflow dashboard for managing Kwinana volunteer applications via the Better Impact API.

## Features

- **Automated Polling:** Checks Better Impact every 30 minutes via GitHub Actions.
- **Immediate Alerts:** Sends an email to the supervisor immediately when a Registration Form is signed or an induction date is entered.
- **Daily Digest:** Sends a consolidated email at 8:00 AM (AWST) outlining non-critical profile changes and flagging **Stalled Workflows** (e.g. pending HR inductions after passing an interview).
- **Live Workflow Dashboard:** A slick frontend web dashboard hosted for free on GitHub Pages that displays the volunteer pipeline (New Applications, Awaiting HR, Awaiting Site Induction) along with recent activity lists.
- **End-to-End Encryption:** Because free GitHub Pages requires a public repository, **all volunteer data is secured using AES-256-GCM encryption**. The Python script encrypts the state and dashboard payloads in the cloud, and the website prompts you for a password to decrypt the data locally in your browser. Nothing readable is ever saved in the repository.

---

## Setup & Configuration

### Step 1: Add Secrets to GitHub

In your GitHub repository, go to **Settings → Secrets and variables → Actions → New repository secret** and add the following:

| Secret Name        | Purpose                                                                                   |
|--------------------|-------------------------------------------------------------------------------------------|
| `BI_API_USERNAME`  | Your Better Impact API key username                                                       |
| `BI_API_PASSWORD`  | Your Better Impact API key password                                                       |
| `SMTP_HOST`        | Your mail server (e.g., `smtp.office365.com`)                                             |
| `SMTP_PORT`        | Usually `587` for TLS                                                                     |
| `SMTP_USERNAME`    | The email address sending the notification                                                |
| `SMTP_PASSWORD`    | Password for the sender email address                                                     |
| `NOTIFY_EMAIL`     | The supervisor's email address receiving the alerts                                       |
| `STATE_PASSWORD`   | **CRITICAL:** A secure password used to AES-encrypt all tracked data in the repository.   |

### Step 2: Configure GitHub Actions Permissions

Since the script needs to update its tracking state:
1. Go to **Settings → Actions → General**.
2. Scroll to **Workflow permissions** and select **Read and write permissions**.
3. Check the box to allow GitHub Actions to create and approve pull requests.

### Step 3: Enable the GitHub Pages Dashboard

To view the frontend dashboard:
1. Go to **Settings → Pages**.
2. Under **Build and deployment**, set the Source to **Deploy from a branch**.
3. Set the branch to `main` and the folder to `/docs`.
4. Click Save. Your dashboard will be accessible at `https://<your-username>.github.io/<repo-name>/`.

---

## Security & Client-Side Decryption

Because GitHub Pages requires public repositories on free accounts, pushing volunteer names to an unencrypted `state.json` is a privacy violation. 

To solve this:
1. **GitHub Actions** reads your `STATE_PASSWORD` and encrypts both `state.json` and `docs/dashboard.json` into unreadable cyphertext.
2. **The Dashboard** intercepts the network request for `dashboard.json`, prompts the user for the password, and uses the browser's native **Web Crypto API** to decrypt the data on the fly.
3. Passwords are saved temporarily via `sessionStorage` to allow page reloads without entering the password again.

No plaintext PII (Personally Identifiable Information) touches the GitHub repository files. 

---

## Monitored Fields

The script currently explicitly monitors these four Better Impact custom fields:
- `Registration Form - Sign`
- `Supervisor Interview Outcome`
- `HR Induction Date`
- `Site Induction Date`

If these fields need to be adapted, you can update the constants at the very top of `poll_better_impact.py`.

---

## Stopping or Pausing the Script

If you need to stop notifications momentarily without destroying the repository:
1. Go to **Actions → Better Impact Induction Notifier**.
2. Click the `...` menu on the right and hit **Disable workflow**.
