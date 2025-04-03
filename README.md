
![output (1)](https://github.com/user-attachments/assets/133c1bc5-ac24-4144-8fa3-93db26043f11)


# Sentra: Local-First Email Security Agent

**Sentra** is a lightweight, headless security agent that monitors your email account for suspicious login activity. Designed for individuals and small teams who care about security but don't want the complexity of enterprise tools, Sentra runs locally, respects privacy, and gives you full control over how login alerts are handled.

---

## Why Sentra?

Most email providers like Gmail or Outlook send alert emails when someone logs into your account from an unknown device or location. But what happens next is entirely passive — maybe you notice the email, maybe you don't.

Sentra watches for those alert emails and immediately acts:

- Parses login alert details (IP, location, time)
- Scores them based on risk factors
- Prompts you with intelligent actions
- Keeps a log of all events and your responses
- Runs offline and respects your data

No dashboards. No cloud syncing. No noise. Just clarity and control.

---

## How It Works

1. **Email Fetching**  
   Sentra connects to your Gmail inbox via IMAP and checks for recent login alert emails (e.g., from `noreply@google.com` with subject `New sign-in`).

2. **Alert Parsing**  
   It extracts key information: IP address, location, and time of login.

3. **Risk Scoring**  
   Sentra applies a rules-based risk model:
   - New IP addresses
   - Logins from high-risk regions
   - Unusual hours (e.g., 2 AM)

4. **Real-Time Alerts**  
   If a login looks suspicious, Sentra notifies you directly in the terminal and gives you a choice:
   - Trust the login (whitelist the IP)
   - Dismiss the alert
   - Open your account security page

5. **Persistent Logging**  
   All events and your decisions are saved to a local log file.

---

## Installation

1. Clone or unzip the Sentra project  
2. Set up a Python virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate 
env\Scripts\activate


