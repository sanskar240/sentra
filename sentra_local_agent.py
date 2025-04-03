import os
import json
import re
import time
import imaplib
import email
from datetime import datetime
from email.header import decode_header
from dotenv import load_dotenv

# Load .env
load_dotenv()
EMAIL = os.getenv("EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")
ALERTS_DIR = "alerts"
KNOWN_IP_FILE = "known_ips.json"
LOG_FILE = "sentra_log.txt"
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "5"))

def load_known_ips():
    try:
        with open(KNOWN_IP_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_known_ips(ips):
    with open(KNOWN_IP_FILE, "w") as f:
        json.dump(ips, f)

def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"[{datetime.now()}] {message}\n")

def fetch_emails_to_alerts():
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(EMAIL, APP_PASSWORD)
        imap.select("inbox")

        status, messages = imap.search(None, 'FROM "noreply@google.com" SUBJECT "New sign-in"')
        for msg_id in messages[0].split()[-5:]:
            res, msg_data = imap.fetch(msg_id, "(RFC822)")
            for response in msg_data:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode()
                                break
                    else:
                        body = msg.get_payload(decode=True).decode()

                    # Extract IP, location, time
                    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
                    loc_match = re.search(r"Location: (.+)", body)
                    time_match = re.search(r"Time: (.+)", body)

                    if ip_match:
                        ip = ip_match.group()
                        location = loc_match.group(1).strip() if loc_match else "Unknown"
                        login_time = time_match.group(1).strip() if time_match else "02:00 AM UTC"
                        alert_file = os.path.join(ALERTS_DIR, f"alert_{ip.replace('.', '_')}.txt")
                        with open(alert_file, "w") as f:
                            f.write(f"IP: {ip}\nLocation: {location}\nTime: {login_time}")
        imap.logout()
    except Exception as e:
        print(f"Email fetch error: {e}")

def score_alert(ip, location, time_str, known_ips):
    score = 0
    if ip not in known_ips:
        score += 3
    if "Russia" in location or "China" in location:
        score += 3
    try:
        hour = int(datetime.strptime(time_str, "%I:%M %p UTC").strftime("%H"))
        if hour < 6 or hour > 22:
            score += 2
    except:
        score += 1
    if location == "Unknown":
        score += 2
    return score

def send_alert(ip, score, location, time_str):
    print(f"\n🚨 ALERT: Suspicious login detected!")
    print(f"IP: {ip}")
    print(f"Score: {score}/10")
    print(f"Location: {location}")
    print(f"Time: {time_str}")
    log_event(f"ALERT - IP: {ip}, Score: {score}, Location: {location}, Time: {time_str}")
    handle_user_response(ip)

def handle_user_response(ip):
    while True:
        print("\n[1] Trust this IP (whitelist)")
        print("[2] Open Google Security Checkup")
        print("[3] View Sentra log")
        print("[4] Skip/Ignore")
        choice = input("Choose an action: ").strip()
        if choice == "1":
            known_ips = load_known_ips()
            if ip not in known_ips:
                known_ips.append(ip)
                save_known_ips(known_ips)
                print(f"✅ IP {ip} whitelisted.")
                log_event(f"User whitelisted IP: {ip}")
            break
        elif choice == "2":
            import webbrowser
            webbrowser.open("https://myaccount.google.com/security-checkup")
        elif choice == "3":
            with open(LOG_FILE, "r") as f:
                print(f.read())
        elif choice == "4":
            print("⚠️ Alert dismissed.")
            log_event(f"User dismissed alert for IP: {ip}")
            break
        else:
            print("❌ Invalid choice. Try again.")

def parse_alert_file(filepath, known_ips):
    with open(filepath, "r") as f:
        content = f.read()

    ip_match = re.search(r"IP:\s*(\d+\.\d+\.\d+\.\d+)", content)
    location_match = re.search(r"Location:\s*(.+)", content)
    time_match = re.search(r"Time:\s*(.+)", content)

    if not (ip_match and location_match and time_match):
        return

    ip = ip_match.group(1)
    location = location_match.group(1).strip()
    time_str = time_match.group(1).strip()

    score = score_alert(ip, location, time_str, known_ips)
    if score >= ALERT_THRESHOLD:
        send_alert(ip, score, location, time_str)

def monitor_alerts():
    print("🔍 Sentra is watching for alert files...\n")
    known_ips = load_known_ips()
    seen_files = set()

    while True:
        fetch_emails_to_alerts()
        for filename in os.listdir(ALERTS_DIR):
            filepath = os.path.join(ALERTS_DIR, filename)
            if filepath not in seen_files and filename.endswith(".txt"):
                parse_alert_file(filepath, known_ips)
                seen_files.add(filepath)
                save_known_ips(known_ips)
        time.sleep(10)

if __name__ == "__main__":
    monitor_alerts()
