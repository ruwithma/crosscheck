import requests
import time
import json
import random
import string

class TempMail:
    def __init__(self):
        self.base_url = "https://www.1secmail.com/api/v1/"
        self.email = ""
        self.login = ""
        self.domain = ""

    def generate_email(self):
        """Generates a random email address using the API."""
        # querying the list of active domains
        try:
             # get generic domain list or just let the api gen one?
             # Simple action: gen 1 random email
             action_url = f"{self.base_url}?action=genRandomMailbox&count=1"
             response = requests.get(action_url)
             if response.status_code == 200:
                 self.email = response.json()[0]
                 self.login, self.domain = self.email.split('@')
                 print(f"[*] Generated Email: {self.email}")
                 return self.email
        except Exception as e:
            print(f"[!] Error generating email: {e}")
            return None

    def check_inbox(self):
        """Checks the inbox for the generated email."""
        if not self.email:
            print("[!] No email generated.")
            return []
        
        action_url = f"{self.base_url}?action=getMessages&login={self.login}&domain={self.domain}"
        try:
            response = requests.get(action_url)
            if response.status_code == 200:
                messages = response.json()
                return messages
        except Exception as e:
            print(f"[!] Error checking inbox: {e}")
            return []

    def get_message_content(self, message_id):
        """Retrieves the content of a specific message."""
        action_url = f"{self.base_url}?action=readMessage&login={self.login}&domain={self.domain}&id={message_id}"
        try:
            response = requests.get(action_url)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"[!] Error getting message content: {e}")
            return None

    def wait_for_email(self, timeout=60, check_interval=5):
        """Waits for an email to arrive."""
        print(f"[*] Waiting for email on {self.email} (Timeout: {timeout}s)...")
        start_time = time.time()
        seen_ids = set()
        
        while time.time() - start_time < timeout:
            messages = self.check_inbox()
            for msg in messages:
                if msg['id'] not in seen_ids:
                    print(f"[+] New email from {msg['from']}: {msg['subject']}")
                    content = self.get_message_content(msg['id'])
                    return content
                    # If we wanted to loop for multiple, we'd add to seen_ids and continue
            time.sleep(check_interval)
        
        print("[-] Timed out waiting for email.")
        return None

if __name__ == "__main__":
    tm = TempMail()
    email = tm.generate_email()
    if email:
        # For testing purposes, we can manually send an email or just wait
        print("Test run: Waiting for 10 seconds to see if anything arrives (unlikely unless you send one now).")
        tm.wait_for_email(timeout=10)
