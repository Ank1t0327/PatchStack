import time
import secrets
from typing import Dict, Tuple, Any, Optional


class VulnerableAuthManager:
    """
    Deliberately vulnerable authentication system demonstrating common authentication flaws:
    1. Username Enumeration (different error messages for invalid user vs wrong password)
    2. Predictable Sequential Session IDs (SESSION-1001, SESSION-1002, etc.)
    3. Missing Rate Limiting / Account Lockout (allows infinite brute-force attempts)
    4. Weak Session Cookies (no HttpOnly, no Secure, no SameSite)
    """

    def __init__(self):
        self.users: Dict[str, str] = {
            "admin": "AdminPassword123!",
            "alice": "SecretAlice2026",
            "bob": "Password123",
        }
        self.session_counter = 1000

    def login(self, username: str, password: str) -> Tuple[bool, str, Dict[str, Any], Optional[str]]:
        # Flaw 1: Username Enumeration
        if username not in self.users:
            return False, "User not found", {}, None

        if self.users[username] != password:
            return False, "Incorrect password", {}, None

        # Flaw 2: Predictable Sequential Session Token
        self.session_counter += 1
        session_id = f"SESSION-{self.session_counter}"

        # Flaw 4: Weak Cookie Metadata (no HttpOnly, no Secure, no SameSite)
        cookie_header = f"session_id={session_id}; Path=/"

        return True, "Login successful", {"username": username, "session_id": session_id}, cookie_header


class SecureAuthManager:
    """
    Secure authentication system enforcing defense-in-depth security best practices:
    1. Uniform Generic Error Messages (mitigates username enumeration)
    2. Cryptographically Secure High-Entropy Session Tokens (secrets.token_urlsafe(32))
    3. Account Lockout & Rate Limiting (locks account for 15 mins after 5 failed attempts)
    4. Secure Cookie Attributes (HttpOnly; Secure; SameSite=Strict)
    """

    def __init__(self):
        self.users: Dict[str, str] = {
            "admin": "AdminPassword123!",
            "alice": "SecretAlice2026",
            "bob": "Password123",
        }
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_until: Dict[str, float] = {}

    def login(self, username: str, password: str) -> Tuple[bool, str, Dict[str, Any], Optional[str]]:
        now = time.time()

        # Check Account Lockout
        if username in self.lockout_until:
            if now < self.lockout_until[username]:
                remaining = int(self.lockout_until[username] - now)
                return False, "Account temporarily locked. Please try again later.", {}, None
            else:
                del self.lockout_until[username]
                self.failed_attempts[username] = 0

        # Uniform authentication check (mitigates Username Enumeration)
        is_valid_user = username in self.users
        is_valid_pass = is_valid_user and self.users[username] == password

        if not is_valid_pass:
            attempts = self.failed_attempts.get(username, 0) + 1
            self.failed_attempts[username] = attempts

            if attempts >= 5:
                self.lockout_until[username] = now + 900  # 15 minutes lockout
                return False, "Account temporarily locked due to excessive failed attempts.", {}, None

            # Always return generic error message
            return False, "Invalid username or password", {}, None

        # Reset failed attempt counter on success
        self.failed_attempts[username] = 0

        # High-Entropy Cryptographically Secure Session ID
        session_id = secrets.token_urlsafe(32)

        # Secure Cookie Flags
        cookie_header = f"session_id={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict"

        return True, "Login successful", {"username": username, "session_id": session_id}, cookie_header
