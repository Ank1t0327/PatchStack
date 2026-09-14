import sqlite3
from typing import Dict, List, Any, Optional, Tuple


class DatabaseManager:
    """
    In-memory SQLite database manager for PatchStack target application,
    demonstrating both vulnerable string-concatenated SQL queries and secure parameterized queries.
    """

    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                role TEXT,
                bio TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                content TEXT
            )
            """
        )
        # Seed users
        seed_users = [
            (101, "user101", "Password101!", "user101@patchstack.local", "user", "Software Developer"),
            (102, "user102", "Password102!", "user102@patchstack.local", "user", "Security Analyst"),
            (103, "user103", "Password103!", "user103@patchstack.local", "user", "DevOps Engineer"),
            (999, "admin", "AdminSecret2026!", "admin@patchstack.local", "admin", "System Administrator"),
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", seed_users)

        # Seed comments
        seed_comments = [
            ("user101", "Welcome to PatchStack security assessment testbed!"),
            ("user102", "Great platform for testing WebApp vulnerabilities."),
        ]
        cursor.executemany("INSERT INTO comments (username, content) VALUES (?, ?)", seed_comments)
        self.conn.commit()

    # --- Day 5: SQL Injection Harness ---

    def get_user_by_id_vulnerable(self, user_id: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Vulnerable SQL Query: Direct string concatenation of user_id.
        """
        cursor = self.conn.cursor()
        query = f"SELECT id, username, email, role, bio FROM users WHERE id = '{user_id}'"
        try:
            cursor.execute(query)
            rows = [dict(row) for row in cursor.fetchall()]
            return True, rows, None
        except sqlite3.Error as e:
            return False, [], str(e)

    def get_user_by_id_secure(self, user_id: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Secure SQL Query: Uses parameterized query binding.
        """
        cursor = self.conn.cursor()
        query = "SELECT id, username, email, role, bio FROM users WHERE id = ?"
        try:
            cursor.execute(query, (user_id,))
            rows = [dict(row) for row in cursor.fetchall()]
            return True, rows, None
        except sqlite3.Error as e:
            return False, [], str(e)

    def search_users_vulnerable(self, term: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Vulnerable Search SQL Query: Unsanitized search filter string concatenation.
        """
        cursor = self.conn.cursor()
        query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{term}%' OR bio LIKE '%{term}%'"
        try:
            cursor.execute(query)
            rows = [dict(row) for row in cursor.fetchall()]
            return True, rows, None
        except sqlite3.Error as e:
            return False, [], str(e)

    def search_users_secure(self, term: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Secure Search SQL Query: Parameterized query binding.
        """
        cursor = self.conn.cursor()
        query = "SELECT id, username, email, role FROM users WHERE username LIKE ? OR bio LIKE ?"
        search_pattern = f"%{term}%"
        try:
            cursor.execute(query, (search_pattern, search_pattern))
            rows = [dict(row) for row in cursor.fetchall()]
            return True, rows, None
        except sqlite3.Error as e:
            return False, [], str(e)

    # --- Day 6: Stored XSS Harness ---

    def add_comment(self, username: str, content: str):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
        self.conn.commit()

    def get_comments(self) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, username, content FROM comments ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]
