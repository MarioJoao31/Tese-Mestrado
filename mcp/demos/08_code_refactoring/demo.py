"""
demo.py  –  08_code_refactoring
----------------------------------
Standalone demonstration of all code refactoring MCP tools.
No LLM or running MCP server required – calls tool functions directly.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.static_analysis_tools import (
    analyze_code_quality,
    detect_code_smells,
    find_dead_code,
    check_security_patterns,
)
from tools.complexity_tools import (
    calculate_cyclomatic_complexity,
    measure_code_metrics,
    analyze_nesting_depth,
    evaluate_coupling,
)
from tools.pattern_detection_tools import (
    detect_design_patterns,
    find_antipatterns,
    analyze_solid_principles,
    detect_duplicate_logic,
)
from tools.refactoring_tools import (
    suggest_refactorings,
    suggest_extract_method,
    improve_naming,
    simplify_conditionals,
)

# ---------------------------------------------------------------------------
# Sample code snippets
# ---------------------------------------------------------------------------

SAMPLE_CODE_BAD = '''\
import os
import json
import re
import sys  # unused

DB_PASSWORD = "super_secret_123"
MAX = 1000

class userManager:
    """Manages users."""

    def __init__(self):
        self._users = []
        self._admins = []
        self._pending = []
        self._logs = []

    def processUserData(self, u, p, e, r, a, t):
        """Process user."""
        if u == True:
            if p != None:
                if len(p) > 8:
                    if e != None:
                        if re.match(r".*@.*", e):
                            result = True
                        else:
                            result = False
                    else:
                        result = False
                else:
                    result = False
            else:
                result = False
        else:
            result = False
        return result

    def validate(self, password):
        import hashlib
        h = hashlib.md5(password.encode()).hexdigest()
        if password == "admin":
            return True
        query = f"SELECT * FROM users WHERE password=\'{password}\'"
        os.system(f"logger {password}")
        return h

    def getUsers(self):
        data = []
        for u in self._users:
            data.append(u)
        return data

    def filterUsers(self, role):
        data = []
        for u in self._users:
            data.append(u)
        return data

    def searchUsers(self, query):
        data = []
        for u in self._users:
            data.append(u)
        return data
'''

SAMPLE_CODE_GOOD = '''\
"""User authentication module."""
import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class User:
    """Represents an authenticated user."""

    username: str
    email: str
    role: str

    def is_admin(self) -> bool:
        """Return True if user has admin role."""
        return self.role == "admin"


class UserRepository:
    """Manages user persistence."""

    def __init__(self) -> None:
        self._users: list[User] = []

    def add(self, user: User) -> None:
        """Add a user to the repository."""
        self._users.append(user)

    def find_by_role(self, role: str) -> list[User]:
        """Return all users matching the given role."""
        return [u for u in self._users if u.role == role]


class AuthService:
    """Handles password hashing and verification."""

    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256 with a random salt."""
        salt = secrets.token_hex(16)
        digest = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{salt}${digest}"

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against its stored hash."""
        try:
            salt, digest = stored_hash.split("$", 1)
        except ValueError:
            return False
        expected = hashlib.sha256((salt + password).encode()).hexdigest()
        return secrets.compare_digest(expected, digest)

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Return True if email matches a basic RFC pattern."""
        return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))
'''


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print(f"\n{'='*62}")
    print(f"  {title}")
    print("="*62)


def show(label: str, result: str) -> None:
    print(f"\n[{label}]")
    try:
        print(json.dumps(json.loads(result), indent=2))
    except json.JSONDecodeError:
        print(result)


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------

def demo_static_analysis() -> None:
    section("Static Analysis (bad code)")
    show("analyze_code_quality", analyze_code_quality(SAMPLE_CODE_BAD))
    show("detect_code_smells", detect_code_smells(SAMPLE_CODE_BAD))
    show("find_dead_code", find_dead_code(SAMPLE_CODE_BAD))
    show("check_security_patterns", check_security_patterns(SAMPLE_CODE_BAD))


def demo_complexity() -> None:
    section("Complexity Metrics")
    show("calculate_cyclomatic_complexity (bad)", calculate_cyclomatic_complexity(SAMPLE_CODE_BAD))
    show("calculate_cyclomatic_complexity (good)", calculate_cyclomatic_complexity(SAMPLE_CODE_GOOD))
    show("measure_code_metrics (bad)", measure_code_metrics(SAMPLE_CODE_BAD))
    show("measure_code_metrics (good)", measure_code_metrics(SAMPLE_CODE_GOOD))
    show("analyze_nesting_depth (bad)", analyze_nesting_depth(SAMPLE_CODE_BAD))
    show("evaluate_coupling (bad)", evaluate_coupling(SAMPLE_CODE_BAD))


def demo_pattern_detection() -> None:
    section("Pattern Detection")
    show("detect_design_patterns (good code)", detect_design_patterns(SAMPLE_CODE_GOOD))
    show("find_antipatterns (bad code)", find_antipatterns(SAMPLE_CODE_BAD))
    show("analyze_solid_principles (bad)", analyze_solid_principles(SAMPLE_CODE_BAD))
    show("analyze_solid_principles (good)", analyze_solid_principles(SAMPLE_CODE_GOOD))
    show("detect_duplicate_logic (bad)", detect_duplicate_logic(SAMPLE_CODE_BAD))


def demo_refactoring() -> None:
    section("Refactoring Suggestions")
    show("suggest_refactorings (bad)", suggest_refactorings(SAMPLE_CODE_BAD))
    show("suggest_extract_method (bad)", suggest_extract_method(SAMPLE_CODE_BAD))
    show("improve_naming (bad)", improve_naming(SAMPLE_CODE_BAD))
    show("simplify_conditionals (bad)", simplify_conditionals(SAMPLE_CODE_BAD))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     08 · Code Refactoring Tools – Demo                  ║")
    print("╚══════════════════════════════════════════════════════════╝")

    demo_static_analysis()
    demo_complexity()
    demo_pattern_detection()
    demo_refactoring()

    print("\n✅  Demo complete.")
