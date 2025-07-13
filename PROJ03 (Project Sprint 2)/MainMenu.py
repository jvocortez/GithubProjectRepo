import sqlite3
import datetime
import uuid
import os
import hashlib # For a *very simple* demonstration of hashing, NOT for production!

# --- Data Models (Essential for the system, even if not fully used in stubbed functions) ---

class MoodEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, mood_score: int, notes: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.mood_score = mood_score
        self.notes = notes

    # to_dict and from_dict omitted for brevity as they are not directly used in this partial code's execution flow.

class JournalEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, title: str, content: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.title = title
        self.content = content

    # to_dict and from_dict omitted.

class Recommendation:
    def __init__(self, recommendation_id: str, title: str, rationale: str):
        self.recommendation_id = recommendation_id
        self.title = title
        self.rationale = rationale

    # to_dict and from_dict omitted.

class User:
    def __init__(self, user_id: str, username: str, password_hash: str, email: str):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        # These lists are not populated in this partial code, but needed for class structure
        self.mood_entries: list[MoodEntry] = []
        self.journal_entries: list[JournalEntry] = []
        self.recommendations: list[Recommendation] = []

    @staticmethod
    def from_dict(data: dict):
        return User(
            user_id=data["user_id"],
            username=data["username"],
            password_hash=data["password_hash"],
            email=data["email"]
        )

# --- Database Class (only essential methods for login/registration are included) ---

class Database:
    def __init__(self, db_path="mental_health_tracker.db"):
        self.db_path = db_path
        self._create_tables()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _create_tables(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mood_entries (
                    entry_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    mood_score INTEGER NOT NULL,
                    notes TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS journal_entries (
                    entry_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                );
            """)
            conn.commit()

    def save_user(self, user: User):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (user_id, username, password_hash, email)
                    VALUES (?, ?, ?, ?);
                """, (user.user_id, user.username, user.password_hash, user.email))
                conn.commit()
                return True
            except sqlite3.IntegrityError as e:
                print(f"Error: Username or Email already exists. ({e})")
                return False
            except Exception as e:
                print(f"An unexpected error occurred while saving user {user.username}: {e}")
                return False

    def get_user_by_username(self, username: str) -> User | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE username = ?;", (username,))
            row = cursor.fetchone()
            if row:
                user_data = dict(row)
                user = User.from_dict(user_data)
                user.mood_entries = [] # Not needed for this partial code, but for consistency
                user.journal_entries = [] # Not needed for this partial code, but for consistency
                user.recommendations = [] # Not needed for this partial code, but for consistency
                return user
            return None

# --- Hashing Functions (essential for login/registration) ---

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

# --- Stubbed Menu Functions (no actual logic, just placeholders) ---

def add_mood_entry(current_user: User):
    input("Simulating adding mood entry. Press Enter to continue...")
    print("Mood entry action simulated.")

def add_journal_entry(current_user: User):
    input("Simulating adding journal entry. Press Enter to continue...")
    print("Journal entry action simulated.")

def view_mood_trends(current_user: User):
    input("Simulating viewing mood trends. Press Enter to continue...")
    print("View mood trends action simulated.")

def view_journal_history(current_user: User):
    input("Simulating viewing journal history. Press Enter to continue...")
    print("View journal history action simulated.")

def get_coping_strategy_recommendations(current_user: User):
    input("Simulating getting coping strategies. Press Enter to continue...")
    print("Coping strategy recommendations action simulated.")

def access_local_support_resources():
    input("Simulating accessing local resources. Press Enter to continue...")
    print("Local support resources action simulated.")

def view_wellness_scores(current_user: User):
    input("Simulating viewing wellness score. Press Enter to continue...")
    print("Wellness score action simulated.")

def delete_my_details(current_user: User) -> bool:
    input("Simulating account deletion. Press Enter to confirm/cancel...")
    print("Account deletion action simulated.")
    return False

# --- CLI Application Logic (Login, Register, and Authenticated Menu) ---

# Global instances (minimal needed for this partial code)
db = Database("mental_health_tracker.db")

def register_user():
    print("\n--- Register New User ---")
    while True:
        username = input("Enter desired username: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        break
    while True:
        password = input("Enter password: ").strip()
        if len(password) < 6:
            print("Password must be at least 6 characters long.")
            continue
        confirm_password = input("Confirm password: ").strip()
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        break
    while True:
        email = input("Enter email: ").strip()
        if "@" not in email or "." not in email:
            print("Please enter a valid email address.")
            continue
        break

    hashed_pw = hash_password(password)
    new_user = User(str(uuid.uuid4()), username, hashed_pw, email)

    if db.save_user(new_user):
        print(f"\nRegistration successful for {username}! You can now log in.")
    else:
        print("\nRegistration failed. Please try a different username/email.")

def login_user() -> User | None:
    print("\n--- User Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    user = db.get_user_by_username(username)

    if user and verify_password(password, user.password_hash):
        print(f"\nWelcome, {user.username}!")
        return user
    else:
        print("\nInvalid username or password.")
        return None

def authenticated_menu(current_user: User):
    while True:
        print("\n--- Authenticated User Menu ---")
        print(f"Welcome, {current_user.username}!")
        print("1. Add Mood Entry")
        print("2. Add Journal Entry")
        print("3. View Mood Trends")
        print("4. View Journal History")
        print("5. Get Coping Strategy Recommendations")
        print("6. Access Local Support Resources")
        print("7. View Wellness Score")
        print("8. Delete My Details (irreversible!)")
        print("9. Logout")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            add_mood_entry(current_user)
        elif choice == '2':
            add_journal_entry(current_user)
        elif choice == '3':
            view_mood_trends(current_user)
        elif choice == '4':
            view_journal_history(current_user)
        elif choice == '5':
            get_coping_strategy_recommendations(current_user)
        elif choice == '6':
            access_local_support_resources()
        elif choice == '7':
            view_wellness_scores(current_user)
        elif choice == '8':
            if delete_my_details(current_user):
                break
        elif choice == '9':
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def main_menu():
    while True:
        print("\n--- Main Menu ---")
        print("1. Login")
        print("2. Register")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            logged_in_user = login_user()
            if logged_in_user:
                authenticated_menu(logged_in_user)
        elif choice == '2':
            register_user()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
