import sqlite3
import datetime
import uuid
import hashlib
import os

class MoodEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, mood_score: int, notes: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.mood_score = mood_score
        self.notes = notes

class JournalEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, title: str, content: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.title = title
        self.content = content

class Recommendation:
    def __init__(self, recommendation_id: str, title: str, rationale: str):
        self.recommendation_id = recommendation_id
        self.title = title
        self.rationale = rationale

class User:
    def __init__(self, user_id: str, username: str, password_hash: str, email: str):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.mood_entries: list[MoodEntry] = []
        self.journal_entries: list[JournalEntry] = []
        self.recommendations: list[Recommendation] = []

    def add_mood_entry(self, mood_score: int, notes: str) -> MoodEntry:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now()
        mood_entry = MoodEntry(entry_id, timestamp, mood_score, notes)
        self.mood_entries.append(mood_entry)
        return mood_entry

    def add_journal_entry(self, title: str, content: str) -> JournalEntry:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now()
        journal_entry = JournalEntry(entry_id, timestamp, title, content)
        self.journal_entries.append(journal_entry)
        return journal_entry

    def add_recommendation(self, recommendation: Recommendation):
        self.recommendations.append(recommendation)

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "username": self.username,
            "password_hash": self.password_hash,
            "email": self.email,
        }

    @staticmethod
    def from_dict(data: dict):
        return User(
            user_id=data["user_id"],
            username=data["username"],
            password_hash=data["password_hash"],
            email=data["email"]
        )

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

    def save_user(self, user: User) -> bool:
        """
        Saves a new user to the database. Returns True on success, False on failure.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (user_id, username, password_hash, email)
                    VALUES (?, ?, ?, ?);
                """, (user.user_id, user.username, user.password_hash, user.email))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
            except Exception as e:
                print(f"An unexpected error occurred while saving user {user.username}: {e}")
                return False

    def get_user_by_username(self, username: str) -> User | None:
        """
        Retrieves a user by their username. Also populates associated data.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE username = ?;", (username,))
            row = cursor.fetchone()
            if row:
                user_data = dict(row)
                user = User.from_dict(user_data)
                user.mood_entries = self.get_mood_entries(user.user_id)
                user.journal_entries = self.get_journal_entries(user.user_id)
                user.recommendations = self.get_recommendations(user.user_id)
                return user
            return None

    def get_mood_entries(self, user_id: str) -> list[MoodEntry]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_id, timestamp, mood_score, notes FROM mood_entries WHERE user_id = ? ORDER BY timestamp ASC;", (user_id,))
            rows = cursor.fetchall()
            return [MoodEntry(row['entry_id'], datetime.datetime.fromisoformat(row['timestamp']), row['mood_score'], row['notes']) for row in rows]

    def get_journal_entries(self, user_id: str) -> list[JournalEntry]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_id, timestamp, title, content FROM journal_entries WHERE user_id = ? ORDER BY timestamp ASC;", (user_id,))
            rows = cursor.fetchall()
            return [JournalEntry(row['entry_id'], datetime.datetime.fromisoformat(row['timestamp']), row['title'], row['content']) for row in rows]

    def get_recommendations(self, user_id: str) -> list[Recommendation]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT recommendation_id, title, rationale FROM recommendations WHERE user_id = ?;", (user_id,))
            rows = cursor.fetchall()
            return [Recommendation(row['recommendation_id'], row['title'], row['rationale']) for row in rows]

def hash_password(password: str) -> str:
    """
    Simulates a password hash using SHA256.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    This is for demonstration purposes only. For real applications, use strong,
    iterative, salted hashing algorithms like bcrypt, scrypt, or Argon2
    via libraries like `passlib` or `flask-bcrypt`.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a simulated hashed password.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    """
    return hash_password(plain_password) == hashed_password

db = Database("mental_health_tracker.db")

def register_user():
    """Handles the user registration process."""
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
        print(f"\nRegistration successful for '{username}'! You can now log in.")
    else:
        print("\nRegistration failed. This usually means the username or email already exists. Please try a different one.")

def login_user() -> User | None:
    """Handles the user login process."""
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
    """
    This function represents the menu displayed after a successful login.
    For this request, it's simplified to just a welcome and logout option.
    """
    while True:
        print("\n--- Authenticated User Menu ---")
        print(f"Logged in as: {current_user.username}")
        print("1. View my details (placeholder)")
        print("2. Logout")

        choice = input("Enter your choice: ").strip()

        if choice == '1':
            print(f"\nUser ID: {current_user.user_id}")
            print(f"Username: {current_user.username}")
            print(f"Email: {current_user.email}")
            print(f"Number of mood entries: {len(current_user.mood_entries)}")
            print(f"Number of journal entries: {len(current_user.journal_entries)}")
            print(f"Number of recommendations: {len(current_user.recommendations)}")
        elif choice == '2':
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def main_menu():
    """Main function to handle initial login/registration flow."""
    print("Welcome to the Community Mental Health Tracker!")

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
            print("Thank you for using the Mental Health Tracker. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":

    main_menu()
