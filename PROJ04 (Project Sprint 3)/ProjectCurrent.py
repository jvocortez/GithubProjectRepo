import sqlite3
import datetime
import uuid
import os
import hashlib # For a *very simple* demonstration of hashing, NOT for production!

# --- Data Models (from previous responses, essential for the system) ---

class MoodEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, mood_score: int, notes: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.mood_score = mood_score
        self.notes = notes

    def to_dict(self):
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "mood_score": self.mood_score,
            "notes": self.notes
        }

    @staticmethod
    def from_dict(data: dict):
        return MoodEntry(
            data["entry_id"],
            datetime.datetime.fromisoformat(data["timestamp"]),
            data["mood_score"],
            data["notes"]
        )

class JournalEntry:
    def __init__(self, entry_id: str, timestamp: datetime.datetime, title: str, content: str):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.title = title
        self.content = content

    def to_dict(self):
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "content": self.content
        }

    @staticmethod
    def from_dict(data: dict):
        return JournalEntry(
            data["entry_id"],
            datetime.datetime.fromisoformat(data["timestamp"]),
            data["title"],
            data["content"]
        )

class Recommendation:
    def __init__(self, recommendation_id: str, title: str, rationale: str):
        self.recommendation_id = recommendation_id
        self.title = title
        self.rationale = rationale

    def to_dict(self):
        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "rationale": self.rationale
        }

    @staticmethod
    def from_dict(data: dict):
        return Recommendation(
            data["recommendation_id"],
            data["title"],
            data["rationale"]
        )

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

# --- Database Class (using SQLite) ---

class Database:
    def __init__(self, db_path="mental_health_tracker.db"):
        self.db_path = db_path
        self._create_tables()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;") # Ensure foreign key constraints are enforced
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

    def get_user_by_id(self, user_id: str) -> User | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE user_id = ?;", (user_id,))
            row = cursor.fetchone()
            if row:
                user_data = dict(row)
                user = User.from_dict(user_data)
                # Populate in-memory lists from DB
                user.mood_entries = self.get_mood_entries(user_id)
                user.journal_entries = self.get_journal_entries(user_id)
                user.recommendations = self.get_recommendations(user_id)
                return user
            return None

    def get_user_by_username(self, username: str) -> User | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE username = ?;", (username,))
            row = cursor.fetchone()
            if row:
                user_data = dict(row)
                user = User.from_dict(user_data)
                # Populate in-memory lists from DB
                user.mood_entries = self.get_mood_entries(user.user_id)
                user.journal_entries = self.get_journal_entries(user.user_id)
                user.recommendations = self.get_recommendations(user.user_id)
                return user
            return None

    def save_mood_entry(self, user_id: str, mood_entry: MoodEntry):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mood_entries (entry_id, user_id, timestamp, mood_score, notes)
                VALUES (?, ?, ?, ?, ?);
            """, (mood_entry.entry_id, user_id, mood_entry.timestamp.isoformat(), mood_entry.mood_score, mood_entry.notes))
            conn.commit()

    def get_mood_entries(self, user_id: str) -> list[MoodEntry]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_id, timestamp, mood_score, notes FROM mood_entries WHERE user_id = ? ORDER BY timestamp ASC;", (user_id,))
            rows = cursor.fetchall()
            return [MoodEntry(row['entry_id'], datetime.datetime.fromisoformat(row['timestamp']), row['mood_score'], row['notes']) for row in rows]

    def save_journal_entry(self, user_id: str, journal_entry: JournalEntry):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO journal_entries (entry_id, user_id, timestamp, title, content)
                VALUES (?, ?, ?, ?, ?);
            """, (journal_entry.entry_id, user_id, journal_entry.timestamp.isoformat(), journal_entry.title, journal_entry.content))
            conn.commit()

    def get_journal_entries(self, user_id: str) -> list[JournalEntry]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_id, timestamp, title, content FROM journal_entries WHERE user_id = ? ORDER BY timestamp ASC;", (user_id,))
            rows = cursor.fetchall()
            return [JournalEntry(row['entry_id'], datetime.datetime.fromisoformat(row['timestamp']), row['title'], row['content']) for row in rows]

    def save_recommendation(self, user_id: str, recommendation: Recommendation):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO recommendations (recommendation_id, user_id, title, rationale)
                VALUES (?, ?, ?, ?);
            """, (recommendation.recommendation_id, user_id, recommendation.title, recommendation.rationale))
            conn.commit()

    def get_recommendations(self, user_id: str) -> list[Recommendation]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT recommendation_id, title, rationale FROM recommendations WHERE user_id = ?;", (user_id,))
            rows = cursor.fetchall()
            return [Recommendation(row['recommendation_id'], row['title'], row['rationale']) for row in rows]

    def delete_user(self, user_id: str) -> bool:
        """
        Deletes a user and all their associated data from the database.
        Uses a transaction to ensure atomicity.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                # Delete related entries first (if not using ON DELETE CASCADE in schema)
                cursor.execute("DELETE FROM mood_entries WHERE user_id = ?;", (user_id,))
                cursor.execute("DELETE FROM journal_entries WHERE user_id = ?;", (user_id,))
                cursor.execute("DELETE FROM recommendations WHERE user_id = ?;", (user_id,))

                # Then delete the user
                cursor.execute("DELETE FROM users WHERE user_id = ?;", (user_id,))
                conn.commit()
                print(f"User with ID {user_id} and all associated data deleted successfully.")
                return True
            except sqlite3.Error as e:
                conn.rollback() # Rollback in case of any error
                print(f"Error deleting user {user_id}: {e}")
                return False

# --- Other supporting classes (for full functionality, not the core of this request) ---
class MentalHealthAPI:
    def __init__(self):
        self._mental_health_content = [
            Content("mh_content_1", "Understanding Anxiety", "A guide to recognizing and managing anxiety.", "https://example.com/anxiety"),
            Content("mh_content_2", "Depression: Signs and Support", "Information about depression symptoms and where to find help.", "https://example.com/depression"),
        ]
        self._local_resources = [
            Resource("res_1", "Local Therapy Center", "123-456-7890", "Therapy", "Imus City"),
            Resource("res_2", "Community Support Group", "support@example.com", "Support Group", "Imus City"),
        ]

    def get_mental_health_content(self, query: str = "") -> list['Content']:
        if query:
            return [c for c in self._mental_health_content if query.lower() in c.title.lower() or query.lower() in c.description.lower()]
        return self._mental_health_content

    def get_local_resources(self, location: str) -> list['Resource']:
        return [res for res in self._local_resources if location.lower() in res.location.lower()]

class Content: # Needs to be defined as it's used by MentalHealthAPI
    def __init__(self, content_id: str, title: str, description: str, url: str):
        self.content_id = content_id
        self.title = title
        self.description = description
        self.url = url

class Resource: # Needs to be defined as it's used by MentalHealthAPI
    def __init__(self, resource_id: str, name: str, contact_info: str, resource_type: str, location: str):
        self.resource_id = resource_id
        self.name = name
        self.contact_info = contact_info
        self.resource_type = resource_type
        self.location = location

class DataAnalyzer:
    def __init__(self, mental_health_api: MentalHealthAPI):
        self.mental_health_api = mental_health_api

    def analyze_mood_logs(self, mood_entries: list[MoodEntry]) -> dict:
        if not mood_entries:
            return {"patterns": "No mood entries to analyze."}
        total_mood = sum(entry.mood_score for entry in mood_entries)
        average_mood = total_mood / len(mood_entries)
        mood_scores_over_time = [(entry.timestamp, entry.mood_score) for entry in mood_entries]
        mood_scores_over_time.sort(key=lambda x: x[0])
        trend = "Stable"
        if len(mood_scores_over_time) >= 2:
            first_mood = mood_scores_over_time[0][1]
            last_mood = mood_scores_over_time[-1][1]
            if last_mood > first_mood + 1:
                trend = "Improving"
            elif last_mood < first_mood - 1:
                trend = "Declining"
        return {
            "average_mood_score": average_mood,
            "trend": trend,
            "number_of_entries": len(mood_entries)
        }

    def suggest_coping_strategies(self, patterns: dict) -> list[Recommendation]:
        recommendations = []
        if patterns.get("trend") == "Declining":
            recommendations.append(Recommendation(str(uuid.uuid4()), "Consider journaling more frequently.", "Journaling can help process thoughts and emotions during a decline."))
            recommendations.append(Recommendation(str(uuid.uuid4()), "Reach out to a trusted friend or family member.", "Social support can be crucial during difficult times."))
            mh_content = self.mental_health_api.get_mental_health_content("coping")
            if mh_content:
                recommendations.append(Recommendation(str(uuid.uuid4()), f"Read about: {mh_content[0].title}", f"Explore resources like: {mh_content[0].url}"))
        elif patterns.get("trend") == "Improving":
            recommendations.append(Recommendation(str(uuid.uuid4()), "Keep up the positive habits!", "Reinforce behaviors that contribute to improved well-being."))
        else:
             recommendations.append(Recommendation(str(uuid.uuid4()), "Explore new self-care techniques.", "Continuously look for ways to enhance your mental wellness."))
        recommendations.append(Recommendation(str(uuid.uuid4()), "Practice mindfulness for 10 minutes daily.", "Mindfulness can reduce stress and improve focus."))
        return recommendations

    def calculate_wellness_score(self, user: User) -> int:
        mood_entries = user.mood_entries
        journal_entries = user.journal_entries

        if not mood_entries and not journal_entries:
            return 50

        mood_component = 0
        if mood_entries:
            avg_mood = sum(e.mood_score for e in mood_entries) / len(mood_entries)
            mood_component = int((avg_mood / 5) * 50)

        journal_component = 0
        if journal_entries:
            journal_frequency_score = min(len(journal_entries), 20) * 2
            journal_component = journal_frequency_score

        wellness_score = min(mood_component + journal_component, 100)
        return wellness_score

# --- CLI Application Logic ---

# Global instances
db = Database("mental_health_tracker.db")
mh_api = MentalHealthAPI()
data_analyzer = DataAnalyzer(mh_api)

def hash_password(password: str) -> str:
    """
    Simulates a password hash.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    This is for demonstration purposes only. Use bcrypt, scrypt, or Argon2.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a simulated hashed password.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    """
    return hash_password(plain_password) == hashed_password

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

def add_mood_entry(current_user: User):
    print("\n--- Add Mood Entry ---")
    while True:
        try:
            mood_score = int(input("Enter mood score (1-5, 1=bad, 5=great): "))
            if 1 <= mood_score <= 5:
                break
            else:
                print("Mood score must be between 1 and 5.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    notes = input("Enter any notes (optional): ")
    
    mood_entry = current_user.add_mood_entry(mood_score, notes)
    db.save_mood_entry(current_user.user_id, mood_entry)
    print("Mood entry added successfully!")

def add_journal_entry(current_user: User):
    print("\n--- Add Journal Entry ---")
    title = input("Enter journal title: ")
    content = input("Enter journal content: ")
    
    journal_entry = current_user.add_journal_entry(title, content)
    db.save_journal_entry(current_user.user_id, journal_entry)
    print("Journal entry added successfully!")

def view_mood_trends(current_user: User):
    print("\n--- Your Mood Trends ---")
    mood_entries = db.get_mood_entries(current_user.user_id)
    if not mood_entries:
        print("No mood entries yet. Add some to see your trends!")
        return
    
    analysis = data_analyzer.analyze_mood_logs(mood_entries)
    print(f"Average Mood Score: {analysis.get('average_mood_score'):.2f}")
    print(f"Mood Trend: {analysis.get('trend')}")
    print("\nRecent Mood Entries:")
    for entry in mood_entries[-5:]: # Show last 5
        print(f"  [{entry.timestamp.strftime('%Y-%m-%d %H:%M')}] Score: {entry.mood_score}, Notes: {entry.notes[:50]}...")

def view_journal_history(current_user: User):
    print("\n--- Your Journal History ---")
    journal_entries = db.get_journal_entries(current_user.user_id)
    if not journal_entries:
        print("No journal entries yet. Start journaling!")
        return
    
    for entry in journal_entries:
        print(f"\n--- {entry.title} ---")
        print(f"Date: {entry.timestamp.strftime('%Y-%m-%d %H:%M')}")
        print(f"Content:\n{entry.content}")
        print("-" * 30)

def get_coping_strategy_recommendations(current_user: User):
    print("\n--- Coping Strategy Recommendations ---")
    mood_entries = db.get_mood_entries(current_user.user_id)
    analysis = data_analyzer.analyze_mood_logs(mood_entries)
    recommendations = data_analyzer.suggest_coping_strategies(analysis)

    if not recommendations:
        print("No specific recommendations at this time.")
        return

    for rec in recommendations:
        print(f"\nTitle: {rec.title}")
        print(f"Rationale: {rec.rationale}")
        
def access_local_support_resources():
    print("\n--- Local Support Resources ---")
    location = input("Enter your city (e.g., Imus City): ").strip() or "Imus City"
    resources = mh_api.get_local_resources(location)
    if not resources:
        print(f"No local resources found for {location}.")
        return
    for res in resources:
        print(f"\nName: {res.name}")
        print(f"Type: {res.resource_type}")
        print(f"Contact: {res.contact_info}")
        print(f"Location: {res.location}")

def view_wellness_scores(current_user: User):
    print("\n--- Your Wellness Score ---")
    wellness_score = data_analyzer.calculate_wellness_score(current_user)
    print(f"Your current wellness score is: {wellness_score}/100")
    print("This score is based on your mood entries and journaling frequency.")
    if wellness_score < 60:
        print("Consider focusing on self-care and seeking support if needed.")
    elif wellness_score < 80:
        print("You're doing well! Keep up the good habits.")
    else:
        print("Excellent work on your mental well-being!")

def delete_my_details(current_user: User) -> bool:
    """
    Prompts the user to confirm deletion of their account and all data.
    Returns True if user is deleted, False otherwise.
    """
    print("\n--- Delete My Account ---")
    print("WARNING: This action is irreversible and will delete all your data!")
    confirm1 = input(f"Type 'YES' to confirm deletion of account '{current_user.username}': ").strip()
    if confirm1 != "YES":
        print("Account deletion cancelled.")
        return False
    
    confirm2 = input("Are you absolutely sure? Type 'DELETE' to proceed: ").strip()
    if confirm2 == "DELETE":
        if db.delete_user(current_user.user_id):
            print("Your account and all associated data have been successfully deleted.")
            return True # Indicates successful deletion, user should be logged out
        else:
            print("Failed to delete account. Please try again or contact support.")
            return False
    else:
        print("Account deletion cancelled.")
        return False


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
        print("8. Delete My Details (irreversible!)") # New option
        print("9. Logout") # Shifted from 8 to 9

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
        elif choice == '8': # New option handler
            if delete_my_details(current_user):
                break # Break out of the authenticated menu if account is deleted
        elif choice == '9': # Updated logout option
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def main_menu():
    """Main function to handle initial login/registration."""
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
    # Optional: Clean up old database for fresh start during development
    # BE CAREFUL WITH THIS IN PRODUCTION OR WITH REAL DATA!
    # if os.path.exists("mental_health_tracker.db"):
    #     os.remove("mental_health_tracker.db")
    #     print("Existing database removed for a fresh start.")

    main_menu()
