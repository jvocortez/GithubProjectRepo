#Database Link: https://drive.google.com/file/d/1-C78nvar5_Jf8MzXtX0AxOfTIazM9DWQ/view?usp=sharing

--------------------------------------------------------------------------

#ProjectMain.py

import sqlite3
import datetime
import uuid
import os
import hashlib
import logging
# import requests # Uncomment if integrating a real external API
import matplotlib.pyplot as plt # For Matplotlib plotting
import io # For saving plot to bytes
import base64 # For encoding plot for Flet image display

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Data Models ---

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
        # No longer storing lists of entries directly here, always fetch from DB

    def add_mood_entry(self, mood_score: int, notes: str) -> MoodEntry:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now()
        mood_entry = MoodEntry(entry_id, timestamp, mood_score, notes)
        return mood_entry

    def add_journal_entry(self, title: str, content: str) -> JournalEntry:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now()
        journal_entry = JournalEntry(entry_id, timestamp, title, content)
        return journal_entry

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
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS journal_entries (
                    entry_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                );
            """)
            conn.commit()
            logging.info("Database tables ensured.")

    def save_user(self, user: User):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (user_id, username, password_hash, email)
                    VALUES (?, ?, ?, ?);
                """, (user.user_id, user.username, user.password_hash, user.email))
                conn.commit()
                logging.info(f"User {user.username} saved successfully.")
                return True
            except sqlite3.IntegrityError as e:
                logging.warning(f"Error: Username or Email already exists. ({e})")
                return False
            except Exception as e:
                logging.error(f"An unexpected error occurred while saving user {user.username}: {e}")
                return False

    def get_user_by_id(self, user_id: str) -> User | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE user_id = ?;", (user_id,))
            row = cursor.fetchone()
            if row:
                return User.from_dict(dict(row))
            return None

    def get_user_by_username(self, username: str) -> User | None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, username, password_hash, email FROM users WHERE username = ?;", (username,))
            row = cursor.fetchone()
            if row:
                return User.from_dict(dict(row))
            return None

    def save_mood_entry(self, user_id: str, mood_entry: MoodEntry):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mood_entries (entry_id, user_id, timestamp, mood_score, notes)
                VALUES (?, ?, ?, ?, ?);
            """, (mood_entry.entry_id, user_id, mood_entry.timestamp.isoformat(), mood_entry.mood_score, mood_entry.notes))
            conn.commit()
            logging.info(f"Mood entry {mood_entry.entry_id} for user {user_id} saved.")

    def update_mood_entry(self, entry_id: str, mood_score: int = None, notes: str = None) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            updates = []
            params = []
            if mood_score is not None:
                updates.append("mood_score = ?")
                params.append(mood_score)
            if notes is not None:
                updates.append("notes = ?")
                params.append(notes)
            
            if not updates:
                logging.warning(f"No fields provided to update for mood entry {entry_id}.")
                return False

            params.append(entry_id)
            query = f"UPDATE mood_entries SET {', '.join(updates)} WHERE entry_id = ?;"
            cursor.execute(query, tuple(params))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Mood entry {entry_id} updated successfully.")
                return True
            else:
                logging.warning(f"Mood entry {entry_id} not found for update.")
                return False

    def delete_mood_entry(self, entry_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM mood_entries WHERE entry_id = ?;", (entry_id,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Mood entry {entry_id} deleted successfully.")
                return True
            else:
                logging.warning(f"Mood entry {entry_id} not found for deletion.")
                return False

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
            logging.info(f"Journal entry {journal_entry.entry_id} for user {user_id} saved.")

    def update_journal_entry(self, entry_id: str, title: str = None, content: str = None) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            updates = []
            params = []
            if title is not None:
                updates.append("title = ?")
                params.append(title)
            if content is not None:
                updates.append("content = ?")
                params.append(content)

            if not updates:
                logging.warning(f"No fields provided to update for journal entry {entry_id}.")
                return False

            params.append(entry_id)
            query = f"UPDATE journal_entries SET {', '.join(updates)} WHERE entry_id = ?;"
            cursor.execute(query, tuple(params))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Journal entry {entry_id} updated successfully.")
                return True
            else:
                logging.warning(f"Journal entry {entry_id} not found for update.")
                return False

    def delete_journal_entry(self, entry_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM journal_entries WHERE entry_id = ?;", (entry_id,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Journal entry {entry_id} deleted successfully.")
                return True
            else:
                logging.warning(f"Journal entry {entry_id} not found for deletion.")
                return False

    def get_journal_entries(self, user_id: str, search_query: str = None) -> list[JournalEntry]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT entry_id, timestamp, title, content FROM journal_entries WHERE user_id = ?"
            params = [user_id]
            if search_query:
                query += " AND (title LIKE ? OR content LIKE ?)"
                params.append(f"%{search_query}%")
                params.append(f"%{search_query}%")
            query += " ORDER BY timestamp ASC;"
            
            cursor.execute(query, tuple(params))
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
            logging.info(f"Recommendation {recommendation.recommendation_id} for user {user_id} saved.")

    def get_recommendations(self, user_id: str) -> list[Recommendation]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT recommendation_id, title, rationale FROM recommendations WHERE user_id = ?;", (user_id,))
            rows = cursor.fetchall()
            return [Recommendation(row['recommendation_id'], row['title'], row['rationale']) for row in rows]

    def delete_user(self, user_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM users WHERE user_id = ?;", (user_id,))
                conn.commit()
                logging.info(f"User with ID {user_id} and all associated data deleted successfully.")
                return True
            except sqlite3.Error as e:
                conn.rollback()
                logging.error(f"Error deleting user {user_id}: {e}")
                return False

# --- API Class (API Integration) ---
class Content:
    def __init__(self, content_id: str, title: str, description: str, url: str):
        self.content_id = content_id
        self.title = title
        self.description = description
        self.url = url

class Resource:
    def __init__(self, resource_id: str, name: str, contact_info: str, resource_type: str, location: str):
        self.resource_id = resource_id
        self.name = name
        self.contact_info = contact_info
        self.resource_type = resource_type
        self.location = location

class MentalHealthAPI:
    def __init__(self):
        # *** SIMULATED API CALLS ***
        # In a real application, you would replace these with 'requests.get()' calls
        # to an actual external API endpoint.
        # Example: self.base_url = "https://api.some_mental_health_service.com"
        # And then in get_mental_health_content:
        # response = requests.get(f"{self.base_url}/content", params={"query": query})
        # response.raise_for_status()
        # return [Content(...) for item in response.json()]

        self._mental_health_content = [
            Content("mh_content_1", "Understanding Anxiety", "A guide to recognizing and managing anxiety.", "https://example.com/anxiety"),
            Content("mh_content_2", "Depression: Signs and Support", "Information about depression symptoms and where to find help.", "https://example.com/depression"),
            Content("mh_content_3", "Coping with Stress", "Techniques to reduce and manage stress effectively.", "https://example.com/stress-coping"),
            Content("mh_content_4", "Mindfulness for Beginners", "Introduction to mindfulness practices.", "https://example.com/mindfulness"),
        ]
        self._local_resources = [
            Resource("res_1", "Local Therapy Center", "123-456-7890", "Therapy", "Imus City"),
            Resource("res_2", "Community Support Group", "support@example.com", "Support Group", "Imus City"),
            Resource("res_3", "Online Crisis Hotline PH", "National Hotline: 1553", "Crisis Hotline", "Philippines (National)"),
            Resource("res_4", "Cavite Mental Wellness Clinic", "046-123-4567", "Clinic", "Dasmarinas City"),
        ]

    def get_mental_health_content(self, query: str = "") -> list['Content']:
        if query:
            return [c for c in self._mental_health_content if query.lower() in c.title.lower() or query.lower() in c.description.lower()]
        return self._mental_health_content

    def get_local_resources(self, location: str) -> list['Resource']:
        return [res for res in self._local_resources if location.lower() in res.location.lower()]

# --- Data Analyzer (with Matplotlib Plotting) ---
class DataAnalyzer:
    def __init__(self, mental_health_api: MentalHealthAPI, db_instance: Database):
        self.mental_health_api = mental_health_api
        self.db = db_instance # DataAnalyzer needs DB access to fetch user data for wellness score and plots

    def analyze_mood_logs(self, mood_entries: list[MoodEntry]) -> dict:
        if not mood_entries:
            return {"patterns": "No mood entries to analyze.", "average_mood_score": 0, "trend": "N/A", "number_of_entries": 0}
        
        total_mood = sum(entry.mood_score for entry in mood_entries)
        average_mood = total_mood / len(mood_entries)
        mood_scores_over_time = [(entry.timestamp, entry.mood_score) for entry in mood_entries]
        mood_scores_over_time.sort(key=lambda x: x[0])
        trend = "Stable"
        if len(mood_scores_over_time) >= 2:
            num_entries = len(mood_scores_over_time)
            if num_entries >= 5:
                first_segment_avg = sum(e[1] for e in mood_scores_over_time[:max(1, num_entries // 5)]) / max(1, num_entries // 5)
                last_segment_avg = sum(e[1] for e in mood_scores_over_time[-max(1, num_entries // 5):]) / max(1, num_entries // 5)
                
                if last_segment_avg > first_segment_avg + 0.5:
                    trend = "Improving"
                elif last_segment_avg < first_segment_avg - 0.5:
                    trend = "Declining"
            else:
                 first_mood = mood_scores_over_time[0][1]
                 last_mood = mood_scores_over_time[-1][1]
                 if last_mood > first_mood + 1:
                     trend = "Improving"
                 elif last_mood < first_mood - 1:
                     trend = "Declining"

        return {
            "patterns": f"Average mood: {average_mood:.2f}. Trend: {trend}.", # Added 'patterns' key
            "average_mood_score": average_mood,
            "trend": trend,
            "number_of_entries": len(mood_entries)
        }

    def suggest_coping_strategies(self, patterns: dict) -> list[Recommendation]:
        recommendations = []
        
        recommendations.append(Recommendation(str(uuid.uuid4()), "Practice deep breathing exercises.", "Can quickly calm your nervous system."))
        recommendations.append(Recommendation(str(uuid.uuid4()), "Ensure you get 7-9 hours of sleep.", "Good sleep hygiene is vital for mental health."))
        recommendations.append(Recommendation(str(uuid.uuid4()), "Engage in regular physical activity.", "Exercise is a proven mood booster."))

        # Check for 'trend' in patterns dictionary
        if patterns.get("trend") == "Declining":
            recommendations.append(Recommendation(str(uuid.uuid4()), "Consider journaling more frequently.", "Journaling can help process thoughts and emotions during a decline."))
            recommendations.append(Recommendation(str(uuid.uuid4()), "Reach out to a trusted friend or family member.", "Social support can be crucial during difficult times."))
            mh_content = self.mental_health_api.get_mental_health_content("stress coping")
            if mh_content:
                recommendations.append(Recommendation(str(uuid.uuid4()), f"Read about: {mh_content[0].title}", f"Explore resources like: {mh_content[0].url}"))
        elif patterns.get("trend") == "Improving":
            recommendations.append(Recommendation(str(uuid.uuid4()), "Keep up the positive habits!", "Reinforce behaviors that contribute to improved well-being."))
            recommendations.append(Recommendation(str(uuid.uuid4()), "Share your progress with someone.", "Celebrating small victories can boost motivation."))
        else:
            recommendations.append(Recommendation(str(uuid.uuid4()), "Explore new self-care techniques.", "Continuously look for ways to enhance your mental wellness."))
            recommendations.append(Recommendation(str(uuid.uuid4()), "Try a new hobby.", "New activities can provide a sense of purpose and joy."))
            
        return recommendations

    def calculate_wellness_score(self, user_id: str) -> int:
        # DataAnalyzer now takes user_id and fetches data using its db instance
        mood_entries = self.db.get_mood_entries(user_id)
        journal_entries = self.db.get_journal_entries(user_id)

        if not mood_entries and not journal_entries:
            return 50

        mood_component = 0
        if mood_entries:
            avg_mood = sum(e.mood_score for e in mood_entries) / len(mood_entries)
            mood_component = int((avg_mood / 5) * 50)

        journal_component = 0
        if journal_entries:
            journal_frequency_score = min(len(journal_entries), 25) * 2
            journal_component = journal_frequency_score

        wellness_score = min(mood_component + journal_component, 100)
        return wellness_score

    def plot_mood_trends(self, user_id: str) -> str | None:
        """
        Generates a Matplotlib plot of mood trends and returns it as a base64 encoded PNG string.
        Returns None if no mood entries or plotting fails.
        """
        mood_entries = self.db.get_mood_entries(user_id)
        if not mood_entries:
            logging.info(f"No mood entries to plot for user {user_id}.")
            return None

        # Sort entries by timestamp to ensure chronological order for plotting
        mood_entries.sort(key=lambda entry: entry.timestamp)

        timestamps = [entry.timestamp for entry in mood_entries]
        scores = [entry.mood_score for entry in mood_entries]
        # notes = [entry.notes if entry.notes else '' for entry in mood_entries] # Not directly used in static plot

        try:
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.plot(timestamps, scores, marker='o', linestyle='-', color='skyblue')
            
            ax.set_title(f"Mood Trend for User: {user_id[:8]}...", fontsize=16) # Show partial ID
            ax.set_xlabel("Date", fontsize=12)
            ax.set_ylabel("Mood Score (1-5)", fontsize=12)
            ax.set_yticks(range(1, 6)) # Ensure Y-axis ticks are 1, 2, 3, 4, 5
            ax.grid(True, linestyle='--', alpha=0.7)
            fig.autofmt_xdate() # Rotate and align X-axis labels

            # Save plot to a bytes buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            plt.close(fig) # Close the figure to free memory
            buf.seek(0)
            
            # Encode to base64
            image_base64 = base64.b64encode(buf.read()).decode('utf-8')
            return image_base64
        except Exception as e:
            logging.error(f"Error generating mood trend plot for user {user_id}: {e}")
            return None

# --- Password Hashing (Utility) ---
def hash_password(password: str) -> str:
    """
    Simulates a password hash.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    This is for demonstration purposes only. Use a strong, dedicated
    password hashing library like `bcrypt`, `scrypt`, or `Argon2` for
    production applications. These libraries are designed to be slow
    and resist brute-force attacks, unlike simple hash functions.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a simulated hashed password.
    *** WARNING: DO NOT USE IN PRODUCTION! ***
    See the warning in hash_password for details.
    """
    return hash_password(plain_password) == hashed_password

--------------------------------------------------------------------------

#controller.py

import logging
import datetime
import uuid
# Import all necessary classes from ProjectMain.py
from ProjectMain import Database, MentalHealthAPI, DataAnalyzer, User, MoodEntry, JournalEntry, Recommendation, hash_password, verify_password, Resource, Content

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AppController:
    def __init__(self):
        self.db = Database()
        self.api = MentalHealthAPI()
        self.data_analyzer = DataAnalyzer(self.api, self.db)
        self.current_user: User | None = None # Holds the currently logged-in user

    def register_user(self, username, password, email) -> tuple[bool, str]:
        if not username or not password or not email:
            return False, "All fields are required."
        if self.db.get_user_by_username(username):
            return False, "Username already exists."
        
        password_hash = hash_password(password)
        new_user = User(str(uuid.uuid4()), username, password_hash, email)
        
        if self.db.save_user(new_user):
            logging.info(f"User {username} registered successfully.")
            return True, "Registration successful! You can now log in."
        else:
            return False, "Registration failed. Username or email might be taken."

    def login_user(self, username, password) -> tuple[bool, str]:
        user = self.db.get_user_by_username(username)
        if user and verify_password(password, user.password_hash):
            self.current_user = user
            logging.info(f"User {username} logged in.")
            return True, "Login successful!"
        else:
            self.current_user = None
            logging.warning(f"Failed login attempt for {username}.")
            return False, "Invalid username or password."

    def logout_user(self):
        logging.info(f"User {self.current_user.username if self.current_user else 'N/A'} logged out.")
        self.current_user = None

    def add_mood_entry(self, mood_score: int, notes: str) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        if not (1 <= mood_score <= 5):
            return False, "Mood score must be between 1 and 5."
        
        mood_entry = self.current_user.add_mood_entry(mood_score, notes)
        self.db.save_mood_entry(self.current_user.user_id, mood_entry)
        logging.info(f"Mood entry added for {self.current_user.username}.")
        return True, "Mood entry added successfully."

    def get_mood_entries(self) -> list[MoodEntry]:
        if not self.current_user:
            return []
        return self.db.get_mood_entries(self.current_user.user_id)

    def update_mood_entry(self, entry_id: str, mood_score: int = None, notes: str = None) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        if mood_score is not None and not (1 <= mood_score <= 5):
            return False, "Mood score must be between 1 and 5 if provided."
        
        success = self.db.update_mood_entry(entry_id, mood_score, notes)
        if success:
            return True, "Mood entry updated."
        else:
            return False, "Failed to update mood entry (not found or no changes)."

    def delete_mood_entry(self, entry_id: str) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        success = self.db.delete_mood_entry(entry_id)
        if success:
            return True, "Mood entry deleted."
        else:
            return False, "Failed to delete mood entry (not found)."

    def add_journal_entry(self, title: str, content: str) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        if not title or not content:
            return False, "Title and content cannot be empty."
        
        journal_entry = self.current_user.add_journal_entry(title, content)
        self.db.save_journal_entry(self.current_user.user_id, journal_entry)
        logging.info(f"Journal entry added for {self.current_user.username}.")
        return True, "Journal entry added successfully."

    def get_journal_entries(self, search_query: str = None) -> list[JournalEntry]:
        if not self.current_user:
            return []
        return self.db.get_journal_entries(self.current_user.user_id, search_query)

    def update_journal_entry(self, entry_id: str, title: str = None, content: str = None) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        success = self.db.update_journal_entry(entry_id, title, content)
        if success:
            return True, "Journal entry updated."
        else:
            return False, "Failed to update journal entry (not found or no changes)."

    def delete_journal_entry(self, entry_id: str) -> tuple[bool, str]:
        if not self.current_user:
            return False, "No user logged in."
        success = self.db.delete_journal_entry(entry_id)
        if success:
            return True, "Journal entry deleted."
        else:
            return False, "Failed to delete journal entry (not found)."

    # --- Methods calling DataAnalyzer and MentalHealthAPI ---
    def get_mood_trends_analysis(self) -> dict:
        """Analyzes mood trends for the current user."""
        if not self.current_user:
            return {"patterns": "No user logged in.", "average_mood_score": 0, "trend": "N/A", "number_of_entries": 0}
        mood_entries = self.db.get_mood_entries(self.current_user.user_id)
        return self.data_analyzer.analyze_mood_logs(mood_entries)

    def get_mood_trend_plot_base64(self) -> str | None:
        """Generates and returns the mood trend plot as a base64 string."""
        if not self.current_user:
            logging.warning("No user logged in for plotting mood trends.")
            return None
        return self.data_analyzer.plot_mood_trends(self.current_user.user_id)

    def get_coping_strategy_recommendations(self) -> list[Recommendation]:
        """Gets coping strategy recommendations based on current mood patterns."""
        if not self.current_user:
            return []
        # First get analysis, then pass it to suggest_coping_strategies
        mood_analysis = self.get_mood_trends_analysis()
        return self.data_analyzer.suggest_coping_strategies(mood_analysis)

    def get_wellness_score(self) -> int:
        """Calculates and returns the user's wellness score."""
        if not self.current_user:
            return 50 # Default score if no user
        return self.data_analyzer.calculate_wellness_score(self.current_user.user_id)

    def get_local_support_resources(self, location: str) -> list[Resource]:
        """Fetches local mental health resources based on location."""
        return self.api.get_local_resources(location)

    def delete_current_user_account(self) -> tuple[bool, str]:
        """Deletes the current user's account and all associated data."""
        if not self.current_user:
            return False, "No user logged in to delete."
        
        user_id_to_delete = self.current_user.user_id
        success = self.db.delete_user(user_id_to_delete)
        if success:
            self.current_user = None # Log out the user after deletion
            return True, "Account deleted successfully."
        else:
            return False, "Failed to delete account."

--------------------------------------------------------------------------

#view.py

import flet as ft
from typing import Callable, Any, List, Dict
import logging

# Assume AppController is imported from controller.py
# from controller import AppController

class AuthView(ft.Column):
    """Handles login and registration pages."""
    def __init__(self, controller: Any, on_login_success: Callable, on_register_success: Callable):
        super().__init__(
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True
        )
        self.controller = controller
        self.on_login_success = on_login_success
        self.on_register_success = on_register_success # This callback is now effectively a no-op for registration success within AuthView

        # Login elements
        self.login_username = ft.TextField(label="Username", autofocus=True)
        self.login_password = ft.TextField(label="Password", password=True, can_reveal_password=True)
        self.login_message = ft.Text("")

        # Register elements
        self.reg_username = ft.TextField(label="Username", autofocus=True)
        self.reg_password = ft.TextField(label="Password", password=True, can_reveal_password=True)
        self.reg_confirm_password = ft.TextField(label="Confirm Password", password=True, can_reveal_password=True)
        self.reg_email = ft.TextField(label="Email")
        self.reg_message = ft.Text("")

        self.content_view = ft.Column()

        self.controls = [
            ft.Container(
                content=self.content_view,
                alignment=ft.alignment.center,
                expand=True
            )
        ]

    def _show_snackbar(self, message: str, color: str = ft.Colors.GREEN_500):
        if self.page:
            self.page.snack_bar = ft.SnackBar(
                ft.Text(message),
                open=True,
                bgcolor=color
            )
            self.page.update()

    def login_clicked(self, e):
        username = self.login_username.value
        password = self.login_password.value
        success, message = self.controller.login_user(username, password)
        self.login_message.value = message
        if self.page: # Ensure page exists before updating
            self.page.update()
        if success:
            self.on_login_success() # Call the external callback to show dashboard
        self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)


    def register_clicked(self, e):
        username = self.reg_username.value
        password = self.reg_password.value
        confirm_password = self.reg_confirm_password.value
        email = self.reg_email.value

        if password != confirm_password:
            self.reg_message.value = "Passwords do not match."
            if self.page: # Ensure page exists before updating
                self.page.update()
            self._show_snackbar("Passwords do not match.", ft.Colors.RED_500)
            return

        # Attempt to register the user
        success, message = self.controller.register_user(username, password, email)
        self.reg_message.value = message
        if self.page:
            self.page.update()
        
        # After successful registration, show the login form and log out the newly registered user
        if success:
            # Important: Log out the user who was automatically logged in by register_user
            # This ensures they have to log in manually
            self.controller.logout_user() 
            self.show_login_form() # Redirect to login form
            self._show_snackbar("Registration successful! Please log in.", ft.Colors.GREEN_500)
        else:
            self._show_snackbar(message, ft.Colors.RED_500)


    def show_login_form(self):
        self.content_view.controls = [
            ft.Text("Login", size=24, weight=ft.FontWeight.BOLD),
            self.login_username,
            self.login_password,
            ft.ElevatedButton("Login", on_click=self.login_clicked),
            self.login_message,
            ft.TextButton("Don't have an account? Register here.", on_click=lambda e: self.show_register_form()),
        ]
        if self.page: # Ensure page exists before updating
            self.page.update()

    def show_register_form(self):
        self.content_view.controls = [
            ft.Text("Register", size=24, weight=ft.FontWeight.BOLD),
            self.reg_username,
            self.reg_password,
            self.reg_confirm_password,
            self.reg_email,
            ft.ElevatedButton("Register", on_click=self.register_clicked),
            self.reg_message,
            ft.TextButton("Already have an account? Login here.", on_click=lambda e: self.show_login_form()),
        ]
        if self.page: # Ensure page exists before updating
            self.page.update()

    def did_mount(self):
        self.show_login_form()


class DashboardView(ft.Column):
    """Handles the main authenticated user dashboard."""
    def __init__(self, controller: Any, on_logout: Callable):
        super().__init__(
            expand=True
        )
        self.controller = controller
        self.on_logout = on_logout

        self.mood_score_input = ft.TextField(label="Mood Score (1-5)", value="3", width=150)
        self.mood_notes_input = ft.TextField(label="Notes", multiline=True)
        self.mood_message = ft.Text("")

        self.journal_title_input = ft.TextField(label="Journal Title")
        self.journal_content_input = ft.TextField(label="Journal Content", multiline=True)
        self.journal_message = ft.Text("")

        self.mood_entries_list = ft.ListView(expand=1, spacing=10, padding=20)
        self.journal_entries_list = ft.ListView(expand=1, spacing=10, padding=20)

        self.mood_trend_analysis_text = ft.Text("")
        
        # Initialize the mood_trend_display_container
        # This container will dynamically hold either the image or a message
        self.mood_trend_display_container = ft.Container(
            content=ft.Text("Click 'View Mood Trends & Plot' to see your mood trend.",
                            text_align=ft.TextAlign.CENTER, color=ft.Colors.GREY_500, size=16),
            alignment=ft.alignment.center,
            width=700, # Adjust size as needed
            height=200, # A reasonable initial height for a message
            visible=True # Ensure the container is visible to show the message
        )
        
        self.recommendations_list = ft.Column([])
        self.local_resources_list = ft.Column([])
        self.local_resource_location_input = ft.TextField(label="City (e.g., Imus City)", value="Imus City")
        self.wellness_score_text = ft.Text("")
        
        self.search_journal_input = ft.TextField(label="Search Journals", width=300, on_submit=self.update_journal_history)

        self.controls = [
            ft.Tabs(
                selected_index=0,
                animation_duration=300,
                tabs=[
                    ft.Tab(
                        text="Mood Tracking",
                        content=ft.Container(
                            padding=20,
                            content=ft.Column([
                                ft.Text("Add New Mood Entry", size=18, weight=ft.FontWeight.BOLD),
                                ft.Row([self.mood_score_input, ft.ElevatedButton("Add Mood", on_click=self.add_mood_entry_clicked)]),
                                self.mood_notes_input,
                                self.mood_message,
                                ft.Divider(),
                                ft.Text("Your Mood Entries", size=18, weight=ft.FontWeight.BOLD),
                                self.mood_entries_list, # Will be populated
                            ], scroll=ft.ScrollMode.ADAPTIVE)
                        ),
                    ),
                    ft.Tab(
                        text="Journaling",
                        content=ft.Container(
                            padding=20,
                            content=ft.Column([
                                ft.Text("Add New Journal Entry", size=18, weight=ft.FontWeight.BOLD),
                                self.journal_title_input,
                                self.journal_content_input,
                                ft.ElevatedButton("Add Journal", on_click=self.add_journal_entry_clicked),
                                self.journal_message,
                                ft.Divider(),
                                ft.Text("Your Journal History", size=18, weight=ft.FontWeight.BOLD),
                                ft.Row([
                                    self.search_journal_input,
                                    ft.IconButton(icon=ft.Icons.SEARCH, on_click=self.update_journal_history)
                                ]),
                                self.journal_entries_list, # Will be populated
                            ], scroll=ft.ScrollMode.ADAPTIVE)
                        ),
                    ),
                    ft.Tab(
                        text="Analysis & Recs",
                        content=ft.Container(
                            padding=20,
                            content=ft.Column([
                                ft.ElevatedButton("View Mood Trends & Plot", on_click=self.view_mood_trends_clicked),
                                self.mood_trend_analysis_text,
                                self.mood_trend_display_container, # Use the container here
                                ft.Divider(),
                                ft.ElevatedButton("Get Coping Strategy Recommendations", on_click=self.get_recommendations_clicked),
                                self.recommendations_list,
                                ft.Divider(),
                                ft.ElevatedButton("View Wellness Score", on_click=self.view_wellness_score_clicked),
                                self.wellness_score_text,
                            ], scroll=ft.ScrollMode.ADAPTIVE)
                        ),
                    ),
                    ft.Tab(
                        text="Resources",
                        content=ft.Container(
                            padding=20,
                            content=ft.Column([
                                ft.Text("Local Support Resources", size=18, weight=ft.FontWeight.BOLD),
                                ft.Row([
                                    self.local_resource_location_input,
                                    ft.ElevatedButton("Find Resources", on_click=self.get_local_resources_clicked)
                                ]),
                                self.local_resources_list,
                                ft.Divider(),
                                ft.TextButton("Delete My Account (Irreversible)", on_click=self.delete_account_clicked, style=ft.ButtonStyle(color=ft.Colors.RED_500)),
                            ], scroll=ft.ScrollMode.ADAPTIVE)
                        )
                    )
                ],
                expand=1,
            )
        ]

    def _show_snackbar(self, message: str, color: str = ft.Colors.GREEN_500):
        if self.page:
            self.page.snack_bar = ft.SnackBar(
                ft.Text(message),
                open=True,
                bgcolor=color
            )
            self.page.update()

    def add_mood_entry_clicked(self, e):
        try:
            mood_score = int(self.mood_score_input.value)
            notes = self.mood_notes_input.value
            success, message = self.controller.add_mood_entry(mood_score, notes)
            self.mood_message.value = message
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.mood_score_input.value = "3"
            self.mood_notes_input.value = ""
            self.update_mood_entries_list()
        except ValueError:
            self.mood_message.value = "Invalid mood score. Please enter a number 1-5."
            self._show_snackbar("Invalid mood score. Please enter a number 1-5.", ft.Colors.RED_500)

    def update_mood_entries_list(self):
        self.mood_entries_list.controls.clear()
        entries = self.controller.get_mood_entries()
        if not entries:
            self.mood_entries_list.controls.append(ft.Text("No mood entries yet."))
        else:
            for entry in entries:
                self.mood_entries_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=10,
                            content=ft.Column([
                                ft.Text(f"Score: {entry.mood_score}", weight=ft.FontWeight.BOLD),
                                ft.Text(f"Date: {entry.timestamp.strftime('%Y-%m-%d %H:%M')}"),
                                ft.Text(f"Notes: {entry.notes if entry.notes else 'N/A'}"),
                                ft.Row([
                                    ft.IconButton(
                                        icon=ft.Icons.EDIT,
                                        tooltip="Edit Mood Entry",
                                        on_click=lambda e, entry_id=entry.entry_id, current_score=entry.mood_score, current_notes=entry.notes: self.open_edit_mood_dialog(entry_id, current_score, current_notes)
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        tooltip="Delete Mood Entry",
                                        on_click=lambda e, entry_id=entry.entry_id: self.delete_mood_entry_clicked(entry_id)
                                    )
                                ])
                            ])
                        )
                    )
                )
        if self.page:
            self.page.update()
    
    def open_edit_mood_dialog(self, entry_id: str, current_score: int, current_notes: str):
        edit_score_field = ft.TextField(label="New Mood Score (1-5)", value=str(current_score))
        edit_notes_field = ft.TextField(label="New Notes", value=current_notes, multiline=True)

        def save_edit(e):
            new_score_val = edit_score_field.value.strip()
            new_notes_val = edit_notes_field.value.strip()
            
            new_score = int(new_score_val) if new_score_val else None
            new_notes = new_notes_val if new_notes_val else None

            success, message = self.controller.update_mood_entry(entry_id, new_score, new_notes)
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.dialog.open = False
            if self.page:
                self.page.update()
            self.update_mood_entries_list()

        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Edit Mood Entry"),
            content=ft.Column([
                edit_score_field,
                edit_notes_field
            ]),
            actions=[
                ft.TextButton("Save", on_click=save_edit),
                ft.TextButton("Cancel", on_click=lambda e: setattr(self.dialog, "open", False) or self.page.update())
            ],
        )
        if self.page:
            self.page.dialog = self.dialog
            self.dialog.open = True
            self.page.update()

    def delete_mood_entry_clicked(self, entry_id: str):
        def confirm_delete(e):
            success, message = self.controller.delete_mood_entry(entry_id)
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.dialog.open = False
            if self.page:
                self.page.update()
            self.update_mood_entries_list()

        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm Deletion"),
            content=ft.Text("Are you sure you want to delete this mood entry?"),
            actions=[
                ft.TextButton("Yes", on_click=confirm_delete),
                ft.TextButton("No", on_click=lambda e: setattr(self.dialog, "open", False) or self.page.update())
            ],
        )
        if self.page:
            self.page.dialog = self.dialog
            self.dialog.open = True
            self.page.update()

    # --- Journal Entry Callbacks ---
    def add_journal_entry_clicked(self, e):
        title = self.journal_title_input.value
        content = self.journal_content_input.value
        success, message = self.controller.add_journal_entry(title, content)
        self.journal_message.value = message
        self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
        self.journal_title_input.value = ""
        self.journal_content_input.value = ""
        self.update_journal_history()

    def update_journal_history(self, e=None): # e=None for when called without event
        self.journal_entries_list.controls.clear()
        search_query = self.search_journal_input.value if self.search_journal_input.value else None
        entries = self.controller.get_journal_entries(search_query)
        if not entries:
            self.journal_entries_list.controls.append(ft.Text("No journal entries yet."))
        else:
            for entry in entries:
                self.journal_entries_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=10,
                            content=ft.Column([
                                ft.Text(f"Title: {entry.title}", weight=ft.FontWeight.BOLD),
                                ft.Text(f"Date: {entry.timestamp.strftime('%Y-%m-%d %H:%M')}"),
                                ft.Text(f"Content: {entry.content[:150]}{'...' if len(entry.content) > 150 else ''}"),
                                ft.Row([
                                    ft.IconButton(
                                        icon=ft.Icons.EDIT,
                                        tooltip="Edit Journal Entry",
                                        on_click=lambda e, entry_id=entry.entry_id, current_title=entry.title, current_content=entry.content: self.open_edit_journal_dialog(entry_id, current_title, current_content)
                                    ),
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        tooltip="Delete Journal Entry",
                                        on_click=lambda e, entry_id=entry.entry_id: self.delete_journal_entry_clicked(entry_id)
                                    )
                                ])
                            ])
                        )
                    )
                )
        if self.page:
            self.page.update()

    def open_edit_journal_dialog(self, entry_id: str, current_title: str, current_content: str):
        edit_title_field = ft.TextField(label="New Title", value=current_title)
        edit_content_field = ft.TextField(label="New Content", value=current_content, multiline=True)

        def save_edit(e):
            new_title_val = edit_title_field.value.strip()
            new_content_val = edit_content_field.value.strip()
            
            new_title = new_title_val if new_title_val else None
            new_content = new_content_val if new_content_val else None

            success, message = self.controller.update_journal_entry(entry_id, new_title, new_content)
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.dialog.open = False
            if self.page:
                self.page.update()
            self.update_journal_history()

        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Edit Journal Entry"),
            content=ft.Column([
                edit_title_field,
                edit_content_field
            ]),
            actions=[
                ft.TextButton("Save", on_click=save_edit),
                ft.TextButton("Cancel", on_click=lambda e: setattr(self.dialog, "open", False) or self.page.update())
            ],
        )
        if self.page:
            self.page.dialog = self.dialog
            self.dialog.open = True
            self.page.update()

    def delete_journal_entry_clicked(self, entry_id: str):
        def confirm_delete(e):
            success, message = self.controller.delete_journal_entry(entry_id)
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.dialog.open = False
            if self.page:
                self.page.update()
            self.update_journal_history()

        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm Deletion"),
            content=ft.Text("Are you sure you want to delete this journal entry?"),
            actions=[
                ft.TextButton("Yes", on_click=confirm_delete),
                ft.TextButton("No", on_click=lambda e: setattr(self.dialog, "open", False) or self.page.update())
            ],
        )
        if self.page:
            self.page.dialog = self.dialog
            self.dialog.open = True
            self.page.update()

    # --- Mood Trends & Plotting ---
    def view_mood_trends_clicked(self, e):
        analysis = self.controller.get_mood_trends_analysis()
        self.mood_trend_analysis_text.value = (
            f"Average Mood Score: {analysis.get('average_mood_score', 0):.2f}\n"
            f"Mood Trend: {analysis.get('trend', 'N/A')}\n"
            f"Total Entries: {analysis.get('number_of_entries', 0)}"
        )
        
        plot_base64 = self.controller.get_mood_trend_plot_base64()
        
        if plot_base64:
            # If there's a plot, set the content of the container to the Image
            self.mood_trend_display_container.content = ft.Image(src_base64=plot_base64)
            self.mood_trend_display_container.height = 450 # Restore height for image
            self.mood_trend_display_container.alignment = ft.alignment.center # Center image
        else:
            # If no plot, set the content of the container to a Text message
            self.mood_trend_display_container.content = ft.Text(
                "Not enough mood entries to generate a plot. Add at least two entries.",
                text_align=ft.TextAlign.CENTER,
                color=ft.Colors.GREY_500,
                size=16
            )
            self.mood_trend_display_container.height = 200 # Adjust height for text message
            self.mood_trend_display_container.alignment = ft.alignment.center # Center the text
            
        self.mood_trend_display_container.visible = True # Ensure the container itself is visible
        
        if self.page:
            self.page.update()


    # --- Recommendations ---
    def get_recommendations_clicked(self, e):
        recs = self.controller.get_coping_strategy_recommendations()
        self.recommendations_list.controls.clear()
        if not recs:
            self.recommendations_list.controls.append(ft.Text("No specific recommendations at this time."))
        else:
            for rec in recs:
                self.recommendations_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=10,
                            content=ft.Column([
                                ft.Text(f"Title: {rec.title}", weight=ft.FontWeight.BOLD),
                                ft.Text(f"Rationale: {rec.rationale}"),
                            ])
                        )
                    )
                )
        if self.page:
            self.page.update()

    # --- Local Resources ---
    def get_local_resources_clicked(self, e):
        location = self.local_resource_location_input.value
        resources = self.controller.get_local_support_resources(location)
        self.local_resources_list.controls.clear()
        if not resources:
            self.local_resources_list.controls.append(ft.Text(f"No local resources found for '{location}'. Try a broader search."))
        else:
            for res in resources:
                # FIX: Change .append() to .controls.append()
                self.local_resources_list.controls.append(
                    ft.Card(
                        content=ft.Container(
                            padding=10,
                            content=ft.Column([
                                ft.Text(f"Name: {res.name}", weight=ft.FontWeight.BOLD),
                                ft.Text(f"Type: {res.resource_type}"),
                                ft.Text(f"Contact: {res.contact_info}"),
                                ft.Text(f"Location: {res.location}"),
                            ])
                        )
                    )
                )
        if self.page:
            self.page.update()

    # --- Wellness Score ---
    def view_wellness_score_clicked(self, e):
        score = self.controller.get_wellness_score()
        message = f"Your current wellness score is: {score}/100\n"
        if score < 60:
            message += "Consider focusing on self-care and seeking support if needed."
        elif score < 80:
            message += "You're doing well! Keep up the good habits."
        else:
            message += "Excellent work on your mental well-being!"
        self.wellness_score_text.value = message
        if self.page:
            self.page.update()

    # --- Delete Account ---
    def delete_account_clicked(self, e):
        def confirm_delete(e):
            logging.info("View: User confirmed account deletion.")
            success, message = self.controller.delete_current_user_account()
            self._show_snackbar(message, ft.Colors.GREEN_500 if success else ft.Colors.RED_500)
            self.dialog.open = False
            if self.page:
                self.page.update()
            if success:
                logging.info("View: Account deletion successful, initiating logout.")
                self.on_logout()
            else:
                logging.warning("View: Account deletion failed, staying on dashboard.")


        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm Account Deletion"),
            content=ft.Text("WARNING: This will permanently delete your account and all data. Are you sure?"),
            actions=[
                ft.TextButton("Yes, Delete My Account", on_click=confirm_delete, style=ft.ButtonStyle(color=ft.Colors.RED_500)),
                ft.TextButton("Cancel", on_click=lambda e: setattr(self.dialog, "open", False) or self.page.update())
            ],
        )
        if self.page:
            self.page.dialog = self.dialog
            self.dialog.open = True
            self.page.update()

    def did_mount(self):
        self.update_mood_entries_list()
        self.update_journal_history()

--------------------------------------------------------------------------

#main.py

import flet as ft
from controller import AppController
from view import AuthView, DashboardView

def main(page: ft.Page):
    page.title = "Mental Health Tracker App"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.LIGHT # You can change this to DARK if preferred

    # Initialize the controller
    controller = AppController()

    def show_auth_view():
        """Displays the login/registration form."""
        page.clean() # Clear all existing controls from the page
        
        # Define the AppBar directly here for AuthView
        page.appbar = ft.AppBar(title=ft.Text("Mental Health Tracker"), center_title=True)
        
        auth_view = AuthView(
            controller=controller,
            on_login_success=show_dashboard_view,
            on_register_success=show_dashboard_view
        )
        
        page.add(auth_view)
        page.update()
        
        # Ensure the initial form is shown after adding to page
        auth_view.show_login_form()


    def show_dashboard_view():
        """Displays the main user dashboard."""
        page.clean() # Clear all existing controls from the page

        # Set the AppBar for the dashboard explicitly here
        page.appbar = ft.AppBar(
            title=ft.Text(f"Welcome, {controller.current_user.username if controller.current_user else 'User'}!"),
            center_title=True,
            actions=[
                ft.IconButton(ft.Icons.LOGOUT, tooltip="Logout", on_click=lambda e: controller.logout_user() or show_auth_view())
            ]
        )
        
        dashboard_view = DashboardView(
            controller=controller,
            on_logout=show_auth_view # When user logs out, return to auth view
        )
        
        page.add(dashboard_view)
        page.update()

        # Ensure dashboard content is updated after adding to page
        dashboard_view.did_mount()


    # Start the application by showing the authentication view
    show_auth_view()

if __name__ == "__main__":
    ft.app(target=main)
