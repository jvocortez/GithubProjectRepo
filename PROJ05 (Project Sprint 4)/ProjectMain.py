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
