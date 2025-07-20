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