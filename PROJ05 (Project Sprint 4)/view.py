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
