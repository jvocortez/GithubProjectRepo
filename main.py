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