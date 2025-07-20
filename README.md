# GithubProjectRepo

#04/07/2025

#User.py only shows the prompts being provided to the user when they first ran the Community Mental Health Tracker. In this partial code, the user is prompted to either log in, register, or exit. Once the user already has an account, they can proceed with logging in. Otherwise, they will need to register first.

#1 - Save the partial User.py code on your computer.
#2 - Once saved, locate where the partial code was saved.
#3 - Double click the address bar in order to highlight and edit it. Once done, type "cmd".
#4 - Once cmd is opened under the location where the partial code was saved, type "wsl" to switch over to the Ubuntu WSL Terminal. 
  *Note: Make sure that Ubuntu is installed on your computer, as well as Python being installed on Ubuntu itself, for you to proceed further.
#5 - Once your cmd successfully switched over to the Ubuntu WSL Terminal, type "<Python version> User.py".
  *In this case, type "python3 User.py" for you to incorporate the partial code onto the terminal.

----------------------

#13/07/2025

#MainMenu.py shows the available main menu options to the user once they have successfully registered for an account and logged in to the tracker. #ProjectCurrent.py, on the other hand, combines both #User.py and #MainMenu.py and added a feature for each main menu option once accessed. There is also an added feature to the code wherein the user is allowed to delete their details if they wish to.

*When it comes to running the code in the Ubuntu WSL Terminal, the steps remained to be the same*

----------------------

#20/07/2025

Upon progressing further with the project, it was realized that it would be best for the overall code to be separated in different modules. Mainly #ProjectMain.py, #controller.py, #view.py, and #main.py.

The function of each modules are as follows:

#ProjectMain.py - Contains the core logic, data models (User, MoodEntry, etc.), database management (SQLite CRUD operations), a placeholder for external API calls, and data analysis functionalities (wellness score, mood trend plots, coping strategies).
#controller.py - Acts as the bridge between the UI and the data/logic, managing user authentication, processing user inputs (mood/journal), retrieving data for trends and recommendations, and interacting with the database and APIs.
#view.py - Defines all user interface components and handles UI interactions using the Flet framework (e.g., login/registration forms, dashboard elements).
#main.py - The application's entry point, handling GUI initialization and switching between login/registration and the main dashboard.

It would also be best to have this tested in Visual Studio Code as it supports flet. This will enable the flet feature of the code. To finalize and polish the code, further API integration or FastAPI integration must be made.
