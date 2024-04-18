import customtkinter as ctk
from tkinter import messagebox

def on_login_pressed():
    username = username_entry.get()
    password = password_entry.get()
    role = role_combobox.get()

    if username == "user" and password == "password" and role == "User":
        open_candidate_selection(username)
    elif username == "admin" and password == "admin123" and role == "Administrator":
        open_admin_dashboard(username)
    else:
        messagebox.showerror("Login Failed", "Invalid credentials or role selection.")

def open_candidate_selection(username):
    selection_window = ctk.CTkToplevel(root)
    selection_window.title("Select Candidate")
    selection_window.geometry("600x400")

    selection_frame = ctk.CTkFrame(selection_window)
    selection_frame.pack(side="left", fill="both", expand=True)

    info_frame = ctk.CTkFrame(selection_window)
    info_frame.pack(side="right", fill="both", expand=True)

    ctk.CTkLabel(selection_frame, text=f"Hello, {username}! Please select a candidate:").pack(pady=20)

    candidates = {
        "Candidate A": "Details about Candidate A: Experience, vision, etc.",
        "Candidate B": "Details about Candidate B: Experience, vision, etc.",
        "Candidate C": "Details about Candidate C: Experience, vision, etc.",
        "Candidate D": "Details about Candidate D: Experience, vision, etc."
    }

    info_text = ctk.CTkLabel(info_frame, text="", wraplength=250)
    info_text.pack(pady=20)

    vote_button = ctk.CTkButton(info_frame, text="Vote", state="disabled",
                                command=lambda: cast_vote(selected_candidate.get(), selection_window))
    vote_button.pack(pady=10)

    selected_candidate = ctk.StringVar(value="")  # Track the selected candidate

    for candidate, details in candidates.items():
        button = ctk.CTkButton(selection_frame, text=candidate,
                               command=lambda c=candidate, d=details: update_info(info_text, vote_button, c, d, selected_candidate))
        button.pack(pady=10)

def update_info(info_label, vote_button, candidate, details, selected_candidate):
    info_label.configure(text=f"{candidate}: {details}")
    selected_candidate.set(candidate)
    vote_button.configure(state="normal")  # Enable the vote button after a candidate is selected

def cast_vote(candidate, window):
    messagebox.showinfo("Vote Cast", f"You have voted for {candidate}.")
    window.destroy()  # Optionally close the selection window after voting

def submit_registration(username, password, confirm_password, email, reg_window):
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    messagebox.showinfo("Registration Complete", f"Registered {username} with email {email}.")
    reg_window.destroy()
    
def open_admin_dashboard(username):
    dashboard_window = ctk.CTkToplevel(root)
    dashboard_window.title("Admin Dashboard")
    dashboard_window.geometry("400x300")
    welcome_label = ctk.CTkLabel(dashboard_window, text=f"Welcome, {username}! This is the admin dashboard.")
    welcome_label.pack(pady=20)

def open_registration():
    reg_window = ctk.CTkToplevel(root)
    reg_window.title("Register")
    reg_window.geometry("400x300")

    # Username entry
    username_entry = ctk.CTkEntry(reg_window, placeholder_text="Username", width=300, height=40)
    username_entry.grid(row=0, column=1, padx=20, pady=10)
    ctk.CTkLabel(reg_window, text="Username:").grid(row=0, column=0, sticky="e")

    # Password entry
    password_entry = ctk.CTkEntry(reg_window, placeholder_text="Password", show="*", width=300, height=40)
    password_entry.grid(row=1, column=1, padx=20, pady=10)
    ctk.CTkLabel(reg_window, text="Password:").grid(row=1, column=0, sticky="e")

    # Confirm password entry
    confirm_password_entry = ctk.CTkEntry(reg_window, placeholder_text="Confirm Password", show="*", width=300, height=40)
    confirm_password_entry.grid(row=2, column=1, padx=20, pady=10)
    ctk.CTkLabel(reg_window, text="Confirm Password:").grid(row=2, column=0, sticky="e")

    # Email entry
    email_entry = ctk.CTkEntry(reg_window, placeholder_text="Email", width=300, height=40)
    email_entry.grid(row=3, column=1, padx=20, pady=10)
    ctk.CTkLabel(reg_window, text="Email:").grid(row=3, column=0, sticky="e")

    # Submit button
    submit_button = ctk.CTkButton(reg_window, text="Submit", command=lambda: submit_registration(
        username_entry.get(), password_entry.get(), confirm_password_entry.get(), email_entry.get(), reg_window))
    submit_button.grid(row=4, column=0, columnspan=2, pady=20, sticky="ew")

root = ctk.CTk()
root.title("Login Interface")
root.geometry("400x300")

username_entry = ctk.CTkEntry(root, placeholder_text="Username", width=300, height=40)
username_entry.grid(row=0, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Username:").grid(row=0, column=0, sticky="e")

password_entry = ctk.CTkEntry(root, show="*", placeholder_text="Password", width=300, height=40)
password_entry.grid(row=1, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Password:").grid(row=1, column=0, sticky="e")

role_combobox = ctk.CTkComboBox(root, values=["User", "Administrator"], width=300, height=40)
role_combobox.set("User")  # Default to 'User'
role_combobox.grid(row=2, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Role:").grid(row=2, column=0, sticky="e")

login_button = ctk.CTkButton(root, text="Login", command=on_login_pressed)
login_button.grid(row=3, column=0, columnspan=2, pady=20, sticky="ew")

register_button = ctk.CTkButton(root, text="Register", command=open_registration)
register_button.grid(row=4, column=0, columnspan=2, pady=10, sticky="ew")

root.mainloop()
