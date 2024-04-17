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
    selection_window.geometry("400x300")

    ctk.CTkLabel(selection_window, text=f"Hello, {username}! Please select a candidate:").pack(pady=20)

    candidates = ["Candidate A", "Candidate B", "Candidate C", "Candidate D"]
    for candidate in candidates:
        button = ctk.CTkButton(selection_window, text=candidate,
                               command=lambda c=candidate: candidate_selected(c, selection_window))
        button.pack(pady=10)

def candidate_selected(candidate, window):
    messagebox.showinfo("Candidate Selected", f"You have selected {candidate}.")
    window.destroy()

def open_admin_dashboard(username):
    dashboard_window = ctk.CTkToplevel(root)
    dashboard_window.title("Admin Dashboard")
    dashboard_window.geometry("400x300")

    ctk.CTkLabel(dashboard_window, text=f"Welcome, {username}! This is the admin dashboard.").pack(pady=20)

def submit_registration(username, password, confirm_password, email, reg_window):
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    messagebox.showinfo("Registration Complete", f"Registered {username} with email {email}.")
    reg_window.destroy()

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

# Username Entry
username_entry = ctk.CTkEntry(root, placeholder_text="Username", width=300, height=40)
username_entry.grid(row=0, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Username:").grid(row=0, column=0, sticky="e")

# Password Entry
password_entry = ctk.CTkEntry(root, show="*", placeholder_text="Password", width=300, height=40)
password_entry.grid(row=1, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Password:").grid(row=1, column=0, sticky="e")

# Role Combobox
role_combobox = ctk.CTkComboBox(root, values=["User", "Administrator"], width=300, height=40)
role_combobox.set("User")  # Default to 'User'
role_combobox.grid(row=2, column=1, padx=20, pady=10, columnspan=2)
ctk.CTkLabel(root, text="Role:").grid(row=2, column=0, sticky="e")

# Login Button
login_button = ctk.CTkButton(root, text="Login", command=on_login_pressed)
login_button.grid(row=3, column=0, columnspan=2, pady=20, sticky="ew")

# Register Button
register_button = ctk.CTkButton(root, text="Register", command=open_registration)
register_button.grid(row=4, column=0, columnspan=2, pady=10, sticky="ew")

root.mainloop()