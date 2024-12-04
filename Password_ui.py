# Alex Gilleylen
#

import tkinter as tk
from tkinter import messagebox
from Password_generator import generate_password
from Password_storage import store_password, retrieve_password

def generate_password_ui():
    try:
        length = int(length_entry.get())
        include_upper = upper_var.get()
        include_digits = digits_var.get()
        include_symbols = symbols_var.get()

        password = generate_password(
            length=length,
            include_upper=include_upper,
            include_digits=include_digits,
            include_symbols=include_symbols,
        )
        result_var.set(password)
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def store_password_ui():
    username = username_entry.get()
    site = site_entry.get()
    password = result_var.get()

    if not username or not site or not password:
        messagebox.showerror("Error", "All fields (username, site, password) are required.")
        return

    try:
        store_password(username, site, password)
        messagebox.showinfo("Success", f"Password stored for {username} on {site}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to store password: {e}")

def retrieve_password_ui():
    username = username_entry.get()
    site = site_entry.get()

    if not username or not site:
        messagebox.showerror("Error", "Both Username and Site/Program fields are required.")
        return

    try:
        retrieved_password = retrieve_password(username, site)
        if retrieved_password:
            messagebox.showinfo("Retrieved Password", f"Password for {username} on {site}: {retrieved_password}")
        else:
            messagebox.showwarning("Not Found", f"No password found for {username} on {site}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve password: {e}")

def clear_fields():
    username_entry.delete(0, tk.END)
    site_entry.delete(0, tk.END)
    length_entry.delete(0, tk.END)
    length_entry.insert(0, "12")
    result_var.set("")
    upper_var.set(True)
    digits_var.set(True)
    symbols_var.set(True)

def exit_program():
    root.destroy()

# Create the main window
root = tk.Tk()
root.title("Password Manager")
root.geometry("700x400")

# Frames for better organization
input_frame = tk.Frame(root, padx=10, pady=10)
input_frame.pack(fill="x")

options_frame = tk.Frame(root, padx=10, pady=10)
options_frame.pack(fill="x")

output_frame = tk.Frame(root, padx=10, pady=10)
output_frame.pack(fill="x")

button_frame = tk.Frame(root, padx=10, pady=20)
button_frame.pack(fill="x")

# Input Fields
tk.Label(input_frame, text="Username:").grid(row=0, column=0, sticky="w")
username_entry = tk.Entry(input_frame, width=30)
username_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Site/Program:").grid(row=1, column=0, sticky="w")
site_entry = tk.Entry(input_frame, width=30)
site_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(input_frame, text="Password Length:").grid(row=2, column=0, sticky="w")
length_entry = tk.Entry(input_frame, width=10)
length_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
length_entry.insert(0, "12")

# Options for Password Generation
tk.Label(options_frame, text="Include:").grid(row=0, column=0, sticky="w")
upper_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

tk.Checkbutton(options_frame, text="Uppercase", variable=upper_var).grid(row=1, column=0, sticky="w")
tk.Checkbutton(options_frame, text="Digits", variable=digits_var).grid(row=1, column=1, sticky="w")
tk.Checkbutton(options_frame, text="Symbols", variable=symbols_var).grid(row=1, column=2, sticky="w")

# Output Section
tk.Label(output_frame, text="Generated Password:").grid(row=0, column=0, sticky="w")
result_var = tk.StringVar()
tk.Entry(output_frame, textvariable=result_var, width=50, state="readonly").grid(row=0, column=1, padx=5, pady=5)

# Buttons
tk.Button(button_frame, text="Generate Password", command=generate_password_ui).grid(row=0, column=0, padx=5, pady=5)
tk.Button(button_frame, text="Store Password", command=store_password_ui).grid(row=0, column=1, padx=5, pady=5)
tk.Button(button_frame, text="Retrieve Password", command=retrieve_password_ui).grid(row=0, column=2, padx=5, pady=5)
tk.Button(button_frame, text="Clear Fields", command=clear_fields).grid(row=0, column=3, padx=5, pady=5)
tk.Button(button_frame, text="Exit", command=exit_program).grid(row=0, column=4, padx=5, pady=5)

# Run the application
root.mainloop()
