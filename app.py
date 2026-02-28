import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import sqlite3
import bcrypt
import time
import random
from datetime import datetime

LOCK_DURATION = 30
MAX_ATTEMPTS = 3

# ---------------- DATABASE ---------------- #

def create_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB,
            attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            lock_time REAL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

create_database()

# ---------------- LOGGING ---------------- #

def log_event(text):
    with open("security_log.txt", "a") as file:
        file.write(f"[{datetime.now().strftime('%d-%m-%Y %I:%M:%S %p')}] {text}\n")

# ---------------- MAIN WINDOW ---------------- #

app = tk.Tk()
app.title("Cyber Security Authentication System")
app.geometry("520x650")
app.config(bg="#1e272e")

register_frame = tk.Frame(app, bg="#2f3640")
login_frame = tk.Frame(app, bg="#2f3640")
admin_frame = tk.Frame(app, bg="#2f3640")

def show_frame(frame):
    register_frame.pack_forget()
    login_frame.pack_forget()
    admin_frame.pack_forget()
    frame.pack(fill="both", expand=True)

# ---------------- PASSWORD STRENGTH ---------------- #

def check_strength(event):
    password = reg_password.get()
    strength = 0

    if len(password) >= 8:
        strength += 1
    if any(c.isupper() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c in "!@#$%^&*" for c in password):
        strength += 1

    if strength <= 1:
        strength_label.config(text="Weak", fg="red")
    elif strength == 2:
        strength_label.config(text="Medium", fg="orange")
    else:
        strength_label.config(text="Strong", fg="green")

# ---------------- REGISTER ---------------- #

def register_user():
    username = reg_username.get()
    password = reg_password.get()

    if username == "" or password == "":
        messagebox.showerror("Error", "Fill all fields")
        return

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (username, hashed))
        conn.commit()
        messagebox.showinfo("Success", "User Registered")
        show_frame(login_frame)
    except:
        messagebox.showerror("Error", "Username already exists")
    conn.close()

tk.Label(register_frame, text="Register",
         font=("Arial", 22), bg="#2f3640", fg="white").pack(pady=20)

reg_username = tk.Entry(register_frame, font=("Arial", 14))
reg_username.pack(pady=10)

reg_password = tk.Entry(register_frame, font=("Arial", 14), show="*")
reg_password.pack(pady=10)
reg_password.bind("<KeyRelease>", check_strength)

strength_label = tk.Label(register_frame, text="",
                          bg="#2f3640", font=("Arial", 12))
strength_label.pack()

tk.Button(register_frame, text="Register",
          bg="#44bd32", fg="white",
          width=20, command=register_user).pack(pady=10)

tk.Button(register_frame, text="Go to Login",
          bg="#0984e3", fg="white",
          width=20, command=lambda: show_frame(login_frame)).pack(pady=5)

# ---------------- CAPTCHA ---------------- #

captcha_question = ""
captcha_answer = 0

def generate_captcha():
    global captcha_question, captcha_answer
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    captcha_answer = a + b
    captcha_question = f"{a} + {b} = ?"
    captcha_label.config(text=captcha_question)

# ---------------- LOGIN ---------------- #

def unlock_account(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET locked=0, attempts=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()

def start_countdown(username, remaining):
    def countdown():
        nonlocal remaining
        if remaining > 0:
            lock_timer.config(text=f"Locked: {remaining}s remaining", fg="orange")
            remaining -= 1
            app.after(1000, countdown)
        else:
            unlock_account(username)
            lock_timer.config(text="Please enter your password again", fg="green")
    countdown()

def login_user():
    username = login_username.get()
    password = login_password.get()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, attempts, locked, lock_time FROM users WHERE username=?",
                   (username,))
    result = cursor.fetchone()

    if not result:
        messagebox.showerror("Error", "User not found")
        return

    stored_password, attempts, locked, lock_time = result

    if locked == 1:
        elapsed = time.time() - lock_time
        if elapsed < LOCK_DURATION:
            start_countdown(username, int(LOCK_DURATION - elapsed))
            return
        else:
            unlock_account(username)

    if attempts >= 1:
        if captcha_entry.get() != str(captcha_answer):
            messagebox.showerror("Error", "Wrong CAPTCHA")
            return

    if bcrypt.checkpw(password.encode(), stored_password):
        messagebox.showinfo("Success", "Login Successful")
        log_event(f"Login Success - {username}")
        cursor.execute("UPDATE users SET attempts=0 WHERE username=?", (username,))
        conn.commit()
    else:
        attempts += 1
        cursor.execute("UPDATE users SET attempts=? WHERE username=?",
                       (attempts, username))
        conn.commit()
        log_event(f"Failed Login - {username}")

        generate_captcha()

        if attempts >= MAX_ATTEMPTS:
            cursor.execute("UPDATE users SET locked=1, lock_time=? WHERE username=?",
                           (time.time(), username))
            conn.commit()
            log_event(f"Account Locked - {username}")
            start_countdown(username, LOCK_DURATION)
        else:
            messagebox.showerror("Error", "Wrong Password")

    conn.close()

# ---------------- LOGIN UI ---------------- #

tk.Label(login_frame, text="Login",
         font=("Arial", 22),
         bg="#2f3640", fg="white").pack(pady=20)

login_username = tk.Entry(login_frame, font=("Arial", 14))
login_username.pack(pady=10)

login_password = tk.Entry(login_frame, font=("Arial", 14), show="*")
login_password.pack(pady=10)

captcha_label = tk.Label(login_frame, text="",
                         bg="#2f3640", fg="white")
captcha_label.pack()

captcha_entry = tk.Entry(login_frame)
captcha_entry.pack(pady=5)

tk.Button(login_frame, text="Login",
          bg="#44bd32", fg="white",
          width=20, command=login_user).pack(pady=10)

lock_timer = tk.Label(login_frame, text="",
                      bg="#2f3640", font=("Arial", 12))
lock_timer.pack(pady=5)

tk.Button(login_frame, text="Admin Panel",
          bg="#fbc531",
          command=lambda: show_frame(admin_frame)).pack(pady=5)

tk.Button(login_frame, text="Go to Register",
          bg="#0984e3",
          command=lambda: show_frame(register_frame)).pack(pady=5)

# ---------------- ADMIN PANEL ---------------- #

def generate_report():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, attempts, locked FROM users")
    users = cursor.fetchall()
    conn.close()

    with open("security_report.txt", "w") as file:
        file.write("Cyber Security Report\n\n")
        for user in users:
            file.write(f"User: {user[0]} | Attempts: {user[1]} | Locked: {user[2]}\n")

    messagebox.showinfo("Report", "Security report generated")

tk.Label(admin_frame, text="Admin Panel",
         font=("Arial", 22),
         bg="#2f3640", fg="white").pack(pady=20)

tk.Button(admin_frame, text="Generate Security Report",
          bg="#44bd32",
          command=generate_report).pack(pady=10)

tk.Button(admin_frame, text="Back to Login",
          bg="#0984e3",
          command=lambda: show_frame(login_frame)).pack(pady=10)

# ---------------- START ---------------- #

show_frame(register_frame)

app.mainloop()

