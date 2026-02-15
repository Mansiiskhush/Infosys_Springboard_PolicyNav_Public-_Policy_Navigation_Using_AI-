import streamlit as st
import sqlite3
import re
import jwt
import datetime
import bcrypt
import base64
import os
import time

# --- Configuration & Security ---
SECRET_KEY = "policy_nav_secret_key"
st.set_page_config(page_title="PolicyNav", layout="centered")

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT UNIQUE,
        password TEXT,
        security_question TEXT,
        security_answer TEXT
    )
    """)
    conn.commit()
    return conn, cursor

conn, cursor = init_db()

# --- Helper Functions ---
def get_base64(file):
    if os.path.exists(file):
        with open(file, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""

def password_strength(password):
    checks = {
        "Length ≥ 8": len(password) >= 8,
        "Uppercase Letter": re.search(r"[A-Z]", password),
        "Lowercase Letter": re.search(r"[a-z]", password),
        "Number": re.search(r"[0-9]", password),
        "Special Character": re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    }
    return checks

def valid_password(password):
    return all(password_strength(password).values())

def valid_email(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email)

def hash_data(data):
    return bcrypt.hashpw(data.encode(), bcrypt.gensalt()).decode()

def check_data(data, hashed):
    try:
        return bcrypt.checkpw(data.encode(), hashed.encode())
    except:
        return False

# --- UI Styling (White Buttons & High Contrast) ---
bg_base64 = get_base64("bg.png")
st.markdown(f"""
<style>
.stApp {{
    background-image: url("data:image/png;base64,{bg_base64}");
    background-size: cover;
    background-position: center;
}}

/* Global text color */
html, body, p, span, label, div {{ color: #0B3C5D !important; font-family: sans-serif; }}
h1, h2, h3, h4 {{ color: #0B3C5D !important; }}

/* --- UPDATED BUTTON STYLING --- */
div.stButton > button {{
    background-color: #FFFFFF !important; /* White background */
    color: #0B3C5D !important;           /* Original Blue text */
    border: 2px solid #0B3C5D !important; /* Blue border */
    font-weight: bold !important;
    border-radius: 5px !important;
    padding: 0.5rem 1rem !important;
}}

div.stButton > button:hover {{
    background-color: #0B3C5D !important; /* Flip on hover */
    color: #FFFFFF !important;           /* White text on hover */
}}

/* --- DROPDOWN SYMBOL FIX --- */
/* Custom arrow for the selectbox to make it obvious */
div[data-baseweb="select"]::after {{
    content: "▼";
    color: #0B3C5D;
    position: absolute;
    right: 15px;
    top: 12px;
    pointer-events: none;
    font-size: 0.8rem;
}}

/* Ensure dropdown background and text are clear */
div[data-baseweb="select"] > div {{
    background-color: rgba(255, 255, 255, 0.9) !important;
    color: #0B3C5D !important;
    border: 1px solid #0B3C5D !important;
}}
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("PolicyNav")
st.markdown("<h4 style='color:#0B3C5D;'>Navigate Public Policy with Confidence</h4>", unsafe_allow_html=True)
st.markdown("---")

# --- Session Management ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# --- Dashboard ---
if st.session_state.logged_in:
    st.header(f"Welcome, {st.session_state.username} 👋")
    if st.button("Logout"):
        st.session_state.clear()
        st.rerun()
    st.stop() 

# --- Tabs ---
tab1, tab2, tab3 = st.tabs(["Login", "Signup", "Forgot Password"])

# --- TAB 1: LOGIN ---
with tab1:
    st.subheader("Login")
    l_email = st.text_input("Email", key="l_email")
    l_pass = st.text_input("Password", type="password", key="l_pass")
    if st.button("Sign In", key="login_btn"):
        cursor.execute("SELECT username, password FROM users WHERE email=?", (l_email,))
        user = cursor.fetchone()
        if user and check_data(l_pass, user[1]):
            st.session_state.logged_in = True
            st.session_state.username = user[0]
            st.rerun()
        else:
            st.error("Invalid email or password.")

# --- TAB 2: SIGNUP ---
with tab2:
    st.subheader("Create Account")
    s_user = st.text_input("Username", key="s_user")
    s_email = st.text_input("Email", key="s_email")
    s_pass = st.text_input("Password", type="password", key="s_pass")
    
    if s_pass:
        for rule, met in password_strength(s_pass).items():
            st.write(f"{'✅' if met else '❌'} {rule}")
            
    s_conf = st.text_input("Confirm Password", type="password", key="s_conf")
    s_q = st.selectbox("Security Question", 
                      ["What is your pet name?", "Mother's maiden name?", "Favorite teacher?"], key="s_q")
    s_a = st.text_input("Security Answer", key="s_a")

    if st.button("Register", key="signup_btn"):
        if not all([s_user, s_email, s_pass, s_conf, s_a]):
            st.error("All fields are required.")
        elif s_pass != s_conf:
            st.error("Passwords do not match.")
        else:
            try:
                cursor.execute("INSERT INTO users(username, email, password, security_question, security_answer) VALUES(?,?,?,?,?)",
                               (s_user, s_email, hash_data(s_pass), s_q, hash_data(s_a.lower())))
                conn.commit()
                st.success("Account created! Please log in.")
            except sqlite3.IntegrityError:
                st.error("Email already exists.")

# --- TAB 3: FORGOT PASSWORD ---
with tab3:
    st.subheader("Reset Password")
    if "reset_step" not in st.session_state:
        st.session_state.reset_step = 1

    if st.session_state.reset_step == 1:
        f_email = st.text_input("Enter Registered Email", key="f_email")
        if st.button("Find Account", key="find_btn"):
            cursor.execute("SELECT security_question FROM users WHERE email=?", (f_email,))
            res = cursor.fetchone()
            if res:
                st.session_state.reset_email_locked = f_email
                st.session_state.reset_q = res[0]
                st.session_state.reset_step = 2
                st.rerun()
            else:
                st.error("Email not found.")

    elif st.session_state.reset_step == 2:
        st.write(f"Question: **{st.session_state.reset_q}**")
        f_ans = st.text_input("Answer", key="f_ans")
        if st.button("Verify Answer", key="verify_btn"):
            cursor.execute("SELECT security_answer FROM users WHERE email=?", (st.session_state.reset_email_locked,))
            if check_data(f_ans.lower(), cursor.fetchone()[0]):
                st.session_state.reset_step = 3
                st.rerun()
            else:
                st.error("Incorrect answer.")

    elif st.session_state.reset_step == 3:
        new_p = st.text_input("New Password", type="password", key="new_p")
        if st.button("Update Password", key="update_btn"):
            if valid_password(new_p):
                cursor.execute("UPDATE users SET password=? WHERE email=?", (hash_data(new_p), st.session_state.reset_email_locked))
                conn.commit()
                st.success("Password updated!")
                st.session_state.reset_step = 1
                time.sleep(1)
                st.rerun()
            else:
                st.error("Password is too weak.")
