
import streamlit as st
import sqlite3
import re
import jwt
import datetime
import bcrypt
import base64
import os
import time

SECRET_KEY = "policy_nav_secret_key"

st.set_page_config(page_title="PolicyNav", layout="centered")


def get_base64(file):
    with open(file, "rb") as f:
        return base64.b64encode(f.read()).decode()

bg_base64 = ""
if os.path.exists("bg.png"):
    bg_base64 = get_base64("bg.png")

st.markdown(f"""
<style>
.stApp {{
    background-image: url("data:image/png;base64,{bg_base64}");
    background-size: cover;
    background-position: center;
}}

html, body, p, span, label, div {{
    color: #0B3C5D !important;
    font-family: sans-serif;
}}

h1, h2, h3, h4 {{
    color: #0B3C5D !important;
}}

button[data-baseweb="tab"] {{
    color: #0B3C5D !important;
    font-weight: 600;
}}
</style>
""", unsafe_allow_html=True)


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
    return bcrypt.checkpw(data.encode(), hashed.encode())


def create_token(email):
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


col1, col2 = st.columns([1, 6])

with col1:
    if os.path.exists("logo.jpg"):
        st.image("logo.jpg", width=70)

with col2:
    st.title("PolicyNav")
    st.markdown("<h4 style='color:#0B3C5D;'>Navigate Public Policy with Confidence</h4>", unsafe_allow_html=True)

st.markdown("---")


if "reset_attempts" not in st.session_state:
    st.session_state.reset_attempts = 0

if "lock_time" not in st.session_state:
    st.session_state.lock_time = 0


if "token" in st.session_state:
    decoded = verify_token(st.session_state.token)

    if decoded:
        st.header(f"Welcome, {st.session_state.username} 👋")
        st.success("You are successfully logged in to PolicyNav.")

        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

        st.stop()
    else:
        st.error("Session expired. Please login again.")
        st.session_state.clear()
        st.rerun()


tab1, tab2, tab3 = st.tabs(["Login", "Signup", "Forgot Password"])


with tab2:

    st.subheader("Create Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if password:
        checks = password_strength(password)
        st.markdown("### Password Requirements:")
        for rule, passed in checks.items():
            if passed:
                st.markdown(f"✅ {rule}")
            else:
                st.markdown(f"❌ {rule}")

    confirm = st.text_input("Confirm Password", type="password")

    question = st.selectbox("Security Question",
        ["What is your pet name?",
         "What is your mother’s maiden name?",
         "What is your favorite teacher?"])

    answer = st.text_input("Security Answer")

    if st.button("Register"):

        if not all([username, email, password, confirm, answer]):
            st.error("All fields required")

        elif not valid_email(email):
            st.error("Invalid email format")

        elif not valid_password(password):
            st.error("Password does not meet criteria")

        elif password != confirm:
            st.error("Passwords do not match")

        else:
            try:
                cursor.execute("""
                INSERT INTO users(username,email,password,security_question,security_answer)
                VALUES(?,?,?,?,?)
                """,
                (username,
                 email,
                 hash_data(password),
                 question,
                 hash_data(answer.lower())))

                conn.commit()
                st.success("Signup successful!")

            except:
                st.error("Email already registered")


with tab1:

    st.subheader("Login")

    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_pass")

    if st.button("Login"):

        cursor.execute("SELECT username,password FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if not user:
            st.error("Email not found")
        else:
            username, hashed_pw = user
            if check_data(password, hashed_pw):
                token = create_token(email)
                st.session_state.token = token
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Incorrect password")


with tab3:

    st.subheader("Reset Password")

    email_input = st.text_input("Enter Email", key="reset_email")

    if st.button("Load Security Question"):

        cursor.execute("SELECT security_question FROM users WHERE email=?", (email_input,))
        result = cursor.fetchone()

        if result:
            st.session_state.reset_user_email = email_input
            st.session_state.question = result[0]
            st.session_state.reset_attempts = 0
        else:
            st.error("Email not found")

    if "question" in st.session_state:

        if st.session_state.get("reset_attempts", 0) >= 5:
            if time.time() - st.session_state.get("lock_time", 0) < 180:
                st.error("Too many attempts. Try again in 3 minutes.")
                st.stop()
            else:
                st.session_state.reset_attempts = 0

        st.info(st.session_state.question)

        answer = st.text_input("Enter Security Answer")

        if st.button("Verify Answer"):

            cursor.execute("SELECT security_answer FROM users WHERE email=?",
                           (st.session_state.reset_user_email,))
            stored = cursor.fetchone()[0]

            if check_data(answer.lower(), stored):
                st.session_state.verified = True
            else:
                st.session_state.reset_attempts += 1
                if st.session_state.reset_attempts >= 5:
                    st.session_state.lock_time = time.time()
                st.error("Incorrect answer")

    if st.session_state.get("verified", False):

        new_pass = st.text_input("New Password", type="password")
        confirm_pass = st.text_input("Confirm New Password", type="password")

        if st.button("Update Password"):

            if not valid_password(new_pass):
                st.error("Password does not meet criteria")

            elif new_pass != confirm_pass:
                st.error("Passwords do not match")

            else:
                cursor.execute("UPDATE users SET password=? WHERE email=?",
                               (hash_data(new_pass),
                                st.session_state.reset_user_email))
                conn.commit()

                st.success("Password updated successfully!")

                for key in ["question", "verified", "reset_user_email"]:
                    if key in st.session_state:
                        del st.session_state[key]

                st.rerun()
