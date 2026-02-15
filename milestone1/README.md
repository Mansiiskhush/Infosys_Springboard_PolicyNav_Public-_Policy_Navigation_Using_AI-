# Milestone 1 – User Authentication System (PolicyNav)

## Description
PolicyNav is a secure user authentication platform designed to help users navigate public policy with confidence. This milestone focuses on building a robust backend for user identity management, featuring secure password handling, session management, and a custom-styled user interface.

## Features Implemented
- **User Signup**: Includes real-time password strength validation and duplicate email detection.
- **Secure Login**: Authenticates users against hashed credentials stored in a SQLite database.
- **Dashboard**: A protected "Welcome" view that displays the user's unique username upon successful login.
- **Advanced Forgot Password**: A 3-step secure reset flow that uses "Identity Locking" to prevent unauthorized password overrides.
- **Enhanced UI/UX**: Custom CSS integration for high-contrast buttons, background images, and brand logos.
- **Security**: Implementation of `bcrypt` for password hashing and `JWT` for session tokens.

## Tech Stack
- **Frontend**: Streamlit
- **Backend**: Python (Streamlit)
- **Database**: SQLite3
- **Security**: Bcrypt, PyJWT
- **Deployment**: Ngrok

## How to Run
1. **Clone the repository** and navigate to the `milestone1` folder.
2. **Install Dependencies**:
   ```bash
   pip install streamlit bcrypt pyjwt
3. **Run the Application**:
   ```bash
   streamlit run app.py
4. **Expose via Ngrok**:
   ```bash
   ngrok http 8501


## Screen Shots

- **Login Page**
<img width="940" height="464" alt="image" src="https://github.com/user-attachments/assets/0016d57d-3041-4452-8e03-64a3af69e68a" />

- **Sign Up Page**
  <img width="940" height="467" alt="image" src="https://github.com/user-attachments/assets/02d79493-aa66-47fa-8ae3-1a711fe9b858" />

- **Forgot Password Page**
  <img width="940" height="459" alt="image" src="https://github.com/user-attachments/assets/7e8a6b8a-30f3-4e5e-9879-b80063724cf9" />

- **Landing page upon login**
  <img width="940" height="471" alt="image" src="https://github.com/user-attachments/assets/65e4a6e3-0aa8-4bb2-87fb-e86fb1e8608e" />

- **Forgot password page when one enters wrong email/ email that is not in the database**
  <img width="940" height="626" alt="image" src="https://github.com/user-attachments/assets/e9b7c08b-98ba-4431-8b20-6d35723d3768" />

- **Upon entering the correct email and verifying it, only then the security question is accessible to the user,and if the user enter the wrong answer, then they can not access the reset password feature**
  <img width="940" height="432" alt="image" src="https://github.com/user-attachments/assets/11db5e3e-4af1-4367-b8aa-62bd974c317e" />

- **Only upon entering the correct security answer, can the user reset the password, and once at this step they can not modify or change the email**
  <img width="940" height="615" alt="image" src="https://github.com/user-attachments/assets/d0ddad5a-fea7-4bff-94b9-9c83f04ea636" />

- **Sign up page also has password requirment verifier, where if the criterias are not met then the user can not create an account**
  <img width="940" height="891" alt="image" src="https://github.com/user-attachments/assets/febfe456-6610-4ea2-b9d9-eca8b3dbf8c0" />
  <img width="940" height="981" alt="image" src="https://github.com/user-attachments/assets/fbb28463-ce7a-4ae7-a646-69c774a63b58" />

- **Page when the user has successfully created their account**
  <img width="940" height="610" alt="image" src="https://github.com/user-attachments/assets/fb051264-814b-4c25-806b-175081528394" />







