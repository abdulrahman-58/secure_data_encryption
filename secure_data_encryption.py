import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- CONFIG ---
USER_FILE = "users.json"
DATA_FILE = "user_data.json"
LOCKOUT_DURATION = 60  # seconds

# --- Generate a consistent key using PBKDF2 ---
def generate_key(password):
    salt = b'static_salt_123'
    kdf = pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    return urlsafe_b64encode(kdf)

# --- Load stored users ---
if os.path.exists(USER_FILE):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
else:
    users = {}

# --- Load stored data ---
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        data_store = json.load(f)
else:
    data_store = {}

# --- Session State Defaults ---
if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# --- Helper Functions ---
def save_users():
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(data_store, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# --- UI ---
st.title("🔐 Secure Multi-User Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Lockout Check ---
if st.session_state.lockout_time:
    remaining = int(LOCKOUT_DURATION - (time.time() - st.session_state.lockout_time))
    if remaining > 0:
        st.warning("🚫 Too many failed attempts. Please wait:")
        countdown_placeholder = st.empty()
        while remaining > 0:
            countdown_placeholder.info(f"⏳ {remaining} seconds remaining...")
            time.sleep(1)
            remaining -= 1
        st.session_state.failed_attempts = 0
        st.session_state.lockout_time = None
        st.rerun()

# --- Home ---
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Multi-User Data System")

# --- Register ---
elif choice == "Register":
    st.subheader("🧾 Register New User")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Register"):
        if new_user in users:
            st.error("❌ Username already exists.")
        elif new_user and new_pass:
            users[new_user] = {
                "password": hash_password(new_pass)
            }
            save_users()
            st.success("✅ User registered successfully!")
        else:
            st.error("⚠️ Please fill in all fields.")

# --- Login ---
elif choice == "Login":
    st.subheader("🔐 User Login")
    user = st.text_input("Username")
    passwd = st.text_input("Password", type="password")

    if st.button("Login"):
        if user in users and users[user]["password"] == hash_password(passwd):
            st.session_state.current_user = user
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success("✅ Login successful!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Wrong credentials. Attempts left: {attempts_left}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time()
                st.session_state.current_user = None
                st.rerun()

# --- Logout ---
elif choice == "Logout":
    st.session_state.current_user = None
    st.success("👋 Logged out successfully.")

# --- Store Data ---
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to store data.")
        st.stop()

    st.subheader("📂 Store Data")
    text = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            key = generate_key(passkey)
            encrypted = encrypt_data(text, key)
            hashed = hash_password(passkey)

            if st.session_state.current_user not in data_store:
                data_store[st.session_state.current_user] = []

            data_store[st.session_state.current_user].append({
                "encrypted_text": encrypted,
                "passkey_hash": hashed
            })
            save_data()
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted)
        else:
            st.error("⚠️ Please fill all fields.")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to retrieve data.")
        st.stop()

    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            key = generate_key(passkey)
            decrypted = decrypt_data(encrypted_input, key)
            if decrypted:
                st.success("✅ Decryption successful!")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time()
                    st.session_state.current_user = None
                    st.rerun()
        else:
            st.error("⚠️ All fields are required.")
