import streamlit as st  # type: ignore
import hashlib
import uuid
from cryptography.fernet import Fernet  # type: ignore

# --- Encryption Setup ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- Initialize Session State ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_authenticated" not in st.session_state:
    st.session_state.is_authenticated = False

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for record in st.session_state.stored_data.values():
        if record["encrypted_text"] == encrypted_text:
            if record["passkey"] == hashed_passkey:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            else:
                st.session_state.failed_attempts += 1
                return None
    return None

# --- Sidebar Menu ---
menu = {
    "🏠 Home": "Home",
    "📂 Store Data": "Store Data",
    "🔍 Retrieve Data": "Retrieve Data",
    "🔑 Login": "Login"
}
choice = st.sidebar.radio("📋 Navigation Menu", list(menu.keys()))
selected_page = menu[choice]

# --- Pages ---
if selected_page == "Home":
    st.title("🛡️ Secure Data Encryption System")
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve data** using encryption and passkeys.")

elif selected_page == "Store Data":
    st.title("🛡️ Secure Data Encryption System")
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            data_id = str(uuid.uuid4())
            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif selected_page == "Retrieve Data":
    st.title("🛡️ Secure Data Encryption System")
    st.subheader("🔍 Retrieve Data")

    if st.session_state.failed_attempts >= 3 and not st.session_state.is_authenticated:
        st.warning("🔒 Too many failed attempts. Please login to retry.")
        st.experimental_rerun()

    encrypted_text = st.text_area("Enter Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Text", decrypted, height=150)
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Locked out. Redirecting to login page...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif selected_page == "Login":
    st.title("🛡️ Secure Data Encryption System")
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure logic in production
            st.session_state.failed_attempts = 0
            st.session_state.is_authenticated = True
            st.success("✅ Reauthorized! You can now retry decryption.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")
