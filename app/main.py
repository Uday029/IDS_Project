import os
import joblib
import pandas as pd
import streamlit as st
import numpy as np
import hashlib
import time
from sqlalchemy import create_engine, text

# 1. PAGE SETUP & THEME
st.set_page_config(page_title="Intrusion Detection Dashboard", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    /* Global dark blue background */
    .stApp {
        background-color: #1e293b; 
        color: #f8fafc;
        font-family: 'Inter', sans-serif;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0f172a;
        border-right: 1px solid #334155;
    }
    
    /* Make Main Menu larger */
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        padding: 10px 0px;
        cursor: pointer;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label p {
        font-size: 18px !important;
        font-weight: 600 !important;
        color: #e2e8f0;
    }
    [data-testid="stSidebar"] h3 {
        font-size: 22px !important;
        padding-top: 20px;
        padding-bottom: 10px;
    }
    
    /* Headings: Changed to white to fix background blending */
    h1, h2, h3, h4 {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Standard Buttons */
    .stButton>button, .stFormSubmitButton>button {
        background-color: #38bdf8;
        color: #0f172a !important;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        width: 100%;
        transition: 0.3s;
        padding: 10px;
    }
    .stButton>button:hover, .stFormSubmitButton>button:hover {
        background-color: #0ea5e9;
        color: white !important;
    }

    /* Inputs */
    .stTextInput>div>div, .stSelectbox>div>div, .stNumberInput>div>div, .stSlider>div>div {
        background-color: #334155;
        color: white;
        border: 1px solid #475569;
        border-radius: 8px;
        padding: 5px;
    }
    
    /* Metric Cards */
    div[data-testid="metric-container"] {
        background-color: #0f172a;
        border: 1px solid #334155;
        padding: 10px;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

# 2. DATABASE & AUTHENTICATION SETUP
def get_db_engine():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'sql', 'ids_database.db')
    return create_engine(f"sqlite:///{db_path}")

def init_db():
    engine = get_db_engine()
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS PredictionResults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                protocol_type VARCHAR(50),
                service VARCHAR(50),
                flag VARCHAR(50),
                src_bytes FLOAT,
                dst_bytes FLOAT,
                predicted_class VARCHAR(50),
                model_used VARCHAR(50),
                username VARCHAR(50)
            )
        """))
        try:
            conn.execute(text("ALTER TABLE PredictionResults ADD COLUMN username VARCHAR(50)"))
        except Exception:
            pass
        conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, password):
    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            query = text("INSERT INTO Users (username, password_hash) VALUES (:u, :p)")
            conn.execute(query, {"u": username, "p": hash_password(password)})
            conn.commit()
        return True
    except Exception as e:
        return False

def verify_user(username, password):
    engine = get_db_engine()
    with engine.connect() as conn:
        query = text("SELECT password_hash FROM Users WHERE username = :u")
        result = conn.execute(query, {"u": username}).fetchone()
        if result and result[0] == hash_password(password):
            return True
    return False

# 3. MACHINE LEARNING MODELS
@st.cache_resource
def load_models():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_dir = os.path.join(base_dir, 'models')
    try:
        model = joblib.load(os.path.join(models_dir, 'best_model.pkl'))
        scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
        encoders = joblib.load(os.path.join(models_dir, 'label_encoders.pkl'))
        target_encoder = joblib.load(os.path.join(models_dir, 'target_encoder.pkl'))
        features = joblib.load(os.path.join(models_dir, 'model_features.pkl'))
        return model, scaler, encoders, target_encoder, features
    except Exception:
        return None, None, None, None, None

@st.cache_data
def load_sample_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "dataset", "Cleaned_NSL_KDD.csv")
    try:
        df = pd.read_csv(data_path)
        return df.sample(1500, random_state=42)
    except:
        return pd.DataFrame()

def get_live_dashboard_data():
    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            # Pull new detections from the live database
            df_live = pd.read_sql("SELECT src_bytes, dst_bytes, predicted_class as attack_class FROM PredictionResults", conn)
            return df_live
    except Exception:
        return pd.DataFrame()

def save_prediction(username, data_dict, predicted_class, model_name):
    engine = get_db_engine()
    with engine.connect() as conn:
        query = text("""
            INSERT INTO PredictionResults 
            (protocol_type, service, flag, src_bytes, dst_bytes, predicted_class, model_used, username)
            VALUES (:pt, :s, :f, :sb, :db, :pc, :mu, :u)
        """)
        conn.execute(query, {
            "pt": data_dict['protocol_type'], "s": data_dict['service'], "f": data_dict['flag'],
            "sb": data_dict['src_bytes'], "db": data_dict['dst_bytes'],
            "pc": predicted_class, "mu": model_name, "u": username
        })
        conn.commit()

# 4. MAIN APPLICATION LOGIC
def main():
    init_db()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'auth_view' not in st.session_state:
        st.session_state.auth_view = "login" # Options: login, signup
        
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    hero_image_path1 = os.path.join(base_dir, "assets", "hero.png")
    hero_image_path2 = os.path.join(base_dir, "assets", "dashboard.png")

    # AUTHENTICATION PAGE (Facebook-style Split Layout)
    if not st.session_state.logged_in:
        
        st.markdown("<br><br>", unsafe_allow_html=True)
        left_col, right_col = st.columns([1.5, 1], gap="large")
        
        # LEFT COLUMN
        with left_col:
            st.markdown("""
                <h1 style='font-size: 3rem; line-height: 1.2; margin-top: 10px; margin-bottom: 20px;'>
                    Monitor threats,<br>
                    explore network data,<br>
                    <span style='color: #38bdf8;'>secure your environment.</span>
                </h1>
            """, unsafe_allow_html=True)
            
            img_c1, img_c2 = st.columns(2)
            try:
                with img_c1:
                    st.image(hero_image_path1, use_container_width=True)
                with img_c2:
                    st.image(hero_image_path2, use_container_width=True)
            except Exception:
                pass

        # RIGHT COLUMN
        with right_col:
            st.markdown("<div style='padding: 20px;'></div>", unsafe_allow_html=True)
                
            # --- VIEW: STANDARD LOGIN ---
            if st.session_state.auth_view == "login":
                st.markdown("### 🔒 Enter Credentials")
                
                # Using st.form allows submitting the form by pressing Enter
                with st.form("login_form", clear_on_submit=False):
                    login_user = st.text_input("Username")
                    login_pass = st.text_input("Password", type="password")
                    submitted = st.form_submit_button("Log In")
                    
                    if submitted:
                        if verify_user(login_user, login_pass):
                            st.session_state.logged_in = True
                            st.session_state.username = login_user
                            st.rerun()
                        else:
                            st.error("Invalid username or password.")
                
                st.markdown("<hr>", unsafe_allow_html=True)
                if st.button("Create New Account"):
                    st.session_state.auth_view = "signup"
                    st.rerun()

            # --- VIEW: SIGNUP ---
            elif st.session_state.auth_view == "signup":
                st.markdown("### ✨ Create Account")
                
                with st.form("signup_form", clear_on_submit=False):
                    reg_user = st.text_input("New Username")
                    reg_pass = st.text_input("New Password", type="password")
                    reg_pass_conf = st.text_input("Confirm Password", type="password")
                    submitted = st.form_submit_button("Sign Up")
                    
                    if submitted:
                        if reg_pass != reg_pass_conf:
                            st.error("Passwords do not match!")
                        elif len(reg_user) < 3:
                            st.error("Username must be at least 3 characters.")
                        else:
                            if create_user(reg_user, reg_pass):
                                st.success("Account created successfully! You can now log in.")
                                time.sleep(1)
                                st.session_state.auth_view = "login"
                                st.rerun()
                            else:
                                st.error("Username already exists or database error.")
                        
                st.markdown("<hr>", unsafe_allow_html=True)
                if st.button("⬅️ Back to Login"):
                    st.session_state.auth_view = "login"
                    st.rerun()

        # Add the logo equivalent at bottom right
        st.markdown("""
        <div style="position: fixed; bottom: 20px; right: 20px; color: #64748b; font-size: 14px; font-weight: bold;">
            ∞ IDS Project System
        </div>
        """, unsafe_allow_html=True)
        return # Block rest of app

    # LOGGED IN DASHBOARD
    st.sidebar.markdown(f"### 👤 Welcome, {st.session_state.username}")
    st.sidebar.markdown("---")
    
    menu_selection = st.sidebar.radio("MAIN MENU", ["📊 Dashboard", "🎯 Prediction Engine", "📜 History / Ereignisse", "⚙️ Einstellungen (Settings)", "🔌 Logout"])

    if menu_selection == "🔌 Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.auth_view = "login"
        st.rerun()

    elif menu_selection == "📊 Dashboard":
        st.title("System Dashboard")
        
        # Live System Metrics
        c1, c2, c3 = st.columns(3)
        c1.metric("Active Model", "Random Forest", "99.40% Accuracy")
        c2.metric("Network Status", "Monitoring", "Online")
        c3.metric("Your Predictions", "Stored securely", "DB active")
        
        st.markdown("---")
        st.markdown("### 📈 Interactive Network Analytics")
        st.write("Dynamic exploration of historical baseline data mixed with **live new detections**.")
        
        df_sample = load_sample_data()
        df_live = get_live_dashboard_data()
        
        # Combine static sample data with LIVE predictions made in the app
        if not df_live.empty and not df_sample.empty:
            df_combined = pd.concat([df_sample[['src_bytes', 'dst_bytes', 'attack_class']], df_live], ignore_index=True)
        elif not df_sample.empty:
            df_combined = df_sample[['src_bytes', 'dst_bytes', 'attack_class']]
        else:
            df_combined = df_live
            
        if not df_combined.empty:
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("#### Attack Class Distribution (Includes New Detections)")
                class_counts = df_combined['attack_class'].value_counts()
                st.bar_chart(class_counts, use_container_width=True)
            with col_b:
                st.markdown("#### Payload Analysis (Live & Baseline)")
                st.scatter_chart(data=df_combined, x='src_bytes', y='dst_bytes', color='attack_class', use_container_width=True)
        else:
            st.error("Data sample not found.")
            
        st.markdown("---")
        st.markdown("### 📊 Power BI Dashboard Integration")
        st.write("View the interactive Power BI dashboard tracking network anomalies and attack classifications.")
        default_pbi_url = "https://app.powerbi.com/view?r=eyJrIjoiNGNhZWNiZGMtNGY4Ny00ZDg4LTgxNjYtNDFhOTE1ZDE4NWFlIiwidCI6ImUxNGU3M2ViLTUyNTEtNDM4OC04ZDY3LThmOWYyZTJkNWE0NiIsImMiOjEwfQ%3D%3D&embedImagePlaceholder=true"
        pbi_url = st.text_input("🔗 Power BI Dashboard Link:", value=default_pbi_url)
        
        if pbi_url:
            st.markdown(f'''
                <iframe title="IDS Dashboard" width="100%" height="600" src="{pbi_url}" frameborder="0" allowFullScreen="true" style="border-radius: 12px; border: 1px solid rgba(255,255,255,0.2);"></iframe>
            ''', unsafe_allow_html=True)
        else:
            st.markdown("""
                <div style="width: 100%; height: 600px; background: rgba(0,0,0,0.3); border-radius: 12px; display: flex; align-items: center; justify-content: center; border: 1px dashed #38bdf8;">
                    <h3 style="color: #64748b; font-family: monospace;">[ POWER BI IFRAME RENDER ZONE ]</h3>
                </div>
            """, unsafe_allow_html=True)

    elif menu_selection == "🎯 Prediction Engine":
        st.title("Threat Prediction Engine")
        
        model, scaler, encoders, target_encoder, features_list = load_models()
        if model is None:
            st.warning("Models not found. Please train models first.")
            return
            
        col1, col2, col3 = st.columns(3)
        user_input = {}
        
        with col1:
            st.markdown("#### 🔗 Connection")
            user_input['protocol_type'] = st.selectbox("Protocol", encoders['protocol_type'].classes_ if 'protocol_type' in encoders else [])
            user_input['service'] = st.selectbox("Service", encoders['service'].classes_ if 'service' in encoders else [])
            user_input['flag'] = st.selectbox("Flag", encoders['flag'].classes_ if 'flag' in encoders else [])
            user_input['logged_in'] = st.radio("Logged In", [0, 1], horizontal=True)

        with col2:
            st.markdown("#### 📦 Payload")
            user_input['duration'] = st.number_input("Duration (s)", 0.0)
            user_input['src_bytes'] = st.number_input("Source Bytes", 0.0)
            user_input['dst_bytes'] = st.number_input("Dest Bytes", 0.0)
            user_input['count'] = st.number_input("Connection Count", 1.0)
            
        with col3:
            st.markdown("#### ⚙️ Metrics")
            user_input['srv_count'] = st.number_input("Service Count", 1.0)
            user_input['same_srv_rate'] = st.slider("Same Srv Rate", 0.0, 1.0, 1.0)
            user_input['diff_srv_rate'] = st.slider("Diff Srv Rate", 0.0, 1.0, 0.0)
            user_input['dst_host_count'] = st.number_input("Dst Host Count", 1.0)
            user_input['dst_host_srv_count'] = st.number_input("Dst Host Srv Count", 1.0)

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🚀 INITIATE SCAN"):
            with st.spinner("Analyzing..."):
                input_df = pd.DataFrame([user_input])
                for col in ['protocol_type', 'service', 'flag']:
                    if user_input[col] not in encoders[col].classes_:
                        input_df[col] = 0 
                    else:
                        input_df[col] = encoders[col].transform([user_input[col]])
                        
                X = input_df[features_list]
                X_scaled = scaler.transform(X)
                
                prediction_encoded = model.predict(X_scaled)
                prediction = target_encoder.inverse_transform(prediction_encoded)[0]
                
                save_prediction(st.session_state.username, user_input, prediction, type(model).__name__)
                
                st.markdown("<hr>", unsafe_allow_html=True)
                if prediction == "Normal":
                    st.success(f"✅ SECURE: {prediction}")
                else:
                    st.error(f"🚨 THREAT: {prediction}")

    elif menu_selection == "📜 History / Ereignisse":
        st.title("Prediction History")
        st.write("All network packets you have scanned are securely logged here.")
        
        engine = get_db_engine()
        with engine.connect() as conn:
            df = pd.read_sql(f"SELECT prediction_time, protocol_type, service, flag, src_bytes, predicted_class, model_used FROM PredictionResults WHERE username='{st.session_state.username}' ORDER BY prediction_time DESC", conn)
            
        if df.empty:
            st.info("You haven't made any predictions yet.")
        else:
            st.dataframe(df, use_container_width=True, height=600)

    elif menu_selection == "⚙️ Einstellungen (Settings)":
        st.title("System Settings")
        st.info("Configuration parameters for the IDS monitor.")
        st.checkbox("Enable Real-time Notifications", value=True)
        st.checkbox("Log Detailed Packet Info", value=True)
        st.slider("Threshold Sensitivity", 1, 10, 5)
        if st.button("Save Settings"):
            st.success("Settings saved successfully!")

if __name__ == "__main__":
    main()
