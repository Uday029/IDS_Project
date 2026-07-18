import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(base_dir)
    data_path = os.path.join(project_dir, "dataset", "Cleaned_NSL_KDD.csv")
    
    if not os.path.exists(data_path):
        print("Data not found. Please run data_cleaning.py first.")
        return

    print("Loading data for training...")
    df = pd.read_csv(data_path)
    
    # We will use a subset of the dataset for training to ensure it runs in a reasonable time for a portfolio project
    # You can increase this if you have more computing power
    print("Sampling data for faster training (using 50,000 rows)...")
    if len(df) > 50000:
        df = df.sample(50000, random_state=42)
    
    # Features to use
    features = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'logged_in', 'count', 'srv_count', 'same_srv_rate', 'diff_srv_rate',
        'dst_host_count', 'dst_host_srv_count'
    ]
    
    X = df[features].copy()
    y = df['attack_class'].copy()
    
    # Preprocessing
    print("Preprocessing data...")
    categorical_cols = ['protocol_type', 'service', 'flag']
    
    # Save encoders for Streamlit app
    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        encoders[col] = le
        
    joblib.dump(encoders, os.path.join(base_dir, 'label_encoders.pkl'))
    
    # Target Encoding
    le_target = LabelEncoder()
    y_encoded = le_target.fit_transform(y)
    joblib.dump(le_target, os.path.join(base_dir, 'target_encoder.pkl'))
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(base_dir, 'scaler.pkl'))
    
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=50, random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "KNN": KNeighborsClassifier(n_neighbors=5),
        "Naive Bayes": GaussianNB(),
        # SVM is computationally expensive, using a smaller C or omitting if too slow. 
        # "SVM": SVC(kernel='linear', probability=True) 
    }
    
    results = {}
    best_model = None
    best_acc = 0
    best_model_name = ""
    
    print("Training models...")
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        results[name] = {'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1': f1}
        print(f"{name} -> Accuracy: {acc:.4f}, F1 Score: {f1:.4f}")
        
        if acc > best_acc:
            best_acc = acc
            best_model = model
            best_model_name = name

    print("\n--- Model Comparison ---")
    results_df = pd.DataFrame(results).T
    print(results_df)
    
    print(f"\nBest Model: {best_model_name} with Accuracy {best_acc:.4f}")
    
    model_path = os.path.join(base_dir, 'best_model.pkl')
    joblib.dump(best_model, model_path)
    print(f"Model saved to {model_path}")
    
    # Save the selected features list for prediction module
    joblib.dump(features, os.path.join(base_dir, 'model_features.pkl'))
    
    print("Machine Learning modeling completed.")

if __name__ == "__main__":
    main()
