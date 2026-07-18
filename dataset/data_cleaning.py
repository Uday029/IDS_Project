import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(base_dir)
    
    train_path = os.path.join(base_dir, "KDDTrain+.txt")
    test_path = os.path.join(base_dir, "KDDTest+.txt")
    excel_dir = os.path.join(project_dir, "excel")
    
    # NSL-KDD features
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
        'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
    ]
    
    print("Loading datasets...")
    train_df = pd.read_csv(train_path, names=columns)
    test_df = pd.read_csv(test_path, names=columns)
    
    # Combine for cleaning
    train_df['dataset_type'] = 'Train'
    test_df['dataset_type'] = 'Test'
    df = pd.concat([train_df, test_df], ignore_index=True)
    
    print("Initial shape:", df.shape)
    
    # 1. Handle missing values
    print("Missing values before:", df.isnull().sum().sum())
    df.dropna(inplace=True)
    
    # 2. Remove duplicates
    duplicates = df.duplicated().sum()
    print("Duplicates found:", duplicates)
    df.drop_duplicates(inplace=True)
    
    # Map specific attacks to broad attack types (DoS, Probe, R2L, U2R, Normal)
    attack_mapping = {
        'normal': 'Normal',
        
        # DoS
        'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS', 
        'land': 'DoS', 'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS', 
        'processtable': 'DoS', 'mailbomb': 'DoS',
        
        # Probe
        'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
        'mscan': 'Probe', 'saint': 'Probe',
        
        # R2L
        'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 
        'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L', 
        'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 
        'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
        
        # U2R
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
        'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
    }
    
    df['attack_class'] = df['label'].map(attack_mapping)
    df['attack_class'].fillna('Unknown', inplace=True)
    
    # Drop difficulty level (not needed for ML usually)
    df.drop('difficulty_level', axis=1, inplace=True)
    
    print("Cleaned shape:", df.shape)
    
    # Save cleaned data to Excel (as requested by user)
    # Excel has a row limit of 1,048,576. Our dataset is ~148k, which fits easily.
    excel_path = os.path.join(excel_dir, "Cleaned_NSL_KDD.xlsx")
    print("Saving to Excel (this might take a minute)...")
    # To avoid huge excel files and long save times, we could take a sample or just write the full dataset
    # We will write the full dataset
    df.to_excel(excel_path, index=False)
    print(f"Cleaned dataset saved to {excel_path}")
    
    # Save a CSV copy for faster loading in other scripts
    csv_path = os.path.join(base_dir, "Cleaned_NSL_KDD.csv")
    df.to_csv(csv_path, index=False)
    
    print("Data cleaning completed successfully!")

if __name__ == "__main__":
    main()
