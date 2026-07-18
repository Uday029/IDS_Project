import os
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(base_dir)
    csv_path = os.path.join(project_dir, "dataset", "Cleaned_NSL_KDD.csv")
    
    if not os.path.exists(csv_path):
        print(f"Error: Could not find {csv_path}. Please run data_cleaning.py first.")
        return

    print("Loading cleaned dataset...")
    # Load only a subset to avoid massive SQL inserts during demonstration, or load all
    df = pd.read_csv(csv_path)
    
    # Optional: limit to 10,000 rows for faster DB import in a demo
    # df = df.sample(10000, random_state=42)
    
    # Try MySQL first, fallback to SQLite
    db_url_mysql = "mysql+mysqlconnector://root:@localhost/IDS_DB"
    db_url_sqlite = f"sqlite:///{os.path.join(project_dir, 'sql', 'ids_database.db')}"
    
    engine = None
    use_sqlite = False
    
    print("Attempting to connect to MySQL on localhost...")
    try:
        # Create engine without DB to create DB first
        temp_engine = create_engine("mysql+mysqlconnector://root:@localhost/")
        with temp_engine.connect() as conn:
            conn.execute(text("CREATE DATABASE IF NOT EXISTS IDS_DB"))
        engine = create_engine(db_url_mysql)
        # Test connection
        with engine.connect() as conn:
            pass
        print("Successfully connected to MySQL database.")
    except Exception as e:
        print(f"MySQL connection failed: {e}")
        print("Falling back to SQLite database...")
        engine = create_engine(db_url_sqlite)
        use_sqlite = True
        
    print(f"Importing {len(df)} rows into NetworkTraffic table...")
    
    # Select columns that match the NetworkTraffic table schema
    cols_to_keep = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'logged_in', 'count', 'srv_count', 'same_srv_rate', 'diff_srv_rate',
        'dst_host_count', 'dst_host_srv_count', 'attack_class', 'dataset_type'
    ]
    df_sql = df[cols_to_keep]
    
    # Insert data
    df_sql.to_sql(name='NetworkTraffic', con=engine, if_exists='replace', index=False)
    
    # Create other tables if using SQLite (MySQL schema handled by schema.sql usually, but we can do it via SQLAlchemy)
    with engine.connect() as conn:
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
                model_used VARCHAR(50)
            )
        """))
    
    print("Data imported successfully!")
    if use_sqlite:
        print(f"SQLite database created at: {os.path.join(project_dir, 'sql', 'ids_database.db')}")

if __name__ == "__main__":
    main()
