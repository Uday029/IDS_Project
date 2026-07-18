-- Create Database
CREATE DATABASE IF NOT EXISTS IDS_DB;
USE IDS_DB;

-- Table for Network Traffic Data
CREATE TABLE IF NOT EXISTS NetworkTraffic (
    id INT AUTO_INCREMENT PRIMARY KEY,
    duration FLOAT,
    protocol_type VARCHAR(50),
    service VARCHAR(50),
    flag VARCHAR(50),
    src_bytes FLOAT,
    dst_bytes FLOAT,
    logged_in INT,
    count FLOAT,
    srv_count FLOAT,
    same_srv_rate FLOAT,
    diff_srv_rate FLOAT,
    dst_host_count FLOAT,
    dst_host_srv_count FLOAT,
    attack_class VARCHAR(50),
    dataset_type VARCHAR(10)
);

-- Table for Attack Types and Descriptions
CREATE TABLE IF NOT EXISTS AttackTypes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_name VARCHAR(50),
    attack_category VARCHAR(50),
    description TEXT
);

-- Table for Prediction Results (from the Streamlit app)
CREATE TABLE IF NOT EXISTS PredictionResults (
    id INT AUTO_INCREMENT PRIMARY KEY,
    prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    protocol_type VARCHAR(50),
    service VARCHAR(50),
    flag VARCHAR(50),
    src_bytes FLOAT,
    dst_bytes FLOAT,
    predicted_class VARCHAR(50),
    model_used VARCHAR(50)
);

-- Insert reference data into AttackTypes
INSERT INTO AttackTypes (attack_name, attack_category, description) VALUES
('neptune', 'DoS', 'SYN flood denial of service'),
('smurf', 'DoS', 'ICMP echo reply flood'),
('satan', 'Probe', 'Network probing tool'),
('ipsweep', 'Probe', 'ICMP sweep across IPs'),
('guess_passwd', 'R2L', 'Brute force password guessing'),
('buffer_overflow', 'U2R', 'Buffer overflow vulnerability exploitation'),
('normal', 'Normal', 'Normal network traffic')
ON DUPLICATE KEY UPDATE description=VALUES(description);
