-- 1. Total number of records in the dataset
SELECT COUNT(*) AS total_records FROM NetworkTraffic;

-- 2. Count of records by Dataset Type (Train vs Test)
SELECT dataset_type, COUNT(*) AS total 
FROM NetworkTraffic 
GROUP BY dataset_type;

-- 3. Total Normal vs Attack traffic
SELECT 
    CASE WHEN attack_class = 'Normal' THEN 'Normal' ELSE 'Attack' END AS traffic_type,
    COUNT(*) AS total
FROM NetworkTraffic
GROUP BY traffic_type;

-- 4. Count of attacks by specific Attack Class
SELECT attack_class, COUNT(*) AS total_count 
FROM NetworkTraffic 
WHERE attack_class != 'Normal'
GROUP BY attack_class 
ORDER BY total_count DESC;

-- 5. Percentage distribution of Attack Classes
SELECT attack_class,
       COUNT(*) * 100.0 / (SELECT COUNT(*) FROM NetworkTraffic WHERE attack_class != 'Normal') AS percentage
FROM NetworkTraffic
WHERE attack_class != 'Normal'
GROUP BY attack_class
ORDER BY percentage DESC;

-- 6. Top 5 most used protocols in attacks
SELECT protocol_type, COUNT(*) AS attack_count
FROM NetworkTraffic
WHERE attack_class != 'Normal'
GROUP BY protocol_type
ORDER BY attack_count DESC
LIMIT 5;

-- 7. Top 5 most targeted services
SELECT service, COUNT(*) AS target_count
FROM NetworkTraffic
WHERE attack_class != 'Normal'
GROUP BY service
ORDER BY target_count DESC
LIMIT 5;

-- 8. Average duration of different attack types
SELECT attack_class, AVG(duration) AS avg_duration
FROM NetworkTraffic
GROUP BY attack_class
ORDER BY avg_duration DESC;

-- 9. Normal vs Attack distribution for 'http' service
SELECT attack_class, COUNT(*) AS total
FROM NetworkTraffic
WHERE service = 'http'
GROUP BY attack_class;

-- 10. Which protocol type is most common for DoS attacks?
SELECT protocol_type, COUNT(*) AS total
FROM NetworkTraffic
WHERE attack_class = 'DoS'
GROUP BY protocol_type
ORDER BY total DESC;

-- 11. Average source bytes and destination bytes for each attack class
SELECT attack_class, AVG(src_bytes) AS avg_src_bytes, AVG(dst_bytes) AS avg_dst_bytes
FROM NetworkTraffic
GROUP BY attack_class;

-- 12. Top 10 combinations of Protocol and Service for Attacks
SELECT protocol_type, service, COUNT(*) AS total_attacks
FROM NetworkTraffic
WHERE attack_class != 'Normal'
GROUP BY protocol_type, service
ORDER BY total_attacks DESC
LIMIT 10;

-- 13. Attack classes with the highest error rates
SELECT attack_class, AVG(same_srv_rate) AS avg_same_srv, AVG(diff_srv_rate) AS avg_diff_srv
FROM NetworkTraffic
GROUP BY attack_class;

-- 14. Find specific flags used primarily in attacks
SELECT flag, COUNT(*) AS attack_count
FROM NetworkTraffic
WHERE attack_class != 'Normal'
GROUP BY flag
ORDER BY attack_count DESC;

-- 15. Proportion of logged-in sessions that resulted in attacks
SELECT logged_in, attack_class, COUNT(*) AS total
FROM NetworkTraffic
GROUP BY logged_in, attack_class;

-- 16. Total volume of data transferred (source + dest) per attack class
SELECT attack_class, SUM(src_bytes + dst_bytes) AS total_data_volume
FROM NetworkTraffic
GROUP BY attack_class
ORDER BY total_data_volume DESC;

-- 17. Traffic anomalies where source bytes are unusually high
SELECT id, protocol_type, service, src_bytes, attack_class
FROM NetworkTraffic
WHERE src_bytes > (SELECT AVG(src_bytes) * 10 FROM NetworkTraffic)
ORDER BY src_bytes DESC
LIMIT 10;

-- 18. Count of recent predictions from the application
SELECT predicted_class, COUNT(*) AS count
FROM PredictionResults
GROUP BY predicted_class;

-- 19. Average destination host count for attacks vs normal
SELECT CASE WHEN attack_class = 'Normal' THEN 'Normal' ELSE 'Attack' END AS traffic_type,
       AVG(dst_host_count) AS avg_dst_host_count
FROM NetworkTraffic
GROUP BY traffic_type;

-- 20. Count predictions made by each machine learning model
SELECT model_used, COUNT(*) AS prediction_count
FROM PredictionResults
GROUP BY model_used;
