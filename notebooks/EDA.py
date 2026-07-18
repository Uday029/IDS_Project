import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as plt_sns
import numpy as np

# Use non-interactive backend for saving plots
import matplotlib
matplotlib.use('Agg')
import seaborn as sns

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(base_dir)
    data_path = os.path.join(project_dir, "dataset", "Cleaned_NSL_KDD.csv")
    img_dir = os.path.join(project_dir, "screenshots")
    
    if not os.path.exists(data_path):
        print("Data not found. Run data_cleaning.py first.")
        return
        
    df = pd.read_csv(data_path)
    print("Generating EDA charts...")
    
    # 1. Class Distribution (Normal vs Attack)
    plt.figure(figsize=(8,6))
    df['is_attack'] = df['attack_class'].apply(lambda x: 'Normal' if x == 'Normal' else 'Attack')
    sns.countplot(data=df, x='is_attack', palette='viridis')
    plt.title("Normal vs Attack Traffic")
    plt.savefig(os.path.join(img_dir, '1_Normal_vs_Attack.png'))
    plt.close()
    
    # 2. Attack Category Distribution
    plt.figure(figsize=(10,6))
    sns.countplot(data=df[df['attack_class'] != 'Normal'], x='attack_class', palette='magma')
    plt.title("Distribution of Attack Categories")
    plt.savefig(os.path.join(img_dir, '2_Attack_Categories.png'))
    plt.close()
    
    # 3. Protocol Type Distribution
    plt.figure(figsize=(8,6))
    sns.countplot(data=df, x='protocol_type', hue='is_attack', palette='Set2')
    plt.title("Protocol Type vs Traffic Type")
    plt.savefig(os.path.join(img_dir, '3_Protocol_vs_Traffic.png'))
    plt.close()
    
    # 4. Top 10 Services
    plt.figure(figsize=(12,6))
    top_services = df['service'].value_counts().nlargest(10).index
    sns.countplot(data=df[df['service'].isin(top_services)], x='service', order=top_services, hue='is_attack')
    plt.title("Top 10 Network Services")
    plt.xticks(rotation=45)
    plt.savefig(os.path.join(img_dir, '4_Top_Services.png'))
    plt.close()
    
    # 5. Flag Distribution
    plt.figure(figsize=(10,6))
    sns.countplot(data=df, x='flag', hue='is_attack')
    plt.title("Network Flags and Attacks")
    plt.xticks(rotation=45)
    plt.savefig(os.path.join(img_dir, '5_Flags.png'))
    plt.close()
    
    # 6. Source Bytes Boxplot
    plt.figure(figsize=(8,6))
    # Log scale due to extreme outliers
    sns.boxplot(data=df, x='is_attack', y='src_bytes')
    plt.yscale('log')
    plt.title("Source Bytes by Traffic Type (Log Scale)")
    plt.savefig(os.path.join(img_dir, '6_Src_Bytes.png'))
    plt.close()
    
    # 7. Destination Bytes Boxplot
    plt.figure(figsize=(8,6))
    sns.boxplot(data=df, x='is_attack', y='dst_bytes')
    plt.yscale('log')
    plt.title("Destination Bytes by Traffic Type (Log Scale)")
    plt.savefig(os.path.join(img_dir, '7_Dst_Bytes.png'))
    plt.close()
    
    # 8. Logged In Status
    plt.figure(figsize=(6,6))
    sns.countplot(data=df, x='logged_in', hue='is_attack')
    plt.title("Logged In Status vs Attack")
    plt.savefig(os.path.join(img_dir, '8_Logged_In.png'))
    plt.close()
    
    # 9. Duration Distribution
    plt.figure(figsize=(10,6))
    sns.histplot(data=df[df['duration'] > 0], x='duration', hue='is_attack', bins=50, log_scale=True)
    plt.title("Connection Duration (Log Scale)")
    plt.savefig(os.path.join(img_dir, '9_Duration.png'))
    plt.close()
    
    # 10. Same Srv Rate Distribution
    plt.figure(figsize=(10,6))
    sns.histplot(data=df, x='same_srv_rate', hue='is_attack', bins=20, multiple="stack")
    plt.title("Same Service Rate")
    plt.savefig(os.path.join(img_dir, '10_Same_Srv_Rate.png'))
    plt.close()
    
    # 11. Diff Srv Rate Distribution
    plt.figure(figsize=(10,6))
    sns.kdeplot(data=df, x='diff_srv_rate', hue='is_attack', common_norm=False, fill=True)
    plt.title("Different Service Rate KDE")
    plt.savefig(os.path.join(img_dir, '11_Diff_Srv_Rate.png'))
    plt.close()
    
    # 12. Correlation Heatmap (Numeric only)
    plt.figure(figsize=(14,10))
    numeric_df = df.select_dtypes(include=[np.number])
    # Take a subset of numeric features to keep it legible
    subset_cols = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count']
    corr = numeric_df[subset_cols].corr()
    sns.heatmap(corr, annot=True, cmap='coolwarm', fmt=".2f")
    plt.title("Correlation Heatmap of Selected Features")
    plt.savefig(os.path.join(img_dir, '12_Correlation_Heatmap.png'))
    plt.close()
    
    # 13. Attack Class by Protocol
    plt.figure(figsize=(10,6))
    sns.countplot(data=df[df['attack_class'] != 'Normal'], x='protocol_type', hue='attack_class')
    plt.title("Attack Categories by Protocol")
    plt.savefig(os.path.join(img_dir, '13_Attack_by_Protocol.png'))
    plt.close()
    
    # 14. Count of connections to the same host
    plt.figure(figsize=(10,6))
    sns.kdeplot(data=df, x='count', hue='is_attack', fill=True)
    plt.title("Connection Count to Same Host (Last 2s)")
    plt.savefig(os.path.join(img_dir, '14_Connection_Count.png'))
    plt.close()
    
    # 15. Scatter Plot Src vs Dst Bytes
    plt.figure(figsize=(10,8))
    sns.scatterplot(data=df.sample(5000), x='src_bytes', y='dst_bytes', hue='is_attack', alpha=0.6)
    plt.xscale('log')
    plt.yscale('log')
    plt.title("Src vs Dst Bytes (Log Scale, 5000 sample)")
    plt.savefig(os.path.join(img_dir, '15_Scatter_Src_Dst.png'))
    plt.close()
    
    print("Generated 15 charts in the screenshots directory.")

if __name__ == "__main__":
    main()
