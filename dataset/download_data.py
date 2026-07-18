import os
import requests

def download_file(url, output_path):
    print(f"Downloading {url}...")
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Saved to {output_path}")
    else:
        print(f"Failed to download from {url}. Status code: {response.status_code}")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # URLs for NSL-KDD dataset
    train_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    test_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
    
    train_path = os.path.join(base_dir, "KDDTrain+.txt")
    test_path = os.path.join(base_dir, "KDDTest+.txt")
    
    download_file(train_url, train_path)
    download_file(test_url, test_path)

if __name__ == "__main__":
    main()
