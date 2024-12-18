import hashlib

file_path = "example_malware.txt"

def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

hash_value = calculate_file_hash(file_path)
print(f"SHA-256 hash dari {file_path}: {hash_value}")
