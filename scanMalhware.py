import os
import hashlib

# Fungsi untuk membaca file hash malware yang dikenal
def load_malware_hashes(database_path):
    if not os.path.exists(database_path):
        print("Database malware tidak ditemukan.")
        return []
    with open(database_path, 'r') as f:
        return [line.strip() for line in f]

# Fungsi untuk menghitung hash file
def calculate_file_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error saat membaca file {file_path}: {e}")
        return None

# Fungsi untuk memindai direktori
def scan_directory(directory, malware_hashes):
    infected_files = []
    suspicious_names = ["Endermanch@BadRabbit.exe", "eicar.com"]  # Nama file yang langsung dianggap sebagai virus
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # Identifikasi file berdasarkan nama
            if file in suspicious_names:
                print(f"File terinfeksi ditemukan (berdasarkan nama): {file_path}")
                infected_files.append(file_path)
                continue

            # Identifikasi file berdasarkan hash
            file_hash = calculate_file_hash(file_path)
            if file_hash and file_hash in malware_hashes:
                print(f"File terinfeksi ditemukan (berdasarkan hash): {file_path}")
                infected_files.append(file_path)
    
    return infected_files

# Main program
if __name__ == "__main__":
    print("Program Pemindai Virus/Malware")
    directory_to_scan = input("Masukkan path direktori untuk discan: ").strip()
    database_path = "malware_hashes.txt"

    # Muat database hash malware
    malware_hashes = load_malware_hashes(database_path)
    if not malware_hashes:
        print("Database malware kosong atau tidak tersedia.")
    else:
        print(f"{len(malware_hashes)} hash malware dimuat.")

    # Pindai direktori
    if os.path.exists(directory_to_scan):
        print("Memulai pemindaian...")
        infected_files = scan_directory(directory_to_scan, malware_hashes)
        if infected_files:
            print("\nPemindaian selesai. File terinfeksi ditemukan:")
            for infected in infected_files:
                print(f"- {infected}")
        else:
            print("\nPemindaian selesai. Tidak ada file terinfeksi ditemukan.")
    else:
        print("Direktori tidak ditemukan.")
