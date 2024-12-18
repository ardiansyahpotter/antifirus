import os


def scan_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(file_path)
            
            
            
if __name__ == "__main__":
    target_directory = r"C:\bin"           
    scan_files(target_directory)
                
            
            
            
            
            
            