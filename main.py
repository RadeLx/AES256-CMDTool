import pyAesCrypt
import os
import json


def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def get_total_files(directory, out_folder):
    total_files = 0
    for root, dirs, files in os.walk(directory):
        if out_folder in root:
            continue
        for file in files:
            if file == "AES256.exe":
                continue
            total_files += 1
    return total_files


def encrypt_folder(src_folder, out_folder, password, total_files):
    processed_files = 0
    file_mapping = {}
    file_id = 1

    for root, dirs, files in os.walk(src_folder):
        if out_folder in root:
            continue

        rel_path = os.path.relpath(root, src_folder)
        out_root = os.path.join(out_folder, rel_path)
        ensure_dir(out_root)

        for file in files:
            if file == "AES256.exe":
                continue
            src_file = os.path.join(root, file)
            new_file_name = f"{file_id}.aes"
            encrypted_file = os.path.join(out_root, new_file_name)
            pyAesCrypt.encryptFile(src_file, encrypted_file, password, bufferSize=64 * 1024)
            file_mapping[new_file_name] = file
            file_id += 1
            processed_files += 1
            print(f"Encrypting {processed_files}/{total_files} ({(processed_files / total_files) * 100:.2f}%)")

    # Save the file mapping
    mapping_file = os.path.join(out_folder, "AES_NAME.txt")
    with open(mapping_file, 'w', encoding='utf-8') as f:
        json.dump(file_mapping, f, ensure_ascii=False)
    pyAesCrypt.encryptFile(mapping_file, mapping_file + ".aes", password, bufferSize=64 * 1024)
    os.remove(mapping_file)


def decrypt_folder(src_folder, out_folder, password, total_files):
    processed_files = 0

    # Decrypt and load the file mapping
    mapping_file = os.path.join(src_folder, "AES_NAME.txt.aes")
    decrypted_mapping_file = os.path.join(src_folder, "AES_NAME.txt")
    pyAesCrypt.decryptFile(mapping_file, decrypted_mapping_file, password, bufferSize=64 * 1024)
    with open(decrypted_mapping_file, 'r', encoding='utf-8') as f:
        file_mapping = json.load(f)
    os.remove(decrypted_mapping_file)

    for root, dirs, files in os.walk(src_folder):
        if out_folder in root:
            continue

        rel_path = os.path.relpath(root, src_folder)
        out_root = os.path.join(out_folder, rel_path)
        ensure_dir(out_root)

        for file in files:
            if file == "AES_NAME.txt.aes" or file.endswith(".exe"):
                continue
            if file.endswith(".aes"):
                encrypted_file = os.path.join(root, file)
                original_file_name = file_mapping.get(file)
                if original_file_name:
                    decrypted_file = os.path.join(out_root, original_file_name)
                    pyAesCrypt.decryptFile(encrypted_file, decrypted_file, password, bufferSize=64 * 1024)
                else:
                    print(f"Warning: No mapping found for {file}")
                processed_files += 1
                print(f"Decrypting {processed_files}/{total_files} ({(processed_files / total_files) * 100:.2f}%)")


def main():
    current_folder = os.getcwd()
    out_folder = os.path.join(current_folder, "OUT")
    ensure_dir(out_folder)
    total_files = get_total_files(current_folder, out_folder)
    print("Total files: ", total_files)
    choice = input("Choose an option: 1: Encrypt, 2: Decrypt: ")
    password = input("Please enter the password: ")

    if choice == '1':
        encrypt_folder(current_folder, out_folder, password, total_files)
        print("Encryption complete. Encrypted files are in the 'out' folder.")
    elif choice == '2':
        decrypt_folder(current_folder, out_folder, password, total_files)
        print("Decryption complete. Decrypted files are in the 'out' folder.")
    else:
        print("Invalid input. Exiting program.")


if __name__ == "__main__":
    main()
