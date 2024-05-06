# AES256-CMDTool
This tool provides a simple command-line interface for encrypting and decrypting files in the current directory. It supports recursive directory processing, ensuring that all files within the selected folder and its subfolders can be encrypted or decrypted.

# Requirements
- Python 3.x
- pyAesCrypt

# Usage
Download the pre-built executable or use PyInstaller to create your own by following these steps:

### Install PyInstaller:
```
pip install pyinstaller
```

### Run PyInstaller:
```
pyinstaller --onefile main.py
```
This command instructs PyInstaller to bundle the application into a single executable file. The executable will be located in the dist directory within your project folder. RENAME the executable as "AES256.exe"
