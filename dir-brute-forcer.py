import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import os

# * ---------------------------
# * Validation Functions
# * ---------------------------

def validate_ipv4(ip):
    # Ensures that the entered IP address is a valid IPv4
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def check_path(path):
    """Checks if a URL exists"""
    url = f"{TARGET.rstrip('/')}/{path.strip()}"
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        print(f"[{r.status_code}] {url}")

        if r.status_code not in [400, 404]:
            print(f"[{r.status_code}] {url} > {r.url}")

    except requests.RequestException as e:
        print(f"[ERROR] {url} - {e}")


# * ---------------------------
# * Input Functions
# * ---------------------------

def get_protocol():
    while True:
        protocol = input("Enter Web Protocol (http/https):\n").lower()
        if protocol in ["http", "https"]:
            return protocol + "://"
        print("[ERROR]: Please enter 'http' or 'https'.\n")


def get_target(protocol):
    while True:
        target = input("Enter Target IP Address:\n").strip()
        if validate_ipv4(target):
            return protocol + target
        print("[ERROR]: Not a valid IPv4 address (example: 192.1.1.168)\n")


def get_threads(default=50):
    while True:
        threads = input(f"Enter Thread Count (Default: {default}):\n").strip()
        if threads == "":
            return default
        if threads.isdigit() and int(threads) > 0:
            return int(threads)
        print("[ERROR]: Please enter a positive number.\n")


def get_directory():
    while True:
        ask = input(
            "Would you like to input the directory to the wordlist? "
            "(Note: if no, program assumes current directory)\n"
        ).lower()
        if ask in ["yes", "y"]:
            while True:
                directory_path = input(
                    "Please enter directory path (do not include filename/extension):\n"
                )
                double_check = input(f"You entered:\n\"{directory_path}\"\nIs this correct? (y/n)\n").lower()
                if double_check in ["yes", "y"]:
                    return directory_path
                elif double_check in ["no", "n"]:
                    continue
                else:
                    print("[ERROR]: Invalid option. Try again (y/n)\n")
        elif ask in ["no", "n"]:
            return os.getcwd()  # default to current directory
        else:
            print("[ERROR]: Please answer yes or no.\n")


def get_wordlist():
    while True:
        wordlist_choice = input("Enter Wordlist Size (small, large):\n").lower()
        if wordlist_choice in ["small", "large"]:
            return wordlist_choice + ".txt"
        print("[ERROR]: Invalid option. Choose 'small' or 'large'.\n")


# * ---------------------------
# * Main Script
# * ---------------------------

PROTOCOL = get_protocol()
TARGET = get_target(PROTOCOL)
THREADS = get_threads()
DIRECTORY = get_directory()
WORDLIST = get_wordlist()

wordlist_path = os.path.join(DIRECTORY, WORDLIST)

# Open wordlist
print(f"Opening {WORDLIST}...")
try:
    with open(wordlist_path) as f:
        paths = f.readlines()
    print(f"{WORDLIST} opened!\n")
except FileNotFoundError:
    print(f"[ERROR]: File {wordlist_path} not found. Exiting.")
    exit(1)

# Start scanning
print("Starting...")
with ThreadPoolExecutor(max_workers=THREADS) as executor:
    executor.map(check_path, paths)
