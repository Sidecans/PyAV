import os
import hashlib
import requests
import time
import platform
from colorama import Fore, Style
import shutil
import argparse
from datetime import datetime

server_url = None # Define the server URL here
hashFile = "hashes.txt"
HASH_META_FILE = "hash.meta"
VT_API_KEY = None # Define your VirusTotal API key here
LOG_FILE = "log.txt"
QUARANTINE_DIR = "quarantine"

def log(message):
  timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
  entry = f"{timestamp} {message}"
  print(entry)
  with open(LOG_FILE, "a") as log_file:
      log_file.write(entry + "\n")

def quar_check():
  if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)
    
def get_hashes():
  try:
    response = requests.get(f"{server_url}/get-hashes")
    if response.status_code == 200:
      return response.text
  except Exception as e:
    log(f"{Fore.RED}[!]{Fore.RESET} Error retrieving signatures: {e}")
  return None

def hash_string(content):
  return hashlib.sha256(content.encode("utf-8")).hexdigest()

def sync_hashes():
  log(f"{Fore.YELLOW}[*]{Fore.RESET} Syncing hashes...")
  content = get_hashes()
  if not content:
    return False
  remote_hash = hash_string(content)
  previous_hash = ""
  if os.path.exists(HASH_META_FILE):
    with open(HASH_META_FILE, "rb") as f:
      previous_hash = f.read().strip()
  if remote_hash == previous_hash:
    log(f"{Fore.GREEN}[*]{Fore.RESET} Virus signature list is up-to-date.")
    return True

  with open(hashFile, 'w') as f:
    f.write(content)
  with open(HASH_META_FILE, 'w') as f:
    f.write(remote_hash)

def load_hashes():
  if not os.path.exists(hashFile):
    return set()
  with open(hashFile, 'r') as f:
    return set(line.strip().lower() for line in f if len(line.strip()) == 32)

def calculate(filepath):
  try:
    with open(filepath, "rb") as f:
      content = f.read()
      return hashlib.md5(content).hexdigest()
  except:
    return None

def scan(directory, hashes):
  log("Scanning...")
  infected = []
  for root, _, files, in os.walk(directory):
    for f in files:
      full_path = os.path.join(root, f)
      hash = calculate(full_path)
      if not hash:
        continue
      if hash in hashes:
        log(f"{Fore.RED}[!]{Fore.RESET} Infected File Found: {full_path}")
        infected.append(full_path)
  log(f"Scan Completed. {len(infected)} infected files found.")
  return infected




def virustotal_scan(filepath):
  log(f"{Fore.YELLOW}[*]{Fore.RESET} Scanning {filepath} with VirusTotal...")
  url = "https://www.virustotal.com/vtapi/v2/file/scan"
  try:
    headers = {"x-apikey": VT_API_KEY}
  except:
    log(f"{Fore.RED}[!]{Fore.RESET} VirusTotal API key not found.")
  try:
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            return check_virustotal_result(analysis_id)
        else:
            log(f"{Fore.RED}[!]{Fore.RESET} Submission failed: {response.status_code}")
            print(response.json())
  except Exception as e:
    log(f"[!] Error scanning file: {e}")

def quarantine(filepath):
  quar_check()
  try:
    filename = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, filename)
    shutil.move(filepath, dest)
    log(f"{Fore.GREEN}[!]{Fore.RESET} Moved {filepath} to quarantine.")
  except Exception as e:
    log(f"{Fore.RED}[!]{Fore.RESET} Error moving {filepath} to quarantine: {e}")



def check_virustotal_result(analysis_id):
  log("[⏳] Waiting for VirusTotal analysis...")
  try:
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
  
    for _ in range(10):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                log(f"[*] VirusTotal results: {malicious} malicious, {suspicious} suspicious")
                return
        time.sleep(3)
    log(f"{Fore.RED}[!]{Fore.RESET} Timeout waiting for analysis results.")
  except:
    log(f"{Fore.RED}[!]{Fore.RESET} VirusTotal API key not found.")



def print_menu():
  print("""\n===PvAV===
  1. Update Virus Signatures
  2. Scan a directory
  3. Deep Scan a file with VirusTotal
  4. Exit""")

def menu():
  sigs = set()
  while True:
    print_menu()
    choice = input("Select an Option")
    if choice == "1":
      sync_hashes()
      sigs = load_hashes()
    elif choice == "2":
      path = input("Enter the directory to scan: ").strip()
      if not os.path.isdir(path):
        log(f"{Fore.YELLOW}[!]{Fore.RESET} Invalid directory.")
        continue
      if not sigs:
        sigs = load_hashes()
      scan(path, sigs)
    elif choice == "3":
      filepath = input("Enter the full file path: ").strip()
      if os.path.isfile(filepath):
        virustotal_scan(filepath)
      else:
        log(f"{Fore.RED}[!]{Fore.RESET} Invalid file path.")
    elif choice == "4":
      log(f"{Fore.YELLOW}[*]{Fore.RESET} Exiting...")
      break

def cli():
  parser = argparse.ArgumentParser(description="PvAV")
  parser.add_argument("--update", action="store_true", help="Update virus signatures")
  parser.add_argument("--scan", type=str, help="Scan a directory")
  parser.add_argument("--deep", type=str, help="Scan a file with VirusTotal")
  args = parser.parse_args()

  if args.update:
      sync_hashes()
  if args.scan:
      sigs = load_hashes()
      scan(args.scan, sigs)
  if args.deep:
      virustotal_scan(args.deep)
  if not any(vars(args).values()):
      menu()

  
if __name__ == "__main__":
  cli()
  
