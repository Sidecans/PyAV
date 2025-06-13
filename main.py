import os
import hashlib
import requests
import time
import platform
from colorama import Fore, Style


server_url = None # Define the server URL here
hashFile = "hashes.txt"
HASH_META_FILE = "hash.meta"

def get_hashes():
  try:
    response = requests.get(f"{server_url}/get-hashes")
    if response.status_code == 200:
      return response.text
  except Exception as e:
    print(f"{Fore.RED}[!]{Fore.RESET} Error retrieving signatures: {e}")
  return None

def hash_string(content):
  return hashlib.sha256(content.encode("utf-8")).hexdigest()

def sync_hashes():
  print(f"{Fore.YELLOW}[*]{Fore.RESET} Syncing hashes...")
  content = get_hashes()
  if not content:
    return False
  remote_hash = hash_string(content)
  previous_hash = ""
  if os.path.exists(HASH_META_FILE):
    with open(HASH_META_FILE, "rb") as f:
      previous_hash = f.read().strip()
  if remote_hash == previous_hash:
    print(f"{Fore.GREEN}[*]{Fore.RESET} Virus signature list is up-to-date.")
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
  print("Scanning...")
  infected = []
  for root, _, files, in os.walk(directory):
    for f in files:
      full_path = os.path.join(root, f)
      hash = calculate(full_path)
      if not hash:
        continue
      if hash in hashes:
        print(f"{Fore.RED}[!]{Fore.RESET} Infected File Found: {full_path}")
        infected.append(full_path)
  print(f"Scan Completed. {len(infected)} infected files found.")
  return infected

if __name__ = "__main__":
  sync_hashes()
  md5_sigs = load_hashes()
  
