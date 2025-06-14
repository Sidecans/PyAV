# PyAV - Simple Python Antivirus
**PyAV** is a lightweight python antivirus with many nice features.

## Features
- Custom CLI
- Custom Menu for easy access
- Malware Scanning
- Server to update Malware Hashes
- VirusTotal integration
- Logging

## Installation
**bash:**
```
git clone https://github.com/Sidecans/PyAV.git
cd PyAV
pip install . -r requirements.txt
```

## Requirements
- flask
- requests
- setuptools
- colorama

## Examples
```
PyAV --scan <path> 
PyAV --update
PyAV --deep <path>
PyAV
```




Credits to [romainmarcoux](https://github.com/romainmarcoux/malicious-hash) for virus signatures.