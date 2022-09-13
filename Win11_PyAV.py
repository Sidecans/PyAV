import os

drive = str(os.getcwd()).split("\\")
drive = drive[0]

def scan(name):
    print("Virus Detected!!!")
    print("Threat Name: " + name)
    


if os.path.exists(drive + "\\Windows\\automks.exe"):
    pass

