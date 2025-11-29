import time
from colorama import Fore
from ServiceAtt import *
import os
import os
import time
from colorama import Fore

info = Fore.GREEN + "info" + Fore.RESET
warning = Fore.RED + "WARNING" + Fore.RESET
error = Fore.RED + "error" + Fore.RESET


# ======================================================
# NORMAL LOG KAYDI
# ======================================================
def log_event(message):
    log_folder = "src"
    os.makedirs(log_folder, exist_ok=True)

    # Log dosyası her çağrıda yeni isim istiyorsan:
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open(log_file, "a", encoding="utf-8") as file:
        file.write(str(message) + "\n")

    print(f"{info}: Log kaydedildi → {log_file}")


# ======================================================
# BLACKLIST LOG – HER ZAMAN AYNI DOSYA
# ======================================================
def log_blacklist(ip):
    log_folder = "src"
    os.makedirs(log_folder, exist_ok=True)

    blacklist_file = os.path.join(log_folder, "blacklist.txt")

    with open(blacklist_file, "a", encoding="utf-8") as file:
        file.write(str(ip) + "\n")

    print(f"{warning}: IP blacklist'e eklendi → {blacklist_file}")
def log_error(message):
    log_folder = "src"
    os.makedirs(log_folder, exist_ok=True)

    error_file = os.path.join(log_folder, "error.log")

    with open(error_file, "a", encoding="utf-8") as file:
        file.write(str(message) + "\n")

    print(f"{info}:Error Log saved {error_file}")
