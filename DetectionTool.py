

import subprocess
import time
from collections import defaultdict

found_networks = defaultdict(list)


def show_title():
    print("")
    print("============================================")
    print("                                            ")
    print("         EVIL TWIN DETECTOR                 ")
    print("         Wi-Fi Threat Scanner               ")
    print("                                            ")
    print("============================================")
    print("")


def scan():
    output = subprocess.check_output(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        encoding="utf-8", errors="ignore"
    )
    return parse_windows(output)

def parse_windows(output):
    networks = {}
    ssid    = None
    current = None

    for line in output.split("\n"):
        line = line.strip()

        if line.startswith("SSID") and not line.startswith("BSSID"):
            ssid = line.split(":", 1)[1].strip()
            networks.setdefault(ssid, [])

        elif line.startswith("BSSID") and ssid:
            bssid   = line.split(":", 1)[1].strip()
            current = {"bssid": bssid, "signal": "?"}
            networks[ssid].append(current)

        elif line.startswith("Signal") and current:
            current["signal"] = line.split(":", 1)[1].strip()

    return networks

def similarity(a, b):
    a = a.lower()
    b = b.lower()
    if a == b:
        return 100
    matches = sum(c1 == c2 for c1, c2 in zip(a, b))
    total   = max(len(a), len(b))
    return int((matches / total) * 100)
def check_networks(networks, target):

    found_any = False
    all_names = list(networks.keys())

    for network_name, entries in networks.items():

        if target != "ALL" and network_name.lower() != target.lower():
            continue

        for entry in entries:

            mac = entry["bssid"]
            sig = entry["signal"]

            if mac not in found_networks[network_name]:
                found_networks[network_name].append(mac)

            # RULE 1 - Same name, different MAC address
            duplicate_mac = len(found_networks[network_name]) > 1

            # RULE 2 - Similar but not identical name nearby
            similar_names = []
            for other_name in all_names:
                if other_name == network_name:
                    continue
                score = similarity(network_name, other_name)
                if score >= 75:
                    similar_names.append((other_name, score))

            found_any = True

            if duplicate_mac or similar_names:
                print("")
                print("============================================")
                print("[!] WARNING - POSSIBLE EVIL TWIN DETECTED  ")
                print("============================================")
                print("[*] Network  : " + network_name)
                print("[*] Signal   : " + sig)

                if duplicate_mac:
                    print("[X] RULE 1   : Same name, different MAC")
                    print("[*] All MACs :")
                    for i, m in enumerate(found_networks[network_name]):
                        print("    [" + str(i+1) + "] " + m)

                if similar_names:
                    print("[X] RULE 2   : Similar network name found nearby")
                    for name, score in similar_names:
                        print("    [!] '" + name + "' looks " + str(score) + "% similar")
                    print("    [!] This could be a typosquat attack")

                print("[!] DO NOT CONNECT TO THIS NETWORK")
                print("============================================")
                print("")

            else:
                print("[+] Safe     : " + network_name +
                      "  |  MAC: " + mac +
                      "  |  Signal: " + sig)

    if not found_any and target != "ALL":
        print("[!] Network '" + target + "' not found nearby.")


def list_networks():
    print("[*] Scanning for nearby networks...")
    networks = scan()

    if not networks:
        print("[!] No networks found.")
        return []

    names = list(networks.keys())
    print("")
    print("--------------------------------------------")
    print("  Networks Found Nearby:")
    print("--------------------------------------------")
    for i, name in enumerate(names):
        print("  [" + str(i+1) + "] " + name)
    print("--------------------------------------------")
    print("")
    return names


def ask_timer():
    print("")
    while True:
        try:
            mins = input("[?] How many minutes do you want to scan? : ").strip()
            mins = int(mins)
            if mins <= 0:
                print("[!] Please enter a number greater than 0.")
                continue
            return mins * 60
        except ValueError:
            print("[!] Please enter a valid number.")



def ask_interval():
    print("")
    while True:
        try:
            secs = input("[?] Scan every how many seconds? (e.g. 10) : ").strip()
            secs = int(secs)
            if secs <= 0:
                print("[!] Please enter a number greater than 0.")
                continue
            return secs
        except ValueError:
            print("[!] Please enter a valid number.")


def ask_target(names):
    print("")
    print("[?] Which network do you want to monitor?")
    print("    [0] ALL networks")
    for i, name in enumerate(names):
        print("    [" + str(i+1) + "] " + name)
    print("")

    while True:
        choice = input("[?] Enter number : ").strip()
        try:
            choice = int(choice)
            if choice == 0:
                return "ALL"
            elif 1 <= choice <= len(names):
                return names[choice - 1]
            else:
                print("[!] Please enter a number from the list.")
        except ValueError:
            print("[!] Please enter a valid number.")


show_title()

names = list_networks()

if not names:
    input("Press Enter to exit.")
else:
    target   = ask_target(names)
    interval = ask_interval()
    duration = ask_timer()

    print("")
    print("============================================")
    print("[*] Target   : " + target)
    print("[*] Interval : every " + str(interval) + " seconds")
    print("[*] Duration : " + str(duration // 60) + " minutes")
    print("[*] Starting scan... CTRL+C to stop early")
    print("============================================")
    print("")

    start_time = time.time()

    while True:
        elapsed   = time.time() - start_time
        remaining = duration - elapsed

        if remaining <= 0:
            print("")
            print("============================================")
            print("[*] Scan complete. Time limit reached.")
            print("============================================")
            break

        print("[*] Scanning... (" + str(int(remaining)) + " seconds remaining)")

        try:
            results = scan()
            check_networks(results, target)
        except Exception as e:
            print("[!] Error: " + str(e))

        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("")
            print("============================================")
            print("[*] Scan stopped by user.")
            print("============================================")
            break

    input("Press Enter to exit.")