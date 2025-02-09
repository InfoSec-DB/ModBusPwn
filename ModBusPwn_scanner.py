import argparse
import shodan
from pymodbus.client import ModbusTcpClient
import time
from colorama import Fore, Style, init
import sys
import math
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
init()

# ANSI Colors for styling
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
CYAN = Fore.CYAN
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

def print_banner():
    """ Displays a banner at startup """
    banner = f'''{RED}
         ;               ,           
         ,;                 '.         
        ;:                   :;        
       ::                     ::       
       ::                     ::       
       ':                     :        
        :.                    :        
     ;' ::                   ::  '     
    .'  ';                   ;'  '.    
   ::    :;                 ;:    ::   
   ;      :;.             ,;:     ::   
   :;      :;:           ,;"      ::   
   ::.      ':;  ..,.;  ;:'     ,.;:   
    "\'...   '::,::::: ;:   .;.;""'    
        '"""....;:::::;,;.;"""         
    .:::.....'\''":::::::'",...;::::;.   
   ;:' '\'"'\\""\";.,;:::::;.'"""\\""\""  ':;   
  ::'         ;::;:::;::..         :;  
 ::         ,;:::::::::::;:..       ::   
 ;'     ,;;:;::::::::::::::;";..    ':.
::     ;:"  ::::::""'\''::::::  ":     ::
 :.    ::   ::::::;  :::::::   :     ; 
  ;    ::   :::::::  :::::::   :    ;  
   '   ::   ::::::....:::::'  ,:   '   
    '  ::    :::::::::::::"   ::       
       ::     ':::::::::"'    ::       
       ':       """""""'      ::       
        ::                   ;:        
        ':;                 ;:"        
          ';              ,;'          
            "'           '"            
              '
{CYAN} [★] SCADA MODBUS SCANNER (MADE BY #AfterDark) [★] {RESET}
'''
    print(banner)

def fetch_shodan_page(api, query, limit, page):
    """ Fetch a single page from Shodan (for multi-threading) """
    try:
        results = api.search(query, limit=limit, page=page)
        return results.get('matches', [])
    except shodan.APIError as e:
        print(f"{RED}[-] Shodan API error on Page {page}: {e}{RESET}")
        return []

def shodan_search(api_key, country, limit, requested_pages, output_file, ip_only, threads):
    """ Multi-threaded search for Modbus devices on Shodan """
    print(f"{CYAN}[+] Searching for Modbus devices in {country} on Shodan...{RESET}")
    try:
        api = shodan.Shodan(api_key)
        query = f"port:502 country:{country}"

        # First request to get total results available
        first_page = api.search(query, limit=limit, page=1)
        total_results = first_page['total']
        
        # Calculate max available pages
        max_available_pages = math.ceil(total_results / limit)

        # Adjust pages if the user requested too many
        pages_to_fetch = min(requested_pages, max_available_pages)

        print(f"{GREEN}[✔] Total Modbus devices found: {total_results}{RESET}")
        print(f"{GREEN}[✔] Max available pages: {max_available_pages} | Fetching up to: {pages_to_fetch} pages using {threads} threads.{RESET}")

        ip_set = set()  # Use a set to remove duplicates
        all_results = []  # Store results before cleaning
        full_data_list = []

        # Use multi-threading to fetch pages in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(fetch_shodan_page, api, query, limit, page): page for page in range(1, pages_to_fetch + 1)}

            for future in as_completed(futures):
                page_results = future.result()
                for result in page_results:
                    ip = result['ip_str']
                    all_results.append(ip)  # Track all IPs before cleaning
                    ip_set.add(ip)  # Add to set (removes duplicates)

                    if not ip_only:
                        org = result.get('org', 'N/A')
                        country_name = result.get('location', {}).get('country_name', 'N/A')
                        result_str = f"{WHITE}[+] IP: {ip} | Organization: {org} | Country: {country_name}{RESET}"
                        full_data_list.append(result_str)

        # Sort & clean results
        ip_list = sorted(ip_set)  # Deduplicated and sorted IPs

        # Display counts
        print(f"{GREEN}[✔] Total Results Before Cleaning: {len(all_results)}{RESET}")
        print(f"{GREEN}[✔] Total Unique Results After Cleaning: {len(ip_list)}{RESET}")

        # Print results
        if ip_only:
            for ip in ip_list:
                print(f"{WHITE}{ip}{RESET}")
        
        if output_file:
            base_filename = output_file.replace(".txt", "")
            full_output = f"{base_filename}_full.txt"
            ip_output = f"{base_filename}_ips.txt"

            # Ensure only unique IPs are saved
            if full_data_list:
                with open(full_output, "w") as f:
                    f.write("\n".join(set(full_data_list)))  # Deduplicated
                print(f"{GREEN}[✔] Full results saved to {full_output}{RESET}")

            if ip_list:
                with open(ip_output, "w") as f:
                    f.write("\n".join(ip_list))  # Deduplicated and sorted
                print(f"{GREEN}[✔] IP-only results saved to {ip_output}{RESET}")

    except shodan.APIError as e:
        print(f"{RED}[-] Shodan API error: {e}{RESET}")

def main():
    print_banner()  # Display Banner

    parser = argparse.ArgumentParser(description="SCADA Modbus Scanner")
    parser.add_argument("-t", "--target", help="Target IP address of the Modbus PLC")
    parser.add_argument("-s", "--shodan", action="store_true", help="Search for Modbus devices using Shodan API")
    parser.add_argument("-a", "--shodan-api", help="Your Shodan API Key")
    parser.add_argument("-c", "--country", help="Filter Shodan results by country (e.g., US, CN, DE)")
    parser.add_argument("-l", "--limit", type=int, default=10, help="Limit number of Shodan results per page (default: 10)")
    parser.add_argument("-p", "--page", type=int, default=1, help="Max page number to fetch results from (default: 1)")
    parser.add_argument("-o", "--output", help="Save results to files with this prefix")
    parser.add_argument("-i", "--ip-only", action="store_true", help="Show only IP addresses in results")
    parser.add_argument("-d", "--detect", action="store_true", help="Detect PLC Model, Firmware, and Serial Number")
    parser.add_argument("-tN", "--threads", type=int, default=5, help="Number of threads for fetching Shodan results (default: 5)")

    args = parser.parse_args()

    if args.shodan:
        if not args.shodan_api:
            print(f"{RED}[-] Error: Shodan API key is required. Use -a <API_KEY>{RESET}")
            sys.exit(1)
        if not args.country:
            print(f"{RED}[-] Error: Country filter is required for Shodan search. Use -c <COUNTRY_CODE>{RESET}")
            sys.exit(1)
        shodan_search(args.shodan_api, args.country, args.limit, args.page, args.output, args.ip_only, args.threads)
        return  

if __name__ == "__main__":
    main()
