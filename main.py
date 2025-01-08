import argparse
import os
import subprocess
import pandas as pd
from modules.scanners import *
from colorama import Fore, Style, init
import warnings

warnings.filterwarnings("ignore")

init(autoreset=True)

class worker():
    def __init__(self, mode: int, targets: str, target_df: pd.DataFrame, org_name: str):
        self.all_targets = targets
        self.target_df = target_df
        self.mode = mode
        self.org_domain = org_name
    def run(self):
        #? Aggressive mode
        if self.mode == 3:
            #? Run bbot with aggressive settings
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.aggressive()
            
            #? Run nuclei on the subdomains
            nuclei(f'{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt').run()

        
        #? Normal mode
        elif self.mode == 2:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
        #? Passive mode
        elif self.mode == 1:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
        else:
            print(f"{Fore.RED}[-] Invalid mode {Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Fill in the CIDR, IP or domain (without http/https) to scan")
    parser.add_argument("-m", "--mode", type=int, required=True, help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive", choices=[1, 2, 3])
    parser.add_argument("-d", "--domain", help="The organisation name necessary for database selection", required=True)
    args = parser.parse_args()

    targets = args.target.split(',')
    cidrs, ipv4, ipv6, domains, urls = [], [], [], [], []

    for target in targets:
        if "http" in target:
            print(f"{Fore.GREEN}[+] Target {target} is a URL{Style.RESET_ALL}")
            urls.append(target)
        elif "/" in target:
            print(f"{Fore.GREEN}[+] Target {target} is CIDR{Style.RESET_ALL}")
            cidrs.append(target)
        elif ":" in target:
            print(f"{Fore.GREEN}[+] Target {target} is an IPv6{Style.RESET_ALL}")
            ipv6.append(target)
        elif target.replace(".", "").isnumeric():
            print(f"{Fore.GREEN}[+] Target {target} is an IP{Style.RESET_ALL}")
            ipv4.append(target)
        else:
            print(f"{Fore.GREEN}[+] Target {target} is a domain{Style.RESET_ALL}")
            domains.append(target)
    
    print(f"{Fore.MAGENTA}[>] CIDRs: {cidrs}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] IPs: {ipv4}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] Domains: {domains}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] IPv6: {ipv6}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] URLs: {urls}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Targets Locked!{Style.RESET_ALL}")

    # Create a DataFrame from the lists
    target_data = {
        'CIDRs': cidrs,
        'IPv4': ipv4,
        'IPv6': ipv6,
        'Domains': domains,
        'URLs': urls
    }
    target_df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in target_data.items()]))

    #? Run the scanner
    scanner = worker(mode=args.mode, targets=args.target, target_df=target_df, org_name=args.domain)
    scanner.run()


if __name__ == "__main__":
    main()
