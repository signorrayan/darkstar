"""
Darkstar - Security Scanning Framework

This is the main entry point for the Darkstar security scanning framework.
It handles command line arguments, target parsing, and orchestration of
various scanning modules based on the selected scan mode.

Modes:
    1. Passive: Light reconnaissance without active scanning
    2. Normal: Standard scanning with passive and selected active modules
    3. Aggressive: Full scanning with all active and aggressive modules

Usage:
    python main.py -t TARGET -m MODE -d DOMAIN -env ENV_FILE

License:
    GNU General Public License v3.0
"""

#  *
#  * This file is part of Darkstar.
#  *
#  * Darkstar is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * Darkstar is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with Darkstar. If not, see <https://www.gnu.org/licenses/>.
#  *

import argparse
from dotenv import load_dotenv
import pandas as pd
import warnings
import sys
from modules.scanners import *
from modules.openvas import openvas
from colorama import Fore, Style, Back, init
from modules.recon import WordPressDetector
from tqdm import tqdm
import time
warnings.filterwarnings("ignore")
init(autoreset=True)

# Move this code outside of global scope to prevent execution during import
def setup_env_from_args(args=None):
    #? First, create a minimal argument parser just to grab the --envfile parameter.
    env_parser = argparse.ArgumentParser(add_help=False)
    env_parser.add_argument("-env", "--envfile", help="envfile location, default .env", default=".env", required=False)
    
    # Only parse sys.argv if args is not provided (for testing)
    if args is None:
        env_args, _ = env_parser.parse_known_args()
    else:
        env_args, _ = env_parser.parse_known_args(args)
    
    #? Load the env file early.
    load_dotenv(env_args.envfile if hasattr(env_args, 'envfile') else ".env")
    
    return env_args

class worker():
    """
    Main worker class that orchestrates and executes scanning operations.
    
    This class is responsible for running the selected scanning modules
    based on the specified mode and managing the workflow between them.
    
    Attributes:
        all_targets (str): Raw target string from command line arguments
        target_df (DataFrame): Parsed targets organized by type
        mode (int): Scan intrusiveness level (1=passive, 2=normal, 3=aggressive)
        org_domain (str): Organization name for database storage
    """
    
    def __init__(self, mode: int, targets: str, target_df: pd.DataFrame, org_name: str):
        self.all_targets = targets
        self.target_df = target_df
        self.mode = mode
        self.org_domain = org_name

    def run(self):
        """
        Execute the scanning process based on the selected mode.
        
        Each mode runs a different set of scanning modules:
        - Mode 3 (Aggressive): Full active scanning with all modules
        - Mode 2 (Normal): Passive scanning plus OpenVAS for IPv4 targets
        - Mode 1 (Passive): Only passive reconnaissance
        """
        #? Aggressive mode
        if self.mode == 3:
            #? Run bbot with aggressive settings
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.aggressive()
            
            # #? Run nuclei on the subdomains
            filename = f'{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt'
            filename = '/tmp/subs.txt'
            nuclei(filename, self.org_domain).run()

            #? Detect wordpress
            wordpress_domains = WordPressDetector().run(filename) 
            print(f"[+] Wordpress Domains: {wordpress_domains}")
            
            #? Nuclei wordpress
            nuclei_wordpress(wordpress_domains, self.org_domain).run()

            if not self.target_df['IPv4'].empty:
                openvas_handler = openvas(targets=self.target_df['IPv4'], org_name=self.org_domain)
                openvas_handler.run()
            else:
                print(f"{Fore.RED}[-] No IPv4 targets found, skipping OpenVAS{Style.RESET_ALL}")
        
        #? Normal mode
        elif self.mode == 2:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
            #? Run OpenVas
            if not self.target_df['IPv4'].empty:
                openvas_handler = openvas(targets=self.target_df['IPv4'], org_name=self.org_domain)
                openvas_handler.run()
            else:
                print(f"{Fore.RED}[-] No IPv4 targets found, skipping OpenVAS{Style.RESET_ALL}")

        #? Passive mode
        elif self.mode == 1:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
        else:
            print(f"{Fore.RED}[-] Invalid mode {Style.RESET_ALL}")


def parse_targets(targets_str):
    """
    Parse and categorize targets by type.
    
    Args:
        targets_str: Comma-separated target string
    
    Returns:
        pd.DataFrame: DataFrame with targets categorized
    """
    targets = targets_str.split(',')
    cidrs, ipv4, ipv6, domains, urls = [], [], [], [], []

    print(f"{Fore.CYAN}[*] {Back.BLACK}Parsing and categorizing targets...{Style.RESET_ALL}")
    with tqdm(total=len(targets), desc="Target Classification", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
        for target in targets:
            if "http" in target:
                print(f"  {Fore.GREEN}[+] Target {Fore.YELLOW}{target}{Fore.GREEN} is a URL{Style.RESET_ALL}")
                urls.append(target)
            elif "/" in target:
                print(f"  {Fore.GREEN}[+] Target {Fore.YELLOW}{target}{Fore.GREEN} is CIDR{Style.RESET_ALL}")
                cidrs.append(target)
            elif ":" in target:
                print(f"  {Fore.GREEN}[+] Target {Fore.YELLOW}{target}{Fore.GREEN} is an IPv6{Style.RESET_ALL}")
                ipv6.append(target)
            elif target.replace(".", "").isnumeric():
                print(f"  {Fore.GREEN}[+] Target {Fore.YELLOW}{target}{Fore.GREEN} is an IP{Style.RESET_ALL}")
                ipv4.append(target)
            else:
                print(f"  {Fore.GREEN}[+] Target {Fore.YELLOW}{target}{Fore.GREEN} is a domain{Style.RESET_ALL}")
                domains.append(target)
            pbar.update(1)
            time.sleep(0.1)  # Small delay for visual effect
    
    print(f"\n{Fore.MAGENTA}[>] Target Summary:{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}[>] CIDRs: {Fore.CYAN}{cidrs}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}[>] IPs: {Fore.CYAN}{ipv4}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}[>] Domains: {Fore.CYAN}{domains}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}[>] IPv6: {Fore.CYAN}{ipv6}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}[>] URLs: {Fore.CYAN}{urls}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}{Back.BLACK}[+] Targets Locked and Ready for Scanning!{Style.RESET_ALL}")

    # Create a DataFrame with proper structure even if lists are empty
    # This ensures it always returns a valid DataFrame with the expected columns
    df = pd.DataFrame(columns=['CIDRs', 'IPv4', 'IPv6', 'Domains', 'URLs'])
    
    # Add data if we have any
    if cidrs:
        df['CIDRs'] = pd.Series(cidrs)
    if ipv4:
        df['IPv4'] = pd.Series(ipv4)
    if ipv6:
        df['IPv6'] = pd.Series(ipv6)
    if domains:
        df['Domains'] = pd.Series(domains)
    if urls:
        df['URLs'] = pd.Series(urls)
        
    return df


def main(args=None):
    """
    Main function that parses arguments and initializes the scanning process.
    
    Handles command line arguments, parses and categorizes targets by type,
    and initializes the worker to run the scanning process.
    
    Args:
        args: Command line arguments (for testing)
    """
    # Initialize environment variables
    setup_env_from_args(args)
    
    #? Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Fill in the CIDR, IP or domain (without http/https) to scan")
    parser.add_argument("-m", "--mode", type=int, required=True, help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive", choices=[1, 2, 3])
    parser.add_argument("-d", "--domain", help="The organisation name necessary for database selection", required=True)
    parser.add_argument("-env", "--envfile", help="envfile location, default .env", default=".env", required=False)
    
    #? Parse arguments
    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)
    
    # Banner
    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.CYAN}DARKSTAR SECURITY SCANNING FRAMEWORK")
    print(f"{Fore.CYAN}Mode: {Fore.YELLOW}{args.mode}{Fore.CYAN} | Target: {Fore.YELLOW}{args.target}{Fore.CYAN} | Organization: {Fore.YELLOW}{args.domain}")
    print(f"{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}\n")
    
    # Parse targets
    target_df = parse_targets(args.target)

    # Display scan mode information
    mode_info = {
        1: f"{Fore.GREEN}PASSIVE MODE{Style.RESET_ALL} - Light reconnaissance without active scanning",
        2: f"{Fore.YELLOW}NORMAL MODE{Style.RESET_ALL} - Standard scanning with passive and selected active modules",
        3: f"{Fore.RED}AGGRESSIVE MODE{Style.RESET_ALL} - Full scanning with all active and aggressive modules"
    }
    print(f"\n{Fore.CYAN}[*] Initializing scan in {mode_info[args.mode]}\n")

    #? Run the scanner
    scanner = worker(mode=args.mode, targets=args.target, target_df=target_df, org_name=args.domain)
    scanner.run()


if __name__ == "__main__":
    main()