from modules.db_helper import *
from modules.vulns import Vulnerability, CVE
from modules.HIBPwned import HIBPwned
import pandas as pd
import os
import subprocess
import base64 
from colorama import Fore, Style, Back, init
import hashlib
import threading
import re
import yaml
from tqdm import tqdm
import time
import shutil

"""
Collection of security scanning modules for the Darkstar framework.

This file contains scanner classes for various reconnaissance and
vulnerability detection methods, including bbot integration, Nuclei
scanning, and WordPress vulnerability detection.
"""

class bbot():
    """
    Wrapper for the bbot (Black Box Operations Tool) scanner.
    
    Provides methods for passive and aggressive reconnaissance using bbot,
    and processes the results to insert findings into the database.
    
    Attributes:
        target (str): The target to scan (domain, IP, CIDR, etc.)
        folder (str): Output folder for bbot results
        foldername (str): Unique folder name for the current scan
        org_name (str): Organization name for database storage
    """
    def __init__(self, target: str, org_name: str):
        self.target = target
        self.folder = f"/app/bbot_output"
        self.foldername = hashlib.md5(os.urandom(10)).hexdigest()
        self.org_name = org_name

        #? Create a directory for bbot output if not exists
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)

    def vulns_to_db(self, df: pd.DataFrame) -> None:
        """
        Process vulnerability findings from bbot output and insert into database.
        
        Args:
            df (DataFrame): DataFrame containing bbot scan results
        """
        vuln_count = sum(1 for _, row in df.iterrows() 
                          if row['Event type'] == "VULNERABILITY" or row["Event type"] == "FINDING")
        
        if vuln_count == 0:
            print(f"{Fore.YELLOW}[!] No vulnerabilities or findings detected in bbot scan{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] Processing {Fore.CYAN}{vuln_count}{Fore.GREEN} vulnerabilities found by bbot{Style.RESET_ALL}")
        
        with tqdm(total=vuln_count, desc="Processing Vulnerabilities", 
                  bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Style.RESET_ALL)) as pbar:
            for index, row in df.iterrows():
                if row['Event type'] == "VULNERABILITY" or row["Event type"] == "FINDING":
                    #? Get the object and store into the database as a vulnerability
                    try:
                        item = eval(row["Event data"])
                        if isinstance(item, str):
                            item = eval(item)
                        severity = "info" if row["Event type"] == "FINDING" else item.get("severity", None)
                        finding_object = Vulnerability(
                            title='asm finding',
                            affected_item=item.get("url", None),
                            tool="bbot",
                            confidence=90,
                            severity=severity,
                            host=item.get("host", None),
                            poc=item.get("url", None),
                            summary=item.get("description", None)
                        )
                        print(f"  {Fore.GREEN}[+] Adding to database: {Fore.CYAN}{finding_object.title} on {finding_object.host}{Style.RESET_ALL}")
                        insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)
                    except Exception as e:
                        print(f"  {Fore.RED}[!] Error processing vulnerability: {e}{Style.RESET_ALL}")
                    pbar.update(1)

    def hibpwned(self) -> None:
        """
        Process discovered emails through Have I Been Pwned API.
        
        Checks if any emails found during the scan have been involved
        in known data breaches.
        """
        email_file = f"{self.folder}/{self.foldername}/emails.txt"
        print(f"{Fore.CYAN}[*] Checking for HaveIBeenPwned data from {email_file}{Style.RESET_ALL}")
        
        if not os.path.exists(email_file):
            print(f"{Fore.YELLOW}[!] No emails file found at {email_file}{Style.RESET_ALL}")
            return
            
        with open(email_file, 'r') as file:
            email_count = sum(1 for _ in file)
        
        if email_count > 0:
            print(f"{Fore.GREEN}[+] Found {Fore.CYAN}{email_count}{Fore.GREEN} emails to check with HaveIBeenPwned{Style.RESET_ALL}")
            hibp = HIBPwned(email_file, self.org_name)
            hibp.run()
        else:
            print(f"{Fore.YELLOW}[!] Email file exists but contains no emails{Style.RESET_ALL}")

    def prep_data(self) -> pd.DataFrame:
        """
        Prepare bbot scan data for database insertion.
        
        Reads the bbot output CSV file and processes it into a suitable format
        for database insertion.
        
        Returns:
            DataFrame: The processed scan results
        """
        output_file = f"{self.folder}/{self.foldername}/output.csv"
        if os.path.exists(output_file):
            print(f"{Fore.GREEN}[+] Reading bbot output from {output_file}{Style.RESET_ALL}")
            
            #? Show a progress bar for file reading
            file_size = os.path.getsize(output_file)
            with tqdm(total=file_size, unit='B', unit_scale=True, 
                     desc="Reading bbot data", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
                last_pos = 0
                #? write to DB
                df = pd.read_csv(output_file)
                current_pos = file_size
                pbar.update(current_pos - last_pos)
            
            print(f"{Fore.GREEN}[+] Loaded {Fore.CYAN}{len(df)}{Fore.GREEN} records from bbot output{Style.RESET_ALL}")
            
            #? Replace NaN with None
            df = df.where(pd.notnull(df), None)

            self.hibpwned()

            #? Check if bbot found any vulns write to vulnerability class and insert to db
            self.vulns_to_db(df)          

            return df    
        else:
            print(f"{Fore.RED}[-] No output file found at {output_file}, something went wrong with bbot scan{Style.RESET_ALL}")
            return pd.DataFrame()

    def passive(self) -> None:
        """
        Run bbot with passive scanning flags.
        
        Executes a non-intrusive scan using bbot's passive modules,
        focusing on subdomain enumeration and data collection without
        active probing.
        """
        print(f"\n{Fore.CYAN}{Back.BLACK}[*] Starting Passive bbot Scan on {self.target}{Style.RESET_ALL}")

        command = ["/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum", "-o", self.folder, "-n", self.foldername, "-y"]
        
        print(f"{Fore.GREEN}[+] Executing bbot with passive settings{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Command: {' '.join(command)}{Style.RESET_ALL}")
        
        #? Create spinner for bbot execution
        spinner = ['|', '/', '-', '\\']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        print(f"{Fore.CYAN}[*] bbot scan in progress...{Style.RESET_ALL}")
        i = 0
        with tqdm(total=100, desc="Passive Scan Progress", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
            prev_progress = 0
            while process.poll() is None:
                i = (i + 1) % len(spinner)
                print(f"\r{Fore.CYAN}[{spinner[i]}] Running passive scan...{Style.RESET_ALL}", end='')
                time.sleep(0.5)
                
                # Simulate progress for visual feedback
                # In a real implementation, you'd parse actual progress from bbot output
                progress = min(prev_progress + 1, 99)  
                pbar.update(progress - prev_progress)
                prev_progress = progress
            
            # Complete the progress bar when done
            pbar.update(100 - prev_progress)
            
        print(f"\n{Fore.GREEN}[+] Passive scan completed!{Style.RESET_ALL}")

        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv intot the database
        print(f"{Fore.CYAN}[*] Processing scan results and storing in database...{Style.RESET_ALL}")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        print(f"{Fore.GREEN}[+] Passive scan data successfully processed{Style.RESET_ALL}")

    def aggressive(self) -> None:
        """
        Run bbot with aggressive scanning flags.
        
        Executes a comprehensive scan using bbot's active and potentially 
        intrusive modules for deeper reconnaissance and vulnerability detection.
        """
        print(f"\n{Fore.RED}{Back.BLACK}[*] Starting AGGRESSIVE bbot Scan on {self.target}{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] WARNING: This is an aggressive scan that may trigger alerts{Style.RESET_ALL}")

        command = ["/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,active,deadly,aggressive,web-thorough,subdomain-enum,cloud-enum,code-enum,affiliates", "-m", "nuclei,baddns,baddns_zone,dotnetnuke,ffuf", "--allow-deadly", "-o", self.folder, "-n", self.foldername, "-y"]

        print(f"{Fore.GREEN}[+] Executing bbot with aggressive settings{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Command: {' '.join(command)}{Style.RESET_ALL}")
        
        #? Create spinner for bbot execution
        spinner = ['|', '/', '-', '\\']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        print(f"{Fore.CYAN}[*] Aggressive bbot scan in progress...{Style.RESET_ALL}")
        i = 0
        with tqdm(total=100, desc="Aggressive Scan Progress", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.RED, Style.RESET_ALL)) as pbar:
            prev_progress = 0
            while process.poll() is None:
                i = (i + 1) % len(spinner)
                print(f"\r{Fore.RED}[{spinner[i]}] Running aggressive scan...{Style.RESET_ALL}", end='')
                time.sleep(0.5)
                
                # Simulate progress for visual feedback
                progress = min(prev_progress + 1, 99)
                pbar.update(progress - prev_progress)
                prev_progress = progress
            
            # Complete the progress bar when done
            pbar.update(100 - prev_progress)
            
        print(f"\n{Fore.GREEN}[+] Aggressive scan completed!{Style.RESET_ALL}")

        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv into the database
        print(f"{Fore.CYAN}[*] Processing aggressive scan results and storing in database...{Style.RESET_ALL}")
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)
        print(f"{Fore.GREEN}[+] Aggressive scan data successfully processed{Style.RESET_ALL}")

class nuclei():
    """
    Wrapper for Nuclei vulnerability scanner.
    
    Provides methods for scanning hosts using Nuclei templates to
    identify security vulnerabilities and misconfigurations.
    
    Attributes:
        file (str): Path to a file containing targets to scan
        org_name (str): Organization name for database storage
    """
    def __init__(self, filename: str, org_name: str):
        self.file = filename
        self.org_name = org_name
        # Count targets for progress tracking
        try:
            with open(self.file, 'r') as f:
                self.target_count = sum(1 for _ in f)
        except:
            self.target_count = 0

    def scan_nuclei(self) -> None:
        """
        Execute the Nuclei scan and process results.
        
        Runs Nuclei against the targets, parses the output to extract
        vulnerability information, and inserts findings into the database.
        """
        keywords = ["unknown", "low", "medium", "high", "critical"]
        
        print(f"{Fore.CYAN}{Back.BLACK}[*] Starting Nuclei scan on targets from {self.file}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scanning {self.target_count} targets for vulnerabilities{Style.RESET_ALL}")
        
        nuclei_command = f"nuclei -l {self.file} -s low,medium,high,critical,unknown -et github -bs 400 -rl 1000"
        print(f"{Fore.YELLOW}    Command: {nuclei_command}{Style.RESET_ALL}")
        
        # Track vulnerabilities found for progress bar
        vulnerabilities_found = []
        
        process = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)
        
        # Create progress bar for nuclei scan
        with tqdm(total=100, desc="Nuclei Scan Progress", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.MAGENTA, Style.RESET_ALL)) as pbar:
            prev_progress = 0
            
            while True:  
                output_line = process.stdout.readline()  
                if not output_line and process.poll() is not None:  
                    break
                
                # Update progress (this is an estimate as nuclei doesn't provide progress info)
                if "%" in output_line:
                    try:
                        percent_match = re.search(r'(\d+)%', output_line)
                        if percent_match:
                            progress = int(percent_match.group(1))
                            pbar.update(progress - prev_progress)
                            prev_progress = progress
                    except:
                        # Simulated progress if we can't parse actual progress
                        progress = min(prev_progress + 1, 99)
                        pbar.update(progress - prev_progress)
                        prev_progress = progress

                if output_line:
                    if any(keyword in output_line for keyword in keywords):
                        vulnerabilities_found.append(output_line)
                        severity = next((kw for kw in keywords if kw in output_line), "unknown")
                        severity_color = {
                            "critical": Fore.RED + Back.BLACK,
                            "high": Fore.RED,
                            "medium": Fore.YELLOW,
                            "low": Fore.GREEN,
                            "unknown": Fore.BLUE
                        }.get(severity, Fore.WHITE)
                        
                        print(f"\n  {severity_color}[VULN] {output_line.strip()}{Style.RESET_ALL}")
                        
                        # extract url with regex
                        url = ""
                        try:
                            url = re.search(r"(?P<url>https?://[^\s]+)", output_line).group("url")
                        except:
                            try:
                                url = re.search(r"(?P<url>http?://[^\s]+)", output_line).group("url")
                            except:
                                try:
                                    #find it port based by x:443 or x:80
                                    url = re.search(r"(?P<url>[^\s]+:[0-9]+)", output_line).group("url")
                                    # cut off port
                                    url = url.split(":")[0]
                                except:
                                    url = "unknown"

                        domain = url 
                        # replace https:// http:// www.
                        domain = domain.replace("https://", "")
                        domain = domain.replace("http://", "")
                        domain = domain.replace("www.", "")

                        epss_percentile = None  

                        # if has / in it, stop at /
                        if "/" in domain:
                            domain = domain.split("/")[0]

                        # extract cve with regex
                        cve = re.search(r"(?P<cve>CVE-[^\s]+)", output_line)

                        # get first element of output line
                        vuln = output_line.split(" ")[0]

                        if cve:
                            cve = cve.group("cve")
                        else:
                            # strip vuln from color
                            vuln = re.sub(r'\x1b[^m]*m', '', vuln)
                            # strip vuln from [
                            vuln = vuln.split("[")[1]
                            # strip vuln from ]
                            vuln = vuln.split("]")[0]

                        vuln2 = vuln
                        before = "Vulnerability found"
                        # if the output line ends with a something inbetween []
                        # get last part of output line
                        last = output_line.split(" ")[-1]
                        # remove enters or spaces at the end
                        last = last.strip()
                        # if last part of output line starts with [
                        if last.endswith("]"):
                            before = vuln 
                            # strip last from color
                            last = re.sub(r'\x1b[^m]*m', '', last)
                            # strip last from ]
                            last = last.split("]")[0]
                            # replace vuln with last
                            vuln2 = vuln
                            vuln = last

                        exploit = False
                        epss = 0.0

                        if cve:
                            before = "CVE match found"
                            # cut off at first :
                            cve = cve.split(":")[0]
                            # cut off at first ]
                            cve = cve.split("]")[0]
                            # remove colors from cve
                            cve = re.sub(r'\x1b[^m]*m', '', cve)
                            cve_number = cve
                        else:
                            cve_number = None
                        
                        # if unknown
                        category = ""
                        category2 = ""
                        
                        if "unknown" in output_line:
                            category = "low"
                            category2 = "unknown"
                        elif "low" in output_line:
                            category = "low"
                            category2 = "low"
                        elif "medium" in output_line:
                            category = "medium"
                            category2 = "medium"
                        elif "high" in output_line:
                            category = "high"
                            category2 = "high"
                        elif "critical" in output_line:
                            category = "critical"
                            category2 = "critical"

                        finding_object = Vulnerability(vuln, url, "nuclei", 97, category, host=domain, cve_number=cve_number, epss=epss_percentile)

                        #? add to database
                        print(f"  {Fore.GREEN}[+] Adding to database: {finding_object}{Style.RESET_ALL}")
                        insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)
            
            # Complete the progress bar
            pbar.update(100 - prev_progress)
        
        vuln_count = len(vulnerabilities_found)
        print(f"\n{Fore.GREEN}[+] Nuclei scan completed! Found {Fore.CYAN}{vuln_count}{Fore.GREEN} vulnerabilities{Style.RESET_ALL}")

    #? Run the nuclei flow
    def run(self) -> None:     
        """
        Start the Nuclei scan in a separate thread.
        
        Creates and starts a new thread to execute the Nuclei scan
        asynchronously, allowing the main program to continue.
        """
        print(f"{Fore.CYAN}[*] Launching Nuclei scanner in background thread{Style.RESET_ALL}")
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()
        print(f"{Fore.GREEN}[+] Nuclei scanner thread started{Style.RESET_ALL}")

class nuclei_wordpress():
    """
    Specialized Nuclei scanner for WordPress vulnerabilities.
    
    Provides methods to scan WordPress installations for known
    vulnerabilities using specialized Nuclei templates.
    
    Attributes:
        domains (str): WordPress domains to scan
        org_name (str): Organization name for database storage
    """
    def __init__(self, domains: str, org_name: str):
        self.domains = domains
        self.org_name = org_name

    def remove_ansi_codes(self, s):
        """
        Remove ANSI color codes from strings.
        
        Args:
            s (str): String that may contain ANSI codes
            
        Returns:
            str: Clean string without ANSI codes
        """
        # This regex matches ANSI escape sequences
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', s)

    def find_first_path_with_nuclei(self, pattern):
        """
        Find a Nuclei template file based on a hash pattern.
        
        Args:
            pattern (str): Template hash to search for
            
        Returns:
            str: Path to the template file, or None if not found
        """
        # Build the find command
        command = ['find', '/', '-name', f'*{pattern}*']
        # Run the command; stderr is suppressed to mimic 2>/dev/null
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        print(f"Result: {result}")
        # Split the output by newline to get a list of paths
        paths = result.stdout.strip().split('\n') if result.stdout else []
        # Iterate over paths and return the first one containing "nuclei"
        for path in paths:
            if "nuclei" in path:
                return path
        return None

    def scan_nuclei(self) -> None:
        """
        Execute WordPress-specific Nuclei scan and process results.
        
        Runs Nuclei against WordPress domains, using template information
        to extract detailed vulnerability data.
        """
        keywords = ["unknown", "low", "medium", "high", "critical"]
        #nuclei_command = f"nuclei -l domains.txt -s low,medium,high,critical,unknown -et github -bs 400 -rl 4000"
        print(f"[+] Running Nuclei wordpress")
        
        nuclei_command = f"nuclei -u \"{self.domains}\" -s low,medium,high,critical,unknown -t github -bs 400 -rl 4000"
        print(nuclei_command)
        process = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)  
        while True:  
            output_line = process.stdout.readline()  
            if not output_line and process.poll() is not None:  
                break  

            if output_line:     
                if any(keyword in output_line for keyword in keywords):  
                    print(f"Output Line: {output_line}")
                    # extract url with regex
                    url = ""
                    try:
                        url = re.search(r"(?P<url>https?://[^\s]+)", output_line).group("url")
                    except:
                        try:
                            url = re.search(r"(?P<url>http?://[^\s]+)", output_line).group("url")
                            #.group("url")
                        except:
                            #find it port based by x:443 or x:80
                            url = re.search(r"(?P<url>[^\s]+:[0-9]+)", output_line).group("url")
                            # cut off port
                            url = url.split(":")[0]

                    domain = url 
                    # replace https:// http:// www.
                    domain = domain.replace("https://", "")
                    domain = domain.replace("http://", "")
                    domain = domain.replace("www.", "")

                    epss_percentile = None  

                    # if has / in it, stop at /
                    if "/" in domain:
                        domain = domain.split("/")[0]

                    # get first element of output line
                    vuln = output_line.split(" ")[0]
                    print(f"Raw vuln: {vuln}")

                    template_hash_value = vuln.rstrip(']').lstrip('[').split('-')[-1].split(':')[0]
                    template_hash_value = self.remove_ansi_codes(template_hash_value)
                    formatted_vuln = vuln.replace(f"-{template_hash_value}", '').strip('[').strip(']')
                    formatted_vuln = self.remove_ansi_codes(formatted_vuln).split(':')[0]
                    print(f"Formatted vuln: {formatted_vuln}")
                   
                    #? Grep extra data from the template hash
                    print(f"Template hash: {template_hash_value}")
                    template_path = self.find_first_path_with_nuclei(template_hash_value)
                    print(f"Template path: {template_path}")
                    if template_path is not None:
                        template_dataframe = yaml.safe_load(open(template_path, 'r'))
                        references = template_dataframe['info']['reference']
                        vuln_title = template_dataframe['info']['name']
                        severity = template_dataframe['info']['severity']
                    
                    if 'CVE' in formatted_vuln or 'cve' in formatted_vuln:
                        cve_number = formatted_vuln
                    else:
                        cve_number = None

                    print(f"Vuln: {vuln_title}")
                    finding_object = Vulnerability(vuln_title, url, "nuclei_wordpress", 97, severity, host=domain, cve_number=cve_number, references=references, poc=url)

                    #? add to database
                    print(f"[+] Adding to database:\n{finding_object}")
                    insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)

    #? Run the nuclei flow
    def run(self) -> None:     
        """
        Start the WordPress Nuclei scan in a separate thread.
        
        Creates and starts a new thread to execute the scan asynchronously.
        """
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()


class nuclie_network():
    """
    Placeholder for network-based Nuclei scanning functionality.
    
    Note: This class appears to be incomplete or under development.
    """
    def __init__(self, worker):
        self.worker = worker

