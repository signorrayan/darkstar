from modules.db_helper import *
from modules.config import fruit_juice
from modules.vulns import Vulnerability, CVE
import pandas as pd
import os
import subprocess
import base64 
from colorama import Fore, Style, init
import hashlib
import threading
import re


fruit_juice = base64.b64decode(fruit_juice).decode("utf-8")

class bbot():
    def __init__(self, target: str):
        self.target = target
        self.folder = f"/home/joost/AttackSurface/release_1.0/bbot_output"
        self.foldername = hashlib.md5(os.urandom(10)).hexdigest()

        #? Create a directory for bbot output if not exists
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)

    def prep_data(self) -> pd.DataFrame:
        if os.path.exists(f"{self.folder}/{self.foldername}/output.csv"):
            #? write to DB
            df = pd.read_csv(f"{self.folder}/{self.foldername}/output.csv")
            
            #? Replace NaN with None
            df = df.where(pd.notnull(df), None)
            return df    
        else:
            print(f"{Fore.RED}[-] No output file found, Something went wrong with bbot scan{Style.RESET_ALL}")
            return pd.DataFrame()

    def passive(self) -> None:
        print(f"{Fore.GREEN}[+] Scanning {self.target} with passive bbot{Style.RESET_ALL}")

        command = ["sudo", "-S", "/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum", "-o", self.folder, "-n", self.foldername, "-y"]
        
        #? Run bbots with passive settings
        process = subprocess.run(command, input=fruit_juice + "\n", capture_output=True, text=True)

        #? Change permissions of the folder
        command = ["sudo", "-S", "chown", "-R", "joost:joost", f"{self.folder}/{self.foldername}"]
        process = subprocess.run(command, input=fruit_juice + "\n", capture_output=True, text=True)

        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv intot the database
        insert_bbot_to_db(self.prep_data())

    def aggressive(self) -> None:
        print(f"{Fore.GREEN}[+] Scanning {self.target} with aggressive bbot{Style.RESET_ALL}")

        command = ["sudo", "-S", "/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,active,deadly,aggressive,web-thorough,subdomain-enum,cloud-enum,code-enum,affiliates", "-m", "nuclei,baddns,baddns_zone,dotnetnuke,ffuf", "--allow-deadly", "-o", self.folder, "-n", self.foldername, "-y"]

        #? Run bbot with aggressive settings
        process = subprocess.run(command, input=fruit_juice + "\n", capture_output=True, text=True)

        command = ["sudo", "-S", "chown", "-R", "joost:joost", f"{self.folder}/{self.foldername}"]
        process = subprocess.run(command, input=fruit_juice + "\n", capture_output=True, text=True)
        
        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv into the database
        insert_bbot_to_db(self.prep_data())


class nuclei():
    def __init__(self, filename: str):
        self.file = filename

    def scan_nuclei(self) -> None:
        keywords = ["unknown", "low", "medium", "high", "critical"]
        #nuclei_command = f"nuclei -l domains.txt -s low,medium,high,critical,unknown -et github -bs 400 -rl 4000"
        nuclei_command = f"nuclei -l {self.file} -s low,medium,high,critical,unknown -et github -bs 400 -rl 1000"
        
        process = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)  
        while True:  
            output_line = process.stdout.readline()  
            if not output_line and process.poll() is not None:  
                break  

            if output_line:     
                if any(keyword in output_line for keyword in keywords):  
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

                    # extract cve with regex
                    cve = re.search(r"(?P<cve>CVE-[^\s]+)", output_line)
                    #print(cve)

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
                    insert_vulnerability_to_database(finding_object)

    #? Run the nuclei flow
    def run(self) -> None:     
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()

class nuclie_network():
    def __init__(self, worker):
        self.worker = worker
    
