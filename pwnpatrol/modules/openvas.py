import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
import requests
import json
import time
import netaddr

class openvas():
    #? Initialize the class
    def __init__(self, worker, targets):
        self.worker = worker
        self.queue_reportIDs = []
        self.queue_scan_names = []
        self.queue_report_location = []
        self.ips = targets
        self.username = 'admin'
        self.password = 'admin'
        self.scan_name = ""
        self.command_prefix = '' 
        self.alive_test = 'ICMP, TCP-ACK Service &amp; ARP Ping'
        self.scanConfigID = "daba56c8-73ec-11df-a475-002264764cea" # Full and very deep ultimate
        self.formatID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        
    #? Gets the report from the openvas container
    def get_report(self, reportID, report_location):
        #print(f"Fetching report for report ID: {reportID}")
        command = subprocess.getoutput(f'{self.command_prefix} "<get_reports report_id=\'{reportID}\' filter=\'apply_overrides=0 levels=hml min_qod=50 first=1 rows=1000 sort=name ignore_pagination=1\' details=\'1\' format_id=\'{self.formatID}\'/>" ')
        
        response = requests.post('http://automatic-propagation-gvmd-1:5000/create_target', json={'command': command})
        report_data = response.json()['message']
        #print(f"Fetched report data:\n {fetchReport}")
        with open(report_location, 'w') as f:
            f.write(report_data)

    #? Create Target
    def create_target(self): 
        self.report_location = f"/tmp/report_openvas_{datetime.now().strftime('%Y%m%d%H%M%S')}.xml"
        self.scan_name = f"Darkstar-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.queue_scan_names.append(self.scan_name)
        self.queue_report_location.append(self.report_location)   
        command = subprocess.getoutput(f'{self.command_prefix} "<CREATE_TARGET><name>{self.scan_name}</name><hosts>{self.ip}</hosts><alive_tests>{self.alive_test}</alive_tests><port_range>1-65535</port_range></CREATE_TARGET>"')

        #? request to the openvas container running on port 5000
        response = requests.post('http://automatic-propagation-gvmd-1:5000/create_target', json={'command': command})
        self.targetID = response.json()['message']
        
        #print(f"Target ID: {self.targetID}")

    #? Create Task
    def create_task(self):
        command = subprocess.getoutput(f'{self.command_prefix} \'<CREATE_TASK><name>{self.scan_name}</name><Comment>Openvas Scan on {self.ip}</Comment><target id=\"{self.targetID}\"/><config id=\"{self.scanConfigID}\"/></CREATE_TASK>\'')
        
        #? request to the openvas container running on port 5000
        response = requests.post('http://automatic-propagation-gvmd-1:5000/create_task', json={'command': command})
        
        self.taskID = response.json()['message']
        #print(f"Task ID: {self.taskID}")

    #? Run Task
    def run_task(self):
        command = subprocess.getoutput(f'{self.command_prefix} \'<start_task task_id=\"{self.taskID}\"/>\'')
        
        response = requests.post('http://automatic-propagation-gvmd-1:5000/run_task', json={'command': command})    
        
        self.reportID = response.json()['message']
        #print(f"Report ID: {self.reportID}")
        self.queue_reportIDs.append(self.reportID)

    #? Wait for Scan
    def check_if_finished(self) -> bool:
        for scan in self.queue_scan_names:
            command_isRunningTask = subprocess.getoutput(f'{self.command_prefix} "<get_reports report_id=\'{self.reportID}\' format_id=\'{self.formatID}\'/>" | xml2 | grep \'progress\' | cut -d \'=\' -f2')
            isRunningTask = requests.post('http://automatic-propagation-gvmd-1:5000/check_if_finished', json={'command': command_isRunningTask})
            
            command_isCompletedTask = subprocess.getoutput(f'{self.command_prefix} "<get_reports report_id=\'{self.reportID}\' format_id=\'{self.formatID}\'/>" | xml2 | grep \'scan_run_status\' | cut -d \'=\' -f2')
            isCompletedTask = requests.post('http://automatic-propagation-gvmd-1:5000/check_if_finished', json={'command': command_isCompletedTask})
            
            if isCompletedTask == 'Done':
                return True, scan
            elif isCompletedTask == 'Running':   
                print(f"Openvas\U0001F33F -> Running: {isRunningTask}%")
                    
        return False, ""

    #? Wait for the scans to finish uses the queue
    def wait_for_scan(self):
        while len(self.queue_scan_names) > 0:
            for idx, scan in enumerate(self.queue_scan_names):
                done, scan = self.check_if_finished()
                if done:
                    self.get_report(reportID=self.queue_reportIDs[idx], report_location=self.queue_report_location[idx])
                    self.process_findings(report_location=self.queue_report_location[idx])
                    self.queue_reportIDs.remove(self.queue_reportIDs[idx])
                    self.queue_scan_names.remove(scan)
                    self.queue_report_location.remove(self.queue_report_location[idx])
                else:
                    #? Sleep 2 minutes
                    time.sleep(60)

    #? Convert the XML to findings
    def process_findings(self, report_location) -> bool:
        # xml
        print(f"Processing findings for report: {report_location}")

        tree = ET.parse(report_location)

        root = tree.getroot()  
        
        # Iterate through each 'result' element in the XML  
        count = 0
        for result in root.findall('.//result'):  
            # Extract the 'id' attribute from the 'result' element  
            result_id = result.get('id')
            
            try: 
                name = result.find('name').text
            except:
                continue
        

            # if name contains httpOnly, Certificate Expired, Weak Encryption, Missing `secure`, VNC Server Unencrypted continue
            if "httpOnly" in name or "Certificate Expired" in name or "Weak Encryption" in name or "Missing `secure`" in name or "VNC Server Unencrypted" in name or "Weak Cipher" in name or "Vulnerable Cipher" in name:
                continue

            # count = count + 1
            # if count > 10:
            #     continue

            # get nvt, then get family, cve, xref, tags
            nvt = result.find('nvt')
            family = nvt.find('family').text
            try:
                cve = nvt.find('cve').text #Might be NOCVE
            except:
                cve = "NOCVE"
            exploit = False
            epss = 0.0

            port = result.find('port').text
            threat = result.find('threat').text
            severity = result.find('severity').text
            poc2 = result.find('description').text
            endsolution = ""

            cve_object = None
            # if not NOCVE
            if cve != "NOCVE":
                response2 = requests.get(f"https://api.first.org/data/v1/epss?cve={str(cve)}")
                if response2.status_code == 200:
                    exploitability = ""
                    epss = response2.json()
                    # {"status":"OK","status-code":200,"version":"1.0","access":"public","total":1,"offset":0,"limit":100,"data":[{"cve":"CVE-2022-27225","epss":"0.001500000","percentile":"0.510960000","date":"2024-01-03"}]}
                    epss = epss.get("data", None)
                    if epss:
                        epss = epss[0].get("percentile", None)
                        if epss:
                            exploitability = str(epss)
                            if float(epss) >= 0.65:
                                exploit = True

                response = requests.get(f"https://cve.circl.lu/api/cve/{cve}")
                if response.status_code == 200 and response.json():
                    cvss = response.json().get("cvss", None)
                    
                    # get CVE details
                    cwe = response.json().get("cwe", None)
                    references = response.json().get("references", None)
                    summary = response.json().get("summary", None)
                    cveid = response.json().get("id", None)

                    # Get optional cve fields (solution, capec)
                    solution2 = response.json().get("solution", None)
                    endsolution = solution2
                    impact = response.json().get("impact", None)
                    access = response.json().get("access", None)

                    #TODO: add all capec
                    published = response.json().get("Published", None)
                    # cvss vector
                    cvssvector = response.json().get("cvss-vector", None)
                    # references
                    references = response.json().get("references", None)
                    
                    # check if CVE is in known_exploited_vulnerabilities.json
                    cisakev = False
                    with open('known_exploited_vulnerabilities.json') as f:
                        data = json.load(f)
                        if cveid in data:
                            cisakev = True


                    # get capec ids + names
                    capec = []
                    capecmain = response.json().get("capec", None)

            
                    if epss:
                        cve_object = self.worker.CVE(cveid, severity, summary, cwe, references, epss, capec, solution2, impact, access)
                        pass
                    else:
                        cve_object = self.worker.CVE(cveid, severity, summary, cwe, references, None, capec, solution2, impact, access)
                        pass
                    cvssvector = str(cvssvector)
                    published = str(published)
                    
                    cve_object.add_extras(cvssvector, published, cisakev)
            try:
                xref = nvt.find('xref').text
            except:
                xref = "NOXREF"
            tags = nvt.find('tags').text
            # check for cvss_base_vector and solution in tags
            cvss_base_vector = ""
            solution = ""
            if "cvss_base_vector" in tags:
                cvss_base_vector = tags.split("cvss_base_vector=")[1].split("|")[0]
            if "solution=" in tags:
                solution = tags.split("solution=")[1].split("|")[0]

            # host and qod
            host = result.find('host')
            qod = result.find('qod')

            # now get host
            host_ip = host.text
            
            # get qod value and type
            qod_value = qod.find('value').text
            qod_type = qod.find('type').text

            # Create finding, add to finding list
            if epss != 0.0 and epss != []:
                self.worker.print_finding("OpenVAS", host_ip, threat, "Network Vuln", name, confidence=str(qod_value), exploitable=exploit, epss=float(epss))
            else:
                self.worker.print_finding("OpenVAS", host_ip, threat, "Network Vuln", name, confidence=str(qod_value))

            if cve != "NOCVE":
                finding = self.worker.Finding(name, host_ip, "OpenVAS", int(qod_value), threat, cve=cve_object, ports=port, poc=poc2, title=name, solution=endsolution, description=poc2, cvss=severity)
                self.worker.findings_list.add_finding(finding)
            else:
                finding = self.worker.Finding(name, host_ip, "OpenVAS", int(qod_value), threat, ports=port, poc=poc2, title=name, solution=endsolution, description=poc2, cvss=severity)
                self.worker.findings_list.add_finding(finding)

    #? Split CIDR if subnet range > /20, limitations of openvas argghhh...
    def split_cidr(self, cidr):
        net = netaddr.IPNetwork(cidr)
        if net.prefixlen < 20:
            return [str(subnet) for subnet in net.subnet(20)]
        else:
            return [str(net)]

    #? Openvas execution flow
    def run(self):
        self.command_prefix = f'gosu gvmd gvm-cli --gmp-username {self.username} --gmp-password \'{self.password}\'  socket --socketpath /run/gvmd/gvmd.sock --xml'
        #? ip range/ip -> split_cidr 
        target_list = []
        #? String to list
        if type(self.ips) == str:
            # convert to list
            ip_list = self.ips.split(' ')
            #? Check if the CIDR is not greater than /20 because of openvas limitations
            for ip in ip_list:
                if '/' not in ip:
                    target_list.append(ip)
                else:
                    target_list.extend(self.split_cidr(ip))
        
        else:
            #? Check if the CIDR is not greater than /20 because of openvas limitations
            for ip in self.ips:
                if '/' not in ip:
                    target_list.append(ip)
                else:
                    target_list.extend(self.split_cidr(ip))

        #? Loop through the target list and run the openvas scan for each IP/CIDR
        for target in target_list:
            self.ip = target
            self.create_target()
            self.create_task()
            self.run_task()
        
        #? Wait for the scan to finish
        threading.Thread(target=self.wait_for_scan).start()