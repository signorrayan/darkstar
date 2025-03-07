import subprocess
import requests
import pandas as pd
import datetime

"""
Vulnerability data models for the Darkstar framework.

This module provides classes to represent vulnerabilities and CVEs,
with functionality to enrich vulnerability data from external sources.
"""

class CVE:
    """
    Representation of a Common Vulnerabilities and Exposures (CVE) entry.
    
    Stores comprehensive information about a CVE, including scores,
    descriptions, related weaknesses, and exploitation data.
    
    Attributes:
        cve (str): CVE identifier (e.g., CVE-2021-12345)
        cvss (float): Common Vulnerability Scoring System score
        epss (float): Exploit Prediction Scoring System score
        summary (str): Description of the vulnerability
        cwe (str): Common Weakness Enumeration identifier
        references (list): References to documentation and advisories
        capec (str): Common Attack Pattern Enumeration and Classification
        solution (str): Remediation guidance
        impact (dict): Impact information
        access (dict): Access vector information
        age (int): Age of the CVE in days
        pocs (list): Proof of Concept references
        kev (bool): Known Exploited Vulnerability status
    """
    
    def __init__(self, cve, cvss=None, summary=None, cwe=None, references=None, epss=None, capec=None, solution=None, impact=None, access=None, age=None, pocs=None, kev=None):  
        self.cve = cve  
        self.cvss = cvss  
        self.epss = epss  
        self.summary = summary   
        self.cwe = cwe  
        self.references = references  
        self.capec = capec
        self.solution = solution
        self.impact = impact 
        self.access = access
        self.age = age
        self.pocs = pocs
        self.kev = kev

    @staticmethod
    def search_epss_by_cve(cve: str) -> float:
        """
        Search for the EPSS score of a CVE.
        
        Args:
            cve (str): CVE identifier to search for
            
        Returns:
            float: EPSS score or 'Unknown' if not found
        """
        command = ["c_scripts/search_epss", 'datasets/epss_scores-current.csv', cve]
        result = subprocess.run(command, capture_output=True, text=True)
        try:
            return float(result.stdout)
        except:
            return 'Unknown'

    def __str__(self):
        """
        String representation of the CVE.
        
        Returns:
            str: Formatted string with CVE information
        """
        return f"{self.cve} | {self.cvss} | {self.epss} | {self.summary} | {self.cwe} | {self.references} | {self.capec} | {self.solution} | {self.impact} | {self.access} | {self.age} | {self.pocs} | {self.kev}"

class Vulnerability():
    """
    Representation of a security vulnerability.
    
    Can represent both CVE-based and non-CVE vulnerabilities with
    comprehensive information about the finding.
    
    Attributes:
        title (str): Vulnerability title
        affected_item (str): Affected URL, file, or component
        tool (str): Scanner or tool that found the vulnerability
        confidence (int): Confidence score (0-100)
        severity (str): Severity rating (e.g., critical, high, medium)
        host (str): Hostname or IP where the vulnerability was found
        cve (CVE): Associated CVE object if applicable
        summary (str): Description of the vulnerability
        impact (str): Potential impact of exploitation
        solution (str): Remediation guidance
        poc (str): Proof of concept or demonstration
        references (list): References to documentation and advisories
        epss (float): Exploit Prediction Scoring System score
        cvss (float): Common Vulnerability Scoring System score
        cwe (str): Common Weakness Enumeration identifier
        capec (str): Common Attack Pattern Enumeration and Classification
    """
    
    def __init__(self, title, affected_item, tool, confidence, severity, host,
                 cve_number="", summary="", impact="", solution="", poc="",
                 references="", epss=None, cvss=None, cwe="", capec=""):
        self.title = title
        self.affected_item = affected_item
        self.tool = tool
        self.confidence = confidence
        self.severity = severity
        self.host = host

        # Use truthiness to decide whether to attempt CVE enrichment.
        if cve_number:  # This evaluates to False for an empty string.
            enriched = self.cve_enricher(cve_number)
            if enriched:
                self.cve = enriched
            else:
                # Optionally, you can set non-CVE attributes here as well
                self.summary = summary
                self.impact = impact
                self.solution = solution
                self.poc = poc
                self.references = references
                self.epss = epss
                self.cvss = cvss
                self.cwe = cwe
                self.capec = capec
        else:
            # No valid CVE provided: assign non-CVE attributes.
            self.summary = summary
            self.impact = impact
            self.solution = solution
            self.poc = poc
            self.references = references
            self.epss = epss
            self.cvss = cvss
            self.cwe = cwe
            self.capec = capec

    def cve_enricher(self, cve_number: str) -> CVE:
        """
        Enrich a vulnerability with CVE data from external sources.
        
        Fetches detailed information about a CVE from multiple sources
        and creates a comprehensive CVE object.
        
        Args:
            cve_number (str): CVE identifier to enrich
            
        Returns:
            CVE: Enriched CVE object or None if not found
        """
        #? Get the epss score for the cve
        epss_percentile = CVE.search_epss_by_cve(cve_number)

        #? Check CISA kev
        kev = False
        cisa_kev_data = pd.read_csv("datasets/known_exploited_vulnerabilities.csv")
        if cve_number in cisa_kev_data['cveID'].values:
            kev = True
        
        #? Get more cve data about the CVE
        response = requests.get(f"https://cve.circl.lu/api/cve/{cve_number}")
        if response.status_code == 200 and response.json():
            #? Extract data from the response
            solution = response.json().get("solution", None)
            impact = response.json().get("impact", None)
            access = response.json().get("access", None)
            references = response.json().get("references", None)
            age_in_days = response.json().get("Published", None)
            cvss = response.json().get("cvss", None)
            cwe = response.json().get("cwe", None)
            capec = response.json().get("capec", None)
            summary = response.json().get("summary", None)
            
            #? Calculate the age of the CVE
            if age_in_days is not None:
                age_in_days = (datetime.datetime.now() - datetime.datetime.strptime(age_in_days, "%Y-%m-%dT%H:%M:%S")).days
            
            #? Create a CVE object
            cve_object = CVE(cve=cve_number, cvss=cvss, epss=epss_percentile, summary=summary, cwe=cwe, references=references, capec=capec, solution=solution, impact=impact, access=access, age=age_in_days, pocs=None, kev=kev)
            return cve_object
        else:
            return None
