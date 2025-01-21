import os
import requests
from datetime import datetime, timezone
from dataclasses import dataclass, field
import re
import subprocess
import mysql.connector
from typing import List
from collections import defaultdict
from config import db_config, CLIENT_ID, CLIENT_SECRET, TENANT_ID


class Vulnerability:
    def __init__(self, title: str, description: str, severity: int, score: int, found_date: str, remediation: str):
        self.title = title
        self.description = description
        self.severity = severity
        self.score = score
        self.found_date = found_date
        self.remediation = remediation
        self.affected_devices: List[str] = []
        self.count: int = 0

# Fetch environment variables

# OAuth 2.0 Token endpoint
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

# Graph API endpoint to fetch devices
#GRAPH_API_URL = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
GRAPH_API_URL = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"

def get_unencrypted_devices_vulnerability(devices):
    unencrypted_devices = [device for device in devices if not device.get('isEncrypted', False)]

    if not unencrypted_devices:
        return []

    current_date = datetime.now(timezone.utc)  # Updated for timezone-aware UTC datetime
    title = "Unencrypted Devices"
    description = "These devices are not encrypted, which could pose a significant security risk, especially if they contain sensitive information."
    severity = 3  # high
    score = 8  # High impact due to the security risk of unencrypted devices

    # Create vulnerability instance for unencrypted devices
    vulnerability = Vulnerability(
        title=title,
        description=description,
        severity=severity,
        score=score,
        found_date=str(current_date.date()),
        remediation="Investigate and ensure all affected devices are encrypted to prevent unauthorized access."
    )
    vulnerability.affected_devices = [device.get("deviceName", "Unknown Device") for device in unencrypted_devices]
    vulnerability.count = len(unencrypted_devices)

    return [vulnerability]


def categorize_devices_by_last_sync(devices):
    current_date = datetime.now(timezone.utc)  # Updated for timezone-aware UTC datetime

  # Validate input
    if not isinstance(devices, list) or not all(isinstance(device, dict) for device in devices):
        raise ValueError("Invalid input: 'devices' must be a list of dictionaries.")


    categories = {
        "1_month": {"title": "Not synced for 1 month", "severity": 1, "score": 2, "devices": []},
        "2_4_months": {"title": "Not synced for 2-4 months", "severity": 1, "score": 3, "devices": []},
        "5_6_months": {"title": "Not synced for 5-6 months", "severity": 2, "score": 4, "devices": []},
        "7_12_months": {"title": "Not synced for 7-12 months", "severity": 2, "score": 5, "devices": []},
        "1_year": {"title": "Not synced for 1+ year", "severity": 2, "score": 6, "devices": []},
        "2_years": {"title": "Not synced for 2+ years", "severity": 2, "score": 6, "devices": []},
        "3_years": {"title": "Not synced for 3+ years", "severity": 3, "score": 7, "devices": []},
    }

    for device in devices:
        last_sync_str = device.get('lastSyncDateTime')
        if not last_sync_str:
            continue

        try:
            # Convert ISO datetime string to a datetime object
            last_sync_date = datetime.fromisoformat(last_sync_str.replace("Z", "+00:00"))
        except ValueError as e:
            print(f"Error parsing date for device {device.get('deviceName', 'Unknown')}: {e}")
            continue

        days_diff = (current_date - last_sync_date).days

        # Categorize based on days since last sync
        if days_diff <= 30:
            continue
        elif 31 <= days_diff <= 120:
            categories["2_4_months"]["devices"].append(device)
        elif 121 <= days_diff <= 180:
            categories["5_6_months"]["devices"].append(device)
        elif 181 <= days_diff <= 365:
            categories["7_12_months"]["devices"].append(device)
        elif 366 <= days_diff <= 730:
            categories["1_year"]["devices"].append(device)
        elif 731 <= days_diff <= 1095:
            categories["2_years"]["devices"].append(device)
        elif days_diff > 1095:
            categories["3_years"]["devices"].append(device)

    vulnerabilities = []
    for key, data in categories.items():
        if data["devices"]:
            vulnerability = Vulnerability(
                title=data["title"],
                description=f"Devices in this category have not synced for {data['title'].lower()}. This could indicate potential issues with management or inactivity.",
                severity=data["severity"],
                score=data["score"],
                found_date=str(current_date.date()),
                remediation="Investigate and ensure the affected devices are actively managed and connected to the network."
            )
            vulnerability.affected_devices = [d.get("deviceName", "Unknown Device") for d in data["devices"]]
            vulnerability.count = len(data["devices"])

            vulnerabilities.append(vulnerability)

    return vulnerabilities

# NVD API endpoint for CVEs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cves_for_windows_version(os_version):
    """
    Given a Windows OS version, retrieve related CVEs.

    :param os_version: The operating system version to check (e.g., "10.0.19045.5132").
    :return: A list of CVEs related to the OS version in the format:
             [[CVE, description, severity, score], [CVE, description, severity, score], ...]
    """
    # Step 1: Parse the OS version
    version_pattern = re.compile(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$')
    match = version_pattern.match(os_version)
    if not match:
        raise ValueError("Invalid os_version format. Expected format like '10.0.19045.5132'.")

    major, minor, build, revision = match.groups()

    # Step 2: Map build numbers to Windows editions
    # This mapping may need to be expanded based on the range of Windows versions you intend to support
    build_to_edition = {
        "19044": "21h2",        # Windows 10 21H2
        "19045": "22h2",        # Windows 10 22H2
        "22621": "22h2", # Windows 11 2022 Update
        "22000": "21h2",        # Windows 11 initial release
        "22361": "23h2",        # Windows 11 22H2
        "26100": "24h2", # Windows 11 2022 Update
    }

    edition = build_to_edition.get(build, "*")  # Use '*' as a wildcard if build is unknown


    # Step 3: Determine the product name based on the major version
    if major == "10":
        product = "windows_10"
    elif major == "11":
        product = "windows_11"
    else:
        product = "windows_unknown"

    # Step 4: Generate the CPE string
    cpe = f"cpe:2.3:o:microsoft:{product}_{edition}:{os_version}:*:*:*:*:*:*:*"

    # Debug: Print the generated CPE
    print(f"Generated CPE: {cpe}")

    # Step 5: Execute the search_vulns.py script to retrieve CVEs
    # Expand the ~ in the path
    script_path = os.path.expanduser("~/Documents/search_vulns/search_vulns.py")

    command = [
        "python3",
        script_path,
        "-q",
        cpe,
        "--ignore-general-cpe-vulns"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running search_vulns.py: {e.stderr}")
        output = []

    # Step 6: Parse the output to extract CVE details
    cves = []
    current_date = datetime.now(timezone.utc)  # Updated for timezone-aware UTC datetime

    for line in output.splitlines():
        line = line.strip()


        if not line:
            continue  # Skip empty lines

        # remove colors
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)

        #print(line)
        # match with CVE regex patern (only CVE-xxxx-xxxx or CVE-xxxx-xxxxx)
        cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,5})')
        match = cve_pattern.match(line)
        remediation = "Update to the latest version of the Windows operating system to address this vulnerability."
        if match:
            cve_id = match.group(1)

            # try to match with /10.0 or /8.8 etc
            score_pattern = re.compile(r'\/(\d{1,2}\.\d)')
            match = score_pattern.search(line)
            cvss = match.group(1)

            # everything after the : of the line is the title
            title_pattern = re.compile(r':(.*)')
            match = title_pattern.search(line)
            description = match.group(1)

            # description can be big, title is first line
            title = description.split('.')
            title = title[0]

            # define severity based on score
            if float(cvss) <= 3.9:
                severity = 1
            elif float(cvss) <= 6.9:
                severity = 2
            elif float(cvss) <= 8.9:
                severity = 3
            else:
                severity = 4

            vulnerability = Vulnerability(
                title=cve_id,
                description=description,
                severity=severity,
                score=cvss,
                found_date=str(current_date.date()),
                remediation=remediation
            )
            cves.append(vulnerability)

        # match = cve_pattern.match(line)
        # if match:
        #     cve_id = match.group(1)
        #     try:
        #         score = float(match.group(2))
        #     except ValueError:
        #         score = None  # Handle cases where the score isn't a valid float
        #     description = match.group(3)

        #     # Determine severity based on CVSS score
        #     if score is not None:
        #         if score <= 3.9:
        #             severity = "Low"
        #         elif score <= 6.9:
        #             severity = "Medium"
        #         elif score <= 8.9:
        #             severity = "High"
        #         else:
        #             severity = "Critical"
        #     else:
        #         severity = "Unknown"

        #     print(f"Found CVE: {cve_id} - {description} (Severity: {severity}, Score: {score if score is not None else 'N/A'})")
        #     cves.append([cve_id, description, severity, score if score is not None else "N/A"])

    return cves

def write_vulnerability_to_db(vuln: Vulnerability):
    try:
        # Establish database connection
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Check if a record with the same title already exists
        check_query = "SELECT COUNT(*) FROM intune_vulnerabilities WHERE title = %s"
        cursor.execute(check_query, (vuln.title,))
        result = cursor.fetchone()

        if result[0] > 0:
            # Update the existing record
            update_query = """
                UPDATE intune_vulnerabilities
                SET description = %s, severity = %s, score = %s, foundDate = %s, 
                    affectedDevices = %s, remediation = %s, count = %s
                WHERE title = %s
            """
            data = (vuln.description, vuln.severity, vuln.score, vuln.found_date, 
                    ', '.join(vuln.affected_devices), vuln.remediation, vuln.count, vuln.title)
            cursor.execute(update_query, data)
            print(f"Vulnerability {vuln.title} updated in the database.")
        else:
            # Insert a new record
            insert_query = """
                INSERT INTO intune_vulnerabilities (title, description, severity, score, foundDate, 
                                             affectedDevices, remediation, count)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            data = (vuln.title, vuln.description, vuln.severity, vuln.score, vuln.found_date, 
                    ', '.join(vuln.affected_devices), vuln.remediation, vuln.count)
            cursor.execute(insert_query, data)
            print(f"Vulnerability {vuln.title} inserted into the database.")

        # Commit the transaction
        conn.commit()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def check_device_for_vulnerabilities(devices):

    devices_by_os = defaultdict(list)
    allvulns = []

    # idea group all devices by os version
    for device in devices:
        os_version = device.get('osVersion')
        if not os_version:
            print(f"No OS version specified for device {device.get('deviceName', 'Unknown Device')}.")
            continue
        devices_by_os[os_version].append(device)
    
    for os_version, devices in devices_by_os.items():
        print(f"Checking for vulnerabilities on(OS Version: {os_version})...")

        try:
            vulnerabilities = get_cves_for_windows_version(os_version)
            # calculate count
            count = len(devices)
            devicelist = []
            for device in devices:
                devicelist.append(device.get('deviceName'))
        
            # create list of devices, by taking only deviceName
            for vuln in vulnerabilities:
                vuln.count = count
                vuln.affected_devices = devicelist
                allvulns.append(vuln)

        except ValueError as e:
            print(f"Error checking for vulnerabilities on OS version {os_version}: {e}")
        

    return allvulns
            



    # if isinstance(vulnerabilities, str):  # Error message, no CVEs found
    #     print(vulnerabilities)
    # else:
    #     print(f"Vulnerabilities found for {device.get('deviceName', 'Unknown Device')} (OS Version: {os_version}):")
    #     for vuln in vulnerabilities:
    #         print(f"CVE: {vuln['cve']} - {vuln['description']} (Severity: {vuln['severity']}, Score: {vuln['score']})")
    #     print("-" * 40)

def get_access_token():
    payload = {
        'client_id': CLIENT_ID,
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    
    response = requests.post(TOKEN_URL, data=payload)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.json()['access_token']

def get_managed_devices(access_token):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(GRAPH_API_URL, headers=headers)
    response.raise_for_status()
    return response.json()

def get_device_apps(device_id, access_token):
    """
    Retrieve detected apps for a specific device using the Microsoft Graph API.

    Parameters:
        device_id (str): The ID of the managed device.
        access_token (str): A valid access token for Microsoft Graph API.

    Returns:
        dict: A dictionary containing the device's detected apps, or an error message.
    """
    # Base URL for the Microsoft Graph API
    base_url = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
    # Construct the API endpoint with the device ID
    endpoint = f"{base_url}/{device_id}?$expand=detectedApps"
    
    # Set up headers with the access token for authentication
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        # Make the GET request to the API
        response = requests.get(endpoint, headers=headers)
        # Raise an HTTPError if the response contains an error status code
        response.raise_for_status()
        # Parse the JSON response
        return response.json()
    except requests.exceptions.RequestException as e:
        # Handle HTTP errors
        return {"error": str(e)}

def comp_policy(access_token):
    """
    Retrieve device compliance policies, skipping default policies, from the Microsoft Graph API.

    Parameters:
        access_token (str): A valid access token for Microsoft Graph API.

    Returns:
        dict: A dictionary containing the list of compliance policies or an error message.
    """
    # Base URL for the Microsoft Graph API
    endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"

    # Set up headers with the access token for authentication
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        # Make the GET request to the API
        response = requests.get(endpoint, headers=headers)
        # Raise an HTTPError if the response contains an error status code
        response.raise_for_status()
        # Parse the JSON response
        policies = response.json().get('value', [])
        
        # Skip default policies
        filtered_policies = [policy for policy in policies if not policy.get('isDefault')]

        windowspolicy = False 
        # iterate over the policies
        for policy in filtered_policies:
            # get odata type
            # '@odata.type': '#microsoft.graph.iosCompliancePolicy', 'roleScopeTagIds': ['0'], 'id': '016f32fa-8773-40fc-992a-b9530f4aa432', 'createdDateTime': '2022-07-06T08:23:08.9811969Z', 'description': 'Disallow older ios versions\n', 'lastModifiedDateTime': '2022-07-06T08:23:57.2277187
            otype = policy.get('@odata.type')

            # options
            # #microsoft.graph.iosCompliancePolicy
            # #microsoft.graph.windows10CompliancePolicy
            # TODO: last option


        print(filtered_policies)
        
        return {"policies": filtered_policies}
    except requests.exceptions.RequestException as e:
        # Handle HTTP errors
        print(str(e))

# GET https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations

def get_app_vulnerabilities(devices):
    app_inventory = []
    for device in devices:
        device_id = device.get('id')
        apps = get_device_apps(device_id, token)
        print(apps)
        app_list = []
        # print all fields of apps
        detectedApps = apps.get('detectedApps')
        for app in detectedApps:
            # get displayname and version
            appid = app.get('id')
            displayName = app.get('displayName')
            version = app.get('version')
            appstring = f"{displayName} - {version}"
            app_list.append(appstring)
            app_name, _, app_version = appstring.partition(" - ")
            print(app_name)
            # the app name containsof multiple subparts starting with a Capital letter, can you extract them?

            

            cpe_query = {"query": [app_name]}  # Adjust query as needed

            # Query the CPE guessing service
            response = requests.post(
                "https://cpe-guesser.cve-search.org/unique",
                json=cpe_query
            )
            
            if response.status_code == 200:
                cpe_data = response.json()
                if isinstance(cpe_data, list) and cpe_data:
                    cpe = cpe_data[0]  # Assume first result is most relevant
                    cpe_with_version = f"{cpe}:{app_version}"
                    print(f"CPE found:{cpe_with_version}")
                    cpe_list.append(cpe_with_version)
                else:
                    print(f"No CPE found for app: {app_name}")
            else:
                print(f"Error querying CPE for app: {app}, Status Code: {response.status_code}")

        app_inventory.append({
            'deviceName': deviceName,
            'operatingSystem': operatingSystem,
            'complianceState': complianceState,
            'apps': app_list
        })

        unique_apps = set()
        for inventory_item in app_inventory:
            unique_apps.update(inventory_item['apps'])
        print(len(unique_apps))

        # Use a CPE guessing service to generate CPEs for each unique app
        cpe_list = []
        for app in unique_apps:
            # Extract app details
            app_name, _, app_version = app.partition(" - ")
            cpe_query = {"query": [app_name]}  # Adjust query as needed

            # Query the CPE guessing service
            response = requests.post(
                "https://cpe-guesser.cve-search.org/unique",
                json=cpe_query
            )
            
            if response.status_code == 200:
                cpe_data = response.json()
                if isinstance(cpe_data, list) and cpe_data:
                    cpe = cpe_data[0]  # Assume first result is most relevant
                    cpe_with_version = f"{cpe}:{app_version}"
                    print(f"CPE found:{cpe_with_version}")
                    cpe_list.append(cpe_with_version)
                else:
                    print(f"No CPE found for app: {app}")
            else:
                print(f"Error querying CPE for app: {app}, Status Code: {response.status_code}")

        # Execute the vulnerability search script for each CPE
        vulnerabilities = []
        for cpe in cpe_list:
            command = [
                "python3",
                "~/Documents/search_vulns/search_vulns.py",
                "-q",
                cpe,
                "--ignore-general-cpe-vulns"
            ]

            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                output = result.stdout
                vulnerabilities.append({
                    'cpe': cpe,
                    'output': output
                })
            except subprocess.CalledProcessError as e:
                print(f"Error running search_vulns.py for CPE {cpe}: {e.stderr}")

        # Debug: Print all vulnerabilities
        for vuln in vulnerabilities:
            print(f"CPE: {vuln['cpe']}\nVulnerabilities:\n{vuln['output']}")

# TODO: endpoint security
# 1 --> Get compliance policy, is there one?
# https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0&tabs=http
# 2 --> get all configuration policies, check for common bad settings
# 3 --> endpoint security 
# https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-windows10endpointprotectionconfiguration-list?view=graph-rest-1.0&tabs=http
# https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-windows10generalconfiguration-list?view=graph-rest-1.0&tabs=http
# 4 --> Defender for endpoint enrollment
# 5 --> Agent to deploy on host

# TODO: cmdb
# outdated devices
# devices with no owner
# devices out of free space


# TODO: defender
# threats, detections


def main():
    try:
        token = get_access_token()
        devices = get_managed_devices(token).get("value", [])

        # Ensure the devices data is structured correctly
        if not isinstance(devices, list) or not all(isinstance(device, dict) for device in devices):
            raise ValueError("API returned invalid device data structure.")

        #TODO: just disabled for debug
        vulnerabilities = categorize_devices_by_last_sync(devices)

        # # Get vulnerability instances for unencrypted devices
        unencrypted_vulnerabilities = get_unencrypted_devices_vulnerability(devices)

        # # Combine the vulnerabilities
        vulnerabilities.extend(unencrypted_vulnerabilities)

        #compliances = comp_policy(token)
        #print(compliances)

        # Get endpoint security policies
        # print("\nFetching endpoint security policies...")
        # endpoint_security_policies = get_intune_policies(token, "/deviceManagement/deviceManagementScripts")
        # print("Endpoint Security Policies:", endpoint_security_policies)

        for vuln in vulnerabilities:
            print(f"Title: {vuln.title}")
            print(f"Description: {vuln.description}")
            print(f"Severity: {vuln.severity}")
            print(f"Score: {vuln.score}")
            print(f"Found Date: {vuln.found_date}")
            print(f"Count: {vuln.count}")
            print(f"Affected Devices: {', '.join(vuln.affected_devices)}")
            print(f"Remediation: {vuln.remediation}")
            print("-" * 40)

        # Process and display device information
        device_vulns = check_device_for_vulnerabilities(devices)
        vulnerabilities.extend(device_vulns)
        for device in devices:
 
            deviceName = device.get('deviceName')
            operatingSystem = device.get('operatingSystem')
            complianceState = device.get('complianceState')

            #TODO: test
            #check_device_for_vulnerabilities(device)


            # azureADRegistered: True
            # emailAddress: aadjoin@nuwelijn.nl
            # isEncrypted: False
            # model: Prowise OPS (80 Pins) PC Module
            # managedDeviceOwnerType: company
            # enrolledDateTime: 2021-06-23T14:21:04Z
            # lastSyncDateTime: 2024-11-12T06:50:16Z
            # osVersion

            email = device.get('emailAddress')
            model = device.get('model')
            enrolledDateTime = device.get('enrolledDateTime')
            lastSyncDateTime = device.get('lastSyncDateTime')
            osVersion = device.get('osVersion')
            isEncrypted = device.get('isEncrypted')


            # print(f"Device Name: {device.get('deviceName')}")
            # print(f"Model: {model}")
            # print(f"OS Version: {osVersion}")
            # print(f"Compliance Status: {device.get('complianceState')}")
            # print(f"Encryption Status: {isEncrypted}")
            # print("-" * 40)

        # Unique app processing

        for vuln in vulnerabilities:
            write_vulnerability_to_db(vuln)
                    
                    
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
    except Exception as ex:
        print(f"An error occurred: {ex}")

if __name__ == "__main__":
    main()