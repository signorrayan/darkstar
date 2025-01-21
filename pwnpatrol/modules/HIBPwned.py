import json
import requests
import time
from modules.recon import RequestsAPI, FindBreaches
from modules.db_helper import insert_vulnerability_to_database, insert_email_data, insert_breached_email_data, insert_password_data
from modules.vulns import Vulnerability
import os
# response codes HTTP
SUCCES = 200
PAGE_NOT_FOUND = 404
TOO_MANY_CALLS = 429

# Number of seconds we sleep for the API call
SLEEP_SECONDS = 6

# If true we scan for password leaks
PASSWORD_SCANNING = True

class HIBPwned:
    def __init__(self, email_file: str, org_name: str):
        self.org_name = org_name
        self.emails = []
        
        with open(email_file, "r") as file:
            self.emails = file.readlines()

    def run(self):
        # Initialize the RequestsAPI class
        api = RequestsAPI()

        # Initialize the FindBreaches class
        find_breaches = FindBreaches()

        # Loop through all the emails
        #? Store email in the database as email_input, as online discoverd emails
        insert_email_data(self.emails, self.org_name)

        for email in self.emails:
            email = email.strip()
            print(f"Checking email: {email}")
            while True:
                # Get the response from the HIBPwned API
                response = api.get_HIBPwned_request(email)
                if response.status_code == SUCCES:
                    breaches = find_breaches.find_email_breach(email, response.json())
                    #? Insert to the email_leaks table
                    insert_breached_email_data(breaches, self.org_name)
                    for breach in breaches:
                        mail = breach[0]
                        # vuln = Vulnerability(
                        #     title="Email address breached",
                        #     affected_item=mail,
                        #     tool="haveibeenpwned.com",
                        #     confidence=80,
                        #     severity="Medium",
                        #     host=self.org_name,
                        #     summary=f"Email breach discovered, it's compromised in an online breach. The company which was breached is {breach[1] if breach[1] else 'unknown'} on {breach[2] if breach[2] else 'unknown'} with the domain {breach[3] if breach[3] else 'unknown'}",
                        #     impact="Email address breached",
                        #     solution="Change password"
                        # )
                        # insert_vulnerability_to_database(vuln, self.org_name)
                    break
                elif response.status_code == TOO_MANY_CALLS:
                    print("Too many calls, sleeping for 6 seconds")
                    time.sleep(SLEEP_SECONDS)
                elif response.status_code == PAGE_NOT_FOUND:
                    print("No breaches found")
                    break
                else:
                    print(f"Error: {response.status_code}")
                    break

            # If we are scanning for passwords
            if PASSWORD_SCANNING:
                while True:
                    # Get the response from the Proxynova API
                    response = api.get_proxynova_request(email)
                    if response.status_code == SUCCES:
                        passwords = find_breaches.find_passwords(email, response.text.splitlines())
                        #? Insert to the password_leaks table
                        insert_password_data(passwords, self.org_name)
                        for password in passwords:
                            mail = password[0]
                            
                            # vuln = Vulnerability(
                            #     title="Found email + password combination in a leak",
                            #     affected_item=mail,
                            #     tool="proxynova.com",
                            #     confidence=80,
                            #     severity="High",
                            #     host=self.org_name,
                            #     summary=f"Email + Password combination found in a leak. The password starts with {password[1]}",
                            #     impact="An attacker can use this password to gain access to the email account",
                            #     solution="Change password immediately"
                            # )
                            # insert_vulnerability_to_database(vuln, self.org_name)
                        break
                    elif response.status_code == TOO_MANY_CALLS:
                        print("Too many calls, sleeping for 6 seconds")
                        time.sleep(SLEEP_SECONDS)
                    else:
                        print(f"Error: {response.status_code}")
                        break


# if __name__ == "__main__":
#     # Initialize the HIBPwned class
#     hibpwned = HIBPwned('./emails.txt', 'test')
#     hibpwned.run()