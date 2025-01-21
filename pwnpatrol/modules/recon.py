import requests
from config import HIBP_KEY

class RequestsAPI:
    def __init__(self):
        self.APIKey = HIBP_KEY

    # Send/Receive HIBPwned request
    def get_HIBPwned_request(self, email):
        headers = {
            "hibp-api-key": self.APIKey
        }
        return requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers=headers
        )

    # Senc/Receive Proxynova request
    def get_proxynova_request(self, email):
        return requests.get(f"https://api.proxynova.com/comb?query={email}")


class FindBreaches:
    # Handles all the breaches and returns a list with all the relevant information
    def find_email_breach(self, email, response):
        breaches = []
        # Parsing the response JSON
        data = response
        for info in data:
            breaches.append([email, info["Name"], info["BreachDate"], info["Domain"]])
        return breaches

    # Handles all the paswords found and returns a list with email/password combinations
    def find_passwords(self, email, response):
        truncated_passwords = []
        for line in response:
            count = line.find(email)
            #print(count)
            if count > 0:
                try:
                    password = line.split(email + ":")[1].split('"')[0]
                    print(f"Leaked Password found: {password}")
                    # Only return first 3 characters of password
                    truncated_passwords.append([email, password[:3]])
                except:
                    password = ""
                    # empty password
                    truncated_passwords.append([email, password])
                
        return truncated_passwords


    