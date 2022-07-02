import requests as req
import json,threading
from datetime import datetime,timedelta
from time import sleep
from collections import OrderedDict

class Client:
    date_key = {"breaches":"ModifiedDate","pastes":"Date"}

    resp_keys = {"breaches":["Title","Domain","BreachDate","AddedDate","ModifiedDate","Description","DataClasses","IsSensitive","IsMalware"],
                "pastes":["Source","Id","Title","Date","EmailCount"]}
    base_url = "https://haveibeenpwned.com/api/v3/"
    def __init__ (self,accounts:list,api_key:str):
        self.api_key = api_key
        self.accounts = accounts
        self.breaches = {a:[] for a in accounts}
        self.pastes = {a:[] for a in accounts}
        self.session = req.Session()

    @property
    def header (self):
        return {'hibp-api-key': self.api_key,
            'user-agent':'breach-check-am',
            'format': 'application/json',
            'timeout': '2.5',
            'HIBP': self.api_key           
            }

    def process_responses(self,responses:json,account:str,resp_type:str):
        
        resp_dict = getattr(self,resp_type)[account]
        last_week = datetime.today() - timedelta(days=7000)
        
        for resp in responses[1:]:
            found_date = resp[Client.date_key[resp_type]]
            if found_date:
                if datetime.strptime(found_date, '%Y-%m-%dT%H:%M:%Sz') > last_week:
                  
                    resp_dict.append({k:resp[k] for k in Client.resp_keys[resp_type]})
                else:
                    continue
                
            else:
                continue

        return


    
    def make_request (self,service:str,parameter:str=None):
        
        try:
            resp = self.session.get(url=f"{Client.base_url}{service}/{parameter}",headers=self.header)
        
            assert type(resp.status_code) == int,  f"Response did not return an integer when passinng: {Client.base_url}{service}/{parameter}"
            if resp.status_code == 429:
                print("Quota exceeded, waiting for 500 miliseconds")
                sleep(1)
            elif resp.status_code == 404:
                return False
            return resp.json()
        except TypeError as te:
            raise te(f"Failed to get JSON response when requesting: {Client.base_url}{service}/{parameter}")

    

    def get_pastes_for_account (self,account:str)->json:

        responses = self.make_request(service="pasteaccount",parameter=account)
        if responses:
            self.process_responses(responses=responses,account=account,resp_type='pastes')
            
        else:
            sleep(1)
            return 0
        return 1
    
    def get_breaches_for_account (self,account:str)->json:
        responses = self.make_request(service="breachedaccount",parameter=f"{account}?truncateResponse=false&includeUnverified=false")
        if responses:
            self.process_responses(responses=responses,account=account,resp_type='breaches')
           
        else:
            sleep(1)
            return 0

        return 1
        
def get_account_breaches_and_pastes (client:Client)->json:


    for account in client.accounts:
        t1 = threading.Thread(target=client.get_breaches_for_account,args=(account,))
        t1.start()
        t2 = threading.Thread(target=client.get_pastes_for_account,args=(account,))
        t2.start()
        t1.join()
        t2.join()

   

    return

def pretty_print(client:Client):

    for account in client.accounts:
        print(f"{len(client.breaches[account])} Breaches found for {account}:")
        print(json.dumps(client.breaches[account], indent=4))
        print(f"{len(client.breaches[account])} Pastes found for {account}:")
        print(json.dumps(client.pastes[account], indent=4))
def main():
    
    accounts = input("paste a comma seperated lists of emails to check:").split(",")
    client = Client(api_key="01c5af59d0dc40689974ed0a2c6c233d",accounts=accounts)

    get_account_breaches_and_pastes(client=client)
    pretty_print(client)
if __name__ == "__main__":
    main()
