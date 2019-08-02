# import sys
from suds.client import Client
import ssl
import stdiomask

# By pass ssl validation issue
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

client = Client("https://your_link/webservices/sswebservice.asmx?wsdl")

username = input("Enter your domain username (Ex: johndoe): ").strip()
password = stdiomask.getpass(prompt='Enter your password: ', mask='*')
token = client.service.Authenticate(username, password, "", "your_domain")

while True:
    # Ask for user input
    choice = input("""What do you want to do? (Enter "e" to exit, "s" to search): """).lower()

    if choice == "e":
        print("Bye!")
        break
    # If user select s to search, print out the search result
    elif choice == "s":
        searchString = input("Enter your search string: ").strip()
        searchSecret=client.service.SearchSecrets(token.Token, searchString)
        print("Here are the results:")
        
        for item in searchSecret["SecretSummaries"]["SecretSummary"]:
            print(item)
        
        # Ask for the secret key id
        secretId= input("Enter the SecretId: ")
        secret = client.service.GetSecret(token.Token, secretId)

        print(secret["Secret"]["Items"])       
    else:
        print("Invalid input. Please try again!")