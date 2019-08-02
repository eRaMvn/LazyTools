import json
import os
import requests

project_list = []

# Get list of projects
project_url = "https://your_bitbucket_url/rest/api/1.0/projects?limit=50"
project_response = json.loads(requests.get(project_url, headers={'Authorization':'Bearer your_apikey_here'}).text)

for project in project_response["values"]:
    project_list.append(project["links"]["self"][0]["href"].split('/')[4])

for project_name in project_list:
    # Get a list of repo for each project
    repo_list = []

    url = "https://your_bitbucket_url/rest/api/1.0/projects/" + project_name + "/repos?limit=50"
    repo_response = json.loads(requests.get(url, headers={'Authorization':'Bearer your_apikey_here'}).text)
   
    for repo in repo_response["values"]:
        for link in repo["links"]["clone"]:
            if link["name"] == "http":
                repo_list.append(link["href"])

    # Set file name
    filename = project_name + "_repo_list.txt"
    # Write the list of repos of each project to the corresponding files
    # Because the repo is a list, we need to use a for loop to write value in the array to a new line in the file
    with open(filename, 'w+') as f:
        for link in repo_list:
            temp = json.dumps(link).split('/') # Create an array to store split string
            temp[2] = "your_username:your_apikey_here@your_bitbucket_url" # Added access key to bitbucket
            f.write("%s\n" % '/'.join(temp).strip('"'))
        f.close()