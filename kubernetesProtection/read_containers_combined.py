### To run in virtual environment
# python3 -m venv .venv
# source .venv/bin/activate
# python3 -m pip install crowdstrike-falconpy

# Export your FALCON_CLIENT_ID and FALCON_CLIENT_SECRET


import os
from falconpy import KubernetesProtection

import logging
import json, csv

# Authenticate to Falcon platform
falcon = KubernetesProtection(client_id=os.getenv("FALCON_CLIENT_ID"),
                            client_secret=os.getenv("FALCON_CLIENT_SECRET")
                            )
# Pagination values
# set the number of results to return
max_rows = 200      # Set the number of results to return
offset = 0          # Start with the first record
total = 1           
position = None

all_containers = []

count = 0
# A simple filter for the query operation
# https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql#t3b5286b
# filter=last_seen:>'2024-08-04T10:42:18.464Z'
# filter=first_seen:>'2024-08-04T10:42:18.464Z'
filter = "image_has_been_assessed: false,running_status: true"

while offset < total:
# while count < 1 :  # or response["status_code"] == 500
    # We use the same integer we use to control our loop for our offset.
    response = falcon.read_containers_combined(filter=filter,
                                                limit=max_rows,
                                                offset=offset,
                                                sort=None)
    
    if response["status_code"] == 200:
        result = response["body"]
        offset = result["meta"]["pagination"]["offset"]
       
        # This will be the same every time, overrides our initial value of 1.
        total = result["meta"]["pagination"]["total"]
        
        if offset == 0:
            print("Total number of results: ", total)
        
        containers = result["resources"]

        # set the new offset
        offset = offset + len(containers)
        print("New offset: ", offset)

        for container in containers:
            all_containers.append(container)

    else:
        # API error has occurred
        for error_result in response["body"]["errors"]:
            print(error_result["message"])
        break

# remove duplicates
filtered_containers = []
done = set()

for container in all_containers:
    if container['container_id'] == None:
        continue
    else:
        if container['container_id'] not in done:
            done.add(container['container_id'])
            filtered_containers.append(container)

with open('containers.json', 'w') as filtered_containers_file:
    filtered_containers_file.write("%s\n" % json.dumps(filtered_containers, indent=2))
    
# Filter required fields into CSV file
# Create CSV header
column_headers = ['container_registry', 'container_repository', 'container_tag', 'container_id', 'container_digest']
with open('containers.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames = column_headers)
    writer.writeheader()

# Filter the data and write to CSV file
for container in filtered_containers:
#for unassessed_container in containers['body']['resources']:
    container_details = {key: value for key, value in container.items() if "container_registry" in key or "container_repository" in key or "container_tag" in key or "container_id" in key or "container_digest" in key}
    #print(container_details)
    with open('containers.csv', 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames = column_headers)
        writer.writerow(container_details)

