### To run in virtual environment
# python3 -m venv .venv
# source .venv/bin/activate
# python3 -m pip install crowdstrike-falconpy


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

all_unassessed_images = []

count = 0
# A simple filter for the query operation
# https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql#t3b5286b
# filter=last_seen:>'2024-08-04T10:42:18.464Z'
# filter=first_seen:>'2024-08-04T10:42:18.464Z'
filter = "image_has_been_assessed: false,running_status: true, last_seen:>'2024-08-05T10:42:18.464Z'"

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

        print(response["body"]["meta"]["pagination"])
       
        # This will be the same every time, overrides our initial value of 1.
        total = result["meta"]["pagination"]["total"]
        
        unassessed_images = result["resources"]

        # set the new offset
        offset = offset + len(unassessed_images)

        for image in unassessed_images:
            all_unassessed_images.append(image)

        with open('unassessed_images.json', 'a') as unassessed_images_file:
            unassessed_images_file.write("%s\n" % json.dumps(unassessed_images, indent=2))

    else:
        # API error has occurred
        for error_result in response["body"]["errors"]:
            print(error_result["message"])
        break
    count = count + 1

# remove duplicates

filtered_images = []
done = set()

for image in all_unassessed_images:
    if image['image_id'] == None:
        continue
    else:
        if image['image_id'] not in done:
            done.add(image['image_id'])
            filtered_images.append(image)

print(len(all_unassessed_images))
print(len(filtered_images))

with open('unassessed_images.json', 'w') as unassessed_images_file:
    unassessed_images_file.write("%s\n" % json.dumps(filtered_images, indent=2))
    
# Filter required fields into CSV file
# Create CSV header
column_headers = ['image_registry', 'image_repository', 'image_tag', 'image_id', 'image_digest']
with open('unassessed_images.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames = column_headers)
    writer.writeheader()

# Filter the data and write to CSV file
for image in filtered_images:
#for unassessed_image in unassessed_images['body']['resources']:
    image_details = {key: value for key, value in image.items() if "image_registry" in key or "image_repository" in key or "image_tag" in key or "image_id" in key or "image_digest" in key}
    #print(image_details)
    with open('unassessed_images.csv', 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames = column_headers)
        writer.writerow(image_details)

