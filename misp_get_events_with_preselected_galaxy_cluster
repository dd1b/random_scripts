from pymisp import ExpandedPyMISP
from config import MISP_URL, MISP_KEY, VERIFY_CERT
import warnings, pdb

import requests, json

# Suppress SSL warnings
warnings.filterwarnings("ignore")

def init_misp():
    return ExpandedPyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)

def get_galaxy_clusters_by_country(countries):
    """
    Search for galaxy clusters related to specific countries.
    e.g: https://{{misp}}/galaxy_clusters/view/29091
    """
    misp = init_misp()
    payload = { #if multiple filters are used, AND is the default operator
        #"galaxy_uuid": "698774c7-8022-42c4-917f-8d6e4f06ada3", #if only Threat Actor Galaxy is preffered
        "elements": {  
            "country": countries,
            #"cfr-suspected-state-sponsor": "People's Republic of China",
            #"cfr-suspected-state-sponsor": "Russian Federation"
        }
    }
    print(f"🔍 Searching for clusters with desired country attribute")
    response = misp.direct_call('galaxy_clusters/restSearch', payload)
    return response



def get_events_by_galaxy_cluster_uuid(uuid):
    """
    Search for events associated with a specific galaxy cluster UUID. 
    Not working for whatever reason 
    """
    misp = init_misp()
    
    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        #"cluster_uuid": uuid,
        "attackGalaxy" : uuid, # "fbd279ab-c095-48dc-ba48-4bece3dd5b0f",
        "metadata": True,
        "requested_attributes": ["info", "id"],
        "returnFormat": "json",
        "limit": 10
    }
    response = requests.post(MISP_URL + "events/restSearch", headers=headers, json=payload, verify=VERIFY_CERT)
    response_json = json.loads(response.text)
    return response_json

def get_events_by_galaxy_cluster_tag(tags):
    """
    Search for events associated with a specific galaxy cluster UUID.
    """
    misp = init_misp()
    
    matched_events = {}
    print(f"🔍 Searching for events identified tags")
    result = misp.search(
        controller='events',
        tags=tags,
        #tags = 'misp-galaxy:threat-actor="Callisto"',
        metadata=True,       # Only return event metadata
        requested_attributes = ["info", "id"],
        pythonify=False      # Optional: set to True if you want MISPEvent objects
    )
    if result:
        matched_events = result
    return matched_events


def main():
    all_tags = []

    if FILE_FLAG: # needed in case the version of MISP don't have the search cluster by attributes capability. Then the clusters will be manual input
        all_tags = ['misp-galaxy:threat-actor="Sofacy"','misp-galaxy:threat-actor="APT 16"']
    else:

        countries = ["IR", "RO"]
        #get all clusters which have desired country attribute 
        clusters = get_galaxy_clusters_by_country(countries)

        if not clusters:
            print("No clusters found.")
            return
    
        
        for cluster in clusters:
            cluster_info = cluster.get("GalaxyCluster", {})
            cluster_uuid = cluster_info.get("uuid")
            cluster_value = cluster_info.get("value")
            cluster_tag_name = cluster_info.get("tag_name")
            all_tags.append(cluster_tag_name)
        
    # search events with selected galaxy clusters
    events = get_events_by_galaxy_cluster_tag(all_tags)
    if not events:
        print("  No events found.")
        
    total_attributes = 0
    for event in events:
        event_data = event.get("Event", {})
        total_attributes += int(event_data.get('attribute_count'))
        print(f"  ➤ Event ID: {event_data.get('id')}, Info: {event_data.get('info')}") #stats  could be done by galaxy and tags
    
    print(f"\nTotal galaxy clusters identified: {len(all_tags)}")
    print(f"Total events identified: {len(events)} and they contain {total_attributes} attributes")

if __name__ == "__main__":
    main()
