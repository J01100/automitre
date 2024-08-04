import sys
import requests
from bs4 import BeautifulSoup
import csv

gid = sys.argv[1]
# URL to fetch
url = "https://attack.mitre.org/software/" + gid

# Send HTTP GET request
response = requests.get(url)
# Check if the request was successful
if response.status_code == 200:
    print("Running...")
    # Parse the response content
    soup = BeautifulSoup(response.text, 'html.parser')
    # Find the specific table
    table = soup.find('table', class_='table techniques-used background table-bordered')
    if table:
        # Find the table body
        tbody = table.find('tbody')
        # Initialize a list to hold the data
        data = []
        # Iterate over each row in the table body
        for row in tbody.find_all('tr'):
            # Find all cells in the row
            cells = row.find_all('td')
            if len(cells) < 4:
                continue  # Skip rows that do not have enough cells
            # Extract the main ID (assuming it's in the second cell)
            main_id_link = cells[1].find('a')
            main_id = main_id_link['href'] if main_id_link else "None"
            # Extract sub IDs and names (assuming they are in the third and fourth cells)
            sub_id_link = cells[2].find('a')
            sub_id = sub_id_link['href'] if sub_id_link else "None"
            # Check if main_id and sub_id are equal
            if main_id == sub_id:
                name = cells[2].text.strip()  # Use the text from the third cell
                sub_id = "None"
            else:
                # Combine text from all elements in the fourth cell for name
                name_parts = [cell.text.strip() for cell in cells[3].find_all(True)]  # Any tag within the cell
                name = ': '.join(name_parts)
            # Append the extracted data to the list (including "None" for missing sub IDs)
            data.append([main_id, sub_id, name])

        # Write data to CSV (outside the loop)
        with open('out.csv', 'w', newline='') as csvfile:
            fieldnames = ['main_id', 'sub_id', 'name']
            writer = csv.writer(csvfile)
            writer.writerow(fieldnames)
            writer.writerows(data)

    else:
        print("The specified table was not found.")
else:
    print(f"Failed to retrieve the URL. Status code: {response.status_code}")

def process_mitre_data(url):
    all_ids = []
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', class_='table techniques-used background table-bordered')
        if table:
            tbody = table.find('tbody')
            for row in tbody.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) < 4:
                    continue
                main_id_link = cells[1].find('a')
                main_id = main_id_link['href'] if main_id_link else "None"
                sub_id_link = cells[2].find('a')
                sub_id = sub_id_link['href'] if sub_id_link else "None"
                if main_id == sub_id:
                    name = cells[2].text.strip()
                    sub_id = "None"
                else:
                    name_parts = [cell.text.strip() for cell in cells[3].find_all(True)]
                    name = ': '.join(name_parts)
                if main_id and main_id != "None":
                    all_ids.append(main_id)
                if sub_id and sub_id != "None" and sub_id != main_id:
                    all_ids.append(sub_id)

    return all_ids

def extract_mitigations_and_detections(response, tid, mitigation_out, detection_out):
    soup = BeautifulSoup(response.text, 'html.parser')
    data_mitigations = []
    data_detections = []

    mitigations_header = soup.find('h2', id='mitigations')
    if mitigations_header:
        mitigations_table = mitigations_header.find_next_sibling('div', class_='tables-mobile').find('table', class_='table table-bordered table-alternate mt-2')
        if mitigations_table:
            for row in mitigations_table.find_all('tr')[1:]:  # Skip header row
                cells = row.find_all('td')
                if len(cells) < 3:
                    continue
                mitigation_id_link = cells[0].find('a')
                mitigation_id = mitigation_id_link['href'].split('/')[-1] if mitigation_id_link else "None"
                mitigation_name_link = cells[1].find('a')
                mitigation_name = mitigation_name_link.text.strip() if mitigation_name_link else "None"
                description_cell = cells[2]
                description = description_cell.find('p').text.strip() if description_cell.find('p') else ""
                data_mitigations.append([tid, mitigation_id, mitigation_name, description])
        else:
            mitigation_description = mitigations_header.find_next_sibling('p').text.strip()
            data_mitigations.append([tid, "", mitigation_description])

    detection_header = soup.find('h2', id='detection')
    if detection_header:
        detection_table = detection_header.find_next_sibling('div', class_='tables-mobile').find('table', class_='table datasources-table table-bordered')
        if detection_table:
            for row in detection_table.find_all('tr')[1:]:  # Skip header row
                cells = row.find_all('td')
                id_value = cells[0].find('a')
                data_source_value = cells[1].find('a')
                data_component_value = cells[2].find('a')
                detects_value = cells[3].find('p').text.strip() if cells[3].find('p') else ""
                if id_value:
                    id_value = id_value['href'].split('/')[-1]
                else:
                    id_value = "None"
                data_source = data_source_value.text.strip() if data_source_value else "None"
                data_component = data_component_value.text.strip() if data_component_value else ""
                data_detections.append([tid, id_value, data_source, data_component, detects_value])

    return data_mitigations, data_detections

# Initial header writing
mitigation_out = "mitigation_desc.csv"
detection_out = "detection_desc.csv"

with open(mitigation_out, 'w', newline='') as csvfile:
    fieldnames = ['tid', 'id', 'name', 'description']
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)

with open(detection_out, 'w', newline='') as csvfile:
    fieldnames = ['tid', 'id', 'data_source', 'data_component', 'detects']
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)

# Process the data
utids = process_mitre_data(url)
domain = "https://attack.mitre.org"

for tid in utids:
    response = requests.get(domain + tid)
    if response.status_code == 200:
        data_mitigations, data_detections = extract_mitigations_and_detections(response, tid, mitigation_out, detection_out)
        with open(mitigation_out, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(data_mitigations)
        with open(detection_out, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(data_detections)

print(str(len(utids)) + " techniques have been crawled")
