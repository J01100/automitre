import sys
import requests
from bs4 import BeautifulSoup
import csv

gid = sys.argv[1]
# URL to fetch
url = "https://attack.mitre.org/software/"+gid

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
        # Write data to CSV
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


def extract_mitigations(url, output_file):
  data = []

  response = requests.get(url)
  if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    mitigations_header = soup.find('h2', id='mitigations')

    if mitigations_header:
      mitigations_table = mitigations_header.find_next_sibling('div', class_='tables-mobile').find('table', class_='table table-bordered table-alternate mt-2')

      if mitigations_table:
        # Process mitigations table as before
        for row in mitigations_table.find_all('tr')[1:]:  # Skip header row
          # ... rest of your code for extracting mitigations
          cells = row.find_all('td')
          if len(cells) < 3:
            continue

          mitigation_id_link = cells[0].find('a')
          mitigation_id = mitigation_id_link['href'].split('/')[-1] if mitigation_id_link else "None"

          mitigation_name_link = cells[1].find('a')
          mitigation_name = mitigation_name_link.text.strip() if mitigation_name_link else "None"

          description_cell = cells[2]
          description = description_cell.find('p').text.strip() if description_cell.find('p') else ""

          data.append([mitigation_id, mitigation_name, description])


      else:
        # Handle case where there's no table, but a paragraph
        mitigation_description = mitigations_header.find_next_sibling('p').text.strip()
        data.append(["", url, mitigation_description])

  # Write data to CSV
  with open(output_file, 'w', newline='') as csvfile:
    fieldnames = ['id', 'name', 'description']
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    writer.writerows(data)


def extract_detections(url, output_file):
  data = []

  response = requests.get(url)
  if response.status_code == 200:
    soup = BeautifulSoup(response.text, 'html.parser')
    detection_header = soup.find('h2', id='detection')

    if detection_header:
      detection_table = detection_header.find_next_sibling('div', class_='tables-mobile').find('table', class_='table datasources-table table-bordered')

      if detection_table:
        # Process detection table
        for row in detection_table.find_all('tr')[1:]:  # Skip header row
          cells = row.find_all('td')

          # Handle empty cells for rows without data source or data component
          id_value = cells[0].find('a')
          data_source_value = cells[1].find('a')
          data_component_value = cells[2].find('a')
          detects_value = cells[3].find('p').text.strip() if cells[3].find('p') else ""

          # Extract ID if it exists
          if id_value:
            id_value = id_value['href'].split('/')[-1]
          else:
            id_value = "None"

          # Extract data source and data component text if they exist
          data_source = data_source_value.text.strip() if data_source_value else "None"
          data_component = data_component_value.text.strip() if data_component_value else ""

          data.append([id_value, data_source, data_component, detects_value])

  # Write data to CSV
  with open(output_file, 'w', newline='') as csvfile:
    fieldnames = ['id', 'data_source', 'data_component', 'detects']
    writer = csv.writer(csvfile)
    writer.writerow(fieldnames)
    writer.writerows(data)

utids = process_mitre_data(url)

for tid in utids:
    extract_mitigations("https://attack.mitre.org"+tid,"mitigation_descriptions.csv")
    extract_detections("https://attack.mitre.org"+tid,"detection_descriptions.csv")
