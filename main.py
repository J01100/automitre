import requests
from bs4 import BeautifulSoup
import csv

# URL to fetch
url = "https://attack.mitre.org/software/S0650/"

# Send HTTP GET request
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
  print("Request was successful!")
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

        print(len(list(set(all_ids))))

# Example usage:
process_mitre_data(url)
