import os
import re
import requests
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from datetime import datetime


def banner():
    print("""
 ▗▄▄▖▗▖  ▗▖▗▄▄▄▖     ▗▄▄▖▗▖   ▗▄▄▄▖
▐▌   ▐▌  ▐▌▐▌       ▐▌   ▐▌     █  
▐▌   ▐▌  ▐▌▐▛▀▀▘    ▐▌   ▐▌     █  
▝▚▄▄▖ ▝▚▞▘ ▐▙▄▄▖    ▝▚▄▄▖▐▙▄▄▖▗▄█▄▖
Author: int0x80                                                    
""")

def fetch_cve_data(url):
    response = requests.get(url)
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        cve_list = []

        for item in root.findall(".//item"):
            title = item.find("title").text
            link = item.find("link").text
            description = item.find("description").text
            full_description = clean_html(description)

            try:
                cve_id = re.search(r"CVE-\d{4}-\d{4,7}", title).group(0)
            except AttributeError:
                cve_id = "N/A"

            pub_date = item.find("pubDate").text
            formatted_date = datetime.strptime(pub_date, '%a, %d %b %Y %H:%M:%S %z').strftime('%b %d')

            cve_list.append({
                "date": formatted_date,
                "title": title,
                "cve_id": cve_id,
                "description": full_description,
                "link": link,
                "full_description": full_description, 
                "published": pub_date
            })
        return cve_list
    else:
        print(f"Failed to fetch data. HTTP Status Code: {response.status_code}")
        return []

def clean_html(raw_html):
    clean = re.compile(r'<strong>(.*?)<\/strong>|<br\s*\/?>')
    return re.sub(clean, '', raw_html).strip()

def display_cve_list(cve_list):
    console = Console()
    viewed_cves = []

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        table = Table(title="Select a CVE to view details", show_header=True, header_style="bold magenta")
        table.add_column("No.", justify="center", style="cyan")
        table.add_column("Date", justify="center", style="cyan")
        table.add_column("Title", justify="left", style="cyan")
        table.add_column("CVE URL", justify="left", style="cyan")

        for index, cve in enumerate(cve_list):
            if index in viewed_cves:
                row_style = "grey39"
            else:
                row_style = None

            table.add_row(
                str(index + 1),
                cve['date'],
                cve['title'],
                cve['link'],
                style=row_style
            )

        console.print(table)
        user_input = input("\nYour selection (enter the number or 'q' to quit): ")

        if user_input.lower() == 'q':
            break

        try:
            selected_index = int(user_input) - 1
            if 0 <= selected_index < len(cve_list):
                display_cve_details(cve_list[selected_index])
                if selected_index not in viewed_cves:
                    viewed_cves.append(selected_index)
            else:
                console.print("Invalid selection. Please choose a valid number.")
        except ValueError:
            console.print("Invalid input. Please enter a number or 'q' to quit.")

def display_cve_details(cve):
    console = Console()
    os.system('cls' if os.name == 'nt' else 'clear')
    table = Table(title=f"CVE Details for {cve['cve_id']}", show_header=True, header_style="bold magenta")
    table.add_column("Date", justify="center", style="cyan")
    table.add_column("CVE ID", justify="center", style="cyan")
    table.add_column("Description", justify="left", style="yellow")
    table.add_column("URL", justify="center", style="green")
    table.add_row(
        cve['date'],
        cve['cve_id'],
        cve['full_description'],
        cve['link']
    )
    console.print(table)
    console.print("\nPublished:", cve['published'])
    console.print("\nPress Enter to go back...")
    input()

if __name__ == "__main__":
    url = "https://cvefeed.io/rssfeed/latest.xml"
    cve_data = fetch_cve_data(url)
    if cve_data:
        display_cve_list(cve_data)
