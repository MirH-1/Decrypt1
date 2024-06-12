import os
import zipfile
import time
import hashlib
import shutil
import requests
import PyPDF2
import re
from tabulate import tabulate


# Function to query VirusTotal for file hash analysis
def query_virustotal(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': 'your_api_key_here'}  # Insert your API key here
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None


# Function to generate SHA-256 checksum for each file
def generate_checksum(file_path):
    hash_function = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_function.update(chunk)
    return hash_function.hexdigest()


# Write the results into a report
def write_report(files, keyword_data):
    with open('report_summary.txt', 'w') as f:
        f.write('FILE STATUS REPORT\n\n')
        f.write(tabulate(files, headers=["File name", "Checksum", "VirusTotal Result"], tablefmt="grid"))
        f.write("\n\nKEYWORD AND EMAIL REPORT\n\n")
        for filename, details in keyword_data.items():
            f.write(f"{filename} Analysis:\n")
            f.write(tabulate(details['keywords'], headers=['Keyword', 'Occurrences'], tablefmt="grid"))
            f.write("\nUnique Emails Found:\n" + "\n".join(details['emails']) + "\n\n")


# Extract text from PDF and process for keywords
def process_pdf_text(file_path):
    text = ""
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            text += page.extract_text() or ""
    return text


# Search for keywords and emails
def search_keywords_emails(text):
    keywords = ['pesel', 'password', 'email']  # Define your keywords
    keyword_counts = {key: text.lower().count(key) for key in keywords}
    emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
    return keyword_counts, list(emails)


# Process files inside the zip
def process_files(zip_path):
    files_report = []
    keywords_report = {}
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for file_name in zip_ref.namelist():
            file_path = f"extracted_files/{file_name}"
            zip_ref.extract(file_name, 'extracted_files/')

            # Process files based on their type
            if file_name.endswith('.pdf'):
                text = process_pdf_text(file_path)
            else:
                continue  # Add conditions for other file types

            # Search for keywords and emails
            keyword_counts, emails = search_keywords_emails(text)
            keyword_results = [[k, v] for k, v in keyword_counts.items()]

            # Generate checksum
            checksum = generate_checksum(file_path)

            # Query VirusTotal
            virus_info = query_virustotal(checksum)
            virus_result = "Unknown" if not virus_info else max(virus_info['data']['attributes']['last_analysis_stats'],
                                                                key=virus_info['data']['attributes'][
                                                                    'last_analysis_stats'].get)

            # Compile reports
            files_report.append([file_name, checksum, virus_result])
            keywords_report[file_name] = {'keywords': keyword_results, 'emails': emails}

    write_report(files_report, keywords_report)


# Main function to handle the zip file processing
def main():
    zip_file_path = input("Please enter the path to the zip file: ")
    if not os.path.exists(zip_file_path) or not zip_file_path.endswith('.zip'):
        print("Invalid file path or file is not a zip file.")
        return

    if zipfile.is_zipfile(zip_file_path):
        print("Processing the zip file...")
        process_files(zip_file_path)
    else:
        print("The provided file is not a valid zip file.")


if __name__ == "__main__":
    main()

