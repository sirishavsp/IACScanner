import argparse
import traceback
from codeScanner.code_validator import *
import os
import logging
import requests
import json

def main():
    directory = "Test/Testfiles"

    # Check if the specified path is a directory
    if not os.path.isdir(directory):
        logging.error(f"Error: '{directory}' is not a directory.")
        return

    # Create the results directory
    results_directory = os.path.join(directory, "results")
    os.makedirs(results_directory, exist_ok=True)

    results = []

    # Configure logging
    log_file = os.path.join(directory, "scan.log")
    logging.basicConfig(level=logging.INFO, filename=log_file, filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s')

    # Iterate over all Terraform files in the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".tf"):
                filepath = os.path.join(root, filename)

                try:
                    # Call run_terraform_scan function from scanner.py
                    logging.info(f"Scanning file: {filepath}")
                    scan_results = run_terraform_scan(filepath)
                    results.extend(scan_results)

                    # Generate report for the current file
                    report_url = f"http://localhost:8080/generate_report/{filename}"
                    response = requests.post(report_url, json={'results': results}, headers={'Content-Type': 'application/json'})

                    if response.status_code == 200:
                        try:
                            report_data = response.json()
                            if 'message' in report_data:
                                logging.error(f"Failed to generate report for file: {filepath}. {report_data['message']}")
                            else:
                                logging.info(f"Report generated for file: {filepath}. Report URL: {report_data['report_url']}")
                        except json.JSONDecodeError:
                            logging.error(f"Failed to generate report for file: {filepath}. Invalid JSON response.")
                    else:
                        logging.error(f"Failed to generate report for file: {filepath}. {response.status_code} {response.reason}")
                except Exception as e:
                    logging.error(f"Error processing file: {filepath}. {str(e)}")
                    traceback.print_exc()  # Print the traceback

    logging.info("Scan completed.")

if __name__ == '__main__':
    main()
