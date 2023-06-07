import argparse
from tabulate import tabulate
from codeScanner.code_validator import *
import os
import logging

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='IaC Security Scanner')
    parser.add_argument('directory', metavar='directory', type=str, help='path to the directory containing Terraform files')
    args = parser.parse_args()

    directory = args.directory

    # Check if the specified directory exists
    if not os.path.exists(directory):
        logging.error(f"Error: Directory '{directory}' does not exist.")
        return

    # Check if the specified path is a directory
    if not os.path.isdir(directory):
        logging.error(f"Error: '{directory}' is not a directory.")
        return

    # Create the results directory
    results_directory = os.path.join(directory, "results")
    os.makedirs(results_directory, exist_ok=True)

    results = []

    # Iterate over all Terraform files in the directory
    for filename in os.listdir(directory):
        if filename.endswith(".tf"):
            filepath = os.path.join(directory, filename)

            try:
                # Call run_terraform_scan function from scanner.py
                logging.info(f"Scanning file: {filepath}")
                scan_results = run_terraform_scan(filepath)
                results.extend(scan_results)

                # Generate report for the current file
                report_filename = f"report_{filename}.html"
                report_filepath = os.path.join(results_directory, report_filename)
                generate_report(report_filepath, scan_results)
                logging.info(f"Report generated for file: {filepath}")
            except Exception as e:
                logging.error(f"Error processing file: {filepath}. {str(e)}")

    logging.info("Scan completed.")

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO, filename='scan.log', filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s')

    main()
