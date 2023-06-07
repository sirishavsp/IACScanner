import os
import re
import hcl
from typing import List, Dict, Union
from radon.complexity import cc_visit

def analyze_terraform_code(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Analyze the given Terraform file for code complexity and best practice violations.
    Return a list of dictionaries, where each dictionary represents an issue found in the file.
    Each dictionary contains the keys "issue", "severity", "line_number", and "recommendation".

    Args:
        file_path (str): The path to the Terraform file.

    Returns:
        A list of dictionaries, where each dictionary represents an issue found in the file.
    """
    results = []

    # Code Complexity Analysis
    with open(file_path, 'r') as file:
        code = file.read()
    complexity_results = cc_visit(code)
    for result in complexity_results:
        if result.complexity >= 10:  # Adjust the complexity threshold as per your needs
            results.append({
                "issue": "High code complexity",
                "severity": "High",
                "line_number": result.lineno,
                "recommendation": f"Refactor the code at line {result.lineno} to reduce complexity."
            })

    # Additional Best Practice Checks
    with open(file_path, "r") as f:
        data = f.read()
        parsed_data = hcl.loads(data)
        
    for block_type in parsed_data:
        for block in parsed_data[block_type]:
            # Add any additional best practice checks as per your requirements
            if block_type == "resource":
                # Example: Check if resource names follow a specific naming convention
                if not re.match(r"^[a-z][a-z0-9_-]*$", block.get("name", "")):
                    results.append({
                        "issue": "Resource naming violation",
                        "severity": "Medium",
                        "line_number": block["_terraform_id"][1],
                        "recommendation": "Update the resource name to follow the specified naming convention."
                    })

    return results

def analyze_terraform_directory(directory_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Analyze all Terraform files in the given directory for code complexity and best practice violations.
    Return a list of dictionaries, where each dictionary represents an issue found in a file.
    Each dictionary contains the keys "file_path", "issue", "severity", "line_number", and "recommendation".

    Args:
        directory_path (str): The path to the directory containing Terraform files.

    Returns:
        A list of dictionaries, where each dictionary represents an issue found in a file.
    """
    results = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".tf"):
                file_path = os.path.join(root, file)
                file_results = analyze_terraform_code(file_path)
                for result in file_results:
                    result["file_path"] = file_path
                results.extend(file_results)

    return results
