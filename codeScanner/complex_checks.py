import difflib
import re
from typing import List, Dict, Union
from hcl import loads as parse_hcl
from radon.complexity import cc_visit
import networkx as nx
from fuzzywuzzy import fuzz
import re
import subprocess
import json
from typing import List, Dict, Union
from fuzzywuzzy import fuzz
from typing import Tuple
import bisect

def extract_comments(file_contents: str) -> List[Tuple[int, str]]:
    comment_pattern = r'/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/'
    comments = [(m.start(), m.group().strip('/*').strip()) 
                for m in re.finditer(comment_pattern, file_contents, re.MULTILINE | re.DOTALL)]
    line_starts = {i: m.start() for i, m in enumerate(re.finditer('\n', file_contents), start=1)}
    line_starts[-1] = -1
    comments = [(bisect.bisect(list(line_starts.values()), start), comment) for start, comment in comments]
    return comments

def find_duplicates(file_contents: str) -> List[Dict[str, Union[str, int]]]:
    results = []
    lines = file_contents.split("\n")

    resource_blocks = {}
    current_resource = None
    current_keys = []

    # Group lines by resource block
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if stripped_line.startswith("resource"):
            if current_resource:
                resource_blocks[current_resource] = current_keys
            current_resource = i
            current_keys = []
        elif current_resource is not None and '=' in stripped_line:
            key = stripped_line.split('=')[0].strip()
            current_keys.append(key)

    if current_resource:
        resource_blocks[current_resource] = current_keys

    # Compare hashes of key sets to find duplicates
    seen_hashes = {}
    for line_num, keys in resource_blocks.items():
        keys_hash = hash(frozenset(keys))
        if keys_hash in seen_hashes:
            results.append({
                "issue": "Duplicate resource block structure detected",
                "severity": "Medium",
                "line_number": seen_hashes[keys_hash] + 1,
                "recommendation": f"Review the duplicate resource block structure at line {line_num + 1}."
                                  f" Consider modifying the structure if not required."
            })
        else:
            seen_hashes[keys_hash] = line_num
        
        comments = extract_comments(file_contents)
        seen_comments = {}
        for i, (line_num, comment) in enumerate(comments):
            for seen_line_num, seen_comment in seen_comments.items():
                similarity = difflib.SequenceMatcher(None, seen_comment, comment).ratio()
                if similarity > 0.6:  # You may adjust this threshold as needed
                    results.append({
                        "issue": "Similar comments detected",
                        "severity": "Low",
                        "line_number": seen_line_num + 1,
                        "recommendation": f"Review the similar comments at lines {seen_line_num+1} and {line_num+1}."
                                        f" Consolidate or clarify the comments to improve code readability."
                    })
                    break
            else:
                seen_comments[line_num] = comment
    return results

def analyze_duplicate_code(file_path: str) -> List[Dict[str, Union[str, int]]]:
    results = []

    try:
        with open(file_path, 'r') as f:
            file_contents = f.read()

        # Perform code analysis
        duplicates = find_duplicates(file_contents)

        # <Rest of the code> ...

        # Merge all analysis results
        results += duplicates
        # <Merge other analysis results to the 'results' list>

    except Exception as e:
        print("Error occured")

    return results

def test_check_for_insecure_system_access(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Checks for insecure system access patterns in Terraform code.
    
    Args:
        file_path (str): The path to the Terraform file.
    
    Returns:
        A list of dictionaries, where each dictionary represents an issue found in the file.
    """
    results = []
    with open(file_path, 'r') as f:
        terraform_code = f.read()
    
    # Perform checks for insecure system access patterns in the Terraform code
    # Example checks:
    if 'plaintext_secret' in terraform_code:
        results.append({
            "issue": "Insecure system access detected",
            "severity": "High",
            "line_number": 0,
            "recommendation": "Ensure that system resources or services are accessed with appropriate permissions or access controls."
        })
    
    # Add more checks for other insecure system access patterns
    
    return results

def test_warn_if_vulnerable_libraries(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Checks for the use of vulnerable libraries or modules in Terraform code.
    
    Args:
        file_path (str): The path to the Terraform file.
    
    Returns:
        A list of dictionaries, where each dictionary represents an issue found in the file.
    """
    results = []
    cmd = f"terraform init -backend=false && terraform get -update && terraform graph"
    try:
        output = subprocess.check_output(cmd, shell=True, cwd=os.path.dirname(file_path)).decode("utf-8")
    except subprocess.CalledProcessError:
        return results
    
    # Parse the Terraform graph and analyze dependencies for potential vulnerabilities
    # Example checks:
    if 'vulnerable_module' in output:
        results.append({
            "issue": "Potentially vulnerable library/module found",
            "severity": "High",
            "line_number": 0,
            "recommendation": "Update the library/module to a secure version or find an alternative if possible."
        })
    
    # Add more checks for other vulnerable libraries/modules
    
    return results

import os
import hcl
from typing import List, Dict, Union

def analyze_dependency(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Analyze the given Terraform file for resource dependencies and identify any issues.
    Return a list of dictionaries, where each dictionary represents a dependency issue found in the file.
    Each dictionary contains the keys "issue", "severity", "resource", "dependency", and "recommendation".

    Args:
        file_path (str): The path to the Terraform file.

    Returns:
        A list of dictionaries, where each dictionary represents a dependency issue found in the file.
    """
    results = []

    with open(file_path, "r") as f:
        data = hcl.load(f)

    for resource in data.get("resource", []):
        resource_type = resource["type"]
        resource_name = resource["name"]
        dependencies = resource.get("depends_on", [])

        for dependency in dependencies:
            if dependency not in data:
                results.append({
                    "issue": "Missing dependency",
                    "severity": "High",
                    "resource": f"{resource_type}.{resource_name}",
                    "dependency": dependency,
                    "recommendation": f"Add {dependency} as a dependency for {resource_type}.{resource_name}."
                })

            if dependency == f"{resource_type}.{resource_name}":
                results.append({
                    "issue": "Circular dependency",
                    "severity": "High",
                    "resource": f"{resource_type}.{resource_name}",
                    "dependency": dependency,
                    "recommendation": f"Remove the circular dependency between {resource_type}.{resource_name} and {dependency}."
                })

    return results


import os
import hcl
import re
from typing import List, Dict, Union

def enforce_naming_conventions(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Enforce naming conventions for resources in the Terraform file.
    Return a list of dictionaries, where each dictionary represents a resource naming issue found in the file.
    Each dictionary contains the keys "issue", "severity", "resource", and "recommendation".

    Args:
        file_path (str): The path to the Terraform file.

    Returns:
        A list of dictionaries, where each dictionary represents a resource naming issue found in the file.
    """
    results = []

    with open(file_path, "r") as f:
        data = hcl.load(f)

    for resource in data.get("resource", []):
        resource_type = resource["type"]
        resource_name = resource["name"]

        # Check if the resource name follows the desired naming convention
        if not re.match(r"^[\w-]+$", resource_name):
            results.append({
                "issue": "Invalid resource name",
                "severity": "Medium",
                "resource": f"{resource_type}.{resource_name}",
                "recommendation": "Use only alphanumeric characters, underscores, and hyphens in the resource name."
            })

        # Additional naming conventions checks can be added here
        # For example, you can check for prefix or suffix patterns, naming length, etc.

    return results
