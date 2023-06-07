import os
import re
import os
import re
from urllib.parse import urlparse
import os
import hcl

def test_warn_if_insecure_permissions(file_path):
    """
    Checks for insecure file permissions in the specified file path.

    Parameters:
    file_path (str): The path to the Terraform file to check.

    Returns:
    List[Dict]: A list of dictionaries representing any insecure file permissions found in the Terraform file.
    """
    if not os.path.exists(file_path):
        return []  # File does not exist, return empty list

    issues = []

    with open(file_path, 'r') as fp:
        file_contents = fp.read()
        parsed_hcl = hcl.loads(file_contents)

    for resource_type, resources in parsed_hcl.get('resource', {}).items():
        if resource_type != 'aws_s3_bucket':
            continue  # Skip non-S3 resources
        for resource_name, resource in resources.items():
            versioning_enabled = resource.get('versioning', {}).get('enabled', False)
            if not versioning_enabled:
                resource_declaration = f'resource "aws_s3_bucket" "{resource_name}"'
                line_number = file_contents.count('\n', 0, file_contents.index(resource_declaration)) + 1
                issues.append({
                    "issue": "Insecure S3 bucket permissions found",
                    "severity": "High",
                    "line_number": line_number,
                    "resource_name": resource_name,
                    "recommendation": "Enable versioning on your S3 bucket to prevent unintended data loss."
                })

    return issues




# Define the mappings outside of the function to make it easy to update
INSECURE_SERVICE_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH (if not properly secured)",
    23: "Telnet",
    25: "SMTP (Use SMTPS instead)",
    80: "HTTP",
    110: "POP3 (Use POP3S instead)",
    143: "IMAP (Use IMAPS instead)",
    389: "LDAP (Use LDAPS or LDAP with STARTTLS instead)",
    465: "SMTPS (Deprecated, Use SMTP with STARTTLS instead)",
    636: "LDAPS (Deprecated, Use LDAP with STARTTLS instead)",
    989: "FTPS Data Transfer (Deprecated, Use FTP with explicit SSL/TLS instead)",
    990: "FTPS Control (Deprecated, Use FTP with explicit SSL/TLS instead)",
    992: "Telnet over SSL/TLS (Deprecated)",
    993: "IMAPS (Deprecated, Use IMAP with STARTTLS instead)",
    995: "POP3S (Deprecated, Use POP3 with STARTTLS instead)"
}

def test_check_for_insecure_services(file_paths):
    insecure_services = []
   
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            continue

        with open(file_path, "r") as f:
            terraform_code = hcl.load(f)  # Load the file as HCL

        # Check each resource in the file
        for resource_type, resource_list in terraform_code.get('resource', {}).items():
            for resource_name, resource_body in resource_list.items():

                # Check AWS security groups for insecure ingress ports
                if resource_type == 'aws_security_group':
                    for ingress in resource_body.get('ingress', []):
                        from_port = ingress.get('from_port')
                        to_port = ingress.get('to_port')

                        # Check if the ports are insecure
                        if from_port in INSECURE_SERVICE_PORTS or to_port in INSECURE_SERVICE_PORTS:
                            insecure_service = {
                                "issue": f"Insecure service detected in resource {resource_name} of type {resource_type} in file: {file_path}",
                                "severity": "High",
                                "line_number": "Unknown",  # Line numbers are not available when parsing HCL
                                "line_content": f"From port: {from_port}, To port: {to_port}",
                                "service": INSECURE_SERVICE_PORTS.get(from_port, INSECURE_SERVICE_PORTS.get(to_port)),
                                "recommendation": "Consider changing the ports to a secure service"
                            }
                            insecure_services.append(insecure_service)

                # Check AWS DB instances for hardcoded passwords
                if resource_type == 'aws_db_instance':
                    if 'password' in resource_body:
                        insecure_service = {
                            "issue": f"Hardcoded password detected in resource {resource_name} of type {resource_type} in file: {file_path}",
                            "severity": "High",
                            "line_number": "Unknown",  # Line numbers are not available when parsing HCL
                            "line_content": f"Password: {resource_body['password']}",
                            "service": "Database",
                            "recommendation": "Avoid hardcoding passwords. Consider using a secure method to store and retrieve passwords, such as AWS Secrets Manager or HashiCorp Vault."
                        }
                        insecure_services.append(insecure_service)

    return insecure_services



def test_check_for_security_issues(file_path):
    """
    Checks for security issues in the specified Terraform file.

    Parameters:
    file_path (str): The path to the file to check.

    Returns:
    List of dictionaries: A list of dictionaries containing the issue details, including issue, severity, line number, and recommendation.
    """
    if not os.path.exists(file_path):
        return []  # File does not exist, return empty list

    results = []

    with open(file_path, 'r') as file:
        lines = file.readlines()
    with open(file_path, 'r') as file:
        content = file.read()
    ip_regex = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"

    for i, line in enumerate(lines):
        matches = re.findall(ip_regex, line)
        for match in matches:
            results.append({
                "issue": "Hardcoded IPs or Domains",
                "severity": "High",
                "line_number": i + 1,
                "recommendation": "Avoid hardcoding IP addresses or domain names. Use variables or other secure mechanisms."
            })

    # Check for unrestricted ingress
    ingress_regex = r"cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]"
    match = re.search(ingress_regex, content)
    if match:
        match_group = match.group()
        line_number = content[:content.index(match_group)].count('\n') + 1
        results.append({
            "issue": "Unrestricted ingress",
            "severity": "Medium",
            "line_number": line_number,
            "recommendation": "Avoid using unrestricted ingress rules. Restrict access to specific IP ranges or security groups."
        })


    # Check for deprecated software/services
    deprecated_regex = r"(?i)deprecated|no_longer_maintained|insecure"
    match = re.search(deprecated_regex, content)
    if match:
        match_group = match.group()
        line_number = content[:content.index(match_group)].count('\n') + 1
        results.append({
            "issue": "Use of deprecated or insecure software/services",
            "severity": "Medium",
            "line_number": line_number,
            "recommendation": "Avoid using deprecated or insecure software/services. Use supported and secure alternatives."
        })

    # Check for encryption configuration
    encryption_regex = r"(?i)encrypted\s*=\s*true"
    if not re.search(encryption_regex, content):
        results.append({
            "issue": "Missing encryption configuration",
            "severity": "Medium",
            "line_number": 1,
            "recommendation": "Enable encryption for data storage resources (e.g., databases, S3 buckets) to protect sensitive data."
        })

    # Check for logging and monitoring configuration
    logging_regex = r"(?i)logging|monitoring"
    if not re.search(logging_regex, content):
        results.append({
            "issue": "Missing logging and monitoring configuration",
            "severity": "Low",
            "line_number": 1,
            "recommendation": "Enable appropriate logging and monitoring configurations (e.g., AWS CloudTrail) for better visibility and security."
        })

    # Check for overly permissive IAM policies
    iam_policies_regex = r"(?i)effect\s*=\s*\"allow\"\s*\n\s*actions\s*=\s*\[\"(?:\*|.*:\*)\"\]\s*\n\s*resources\s*=\s*\[\"(?:\*|.*:\*)\"\]\s*\n"
    if re.search(iam_policies_regex, content):
        results.append({
            "issue": "Overly permissive IAM policies",
            "severity": "High",
            "line_number": content.index(re.search(iam_policies_regex, content).group()),
            "recommendation": "Avoid granting overly permissive IAM policies. Apply the principle of least privilege and restrict permissions to the necessary actions and resources."
        })

    # Check for unused resources
    resource_regex = r"resource\s+\"[^\"].+?\""
    resource_references = re.findall(resource_regex, content)
    resource_declarations = re.findall(r"(?<!#)resource\s+\"[^\"].+?\"", content)
    unused_resources = [resource for resource in resource_declarations if resource not in resource_references]
    for unused_resource in unused_resources:
        results.append({
            "issue": "Unused resource",
            "severity": "Medium",
            "line_number": content.index(unused_resource),
            "recommendation": "Remove unused resources to reduce potential attack surface and improve maintainability."
        })

    # Check for sensitive data exposure
    sensitive_data_regex = r"(?i)(?:password|secret|key|token)\s*=\s*\"[^\"].*?\""
    sensitive_data_matches = re.finditer(sensitive_data_regex, content)
    for match in sensitive_data_matches:
        results.append({
            "issue": "Sensitive data exposure",
            "severity": "High",
            "line_number": content[:match.start()].count('\n') + 1,
            "recommendation": "Avoid exposing sensitive data. Store credentials and secrets securely using tools like secrets managers or parameter stores."
        })

    cloud_service_regex = r"(?i)aws_[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\."
    cloud_service_matches = re.finditer(cloud_service_regex, content)
    for match in cloud_service_matches:
        results.append({
            "issue": "Cloud service misconfiguration",
            "severity": "Medium",
            "line_number": content[:match.start()].count('\n') + 1,
            "recommendation": "Ensure proper configuration of cloud services (e.g., AWS S3 buckets, databases) to enforce security controls and prevent unauthorized access."
        })


    insecure_communication_regex = r"(?i)protocol\s*=\s*\"http\""
    if re.search(insecure_communication_regex, content):
        match = re.search(insecure_communication_regex, content)
        results.append({
            "issue": "Insecure communication",
            "severity": "Medium",
            "line_number": content[:match.start()].count('\n') + 1,
            "recommendation": "Use secure communication protocols (e.g., HTTPS) instead of plain HTTP to protect data in transit."
        })

    version_control_exclude_regex = r"(?i)exclude\s*=\s*\[\".+\"\]"
    if re.search(version_control_exclude_regex, content):
        match = re.search(version_control_exclude_regex, content)
        results.append({
            "issue": "Version control exclusions",
            "severity": "Low",
            "line_number": content[:match.start()].count('\n') + 1,
            "recommendation": "Avoid excluding Terraform files or directories from version control. Ensure all code changes are tracked and reviewed for security."
        })


    return results


# Define the mappings outside of the function to make it easy to update
UNENCRYPTED_PROTOCOL_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    23: "Telnet",
    80: "HTTP",
    110: "POP3 (Use secure version: POP3S)",
    135: "Microsoft RPC (potential for numerous vulnerabilities)",
    137: "NetBIOS Name Service (potential for information leaks and DoS attacks)",
    138: "NetBIOS Datagram Service (potential for information leaks and DoS attacks)",
    139: "NetBIOS Session Service/SMB (potential for numerous vulnerabilities, use SMB over IP, port 445)",
    161: "SNMP (potential for information leaks, use SNMPv3)",
    389: "LDAP (Use secure version: LDAPS on port 636)",
    443: "HTTPS (potential for vulnerabilities if SSL/TLS versions are not kept up-to-date)",
    445: "Microsoft SMB over IP (potential for numerous vulnerabilities if not secured)",
    515: "Line Printer Daemon (potential for numerous vulnerabilities)",
    1433: "Microsoft SQL Server (potential for numerous vulnerabilities if not secured)",
    1521: "Oracle Database Server (potential for numerous vulnerabilities if not secured)",
    2049: "Network File System (NFS, potential for numerous vulnerabilities if not secured)",
    3306: "MySQL (potential for numerous vulnerabilities if not secured)",
    3389: "Microsoft RDP (potential for numerous vulnerabilities if not secured)",
    5432: "PostgreSQL (potential for numerous vulnerabilities if not secured)",
    5900: "VNC (potential for numerous vulnerabilities if not secured)",
    6000: "X11 (potential for numerous vulnerabilities if not secured)"
}

def test_warn_if_unencrypted_network_protocols(file_paths):
    insecure_network_protocols = []
    
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            continue

        with open(file_path, "r") as f:
            terraform_code = hcl.load(f)

        # Check each resource in the file
        for resource_type, resource_list in terraform_code.get('resource', {}).items():
            for resource_name, resource_body in resource_list.items():

                # Check AWS security groups for insecure ingress ports
                if resource_type == 'aws_security_group':
                    for ingress in resource_body.get('ingress', []):
                        from_port = ingress.get('from_port')
                        to_port = ingress.get('to_port')

                        # Check if the ports are insecure
                        if from_port in UNENCRYPTED_PROTOCOL_PORTS or to_port in UNENCRYPTED_PROTOCOL_PORTS:
                            unencrypted_protocol = {
                                "issue": f"Potentially unencrypted or unauthenticated network protocol found in resource {resource_name} of type {resource_type} in file: {file_path}",
                                "severity": "High",
                                "line_number": "Unknown",  # Line numbers are not available when parsing HCL
                                "line_content": f"From port: {from_port}, To port: {to_port}",
                                "protocol": UNENCRYPTED_PROTOCOL_PORTS.get(from_port, UNENCRYPTED_PROTOCOL_PORTS.get(to_port)),
                                "recommendation": "Replace the unencrypted protocol with a secure protocol."
                            }
                            insecure_network_protocols.append(unencrypted_protocol)


import re
import logging

logging.basicConfig(level=logging.INFO)

def detect_weak_passwords_in_line(line, line_num):
    password_pattern = re.compile(r'password\s*=\s*("|\'|\`)[^\s("|\'|\`)]*\1')
    password_matches = password_pattern.findall(line)

    results = []
    for match in password_matches:
        results.append({
            "issue": "Weak password detected",
            "severity": "High",
            "line_number": line_num,
            "context": line.strip(),
            "recommendation": "Use a strong and complex password or passphrase."
        })
    return results

def detect_weak_secrets_in_line(line, line_num, secrets):
    results = []
    for secret in secrets:
        if secret in line and not line.strip().startswith("#"):  # exclude comments
            results.append({
                "issue": "Found weak secret",
                "severity": "High",
                "line_number": line_num,
                "context": line.strip(),
                "recommendation": "Store secrets in a secure and encrypted location (e.g. AWS Secrets Manager), and use appropriate access controls to protect them."
            })
    return results

def analyze_file_for_weak_passwords_and_secrets(file_path):
    """
    Checks for weak secrets in Terraform file.

    Returns:
        A list of recommendations for fixing the issue.
    """
    secrets = ["password", "pwd", "secret", "access_key", "secret_key", "private_key", "ssh_key"]
    results = []

    try:
        with open(file_path, "r") as f:
            for line_num, line in enumerate(f, 1):
                results.extend(detect_weak_passwords_in_line(line, line_num))
                results.extend(detect_weak_secrets_in_line(line, line_num, secrets))
    except FileNotFoundError:
        logging.error(f"File {file_path} not found.")
    except IOError:
        logging.error(f"Could not open file {file_path}.")

    return results

import re
import logging

logging.basicConfig(level=logging.INFO)

def test_warn_if_insecure_config(file_path):
    insecure_patterns = [
        (re.compile(pattern, re.I), message, severity) for pattern, message, severity in [
        (r'(?i)\bmd5\b', "Use of insecure hash function", "High"),
        (r'(?i)\bsha1\b', "Use of insecure hash function", "High"),
        (r'(?i)\brc4\b', "Use of insecure encryption algorithm", "High"),
        (r'(?i)\btls1\b', "Use of insecure network protocol", "High"),
        (r'(?i)\bssl2\b', "Use of insecure network protocol", "High"),
        (r'(?i)\bssl3\b', "Use of insecure network protocol", "High"),
        (r'(?i)\bdes\b', "Use of weak encryption algorithm", "Medium"),
        (r'(?i)\brc2\b', "Use of weak encryption algorithm", "Medium"),
        (r'(?i)\bplaintext\b', "Use of plaintext data transmission", "High"),
        (r'(?i)\bftp\b', "Use of insecure network protocol", "High"),
        (r'(?i)\btelnet\b', "Use of insecure network protocol", "High"),
        (r'(?i)\brlogin\b', "Use of insecure network protocol", "High"),
        (r'(?i)\brsh\b', "Use of insecure network protocol", "High"),
        (r'(?i)\btftp\b', "Use of insecure network protocol", "High"),
        (r'(?i)\bsendmail\b', "Use of insecure email server", "Medium"),
        (r'(?i)\bsmtp\b', "Use of insecure email server", "Medium"),
        (r'(?i)\bxp_cmdshell\b', "Use of insecure command shell", "High"),
        (r'(?i)\bexec\b', "Use of insecure command execution", "High"),
        (r'(?i)\bshell\b', "Use of insecure command shell", "High"),
        (r'(?i)\bxp_regwrite\b', "Use of insecure registry write", "High"),
        (r'(?i)\bxp_regdelete\b', "Use of insecure registry delete", "High"),
        (r'(?i)\bxp_fileexist\b', "Use of insecure file existence check", "Medium"),
        (r'(?i)\bxp_filecopy\b', "Use of insecure file copy", "Medium"),
        (r'\b(api_key|api_secret|password|secret|token)\s*=\s*("|\'|\`)[^\s("|\'|\`)]*\1', "Hardcoded secrets found", "High"),
        (r'\bchmod\s+[467][0-7][0-7]', "Insecure file permissions", "Medium"),
        (r'\bTRACE\b', "Use of insecure HTTP method", "Medium"),
        (r'\bTRACK\b', "Use of insecure HTTP method", "Medium"),
        ]
    ]

    unique_results = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')

            for i, line in enumerate(lines, start=1):
                if line.strip().startswith("#"):  # ignore comments
                    continue

                for insecure_pattern, message, severity in insecure_patterns:
                    if insecure_pattern.search(line):
                        result = {
                            'line_number': i,
                            'recommendation': message,
                            'severity': severity,
                            'issue': 'Config issue found',
                            'context': line.strip(),
                        }
                        unique_results.add(frozenset(result.items()))
    except FileNotFoundError:
        logging.error(f"File {file_path} not found.")
    except IOError:
        logging.error(f"Could not open file {file_path}.")
    except UnicodeDecodeError:
        logging.error(f"File {file_path} is not in UTF-8 format.")

    return sorted((dict(item) for item in unique_results), key=lambda x: x['line_number'])

from typing import List, Dict, Union
import hcl

def test_check_for_unintended_destruction(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Parse the Terraform file and identify any resources or data that may be unintentionally destroyed.
    Return a list of dictionaries, where each dictionary represents an issue found in the file.
    Each dictionary contains the keys "issue", "severity", "line_number", and "recommendation".

    Args:
        file_path (str): The path to the Terraform file.
        severity_levels (Dict[str, str]): A dictionary specifying the severity levels for different issues.

    Returns:
        A list of dictionaries, where each dictionary represents an issue found in the file.
    """
    # Define custom severity levels for different issues
    severity_levels = {
        "Unintended resource destruction detected": "High",
        "Unintended data destruction detected": "High"
    }

    with open(file_path, "r") as f:
        data = f.read()
        parsed_data = hcl.loads(data)

    issues = []
    process_blocks(parsed_data, issues, severity_levels)

    return issues

def process_blocks(blocks, issues, severity_levels, parent_path="", parent_line_number=0):
    if isinstance(blocks, dict):  # Add this line to check if blocks is a dictionary
        for block_type, block_list in blocks.items():
            for block in block_list:
                if isinstance(block, dict):  # Add this line to check if block is a dictionary
                    block_id = block.get('_terraform_id')
                    if isinstance(block_id, list) and len(block_id) > 0:
                        block_path = f"{parent_path}.{block_type}[{block_id[0]}]"
                    else:
                        block_path = f"{parent_path}.{block_type}"

                    line_number = block["_terraform_id"][1] + parent_line_number
                    process_lifecycle(block, block_path, line_number, issues, severity_levels)
                    if "resource" in block:
                        process_blocks(block["resource"], issues, severity_levels, block_path, line_number)
                    if "data" in block:
                        process_blocks(block["data"], issues, severity_levels, block_path, line_number)


def process_lifecycle(block, block_path, line_number, issues, severity_levels):
    if block.get("lifecycle") and block["lifecycle"].get("prevent_destroy"):
        issue_type = "Unintended resource destruction detected" if block.get("resource") else "Unintended data destruction detected"
        severity = severity_levels.get(issue_type, "High")
        recommendation = f"Check if the 'prevent_destroy' argument is intended for {block_path}."
        issues.append({
            "issue": issue_type,
            "severity": severity,
            "line_number": line_number,
            "recommendation": recommendation
        })


