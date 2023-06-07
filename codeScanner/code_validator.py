from .security_checks import *
from .complex_checks import *
from .security_improvements import *
from .complexity_analyser import *

def run_terraform_scan(filepath):
    results = []

    # Check for hard-coded IPs or domains
    hardcoded_ips_or_domains = test_check_for_security_issues(filepath)
    if hardcoded_ips_or_domains:
        results.extend(hardcoded_ips_or_domains)

    # Check for insecure file or directory permissions
    insecure_permissions = test_warn_if_insecure_permissions(filepath)
    if insecure_permissions:
        results.extend(insecure_permissions)

    # Check for insecure network protocols
    insecure_network_protocols = test_warn_if_unencrypted_network_protocols(filepath)
    if insecure_network_protocols:
        results.extend(insecure_network_protocols)

    # Check for insecure services
    insecure_services = test_check_for_insecure_services(filepath)
    if insecure_services:
        results.extend(insecure_services)

    # Check for weak secrets
    weak_secrets = analyze_file_for_weak_passwords_and_secrets(filepath)
    if weak_secrets:
        results.extend(weak_secrets)

    # Check for weak config
    weak_config = test_warn_if_insecure_config(filepath)
    if weak_config:
        results.extend(weak_config)

    # Check for duplicate code not working
    duplicate_code = analyze_duplicate_code(filepath)
    if duplicate_code:
        results.extend(duplicate_code)

    # Call suggest_security_improvements and append its results to the results list not working
    suggestions = test_suggest_security_improvements(filepath)
    if suggestions:
        results.extend(suggestions)

    # Check for unintended destruction
    unintended_destruction = test_check_for_unintended_destruction(filepath)
    if unintended_destruction:
        results.extend(unintended_destruction)

    # Check for insecure system access
    insecure_system_access = test_check_for_insecure_system_access(filepath)
    if insecure_system_access:
        results.extend(insecure_system_access)

    # Check for insecure system access
    warn_if_vulnerable_libraries = test_warn_if_vulnerable_libraries(filepath)
    if warn_if_vulnerable_libraries:
        results.extend(warn_if_vulnerable_libraries)

    return results
