from typing import List, Dict, Union
from hcl import loads as parse_hcl

def test_suggest_security_improvements(file_path: str) -> List[Dict[str, Union[str, int]]]:
    """
    Check the given Terraform file for security vulnerabilities and suggest improvements.
    """
    results = []

    try:
        with open(file_path, "r") as f:
            data = f.read()
            parsed_data = parse_hcl(data)
            resource_blocks = parsed_data.get("resource", [])
            
            for block in resource_blocks:
                if is_aws_resource(block):
                    security_issues = get_security_issues(block)
                    results.extend(security_issues)
    
    except Exception as e:
        error_message = str(e)
     

    return results

def is_aws_resource(block):
    if isinstance(block, dict):
        return block.get("provider") and block.get("type") and block.get("provider")[0] == "aws"
    return False


def get_security_issues(block):
    issues = []
    
    deprecated_resources = {
        "aws_security_group_rule": {
            "issue": "Ingress and egress rules are too permissive",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the ingress and egress rules for {block['type']} "
                              f"at line {block['lineno']} and limit access to the minimum "
                              f"required for your use case."
        },
        "aws_s3_bucket_policy": {
            "issue": "S3 bucket policy is too permissive",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the S3 bucket policy at line {block['lineno']} and "
                              f"limit access to the minimum required for your use case."
        },
        "aws_db_instance": {
            "issue": "RDS instance is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible, or use a private subnet."
        },
        "aws_ssm_parameter": {
            "issue": "Sensitive data is stored in plaintext",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} "
                              f"and encrypt the parameter value or use SSM Parameter Store's "
                              f"SecureString parameter type."
        },
        "aws_db_password": {
            "issue": "Database password is stored in plaintext",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and "
                              f"update it to use AWS Secrets Manager to store and manage "
                              f"secrets securely."
        },
        "aws_iam_user_login_profile": {
            "issue": "IAM user login profile with password",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and "
                              f"consider using IAM user access keys instead of password-based login profiles."
        },
         "aws_ebs_volume": {
            "issue": "EBS volume has public access",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"it is not publicly accessible. Restrict access to the required resources."
        },
        "aws_redshift_cluster": {
            "issue": "Redshift cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible. Use appropriate security groups "
                              f"and VPC settings to restrict access."
        },
                "aws_rds_cluster": {
            "issue": "RDS cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible, or use a private subnet."
        },
        "aws_s3_bucket_acl": {
            "issue": "S3 bucket ACL allows public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the bucket ACL does not allow public access. Restrict access to authorized entities."
        },
        "aws_lambda_function": {
            "issue": "Lambda function has excessive permissions",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and limit the permissions "
                              f"granted to the function. Follow the principle of least privilege."
        },
        "aws_cloudfront_distribution": {
            "issue": "CloudFront distribution allows public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the distribution is properly configured to restrict access to authorized users."
        },
                "aws_sqs_queue_policy": {
            "issue": "SQS queue policy allows public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the queue policy restricts access to authorized entities only."
        },
        "aws_kms_key": {
            "issue": "KMS key is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible. Limit access to authorized users or roles."
        },
        "aws_api_gateway_rest_api": {
            "issue": "API Gateway REST API allows public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the API Gateway REST API is properly secured with appropriate authorization mechanisms."
        },
        "aws_athena_named_query": {
            "issue": "Athena named query allows public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the named query is properly secured with appropriate access controls."
        },
        "aws_elasticsearch_domain": {
            "issue": "Elasticsearch domain has public access",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"it is not publicly accessible. Configure access policies "
                              f"and VPC settings to restrict access."
        },
                "aws_cloudfront_origin_access_identity": {
            "issue": "CloudFront origin access identity is not used",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"the CloudFront distribution is configured to use an origin access identity "
                              f"for improved access control and security."
        },
        "aws_neptune_cluster": {
            "issue": "Neptune cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible. Restrict access to authorized entities only."
        },
        "aws_eks_cluster": {
            "issue": "EKS cluster has public access enabled",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"public access is disabled for the EKS cluster to prevent unauthorized access."
        },
        "aws_rds_cluster": {
            "issue": "RDS cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the {block['type']} at line {block['lineno']} to "
                              f"not be publicly accessible. Restrict access to authorized entities only."
        },
                "aws_cloudtrail": {
            "issue": "CloudTrail is not enabled or properly configured",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure that "
                              f"CloudTrail is enabled and properly configured to capture all necessary "
                              f"API activities for auditing and security purposes."
        },
        "aws_sqs_queue_policy": {
            "issue": "SQS queue policy is too permissive",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the SQS queue policy at line {block['lineno']} and "
                              f"limit access to the minimum required for your use case."
        },
        "aws_glue_security_configuration": {
            "issue": "Glue security configuration is not properly configured",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the {block['type']} at line {block['lineno']} and ensure "
                              f"that appropriate security configurations are in place for Glue jobs "
                              f"and crawlers."
        },
        "aws_elasticache_security_group": {
            "issue": "ElastiCache security group is too permissive",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the ElastiCache security group at line {block['lineno']} and "
                              f"limit access to the minimum required for your use case."
        },
        "aws_iam_user_policy_attachment": {
            "issue": "IAM user policy attachment should be reviewed",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the IAM user policy attachment at line {block['lineno']} and "
                              f"ensure that the attached policies adhere to the principle of least privilege."
        },
                "aws_s3_bucket_acl": {
            "issue": "S3 bucket ACL is too permissive",
            "severity": "Medium",
            "line_number": block["lineno"],
            "recommendation": f"Review the S3 bucket ACL at line {block['lineno']} and "
                              f"limit access to the minimum required for your use case."
        },
        "aws_dms_endpoint": {
            "issue": "DMS endpoint is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the DMS endpoint at line {block['lineno']} to "
                              f"not be publicly accessible, or use a private subnet."
        },
        "aws_kms_key": {
            "issue": "KMS key policy is too permissive",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Review the KMS key policy at line {block['lineno']} and "
                              f"limit access to the minimum required for your use case."
        },
        "aws_rds_cluster": {
            "issue": "RDS cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the RDS cluster at line {block['lineno']} to "
                              f"not be publicly accessible, or use a private subnet."
        },
        "aws_neptune_cluster": {
            "issue": "Neptune cluster is publicly accessible",
            "severity": "High",
            "line_number": block["lineno"],
            "recommendation": f"Update the Neptune cluster at line {block['lineno']} to "
                              f"not be publicly accessible, or use a private subnet."
        }


    }

    resource_type = block["type"]
    if resource_type in deprecated_resources:
        issues.append(deprecated_resources[resource_type])

    return issues

