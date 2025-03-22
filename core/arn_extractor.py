"""
ARN extraction and parsing utilities.
"""
import re

def extract_arns_from_error(error_message):
    """
    Extract ARNs from AWS error messages.
    
    Args:
        error_message (str): Error message from AWS API
        
    Returns:
        list: Extracted ARNs
    """
    if not error_message:
        return []
    
    # List to hold all ARNs found
    arns = []
    
    # Pattern to match AWS ARNs
    arn_pattern = r'arn:aws:[\w\-]+:[^:]*:[\d]*:[\w\-\/\.:]+'
    
    # Find all ARNs in the message
    found_arns = re.findall(arn_pattern, error_message)
    
    # Add all unique ARNs to the list
    for arn in found_arns:
        if arn not in arns:
            arns.append(arn)
    
    return arns

def parse_arn(arn):
    """
    Parse an AWS ARN into its components.
    
    Args:
        arn (str): AWS ARN
        
    Returns:
        tuple: (service, resource_type, resource_name, region, account_id)
    """
    # Basic ARN format: arn:partition:service:region:account-id:resource-type/resource-id
    if not arn or ':' not in arn:
        return None, None, None, None, None
    
    # Split the ARN into its components
    parts = arn.split(':')
    if len(parts) < 6:
        return None, None, None, None, None
    
    service = parts[2]
    region = parts[3]
    account_id = parts[4]
    resource = parts[5]
    
    # Handle resource part based on service
    if service == 'iam':
        if '/' in resource:
            resource_type, resource_name = resource.split('/', 1)
            # Handle paths in IAM names
            if '/' in resource_name:
                resource_name = resource_name.split('/')[-1]
            return service, resource_type, resource_name, region, account_id
        else:
            return service, None, resource, region, account_id
    
    elif service == 's3':
        # S3 ARNs have a different format: arn:aws:s3:::bucket-name[/object-name]
        if resource.startswith('::'):
            bucket_name = resource[2:]
            if '/' in bucket_name:
                bucket_name, object_name = bucket_name.split('/', 1)
                return service, 'bucket', bucket_name, region, account_id
            else:
                return service, 'bucket', bucket_name, region, account_id
        return service, None, resource, region, account_id
    
    elif service == 'lambda':
        if ':function:' in resource:
            function_name = resource.split(':function:')[1]
            return service, 'function', function_name, region, account_id
        else:
            return service, None, resource, region, account_id
    
    # Handle other services generically
    elif '/' in resource:
        resource_type, resource_name = resource.split('/', 1)
        return service, resource_type, resource_name, region, account_id
    else:
        return service, None, resource, region, account_id