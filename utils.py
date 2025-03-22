"""
Utility functions for AWS Permission Toolkit.
"""
import json
import boto3
import re
import datetime
import os
from botocore.exceptions import ClientError

def format_json(data):
    """
    Format JSON data with proper indentation.
    
    Args:
        data (dict): JSON data to format
        
    Returns:
        str: Formatted JSON string
    """
    return json.dumps(data, indent=2, default=str)

def safe_api_call(client, operation_name, **kwargs):
    """
    Make an AWS API call safely, handling exceptions.
    
    Args:
        client: Boto3 client object
        operation_name (str): Name of the operation to call
        **kwargs: Arguments to pass to the operation
        
    Returns:
        tuple: (result, error_message)
    """
    try:
        method = getattr(client, operation_name)
        result = method(**kwargs)
        return result, None
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        return None, f"{error_code}: {error_message}"
    except Exception as e:
        return None, str(e)

def get_aws_account_id(session):
    """
    Get the AWS account ID from the current session.
    
    Args:
        session: Boto3 session object
        
    Returns:
        str: AWS account ID or None if not available
    """
    try:
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        return identity.get('Account')
    except Exception:
        return None

def get_timestamp():
    """
    Get the current timestamp in a format suitable for filenames.
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

def create_output_filename(prefix, extension="json"):
    """
    Create a filename with timestamp.
    
    Args:
        prefix (str): Filename prefix
        extension (str): File extension (default: json)
        
    Returns:
        str: Filename with timestamp
    """
    timestamp = get_timestamp()
    return f"{prefix}_{timestamp}.{extension}"

def generate_resource_filename(resource_type, resource_name, region=None, account_id=None):
    """
    Generate a standardized filename for a resource.
    
    Args:
        resource_type (str): Type of resource
        resource_name (str): Name of resource
        region (str): AWS region
        account_id (str): AWS account ID
        
    Returns:
        str: Standardized filename
    """
    timestamp = get_timestamp()
    
    # Make resource name safe for filenames
    safe_name = re.sub(r'[^\w\-\.]', '_', resource_name)
    
    # Build filename components
    components = [timestamp, safe_name]
    
    if region:
        components.append(region)
        
    if account_id:
        components.append(account_id)
        
    return '_'.join(components) + '.json'

def save_to_file(data, filepath):
    """
    Save data to a JSON file.
    
    Args:
        data: Data to save
        filepath (str): Path to save the file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error saving file: {e}")
        return False

def is_valid_arn(arn):
    """
    Check if a string is a valid AWS ARN.
    
    Args:
        arn (str): String to check
        
    Returns:
        bool: True if valid ARN, False otherwise
    """
    if not arn or not isinstance(arn, str):
        return False
        
    # Basic ARN pattern
    pattern = r'^arn:aws(-[a-z]+)?:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:[0-9]{12}:[a-zA-Z0-9-_/:.]+$'
    return bool(re.match(pattern, arn))

def get_service_from_arn(arn):
    """
    Extract the service name from an ARN.
    
    Args:
        arn (str): ARN to parse
        
    Returns:
        str: Service name or None if invalid ARN
    """
    if not is_valid_arn(arn):
        return None
        
    # ARN format: arn:partition:service:region:account-id:resource
    parts = arn.split(':')
    if len(parts) >= 3:
        return parts[2]
    return None

def kebab_to_snake(kebab_str):
    """
    Convert kebab-case to snake_case.
    
    Args:
        kebab_str (str): String in kebab-case
        
    Returns:
        str: String in snake_case
    """
    return kebab_str.replace('-', '_')

def snake_to_kebab(snake_str):
    """
    Convert snake_case to kebab-case.
    
    Args:
        snake_str (str): String in snake_case
        
    Returns:
        str: String in kebab-case
    """
    return snake_str.replace('_', '-')