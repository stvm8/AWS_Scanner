"""
Core functions for enumerating AWS permissions.
"""
import boto3
import json
import os
import datetime
import re
import threading
from botocore.exceptions import ClientError

blue = '\033[94m'
green = '\033[92m'
red = '\033[91m'
bold = '\033[1m'
yellow = "\033[93m"
cyan = "\033[96m"
magenta = "\033[95m"
reset = "\033[0m"

# Thread-local storage for better output in parallel mode
thread_local = threading.local()

def enumerate_permissions(profile_name=None, region_name=None, op_file=None, verbose=False, quiet_mode=False):
    """
    Enumerate permissions using AWS CLI/SDK operations.
    
    Args:
        profile_name (str): AWS profile name
        region_name (str): AWS region name
        op_file (str): Path to operations file (JSON)
        verbose (bool): Enable verbose output
        quiet_mode (bool): Minimize console output for multi-region scanning
    
    Returns:
        tuple: (results, discovered_arns)
    """
    # Create a boto3 session
    session_kwargs = {}
    if profile_name:
        session_kwargs['profile_name'] = profile_name
    if region_name:
        session_kwargs['region_name'] = region_name
    
    session = boto3.Session(**session_kwargs)
    
    # Get current region
    current_region = region_name or session.region_name or 'us-east-1'
    
    # Add a region prefix to output in multi-region mode
    region_prefix = f"[{current_region}] " if hasattr(thread_local, 'region') else ""
    
    # Get the caller identity
    try:
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity().get('Account', 'unknown')
        caller_arn = sts_client.get_caller_identity().get('Arn', 'unknown')
        
        if not quiet_mode:
            print(f"{region_prefix}Current identity: {yellow}{caller_arn}{reset}")
            print(f"{region_prefix}Account ID: {yellow}{account_id}{reset}")
            print(f"{region_prefix}Region: {yellow}{current_region}{reset}")
    except Exception as e:
        if not quiet_mode:
            print(f"{region_prefix}Could not get caller identity: {str(e)}")
        account_id = 'unknown'
        caller_arn = 'unknown'
    
    # Load operations
    operations = load_operations(op_file)
    if not operations:
        return {}, set()
    
    # If using default operations, show appropriate message
    if not quiet_mode:
        if not op_file:
            print(f"\n{region_prefix}{bold}Default services and operations:{reset}")
        else:
            print(f"\n{region_prefix}{bold}Operations from {op_file}:{reset}")
        
        # Print a table of operations
        print(f"{region_prefix}" + "=" * 60)
        print(f"{region_prefix}{'Service':<15} {'Operation':<35} {'Status':<10}")
        print(f"{region_prefix}" + "-" * 60)
    
    # Execute operations
    results = {
        'metadata': {
            'timestamp': datetime.datetime.now().isoformat(),
            'profile': profile_name,
            'region': current_region,
            'account_id': account_id,
            'caller_arn': caller_arn
        },
        'operations': {}
    }
    
    # Discovered ARNs from error messages
    discovered_arns = set()
    
    # Track counts
    allowed_count = 0
    denied_count = 0
    
    for operation in operations:
        try:
            service = operation.get('service', '')
            op_name = operation.get('operation', '')
            params = operation.get('params', {})
            description = operation.get('description', f"{service}:{op_name}")
            
            if not service or not op_name:
                if not quiet_mode:
                    print(f"{region_prefix}{red}[!] Invalid operation entry (missing service or operation){reset}")
                continue
            
            # Create a service client
            client = session.client(service)
            
            # Execute the operation
            response = getattr(client, op_name)(**params)
            
            # Store the result
            results['operations'][f"{service}:{op_name}"] = {
                'allowed': True,
                'params': params,
                'response': response if verbose else "Response hidden (use --verbose to see it)"
            }
            
            # Print row in table for successful operation
            if not quiet_mode:
                print(f"{region_prefix}{service:<15} {op_name:<35} {green}Allowed{reset}")
            allowed_count += 1
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            # Check for access denied errors
            if error_code in ['AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation']:
                # Print row in table for denied operation
                if not quiet_mode:
                    print(f"{region_prefix}{service:<15} {op_name:<35} {red}Denied{reset}")
                denied_count += 1
                
                # Store the result
                results['operations'][f"{service}:{op_name}"] = {
                    'allowed': False,
                    'params': params,
                    'error_code': error_code,
                    'error_message': error_message
                }
                
                # Extract ARNs from error message
                arns = extract_arns_from_message(error_message)
                if arns:
                    discovered_arns.update(arns)
                    
            else:
                # Other errors (not access denied)
                # Print row in table for error operation
                if not quiet_mode:
                    print(f"{region_prefix}{service:<15} {op_name:<35} {yellow}Error{reset}")
                denied_count += 1
                
                # Store the result
                results['operations'][f"{service}:{op_name}"] = {
                    'allowed': False,
                    'params': params,
                    'error_code': error_code,
                    'error_message': error_message
                }
                
                # Still check for ARNs in the error
                arns = extract_arns_from_message(error_message)
                if arns:
                    discovered_arns.update(arns)
                    
        except Exception as e:
            # Print row in table for exception
            if not quiet_mode:
                print(f"{region_prefix}{service:<15} {op_name:<35} {yellow}Exception{reset}")
            denied_count += 1
            
            # Store the result
            results['operations'][f"{service}:{op_name}"] = {
                'allowed': False,
                'params': params,
                'error': str(e)
            }
    
    # Close the table
    if not quiet_mode:
        print(f"{region_prefix}" + "=" * 60)
        
        # If using default ops, show message about custom operations
        if not op_file:
            print(f"{region_prefix}{yellow}Use --op_file to specify custom operations.{reset}")
    
    # Add summary counts to results
    results['summary'] = {
        'allowed_count': allowed_count,
        'denied_count': denied_count,
        'total_count': allowed_count + denied_count
    }
    
    return results, discovered_arns

def load_operations(op_file=None):
    """
    Load operations from file or use default.
    
    Args:
        op_file (str): Path to operations file (JSON)
    
    Returns:
        list: Operations to execute
    """
    # Default operations (minimal set)
    default_operations = [
        {"service": "iam", "operation": "list_users", "params": {}, "description": "List IAM users"},
        {"service": "iam", "operation": "list_roles", "params": {}, "description": "List IAM roles"},
        {"service": "iam", "operation": "list_groups", "params": {}, "description": "List IAM groups"},
        {"service": "ec2", "operation": "describe_instances", "params": {}, "description": "List EC2 instances"},
        {"service": "ec2", "operation": "describe_security_groups", "params": {}, "description": "List EC2 security groups"},
        {"service": "sqs", "operation": "list_queues", "params": {}, "description": "List SQS queues"},
        {"service": "lambda", "operation": "list_functions", "params": {}, "description": "List Lambda functions"},
        {"service": "secretsmanager", "operation": "list_secrets", "params": {}, "description": "List Secrets Manager secrets"}
    ]
    
    # Try to load operations from file if provided
    if op_file:
        try:
            print(f"Loading operations from: {op_file}")
            with open(op_file, 'r') as f:
                ops = json.load(f)
                
                if isinstance(ops, list):
                    return ops
                elif isinstance(ops, dict) and 'operations' in ops:
                    return ops['operations']
                else:
                    print(f"{yellow}Warning: Invalid operations file format. Using default operations.{reset}")
                    return default_operations
                    
        except Exception as e:
            print(f"{red}Error loading operations file: {str(e)}{reset}")
            print(f"{yellow}Using default operations instead.{reset}")
            return default_operations
    
    # Use default operations if no file provided
    return default_operations

def extract_arns_from_message(message):
    """
    Extract valid ARNs from error messages.
    
    Args:
        message (str): Error message
        
    Returns:
        set: Set of valid discovered ARNs
    """
    if not message:
        return set()
        
    # ARN pattern regex - more precise to capture valid ARNs
    arn_pattern = r'arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-\/\.]+'
    
    # Find all ARNs in the message
    arns_found = re.findall(arn_pattern, message)
    
    # Filter to ensure we only keep valid ARNs
    valid_arns = set()
    for arn in arns_found:
        # Validate that this is a proper ARN with appropriate structure
        if is_valid_arn(arn):
            valid_arns.add(arn)
    
    return valid_arns

def is_valid_arn(arn):
    """Check if an ARN appears to be valid"""
    # Basic structure validation
    if not arn or len(arn.split(':')) < 6:
        return False
    
    # Get the parts
    parts = arn.split(':')
    
    # Prefix should be "arn"
    if parts[0] != 'arn':
        return False
    
    # Partition should be "aws" or "aws-cn", etc.
    if not parts[1].startswith('aws'):
        return False
    
    # Service should not be empty
    if not parts[2]:
        return False
    
    # Account ID should be 12 digits
    if not parts[4].isdigit() or len(parts[4]) != 12:
        return False
    
    # Resource should not be empty
    if not parts[5]:
        return False
    
    # If we're looking at IAM resources, do a deeper validation
    if parts[2] == 'iam':
        resource_part = parts[5]
        if '/' in resource_part:
            resource_type, resource_name = resource_part.split('/', 1)
            if not resource_type or not resource_name:
                return False
            
            # Common IAM resource types
            valid_types = ['user', 'role', 'group', 'policy', 'instance-profile', 'server-certificate']
            if resource_type not in valid_types:
                return False
                
        return True
        
    return True

def save_results(results, discovered_arns, output_dir):
    """
    Save enumeration results to a file.
    
    Args:
        results (dict): Enumeration results
        discovered_arns (set): Set of discovered ARNs
        output_dir (str): Output directory
        
    Returns:
        str: Path to saved file
    """
    # Create output directory if not exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename with timestamp and region
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    region = results.get('metadata', {}).get('region', 'unknown')
    filename = f"permission_enum_{region}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Add discovered ARNs to results
    results['discovered_arns'] = list(discovered_arns)
    
    # Save to file
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return os.path.abspath(filepath)