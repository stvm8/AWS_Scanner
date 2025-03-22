"""
Further enumeration of IAM resources discovered during permission scanning.
"""
import boto3
import json
import os
import datetime
from botocore.exceptions import ClientError
from .arn_extractor import parse_arn

blue = '\033[94m'
cyan = '\033[96m'
green = '\033[92m'
red = '\033[91m'
bold = '\033[1m'
yellow = "\033[93m"
reset = "\033[0m"

def extract_findings(resource_results, resource_type, resource_name):
    """
    Extract findings from resource enumeration results.
    
    Args:
        resource_results (dict): Enumeration results for a resource
        resource_type (str): Resource type (user, role, group)
        resource_name (str): Resource name
        
    Returns:
        list: List of findings
    """
    findings = []
    
    # Get policy versions if available
    policy_versions = resource_results.get('policy_versions', {})
    
    # Extract region from results if available
    region = resource_results.get('region', 'global')
    
    # Check for policies
    for policy_tuple in resource_results.get('policies', []):
        policy_type = policy_tuple[0]
        policy_name = policy_tuple[1]
        policy_arn = policy_tuple[2]
        
        if policy_type == 'attached':
            # For attached policies, simply add the ARN as extra info
            # The versions will be displayed in the "Value" column
            value = policy_name
            if policy_name in policy_versions:
                value = f"{policy_name}\nVersions: {policy_versions[policy_name]}"
            
            findings.append({
                'finding_type': 'Attached Policy',
                'resource_type': resource_type,
                'resource_name': resource_name,
                'detail_type': 'Policy Name',
                'detail_value': value,
                'extra_info': f"{policy_arn}\n(Region: {region})"
            })
        elif policy_type in ['inline', 'inline_content']:
            findings.append({
                'finding_type': 'Inline Policy',
                'resource_type': resource_type,
                'resource_name': resource_name,
                'detail_type': 'Policy Name',
                'detail_value': policy_name,
                'extra_info': f"No ARN (inline) (Region: {region})"
            })
    
    # Check for operations results
    for op_name, op_result in resource_results.get('operations', {}).items():
        if op_result.get('status') != 'success':
            continue
            
        response = op_result.get('response', {})
        
        # Handle specific operations
        if op_name == 'list-access-keys' and 'AccessKeyMetadata' in response:
            for key in response['AccessKeyMetadata']:
                findings.append({
                    'finding_type': 'Access Key',
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'detail_type': 'Access Key ID',
                    'detail_value': key.get('AccessKeyId', 'Unknown'),
                    'extra_info': f"Status: {key.get('Status', 'Unknown')} (Region: {region})"
                })
                
        elif op_name == 'list-groups-for-user' and 'Groups' in response:
            for group in response['Groups']:
                findings.append({
                    'finding_type': 'Group Membership',
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'detail_type': 'Group Name',
                    'detail_value': group.get('GroupName', 'Unknown'),
                    'extra_info': f"{group.get('Arn', 'No ARN')} (Region: {region})"
                })
                
        elif op_name == 'get-login-profile' and 'LoginProfile' in response:
            findings.append({
                'finding_type': 'Console Access',
                'resource_type': resource_type,
                'resource_name': resource_name,
                'detail_type': 'Password Last Used',
                'detail_value': response['LoginProfile'].get('CreateDate', 'Unknown'),
                'extra_info': f"Password Reset Required: {response['LoginProfile'].get('PasswordResetRequired', 'Unknown')} (Region: {region})"
            })
            
        elif op_name == 'list-instance-profiles-for-role' and 'InstanceProfiles' in response:
            for profile in response['InstanceProfiles']:
                findings.append({
                    'finding_type': 'Instance Profile',
                    'resource_type': resource_type,
                    'resource_name': resource_name,
                    'detail_type': 'Profile Name',
                    'detail_value': profile.get('InstanceProfileName', 'Unknown'),
                    'extra_info': f"{profile.get('Arn', 'No ARN')}-(Region: {region})"
                })
    
    return findings

def print_findings_summary(findings):
    """
    Print a summary table of all findings.
    
    Args:
        findings (list): List of findings
    """
    if not findings:
        print("\nNo significant findings discovered.")
        return
    
    try:
        # Try to use rich for nicer tables
        from rich.console import Console
        from rich.table import Table
        from rich import box
        
        console = Console()
        table = Table(title="\nIAM Enumeration Findings", show_lines=True, box=box.ROUNDED)
        
        # Add columns with appropriate width
        table.add_column("Finding Type", style="cyan", justify="left")
        table.add_column("Resource", style="green", justify="left")
        table.add_column("Detail Type", style="yellow", justify="left")
        table.add_column("Value", style="white", justify="left")
        table.add_column("Additional Info", style="magenta", justify="left")
        
        # Add rows
        for finding in findings:
            table.add_row(
                finding.get('finding_type', 'Unknown'),
                f"{finding.get('resource_type', 'Unknown')}: {finding.get('resource_name', 'Unknown')}",
                finding.get('detail_type', 'Unknown'),
                finding.get('detail_value', 'Unknown'),
                finding.get('extra_info', '')
            )
        
        # Print the table
        console.print("\nFindings Summary:")
        console.print(table)
        console.print("\n*** It is recommended to check for all policy versions as it might contain hidden information.", style="italic")
        
    except ImportError:
        # Fall back to ASCII table if rich is not available
        print("\nFindings Summary:")
        print("-" * 120)
        print("| {:<15} | {:<20} | {:<15} | {:<30} | {:<30} |".format(
            "Finding Type", "Resource", "Detail Type", "Value", "Additional Info"))
        print("-" * 120)
        
        for finding in findings:
            resource = f"{finding.get('resource_type', 'Unknown')}: {finding.get('resource_name', 'Unknown')}"
            detail_value = finding.get('detail_value', 'Unknown')
            extra_info = finding.get('extra_info', '')
            
            # Handle long values
            if len(extra_info) > 30:
                # Split into multiple lines
                first_line = extra_info[:30]
                remaining = extra_info[30:]
                
                print("| {:<15} | {:<20} | {:<15} | {:<30} | {:<30} |".format(
                    finding.get('finding_type', 'Unknown'),
                    resource,
                    finding.get('detail_type', 'Unknown'),
                    detail_value,
                    first_line))
                
                # Print additional lines for long content
                for i in range(0, len(remaining), 30):
                    chunk = remaining[i:i+30]
                    print("| {:<15} | {:<20} | {:<15} | {:<30} | {:<30} |".format(
                        "", "", "", "", chunk))
            else:
                print("| {:<15} | {:<20} | {:<15} | {:<30} | {:<30} |".format(
                    finding.get('finding_type', 'Unknown'),
                    resource,
                    finding.get('detail_type', 'Unknown'),
                    detail_value,
                    extra_info))
            
        print("-" * 120)

def ask_for_further_enumeration(discovered_arns, profile_name=None, region_name=None):
    """
    Ask user if they want to further enumerate discovered IAM resources.
    
    Args:
        discovered_arns (set): Set of discovered ARNs
        profile_name (str): AWS profile name
        region_name (str): AWS region name
    
    Returns:
        tuple: (results, policies)
    """
    # Filter IAM ARNs
    iam_arns = []
    for arn in discovered_arns:
        if ':iam:' in arn:
            iam_arns.append(arn)
    
    if not iam_arns:
        print("No IAM resources discovered for further enumeration.")
        return {}, []
    
    # Parse ARNs to get resource types and names
    iam_resources = []
    for arn in iam_arns:
        service, resource_type, resource_name, _, _ = parse_arn(arn)
        if service == 'iam' and resource_type and resource_name:
            iam_resources.append((resource_type, resource_name, arn))
    
    if not iam_resources:
        print("No valid IAM resources discovered for further enumeration.")
        return {}, []
    
    # Display discovered resources
    print("\nDiscovered IAM resources:")
    for i, (res_type, res_name, _) in enumerate(iam_resources, 1):
        print(f"{i}. {yellow}{res_type}{reset}: {res_name}")
    
    # Ask if user wants to enumerate further
    choice = input("\nDo you want to enumerate these resources further? (y/n): ")
    if choice.lower() != 'y':
        return {}, []
    
    # Create session
    session_kwargs = {}
    if profile_name:
        session_kwargs['profile_name'] = profile_name
    if region_name:
        session_kwargs['region_name'] = region_name
    
    session = boto3.Session(**session_kwargs)
    
    # Store region for findings
    current_region = region_name or session.region_name or 'global'
    
    # Load IAM operations
    iam_operations = load_iam_operations()
    
    # Enumerate each resource
    results = {}
    policies = []
    all_findings = []
    
    for res_type, res_name, arn in iam_resources:
        res_operations = iam_operations.get(res_type, {})
        if not res_operations:
            continue
        
        print(f"\nEnumerating {res_type}: {res_name}...")
        resource_results = enumerate_iam_resource(session, res_type, res_name, res_operations)
        
        # Add region to resource results
        resource_results['region'] = current_region
        
        # Use string key instead of tuple
        key = f"{res_type}:{res_name}"
        results[key] = resource_results
        
        # Collect policies for policy_reader
        if 'policies' in resource_results:
            policies.extend(resource_results['policies'])
            
        # Collect findings for summary table
        findings = extract_findings(resource_results, res_type, res_name)
        all_findings.extend(findings)
    
    # Display summary table of findings
    print_findings_summary(all_findings)
    
    return results, policies

def load_iam_operations():
    """
    Load IAM operations for further enumeration.
    
    Returns:
        dict: IAM operations by resource type
    """
    # Default IAM operations
    default_operations = {
        "user": {
            "list-attached-user-policies": {"param_name": "UserName"},
            "list-user-policies": {"param_name": "UserName"},
            "list-groups-for-user": {"param_name": "UserName"},
            "get-user": {"param_name": "UserName"},
            "list-access-keys": {"param_name": "UserName"},
            "get-login-profile": {"param_name": "UserName"}
        },
        "role": {
            "list-attached-role-policies": {"param_name": "RoleName"},
            "list-role-policies": {"param_name": "RoleName"},
            "get-role": {"param_name": "RoleName"},
            "list-instance-profiles-for-role": {"param_name": "RoleName"}
        },
        "group": {
            "list-attached-group-policies": {"param_name": "GroupName"},
            "list-group-policies": {"param_name": "GroupName"},
            "get-group": {"param_name": "GroupName"}
        },
        "policy": {
            "get-policy": {"param_name": "PolicyArn"},
            "list-policy-versions": {"param_name": "PolicyArn"}
        }
    }
    
    # Try to load from file if exists
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'iam_operations.json')
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                custom_operations = json.load(f)
                
                # Merge with defaults (custom takes precedence)
                operations = default_operations.copy()
                for res_type, ops in custom_operations.items():
                    if res_type in operations:
                        operations[res_type].update(ops)
                    else:
                        operations[res_type] = ops
                
                return operations
    except Exception as e:
        print(f"Error loading IAM operations file: {e}")
        print("Using default operations instead.")
    
    return default_operations

def enumerate_iam_resource(session, resource_type, resource_name, operations):
    """
    Enumerate an IAM resource using specified operations.
    
    Args:
        session: AWS boto3 session
        resource_type (str): IAM resource type (user, role, group)
        resource_name (str): Resource name
        operations (dict): Operations to perform
    
    Returns:
        dict: Enumeration results including policies
    """
    client = session.client('iam')
    results = {'operations': {}}
    policies = []
    
    # Store policy versions separately to use in findings
    policy_versions = {}
    
    for operation, config in operations.items():
        op_name = operation.replace('-', '_')  # boto3 uses snake_case
        param_name = config.get('param_name', 'Name')
        params = {param_name: resource_name}
        
        try:
            method = getattr(client, op_name)
            response = method(**params)
            results['operations'][operation] = {"status": "success", "response": response}
            
            print(f"  ✓ {operation}")
            
            # Extract policies for policy_reader
            if operation == 'list-attached-user-policies' or operation == 'list-attached-role-policies' or operation == 'list-attached-group-policies':
                for policy in response.get('AttachedPolicies', []):
                    policy_arn = policy.get('PolicyArn')
                    policy_name = policy.get('PolicyName')
                    if policy_arn and policy_name:
                        # Try to list policy versions
                        try:
                            versions_response = client.list_policy_versions(PolicyArn=policy_arn)
                            if 'Versions' in versions_response and versions_response['Versions']:
                                versions = [f"{version.get('VersionId')}" for version in versions_response.get('Versions', [])]
                                versions_str = ", ".join(versions)
                                # Store versions for later use in findings
                                policy_versions[policy_name] = versions_str
                                #print(f"    - Available versions for {policy_name}: {versions_str}")
                        except Exception as e:
                            # Silently ignore version listing errors
                            pass
                            
                        # Add the policy to the list (with or without versions)
                        policies.append(('attached', policy_name, policy_arn, resource_type, resource_name))
            
            elif operation == 'list-user-policies' or operation == 'list-role-policies' or operation == 'list-group-policies':
                for policy_name in response.get('PolicyNames', []):
                    if policy_name:
                        # Add the inline policy to the list
                        policies.append(('inline', policy_name, None, resource_type, resource_name))
                        
                        # Try to get policy document if it's an inline policy
                        if resource_type == 'user':
                            get_policy_op = 'get_user_policy'
                            params = {'UserName': resource_name, 'PolicyName': policy_name}
                        elif resource_type == 'role':
                            get_policy_op = 'get_role_policy'
                            params = {'RoleName': resource_name, 'PolicyName': policy_name}
                        elif resource_type == 'group':
                            get_policy_op = 'get_group_policy'
                            params = {'GroupName': resource_name, 'PolicyName': policy_name}
                        
                        try:
                            policy_method = getattr(client, get_policy_op)
                            policy_response = policy_method(**params)
                            # Update the last added policy with content
                            policies[-1] = ('inline_content', policy_name, None, resource_type, resource_name, policy_response.get('PolicyDocument'))
                        except Exception as e:
                            # Silently ignore policy document retrieval errors
                            pass
            
        except ClientError as e:
            # Store error but don't display it
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            results['operations'][operation] = {"status": "error", "error": f"{error_code}: {error_message}"}
            
        except Exception as e:
            # Store error but don't display it
            results['operations'][operation] = {"status": "error", "error": str(e)}
    
    # Add policy versions to results to use in findings
    results['policy_versions'] = policy_versions
    results['policies'] = policies
    return results