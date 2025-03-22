"""
Policy reader and explainer for AWS IAM policies.
"""
import boto3
import json
import os
import datetime
import re

blue = '\033[94m'
cyan = '\033[96m'
green = '\033[92m'
red = '\033[91m'
bold = '\033[1m'
yellow = "\033[93m"
reset = "\033[0m"

def process_policies(policies, session, output_dir=None):
    """
    Process discovered policies - download, save, and explain them.
    
    Args:
        policies (list): List of policy tuples
        session: AWS boto3 session
        output_dir (str): Output directory
    
    Returns:
        list: Processed policy files
    """
    if not policies:
        print("No policies found to process.")
        return []
    
    # Create output directory if specified (default is 'policies')
    if not output_dir:
        output_dir = 'policies'
    os.makedirs(output_dir, exist_ok=True)
    
    client = session.client('iam')
    region = session.region_name or 'us-east-1'
    
    # Try to get caller identity for account ID
    try:
        account_id = session.client('sts').get_caller_identity().get('Account', 'unknown')
    except:
        account_id = 'unknown'
    
    processed_files = []
    allow_s3_list_buckets = False
    # Keep track of already processed policies to avoid duplicates
    processed_policy_names = set()
    
    # Process each policy
    for policy_info in policies:
        if len(policy_info) >= 5:
            policy_type = policy_info[0]
            policy_name = policy_info[1]
            policy_arn = policy_info[2]
            resource_type = policy_info[3]
            resource_name = policy_info[4]
            
            policy_document = None
            
            # Removed policy version listing here - it's now only in further_enum.py
            
            # For inline policies with content
            if policy_type == 'inline_content' and len(policy_info) >= 6:
                policy_document = policy_info[5]
                print(f"\n{green}Processing inline policy: {policy_name} for {resource_type} {resource_name}{reset}")
            
            # For attached policies, get the policy document
            elif policy_type == 'attached' and policy_arn:
                try:
                    print(f"\n{green}Processing attached policy: {policy_name} ({policy_arn}){reset}")
                    policy_response = client.get_policy(PolicyArn=policy_arn)
                    policy_version = policy_response['Policy']['DefaultVersionId']
                    
                    version_response = client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_version
                    )
                    
                    policy_document = version_response['PolicyVersion']['Document']
                except Exception as e:
                    print(f"  ! Error retrieving policy document: {str(e)}")
                    continue
            
            # For inline policies without content, try to get the document
            elif policy_type == 'inline' and not policy_arn:
                try:
                    print(f"\nProcessing inline policy: {policy_name} for {resource_type} {resource_name}")
                    
                    if resource_type == 'user':
                        policy_response = client.get_user_policy(
                            UserName=resource_name,
                            PolicyName=policy_name
                        )
                    elif resource_type == 'role':
                        policy_response = client.get_role_policy(
                            RoleName=resource_name,
                            PolicyName=policy_name
                        )
                    elif resource_type == 'group':
                        policy_response = client.get_group_policy(
                            GroupName=resource_name,
                            PolicyName=policy_name
                        )
                    
                    policy_document = policy_response['PolicyDocument']
                except Exception as e:
                    print(f"  ! Error retrieving policy document: {str(e)}")
                    continue
            
            # Save and explain the policy
            if policy_document:
                # Generate filename
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_name = re.sub(r'[^\w\-\.]', '_', f"{resource_name}_{policy_name}")
                filename = f"{timestamp}_{safe_name}_{region}_{account_id}.json"
                
                # Check if we have already processed this policy (to avoid duplicates)
                unique_policy_id = f"{policy_name}_{resource_type}_{resource_name}"
                if unique_policy_id in processed_policy_names:
                    print(f"\nSkipping duplicate policy: {policy_name}")
                    continue
                
                processed_policy_names.add(unique_policy_id)
                
                # Generate filename without timestamp
                safe_name = re.sub(r'[^\w\-\.]', '_', f"{resource_name}_{policy_name}")
                filename = f"{safe_name}_{region}_{account_id}.json"
                filepath = os.path.join(output_dir, filename)
                
                # Save policy document
                with open(filepath, 'w') as f:
                    json.dump(policy_document, f, indent=2)
                
                print(f"  ✓ Policy saved to: {cyan}{filepath}{reset}")
                processed_files.append(filepath)
                
                # Explain the policy
                policy_allows_s3_listing = explain_policy(policy_document, policy_name, resource_type, resource_name)
                
                # Check if policy allows S3 bucket listing
                if policy_allows_s3_listing:
                    allow_s3_list_buckets = True
    
    # Check if any policy allows S3 bucket listing and ask about enumeration
    if allow_s3_list_buckets:
        from core.s3_bucket_enum import enumerate_single_bucket
        
        print(f"\nThis {yellow}{policy_name}{reset} policy allows listing S3 buckets. Would you like to enumerate a specific bucket?")
        choice = input("Enter bucket name (or press Enter to skip): ")
        
        if choice.strip():
            bucket_name = choice.strip()
            
            # Use parent directory as output location
            output_location = os.path.dirname(output_dir)  # Use parent of policies dir
            
            enumerate_single_bucket(
                bucket_name,
                profile_name=session.profile_name,
                region_name=region,
                output_dir=output_location
            )
    
    print(f"\n{bold}{yellow}Note: Manual enumeration might be needed depending on the service and its associated policies.{reset}{reset}")
    return processed_files

def explain_policy(policy_document, policy_name, resource_type, resource_name):
    """
    Explain an IAM policy in simple English.
    
    Args:
        policy_document (dict): IAM policy document
        policy_name (str): Policy name
        resource_type (str): Resource type (user, role, group)
        resource_name (str): Resource name
        
    Returns:
        bool: True if policy allows S3 bucket listing
    """
    print("\nPolicy Summary:")
    print(f"  Policy Name: {yellow}{policy_name}{reset}")
    print(f"  Attached to: {resource_type} '{yellow}{resource_name}{reset}'")
    
    # Flag to track if policy allows S3 bucket listing
    allows_s3_bucket_listing = False
    
    # Handle policy document
    try:
        if not policy_document:
            print("  ! Empty policy document")
            return allows_s3_bucket_listing
            
        # Extract statements
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Count by effect
        allow_actions = []
        deny_actions = []
        
        for statement in statements:
            effect = statement.get('Effect', '')
            actions = statement.get('Action', [])
            
            if not actions:
                continue
                
            # Convert to list if it's a string
            if isinstance(actions, str):
                actions = [actions]
            
            # Add to appropriate list
            if effect.lower() == 'allow':
                allow_actions.extend(actions)
                # Check for S3 bucket listing permission
                if 's3:ListBucket' in actions or 's3:ListAllMyBuckets' in actions or 's3:*' in actions or '*' in actions:
                    allows_s3_bucket_listing = True
            elif effect.lower() == 'deny':
                deny_actions.extend(actions)
                # If explicitly denied, override the allow
                if 's3:ListBucket' in actions or 's3:ListAllMyBuckets' in actions or 's3:*' in actions or '*' in actions:
                    allows_s3_bucket_listing = False
        
        # Group by service
        allow_by_service = {}
        deny_by_service = {}
        
        for action in allow_actions:
            if ':' in action:
                service, perm = action.split(':', 1)
                if service not in allow_by_service:
                    allow_by_service[service] = []
                allow_by_service[service].append(perm)
        
        for action in deny_actions:
            if ':' in action:
                service, perm = action.split(':', 1)
                if service not in deny_by_service:
                    deny_by_service[service] = []
                deny_by_service[service].append(perm)
        
        # Print summary in a table format
        print("\n  Permissions Table:")
        
        # Try to use rich for a nicer table
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            
            console = Console()
            table = Table(title="\nPolicy Permissions", show_lines=True, box=box.ROUNDED)
            
            # Add columns
            table.add_column("Service", style="cyan", justify="left")
            table.add_column("Allowed", style="green", justify="left")
            table.add_column("Denied", style="red", justify="left")
            
            # Get all unique services from both allow and deny lists
            all_services = sorted(set(list(allow_by_service.keys()) + list(deny_by_service.keys())))
            
            # Add rows for each service
            for service in all_services:
                allowed = allow_by_service.get(service, [])
                denied = deny_by_service.get(service, [])
                
                # Format permissions as bullet lists
                allowed_text = "\n".join([f"• {perm}" for perm in sorted(allowed)]) if allowed else ""
                denied_text = "\n".join([f"• {perm}" for perm in sorted(denied)]) if denied else ""
                
                table.add_row(service, allowed_text, denied_text)
            
            # Print the table
            console.print(table)
            
        except ImportError:
            # Fall back to simple ASCII table if rich is not available
            print("  +-----------+----------------------------+----------------------------+")
            print("  | Service   | Allowed                    | Denied                     |")
            print("  +-----------+----------------------------+----------------------------+")
            
            # Get all unique services from both allow and deny lists
            all_services = sorted(set(list(allow_by_service.keys()) + list(deny_by_service.keys())))
            
            for service in all_services:
                allowed = allow_by_service.get(service, [])
                denied = deny_by_service.get(service, [])
                
                # Print service row header
                print(f"  | {service:<9} | {'':<26} | {'':<26} |")
                
                # Get the max length of the two permission lists
                max_perms = max(len(allowed), len(denied))
                
                # Print permissions as rows
                for i in range(max_perms):
                    allow_perm = f"• {allowed[i]}" if i < len(allowed) else ""
                    deny_perm = f"• {denied[i]}" if i < len(denied) else ""
                    
                    # Truncate long permissions
                    if len(allow_perm) > 26:
                        allow_perm = allow_perm[:23] + "..."
                    if len(deny_perm) > 26:
                        deny_perm = deny_perm[:23] + "..."
                        
                    print(f"  | {'':<9} | {allow_perm:<26} | {deny_perm:<26} |")
                
                # Add separator line between services
                print("  | {0} | {0} | {0} |".format("-" * 9))
            
            # Print table footer
            print("  +-----------+----------------------------+----------------------------+")
        
        # Check for interesting permissions
        interesting_perms = check_interesting_permissions(allow_by_service)
        if interesting_perms:
            print("\n  Interesting permissions found:")
            for perm in interesting_perms:
                print(f"    - {perm}")
                
        # print("\n  What you could try next:")
        # suggest_next_steps(allow_by_service)
        
        return allows_s3_bucket_listing
        
    except Exception as e:
        print(f"  ! Error explaining policy: {str(e)}")
        return False

def check_interesting_permissions(permissions_by_service):
    """
    Check for interesting/powerful permissions in the policy.
    
    Args:
        permissions_by_service (dict): Permissions grouped by service
        
    Returns:
        list: Interesting permissions found
    """
    interesting = []
    
    # Check for admin access
    if 'iam' in permissions_by_service:
        iam_perms = permissions_by_service['iam']
        if '*' in iam_perms:
            interesting.append("Full IAM access - can create/modify users, roles, and policies")
        elif any(p.startswith('Create') for p in iam_perms):
            interesting.append("Can create IAM resources")
        elif any(p.startswith('Put') for p in iam_perms):
            interesting.append("Can modify IAM resources")
        elif 'PassRole' in iam_perms:
            interesting.append("Can pass IAM roles to other AWS services - potential for privilege escalation")
            
    # Check for lambda execution
    if 'lambda' in permissions_by_service:
        lambda_perms = permissions_by_service['lambda']
        if 'InvokeFunction' in lambda_perms or '*' in lambda_perms:
            interesting.append("Can invoke Lambda functions")
        if 'UpdateFunctionCode' in lambda_perms or '*' in lambda_perms:
            interesting.append("Can modify Lambda function code")
            
    # Check for S3 access
    if 's3' in permissions_by_service:
        s3_perms = permissions_by_service['s3']
        if '*' in s3_perms:
            interesting.append("Full S3 access - can read/write all buckets")
        elif any(p in s3_perms for p in ['PutObject', 'CreateBucket']):
            interesting.append("Can write to S3 buckets")
        elif any(p in s3_perms for p in ['GetObject', 'ListBucket']):
            interesting.append("Can read S3 buckets/objects")
            
    # Check for Secrets Manager access
    if 'secretsmanager' in permissions_by_service:
        sm_perms = permissions_by_service['secretsmanager']
        if 'GetSecretValue' in sm_perms or '*' in sm_perms:
            interesting.append("Can retrieve secret values from Secrets Manager")
        if 'CreateSecret' in sm_perms or '*' in sm_perms:
            interesting.append("Can create new secrets in Secrets Manager")
            
    # Check for SSM Parameter Store access
    if 'ssm' in permissions_by_service:
        ssm_perms = permissions_by_service['ssm']
        if 'GetParameter' in ssm_perms or 'GetParameters' in ssm_perms or '*' in ssm_perms:
            interesting.append("Can retrieve parameters from SSM Parameter Store")
        if 'PutParameter' in ssm_perms or '*' in ssm_perms:
            interesting.append("Can create/modify parameters in SSM Parameter Store")
            
    # Check for EC2 instance access
    if 'ec2' in permissions_by_service:
        ec2_perms = permissions_by_service['ec2']
        if 'RunInstances' in ec2_perms or '*' in ec2_perms:
            interesting.append("Can launch EC2 instances")
        if 'CreateKeyPair' in ec2_perms or '*' in ec2_perms:
            interesting.append("Can create EC2 key pairs")
        
    # Check for KMS decrypt
    if 'kms' in permissions_by_service:
        kms_perms = permissions_by_service['kms']
        if 'Decrypt' in kms_perms or '*' in kms_perms:
            interesting.append("Can decrypt data using KMS keys")
        if 'CreateKey' in kms_perms or '*' in kms_perms:
            interesting.append("Can create KMS keys")
            
    # Check for STS assume role
    if 'sts' in permissions_by_service:
        sts_perms = permissions_by_service['sts']
        if 'AssumeRole' in sts_perms or '*' in sts_perms:
            interesting.append("Can assume other IAM roles")
            
    # Check for CloudFormation
    if 'cloudformation' in permissions_by_service:
        cfn_perms = permissions_by_service['cloudformation']
        if 'CreateStack' in cfn_perms or '*' in cfn_perms:
            interesting.append("Can create CloudFormation stacks - potential for privilege escalation")
    
    # Check for RDS
    if 'rds' in permissions_by_service:
        rds_perms = permissions_by_service['rds']
        if 'CreateDBInstance' in rds_perms or '*' in rds_perms:
            interesting.append("Can create RDS database instances")
    
    # Check for DynamoDB
    if 'dynamodb' in permissions_by_service:
        ddb_perms = permissions_by_service['dynamodb']
        if 'PutItem' in ddb_perms or '*' in ddb_perms:
            interesting.append("Can write to DynamoDB tables")
        elif 'GetItem' in ddb_perms or 'Query' in ddb_perms or 'Scan' in ddb_perms:
            interesting.append("Can read from DynamoDB tables")
            
    return interesting