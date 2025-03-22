"""
AWS Privilege Escalation Detector

This module detects high-risk permissions that could lead to privilege escalation in AWS.
"""
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Define high risk permission combinations for privilege escalation
HIGH_RISK_PERMISSIONS = [
    {
        "id": "01",
        "permissions": ["iam:CreatePolicyVersion"],
        "description": "Allows attaching a new policy version which could contain escalated privileges",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "02",
        "permissions": ["iam:SetDefaultPolicyVersion"],
        "description": "Allows changing the default policy version to a version that might contain escalated privileges",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "03",
        "permissions": ["iam:PassRole", "ec2:RunInstances"],
        "description": "Allows passing an administrative role to a new EC2 instance",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws" 
    },
    {
        "id": "04",
        "permissions": ["iam:CreateAccessKey"],
        "description": "Allows creating access keys for existing users",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "05",
        "permissions": ["iam:CreateLoginProfile"],
        "description": "Allows setting console password for users that don't have one",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "06",
        "permissions": ["iam:UpdateLoginProfile"],
        "description": "Allows changing user's console password",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "07",
        "permissions": ["iam:AttachUserPolicy"],
        "description": "Allows attaching managed policies to users",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "08",
        "permissions": ["iam:AttachGroupPolicy"],
        "description": "Allows attaching managed policies to groups",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "09",
        "permissions": ["iam:AttachRolePolicy"],
        "description": "Allows attaching managed policies to roles",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "10",
        "permissions": ["iam:PutUserPolicy"],
        "description": "Allows creating/updating inline policies for users",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "11",
        "permissions": ["iam:PutGroupPolicy"],
        "description": "Allows creating/updating inline policies for groups",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "12",
        "permissions": ["iam:PutRolePolicy"],
        "description": "Allows creating/updating inline policies for roles",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "13",
        "permissions": ["iam:AddUserToGroup"],
        "description": "Allows adding users to groups that may have higher privileges",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "14",
        "permissions": ["iam:UpdateAssumeRolePolicy"],
        "description": "Allows modifying which principals can assume a role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "15",
        "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Allows creating and invoking Lambda functions with an administrative role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "16",
        "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
        "description": "Allows creating Lambda functions triggered by events with an administrative role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "17",
        "permissions": ["lambda:UpdateFunctionCode"],
        "description": "Allows modifying code of existing Lambda functions",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "18",
        "permissions": ["iam:PassRole", "glue:CreateDevEndpoint", "glue:GetDevEndpoint"],
        "description": "Allows creating Glue development endpoints with an administrative role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "19",
        "permissions": ["glue:UpdateDevEndpoint", "glue:GetDevEndpoint"],
        "description": "Allows modifying Glue development endpoints",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "20",
        "permissions": ["iam:PassRole", "cloudformation:CreateStack", "cloudformation:DescribeStacks"],
        "description": "Allows creating CloudFormation stacks with an administrative role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    },
    {
        "id": "21",
        "permissions": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"],
        "description": "Allows creating and activating Data Pipelines with an administrative role",
        "reference": "https://bishopfox.com/blog/privilege-escalation-in-aws"
    }
]

# Add additional high-value individual permissions for pentesting
ADDITIONAL_PENTESTING_PERMISSIONS = [
    {"service": "s3", "actions": ["GetObject", "PutObject"], "risk": "Data access and exfiltration"},
    {"service": "secretsmanager", "actions": ["GetSecretValue"], "risk": "Access to sensitive credentials"},
    {"service": "ssm", "actions": ["GetParameter", "GetParameters"], "risk": "Access to sensitive configuration"},
    {"service": "ec2", "actions": ["DescribeInstances"], "risk": "Enumeration of compute resources"},
    {"service": "rds", "actions": ["DescribeDBInstances"], "risk": "Database enumeration"},
    {"service": "sts", "actions": ["AssumeRole"], "risk": "Identity assumption"}
]

def check_policy_for_privilege_escalation(policy_document, policy_name, attached_to=None):
    """
    Check a policy document for potential privilege escalation permissions.
    
    Args:
        policy_document (dict): The policy document to check
        policy_name (str): Name of the policy
        attached_to (str): Entity the policy is attached to
        
    Returns:
        list: List of findings related to privilege escalation
    """
    findings = []
    
    # Extract all allowed actions from the policy
    allowed_actions = extract_allowed_actions(policy_document)
    
    # Check for each high-risk permission combination
    for risk in HIGH_RISK_PERMISSIONS:
        # For combination permissions, check if all required permissions are present
        if all(perm in allowed_actions for perm in risk["permissions"]):
            finding = {
                "policy_name": policy_name,
                "attached_to": attached_to,
                "risk_id": risk["id"],
                "permissions": risk["permissions"],
                "description": risk["description"],
                "reference": risk["reference"]
            }
            findings.append(finding)
    
    # Also check for generally useful permissions for pentesting
    for pentest_perm in ADDITIONAL_PENTESTING_PERMISSIONS:
        service = pentest_perm["service"]
        for action in pentest_perm["actions"]:
            full_perm = f"{service}:{action}"
            if full_perm in allowed_actions or f"{service}:*" in allowed_actions or "*:*" in allowed_actions:
                finding = {
                    "policy_name": policy_name,
                    "attached_to": attached_to,
                    "risk_id": "PT",  # Pentest
                    "permissions": [full_perm],
                    "description": pentest_perm["risk"],
                    "reference": None
                }
                findings.append(finding)
    
    return findings

def extract_allowed_actions(policy_document):
    """
    Extract all allowed actions from a policy document.
    
    Args:
        policy_document (dict): The policy document
        
    Returns:
        set: Set of allowed actions
    """
    allowed_actions = set()
    
    # Process each statement in the policy
    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        effect = statement.get("Effect", "")
        action = statement.get("Action", [])
        
        # Only process Allow statements
        if effect.lower() != "allow":
            continue
        
        # Convert to list if it's a string
        if isinstance(action, str):
            action = [action]
        
        # Add each action to the set
        for act in action:
            # Handle wildcard permissions
            if "*" in act:
                # Service wildcard (e.g., "s3:*")
                if act.endswith(":*"):
                    service = act.split(":")[0]
                    # Add all known permissions for this service from our high-risk list
                    for risk in HIGH_RISK_PERMISSIONS:
                        for perm in risk["permissions"]:
                            if perm.startswith(f"{service}:"):
                                allowed_actions.add(perm)
                    
                    # Add pentesting permissions for this service
                    for perm in ADDITIONAL_PENTESTING_PERMISSIONS:
                        if perm["service"] == service:
                            for action_name in perm["actions"]:
                                allowed_actions.add(f"{service}:{action_name}")
                
                # Full wildcard ("*")
                elif act == "*":
                    # Add all permissions from our high-risk list
                    for risk in HIGH_RISK_PERMISSIONS:
                        for perm in risk["permissions"]:
                            allowed_actions.add(perm)
                    
                    # Add all pentesting permissions
                    for perm in ADDITIONAL_PENTESTING_PERMISSIONS:
                        for action_name in perm["actions"]:
                            allowed_actions.add(f"{perm['service']}:{action_name}")
                
                # Wildcard in action (e.g., "s3:Get*")
                else:
                    service, action_pattern = act.split(":")
                    # We would need a complete list of AWS actions to fully expand this
                    # For now, add it as-is for pattern matching later
                    allowed_actions.add(act)
            else:
                allowed_actions.add(act)
    
    return allowed_actions

def display_privilege_escalation_findings(findings, total_policies):
    """
    Display findings related to privilege escalation using rich library.
    
    Args:
        findings (list): List of findings
        total_policies (int): Total number of policies analyzed
    """
    try:
        console = Console()
        
        if not findings:
            console.print(Panel(
                f"[bold green]No privilege escalation paths found in {total_policies} analyzed policies[/bold green]\n\n"
                "However, always verify permissions manually and consider least privilege principles.",
                title="Security Assessment", 
                border_style="green",
                expand=False
            ))
            return
        
        # Group findings by policy
        findings_by_policy = {}
        for finding in findings:
            policy_key = finding["policy_name"]
            if policy_key not in findings_by_policy:
                findings_by_policy[policy_key] = []
            findings_by_policy[policy_key].append(finding)
        
        # Create a table for privilege escalation findings
        table = Table(title=f"[bold]Privilege Escalation Findings ({len(findings)} paths in {total_policies} policies)[/bold]",
                     box=box.ROUNDED, highlight=True, show_header=True, title_justify="left")
        
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Risk", style="red bold", no_wrap=True)
        table.add_column("Permissions", style="white")
        table.add_column("Policy", style="blue")
        table.add_column("Attached To", style="magenta")
        
        # Add each finding to the table
        for finding in findings:
            # For privilege escalation findings (with numeric IDs)
            if finding["risk_id"].isdigit():
                table.add_row(
                    finding["risk_id"],
                    ":bangbang: [yellow]Privilege Escalation[/yellow]",
                    ", ".join(finding["permissions"]),
                    finding["policy_name"],
                    finding["attached_to"] or "Unknown"
                )
            # For pentesting utility permissions
            else:
                table.add_row(
                    "PT",
                    ":space_invader: [purple]Pentest Utility[/purple]",
                    ", ".join(finding["permissions"]),
                    finding["policy_name"],
                    finding["attached_to"] or "Unknown"
                )
        
        # Print the table
        console.print(table)
        
        # Reference panel
        console.print(Panel(
            "[bold red]Refer to[/bold red] [link=https://bishopfox.com/blog/privilege-escalation-in-aws]https://bishopfox.com/blog/privilege-escalation-in-aws[/link] [bold red]for exploitation techniques.[/bold red]",
            title="Security Recommendations", 
            border_style="red",
            expand=False
        ))
        
    except ImportError:
        # Fallback to simple text output if rich is not available
        print("\n==== PRIVILEGE ESCALATION FINDINGS ====")
        print(f"Found {len(findings)} potential privilege escalation paths in {total_policies} policies\n")
        
        for finding in findings:
            print(f"ID: {finding['risk_id']}")
            if finding["risk_id"].isdigit():
                print("Risk: Privilege Escalation")
            else:
                print("Risk: Pentest Utility")
            print(f"Permissions: {', '.join(finding['permissions'])}")
            print(f"Policy: {finding['policy_name']}")
            print(f"Attached To: {finding['attached_to'] or 'Unknown'}")
            print(f"Description: {finding['description']}")
            if finding["reference"]:
                print(f"Reference: {finding['reference']}")
            print("-" * 40)
        
        print("\nRefer to https://bishopfox.com/blog/privilege-escalation-in-aws for exploitation techniques.")

def display_policy_summary(policy_document, policy_name, attached_to=None):
    """
    Display a concise summary of a policy document.
    
    Args:
        policy_document (dict): The policy document to summarize
        policy_name (str): Name of the policy
        attached_to (str): Entity the policy is attached to
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        
        console = Console()
        
        # Create policy summary table
        table = Table(title=f"Policy Summary: {policy_name}", box=box.ROUNDED, show_header=True)
        
        if attached_to:
            table.caption = f"Attached to: {attached_to}"
        
        table.add_column("Service", style="cyan")
        table.add_column("Actions", style="green")
        table.add_column("Resources", style="yellow")
        table.add_column("Conditions", style="magenta")
        
        # Extract and organize permissions by service
        service_permissions = {}
        
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            conditions = stmt.get("Condition", {})
            
            # Skip Deny statements for now
            if effect.lower() != "allow":
                continue
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Group by service
            for action in actions:
                service = action.split(':')[0] if ':' in action else "other"
                action_name = action.split(':')[1] if ':' in action else action
                
                if service not in service_permissions:
                    service_permissions[service] = {
                        "actions": set(),
                        "resources": set(),
                        "conditions": set()
                    }
                
                service_permissions[service]["actions"].add(action_name)
                service_permissions[service]["resources"].update(resources)
                
                # Add conditions as strings
                if conditions:
                    for condition_operator, condition_values in conditions.items():
                        for key, value in condition_values.items():
                            if isinstance(value, list):
                                value_str = ", ".join(value)
                            else:
                                value_str = str(value)
                            service_permissions[service]["conditions"].add(f"{condition_operator}:{key}={value_str}")
        
        # Add rows to the table
        for service, details in sorted(service_permissions.items()):
            # Limit length of action lists
            actions = details["actions"]
            if len(actions) > 5:
                actions_display = ", ".join(sorted(list(actions)[:4])) + f"... ({len(actions) - 4} more)"
            else:
                actions_display = ", ".join(sorted(list(actions)))
            
            # Limit length of resource lists
            resources = details["resources"]
            if len(resources) > 3:
                resources_display = ", ".join(sorted(list(resources)[:2])) + f"... ({len(resources) - 2} more)"
            else:
                resources_display = ", ".join(sorted(list(resources)))
            
            # Conditions
            conditions = details["conditions"]
            conditions_display = ", ".join(sorted(list(conditions))) if conditions else "None"
            
            table.add_row(
                service,
                actions_display,
                resources_display,
                conditions_display[:50] + "..." if len(conditions_display) > 50 else conditions_display
            )
        
        console.print(table)
    
    except ImportError:
        # Fallback to simple text output
        print(f"\n==== POLICY SUMMARY: {policy_name} ====")
        if attached_to:
            print(f"Attached to: {attached_to}")
        
        # Extract and organize permissions by service
        service_permissions = {}
        
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            
            # Skip Deny statements for now
            if effect.lower() != "allow":
                continue
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Group by service
            for action in actions:
                service = action.split(':')[0] if ':' in action else "other"
                action_name = action.split(':')[1] if ':' in action else action
                
                if service not in service_permissions:
                    service_permissions[service] = {
                        "actions": set(),
                        "resources": set()
                    }
                
                service_permissions[service]["actions"].add(action_name)
                service_permissions[service]["resources"].update(resources)
        
        # Print permissions by service
        for service, details in sorted(service_permissions.items()):
            print(f"\nService: {service}")
            print(f"Actions: {', '.join(sorted(list(details['actions'])))}")
            print(f"Resources: {', '.join(sorted(list(details['resources'])))}")

def analyze_policies(policies):
    """
    Analyze multiple policies for privilege escalation risks.
    
    Args:
        policies (list): List of policies with their documents
        
    Returns:
        list: List of findings
    """
    all_findings = []
    
    for policy_info in policies:
        # Extract policy information
        policy_type = policy_info[0]  # 'attached', 'inline', etc.
        policy_name = policy_info[1]
        policy_arn = policy_info[2]
        resource_type = policy_info[3]  # 'user', 'role', 'group'
        resource_name = policy_info[4]
        
        # Get policy document
        policy_document = None
        if len(policy_info) >= 6:
            policy_document = policy_info[5]
        
        if policy_document:
            # Display policy summary using the new format
            attached_to = f"{resource_type}:{resource_name}"
            from .policy_display import display_policy_summary
            display_policy_summary(policy_document, policy_name, attached_to)
            
            # Check for privilege escalation
            findings = check_policy_for_privilege_escalation(policy_document, policy_name, attached_to)
            all_findings.extend(findings)
    
    # Display findings
    display_privilege_escalation_findings(all_findings, len(policies))
    
    return all_findings