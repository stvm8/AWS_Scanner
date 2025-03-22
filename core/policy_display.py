"""
Function to display policies in the revised format.
"""

def display_policy_summary(policy_document, policy_name, attached_to=None):
    """
    Display a policy document in the requested format.
    
    Args:
        policy_document (dict): The policy document to display
        policy_name (str): Name of the policy
        attached_to (str): Entity the policy is attached to
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        
        console = Console()
        
        # Create policy summary table
        table = Table(box=box.ROUNDED, show_header=True)
        
        # Create header with policy name and attachment info, left-aligned
        header_text = f"{policy_name}"
        if attached_to:
            header_text += f" attached to {attached_to}"
        
        # Add title with left alignment
        table.title = f"[bold]{header_text}[/bold]"
        table.title_justify = "left"
        
        # Add columns as requested (no Allowed column)
        table.add_column("Service", style="cyan")
        table.add_column("Actions & Explanations", style="yellow")
        table.add_column("Denied", style="red")
        
        # Extract and organize permissions by service
        service_permissions = {}
        
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            
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
                        "allowed": set(),
                        "denied": set(),
                        "resources": set()
                    }
                
                # Add to appropriate effect category
                if effect.lower() == "allow":
                    service_permissions[service]["allowed"].add(action_name)
                    service_permissions[service]["resources"].update(resources)
                elif effect.lower() == "deny":
                    service_permissions[service]["denied"].add(action_name)
        
        # Generate explanations for allowed permissions
        PERMISSION_EXPLANATIONS = {
            "iam": {
                "CreatePolicyVersion": "Can create new policy versions (privilege escalation risk)",
                "SetDefaultPolicyVersion": "Can change active policy version (privilege escalation risk)",
                "PassRole": "Can pass roles to services (privilege escalation risk)",
                "CreateAccessKey": "Can create access keys for users",
                "CreateLoginProfile": "Can set console passwords",
                "UpdateLoginProfile": "Can change user passwords",
                "AttachUserPolicy": "Can attach policies to users",
                "AttachGroupPolicy": "Can attach policies to groups",
                "AttachRolePolicy": "Can attach policies to roles",
                "PutUserPolicy": "Can create inline user policies",
                "PutGroupPolicy": "Can create inline group policies",
                "PutRolePolicy": "Can create inline role policies",
                "AddUserToGroup": "Can add users to groups",
                "UpdateAssumeRolePolicy": "Can modify who can assume roles",
                "*": "FULL IAM CONTROL - HIGH RISK"
            },
            "s3": {
                "GetObject": "Can read S3 objects",
                "PutObject": "Can write S3 objects",
                "DeleteObject": "Can delete S3 objects",
                "ListBucket": "Can list bucket contents",
                "ListAllMyBuckets": "Can list all buckets",
                "*": "FULL S3 CONTROL"
            },
            "ec2": {
                "RunInstances": "Can launch EC2 instances",
                "DescribeInstances": "Can list EC2 instances",
                "StartInstances": "Can start stopped instances",
                "StopInstances": "Can stop running instances",
                "CreateSecurityGroup": "Can create security groups",
                "*": "FULL EC2 CONTROL"
            },
            "lambda": {
                "CreateFunction": "Can create Lambda functions (code execution)",
                "InvokeFunction": "Can execute Lambda functions",
                "UpdateFunctionCode": "Can modify function code (code execution)",
                "CreateEventSourceMapping": "Can create event triggers",
                "*": "FULL LAMBDA CONTROL"
            },
            "secretsmanager": {
                "GetSecretValue": "Can read secret values",
                "CreateSecret": "Can create new secrets",
                "PutSecretValue": "Can modify secrets",
                "*": "FULL SECRETS CONTROL"
            },
            "kms": {
                "Decrypt": "Can decrypt data",
                "Encrypt": "Can encrypt data",
                "GenerateDataKey": "Can generate encryption keys",
                "*": "FULL KMS CONTROL"
            },
            # Add more services and explanations as needed
        }
        
        # Add a generic explanation for any service not explicitly covered
        DEFAULT_EXPLANATIONS = {
            "*": "FULL CONTROL OF SERVICE"
        }
        
        # Helper function to get explanation for an action
        def get_explanation(service, action):
            # Check if we have specific explanations for this service
            if service in PERMISSION_EXPLANATIONS:
                # Check for specific action
                if action in PERMISSION_EXPLANATIONS[service]:
                    return PERMISSION_EXPLANATIONS[service][action]
                # Check for wildcard
                elif action.endswith("*"):
                    prefix = action[:-1]  # Remove * for prefix matching
                    for known_action, explanation in PERMISSION_EXPLANATIONS[service].items():
                        if known_action.startswith(prefix):
                            return explanation.replace(known_action, action)
                # Fall back to wildcard explanation
                elif "*" in PERMISSION_EXPLANATIONS[service]:
                    return PERMISSION_EXPLANATIONS[service]["*"]
            
            # Use default explanations
            if action == "*":
                return DEFAULT_EXPLANATIONS["*"].replace("SERVICE", service.upper())
            return f"Can {action.replace('-', ' ').lower()}"
        
        # Add rows to the table
        for service, details in sorted(service_permissions.items()):
            allowed = details["allowed"]
            denied = details["denied"]
            
            # Format explanations as bullet points
            explanations = []
            for action in sorted(allowed):
                explanation = get_explanation(service, action)
                explanations.append(f"• [white]{action}[/white]: {explanation}")
            
            explanations_display = "\n".join(explanations)
            denied_display = ", ".join(sorted(denied)) if denied else "None"
            
            table.add_row(
                service,
                explanations_display,
                denied_display
            )
        
        console.print(table)
    
    except ImportError:
        # Fallback to simple text output
        print(f"\n==== {policy_name} ====")
        if attached_to:
            print(f"Attached to: {attached_to}")
        
        print("\nService | Actions & Explanations | Denied")
        print("-" * 80)
        
        # Extract and organize permissions by service
        service_permissions = {}
        
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            
            # Group by service
            for action in actions:
                service = action.split(':')[0] if ':' in action else "other"
                action_name = action.split(':')[1] if ':' in action else action
                
                if service not in service_permissions:
                    service_permissions[service] = {
                        "allowed": set(),
                        "denied": set()
                    }
                
                # Add to appropriate effect category
                if effect.lower() == "allow":
                    service_permissions[service]["allowed"].add(action_name)
                elif effect.lower() == "deny":
                    service_permissions[service]["denied"].add(action_name)
        
        # Print permissions by service
        for service, details in sorted(service_permissions.items()):
            allowed = details["allowed"]
            denied = details["denied"]
            
            denied_display = ", ".join(sorted(denied)) if denied else "None"
            
            # Print with bullet points for each action
            print(f"{service} | ", end="")
            for action in sorted(allowed):
                explanation = f"Can {action.replace('-', ' ').lower()}"
                print(f"• {action}: {explanation}")
            print(f" | {denied_display}")