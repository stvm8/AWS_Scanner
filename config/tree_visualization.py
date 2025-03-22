"""
Function to display findings in a tree-based format with filtering.
"""
import os
from collections import defaultdict

blue = '\033[94m'
cyan = '\033[96m'
green = '\033[92m'
red = '\033[91m'
bold = '\033[1m'
yellow = "\033[93m"
magenta = "\033[95m"
reset = "\033[0m"

def print_tree_findings(findings):
    """
    Print findings in a tree-based format, filtering out IAM Operation entries.
    
    Args:
        findings (list): List of findings
    """
    if not findings:
        print("\nNo significant findings discovered.")
        return
    
    # Filter out IAM Operation entries
    filtered_findings = [
        finding for finding in findings 
        if not finding.get('finding_type', '').startswith('IAM Operation:')
    ]
    
    if not filtered_findings:
        print("\nNo significant findings discovered after filtering operations.")
        return
    
    # Attempt to use rich for enhanced tree visualization
    try:
        from rich.console import Console
        from rich.tree import Tree
        from rich.text import Text
        
        console = Console()
        main_tree = Tree("[bold]IAM Enumeration Findings[/bold]")
        
        # Group findings by resource
        resource_findings = defaultdict(list)
        for finding in filtered_findings:
            resource_key = f"{finding.get('resource_type', 'Unknown')}:{finding.get('resource_name', 'Unknown')}"
            resource_findings[resource_key].append(finding)
        
        # Add resources to the tree
        for resource_key, items in resource_findings.items():
            # Skip if no items after filtering
            if not items:
                continue
                
            # Split resource type and name
            res_parts = resource_key.split(':', 1)
            res_type = res_parts[0].capitalize() if len(res_parts) > 0 else "Unknown"
            res_name = res_parts[1] if len(res_parts) > 1 else "Unknown"
            
            # Create resource branch
            resource_branch = main_tree.add(f"[bold blue]{res_type}:[/bold blue] [cyan]{res_name}[/cyan]")
            
            # Group findings by type
            finding_types = defaultdict(list)
            for item in items:
                finding_types[item.get('finding_type', 'Unknown')].append(item)
            
            # Add finding types to resource branch
            for finding_type, type_items in finding_types.items():
                type_branch = resource_branch.add(f"[bold yellow]{finding_type}[/bold yellow] ({len(type_items)})")
                
                # Add individual findings
                for item in type_items:
                    detail_value = item.get('detail_value', 'Unknown')
                    extra_info = item.get('extra_info', '')
                    
                    # Create leaf node with details
                    if extra_info:
                        item_text = Text.from_markup(f"[green]{detail_value}[/green]\n")
                        item_text.append(f"    {extra_info}", style="dim")
                        type_branch.add(item_text)
                    else:
                        type_branch.add(f"[green]{detail_value}[/green]")
        
        # Print the tree
        console.print(main_tree)
        
        # Additional information
        console.print("\n[italic]*** It is recommended to check for all policy versions as it might contain hidden information.[/italic]")
    
    except (ImportError, Exception) as e:
        # Fallback to simple ASCII tree if rich is not available or fails
        print_ascii_tree_findings(filtered_findings)

def print_ascii_tree_findings(findings):
    """
    Print findings in a simple ASCII tree format as fallback.
    
    Args:
        findings (list): List of findings
    """
    print("\nIAM Enumeration Findings:")
    
    # Group findings by resource
    resource_findings = defaultdict(list)
    for finding in findings:
        resource_key = f"{finding.get('resource_type', 'Unknown')}:{finding.get('resource_name', 'Unknown')}"
        resource_findings[resource_key].append(finding)
    
    # Print resources and their findings
    for resource_key, items in resource_findings.items():
        # Skip if no items after filtering
        if not items:
            continue
            
        # Split resource type and name
        res_parts = resource_key.split(':', 1)
        res_type = res_parts[0].capitalize() if len(res_parts) > 0 else "Unknown"
        res_name = res_parts[1] if len(res_parts) > 1 else "Unknown"
        
        # Print resource header
        print(f"\n{bold}├── {blue}{res_type}:{reset} {cyan}{res_name}{reset}")
        
        # Group findings by type
        finding_types = defaultdict(list)
        for item in items:
            finding_types[item.get('finding_type', 'Unknown')].append(item)
        
        # Print finding types and items
        type_count = len(finding_types)
        for i, (finding_type, type_items) in enumerate(finding_types.items(), 1):
            is_last_type = (i == type_count)
            type_prefix = "└── " if is_last_type else "├── "
            
            # Print finding type header
            print(f"{bold}│   {type_prefix}{yellow}{finding_type}{reset} ({len(type_items)})")
            
            # Print individual findings
            item_count = len(type_items)
            for j, item in enumerate(type_items, 1):
                is_last_item = (j == item_count)
                item_prefix = "    " if is_last_type else "│   "
                item_branch = "└── " if is_last_item else "├── "
                
                detail_value = item.get('detail_value', 'Unknown')
                extra_info = item.get('extra_info', '')
                
                # Print item details
                print(f"│   {item_prefix}{item_branch}{green}{detail_value}{reset}")
                
                # Print extra info if available, indented properly
                if extra_info:
                    extra_prefix = "    " if is_last_item else "│   "
                    indented_info = extra_info.replace("\n", f"\n│   {item_prefix}    ")
                    print(f"│   {item_prefix}    {extra_prefix}{indented_info}")
    
    # Additional information
    print(f"\n{yellow}*** It is recommended to check for all policy versions as it might contain hidden information.{reset}")