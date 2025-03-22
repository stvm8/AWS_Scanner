"""
S3 bucket enumeration functions for the AWS Permission Toolkit.
"""
import boto3
import json
import os
import datetime
from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table
from rich import box

# Initialize rich console
console = Console()

def enumerate_single_bucket(bucket_name, profile_name=None, region_name=None, output_dir='results', op_file=None):
    """
    Enumerate a specific S3 bucket using operations from JSON config.
    
    Args:
        bucket_name (str): S3 bucket name
        profile_name (str): AWS profile name
        region_name (str): AWS region name
        output_dir (str): Output directory for results
        op_file (str): Path to the JSON file containing S3 operations
        
    Returns:
        dict: Results of the enumeration
    """
    # Create session
    session_kwargs = {}
    if profile_name:
        session_kwargs['profile_name'] = profile_name
    if region_name:
        session_kwargs['region_name'] = region_name
    
    session = boto3.Session(**session_kwargs)
    client = session.client('s3')
    
    # Load operations from JSON
    operations = []
    
    # Try to load operations from the specified file first
    if op_file and os.path.exists(op_file):
        config_path = op_file
    else:
        # Fallback to default locations
        possible_paths = [
            # User-specified path via op_file
            op_file,
            # Current directory
            os.path.join(os.getcwd(), 's3_operations.json'),
            # Config subdirectory of current directory
            os.path.join(os.getcwd(), 'config', 's3_operations.json'),
            # Same directory as the script
            os.path.join(os.path.dirname(__file__), 's3_operations.json'),
            # Config subdirectory relative to the script
            os.path.join(os.path.dirname(__file__), 'config', 's3_operations.json'),
            # Parent directory's config folder (original path)
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 's3_operations.json')
        ]
        
        # Find the first existing path
        config_path = None
        for path in possible_paths:
            if path and os.path.exists(path):
                config_path = path
                break
    
    # Load operations from the config file
    try:
        if config_path and os.path.exists(config_path):
            console.print(f"Loading operations from: [cyan]{config_path}[/cyan]")
            with open(config_path, 'r') as f:
                config = json.load(f)
                operations = config.get('s3_operations', [])
                if not operations:
                    console.print("[yellow]Warning: No 's3_operations' key found in the config file or it's empty.[/yellow]")
        else:
            raise FileNotFoundError(f"Could not find S3 operations file in any of the expected locations.")
    except Exception as e:
        console.print(f"[red]Error loading S3 operations file: {e}[/red]")
        console.print("[yellow]Please provide a valid s3_operations.json file.[/yellow]")
        return {}
    
    if not operations:
        console.print("[yellow]No operations found in the config file. Exiting.[/yellow]")
        return {}
    
    console.print(f"\nEnumerating S3 bucket: [bold cyan]{bucket_name}[/bold cyan]")
    console.print("=" * 50)
    console.print(f"Using [green]{len(operations)}[/green] operations from: [cyan]{config_path}[/cyan]")
    
    # Prepare results dictionary for saving
    results = {
        'bucket_name': bucket_name,
        'timestamp': datetime.datetime.now().isoformat(),
        'operations': {}
    }
    
    # Execute each operation
    successful_operations = 0
    
    for op in operations:
        operation = op.get('operation')
        params = op.get('params', {})
        display_config = op.get('display', {})
        
        # Skip if operation is not specified
        if not operation:
            console.print("[yellow]Warning: Skipping operation entry with no 'operation' field[/yellow]")
            continue
        
        # Convert operation name from kebab-case to snake_case for boto3
        method_name = operation.replace('-', '_')
        
        try:
            # Add bucket name to parameters
            all_params = {'Bucket': bucket_name, **params}
            
            # Execute the operation
            method = getattr(client, method_name)
            response = method(**all_params)
            
            # Store result
            results['operations'][operation] = {
                'status': 'success',
                'params': params,
                'response': response
            }
            
            # Only display successful results
            successful_operations += 1
            
            # Display result - generic approach
            console.print(f"\n[green]✓[/green] [bold]{operation}[/bold]")
            
            # Display simple response message based on the type
            display_type = display_config.get('type', 'generic')
            display_message = display_config.get('message', 'Operation successful')
            
            # Handle showing the response in a generic way
            if display_type == 'objects' and 'Contents' in response:
                console.print(f"  Objects found: [green]{len(response['Contents'])}[/green]")
                for obj in response.get('Contents', [])[:5]:  # Show at most 5
                    console.print(f"  - [cyan]{obj.get('Key')}[/cyan] ([green]{obj.get('Size')}[/green] bytes)")
            else:
                # Just print the message as-is
                console.print(f"  {display_message}")
                
                # If the response is not too complex, print a simple representation
                if isinstance(response, dict) and len(response) < 5:
                    for key, value in response.items():
                        if not isinstance(value, (dict, list)) or (isinstance(value, list) and len(value) < 3):
                            console.print(f"  {key}: [cyan]{value}[/cyan]")
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            # Store error but don't display detailed error messages
            results['operations'][operation] = {
                'status': 'error',
                'params': params,
                'error': f"{error_code}: {error_message}"
            }
            
        except Exception as e:
            # Store error but don't display detailed error messages
            results['operations'][operation] = {
                'status': 'error',
                'params': params,
                'error': str(e)
            }
    
    # Print summary of operations
    if successful_operations == 0:
        console.print(f"\n[yellow]No successful operations against bucket: {bucket_name}[/yellow]")
    else:
        console.print(f"\n[green]Successfully executed {successful_operations} of {len(operations)} operations.[/green]")
    
    # Always save results to the output directory
    save_bucket_results(results, output_dir)
    
    return results

def print_bucket_summary_table(table_data):
    """
    Print a summary table of bucket information using rich.
    
    Args:
        table_data (dict): Dictionary containing bucket information
    """
    # Filter out "Not checked" values
    filtered_data = {k: v for k, v in table_data.items() if v != 'Not checked'}
    
    # If we don't have any successful operations, just show basic info
    if len(filtered_data) <= 2:  # Only bucket_name and region
        # Just print a message with bucket name and region
        console.print(f"\n[bold]S3 Bucket:[/bold] [cyan]{table_data['bucket_name']}[/cyan] ([cyan]{table_data['region']}[/cyan])")
        return
    
    # Create a rich table
    table = Table(show_header=True, header_style="bold", box=box.SQUARE)
    
    # Add columns
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    # Add rows
    for key, value in filtered_data.items():
        # Format the key for display (replace underscores with spaces, title case)
        display_key = key.replace('_', ' ').title()
        
        # Color code certain values
        if 'public' in key.lower():
            if 'no' in value.lower() or 'blocked' in value.lower():
                value_display = f"[green]{value}[/green]"
            elif 'yes' in value.lower() or 'public' in value.lower():
                value_display = f"[red]{value}[/red]"
            else:
                value_display = value
        elif 'policy' in key.lower():
            if 'no policy' in value.lower():
                value_display = f"[yellow]{value}[/yellow]"
            elif 'exists' in value.lower():
                value_display = f"[cyan]{value}[/cyan]"
            else:
                value_display = value
        elif 'encryption' in key.lower():
            if 'enabled' in value.lower():
                value_display = f"[green]{value}[/green]"
            elif 'not enabled' in value.lower() or 'disabled' in value.lower():
                value_display = f"[red]{value}[/red]"
            else:
                value_display = value
        else:
            value_display = value
            
        table.add_row(display_key, value_display)
    
    # Print the table if we have more than just the basics
    if len(filtered_data) > 2:  # More than just bucket_name and region
        console.print("\n[bold]Bucket Summary:[/bold]")
        console.print(table)

def save_bucket_results(results, output_dir):
    """
    Save S3 bucket enumeration results to a file.
    
    Args:
        results (dict): Enumeration results
        output_dir (str): Output directory
        
    Returns:
        str: Path to saved file
    """
    # Create output directory if not exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename with timestamp and bucket name
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    bucket_name = results.get('bucket_name', 'unknown')
    filename = f"s3_bucket_{bucket_name}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Save to file
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    console.print(f"\nResults saved to: [cyan]{filepath}[/cyan]")
    return filepath

def list_bucket_objects(bucket_name, profile_name=None, region_name=None, max_items=100):
    """
    List objects in a specific S3 bucket.
    
    Args:
        bucket_name (str): S3 bucket name
        profile_name (str): AWS profile name
        region_name (str): AWS region name
        max_items (int): Maximum number of items to list
        
    Returns:
        list: List of objects in the bucket
    """
    # Create session
    session_kwargs = {}
    if profile_name:
        session_kwargs['profile_name'] = profile_name
    if region_name:
        session_kwargs['region_name'] = region_name
    
    session = boto3.Session(**session_kwargs)
    client = session.client('s3')
    
    try:
        response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=max_items)
        objects = response.get('Contents', [])
        
        if objects:
            # Create a rich table for objects
            table = Table(show_header=True, header_style="bold", box=box.SQUARE)
            
            # Add columns
            table.add_column("Object Key", style="cyan")
            table.add_column("Size", justify="right")
            table.add_column("Last Modified")
            table.add_column("Storage Class")
            
            # Add rows
            for obj in objects:
                last_modified = obj.get('LastModified', '').strftime('%Y-%m-%d %H:%M:%S') if obj.get('LastModified') else 'Unknown'
                size = obj.get('Size', 0)
                
                # Format size
                if size > 1024*1024*1024:
                    size_str = f"{size/(1024*1024*1024):.2f} GB"
                elif size > 1024*1024:
                    size_str = f"{size/(1024*1024):.2f} MB"
                elif size > 1024:
                    size_str = f"{size/1024:.2f} KB"
                else:
                    size_str = f"{size:,} bytes"
                
                storage_class = obj.get('StorageClass', 'Unknown')
                
                # Add row with different storage class colors
                storage_class_style = ""
                if storage_class == "STANDARD":
                    storage_class_style = "green"
                elif "REDUCED" in storage_class:
                    storage_class_style = "yellow"
                elif "GLACIER" in storage_class:
                    storage_class_style = "blue"
                
                table.add_row(
                    obj.get('Key', 'Unknown'),
                    size_str,
                    last_modified,
                    f"[{storage_class_style}]{storage_class}[/{storage_class_style}]" if storage_class_style else storage_class
                )
            
            console.print("\n[bold]Bucket Objects:[/bold]")
            console.print(table)
            
            if response.get('IsTruncated'):
                console.print(f"\n[yellow]Note: Result is truncated. Only showing {len(objects)} out of more objects.[/yellow]")
        else:
            console.print("\n[yellow]No objects found in the bucket.[/yellow]")
        
        return objects
    except Exception as e:
        console.print(f"\n[red]Error listing objects: {str(e)}[/red]")
        return []