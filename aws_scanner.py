#!/usr/bin/env python3
"""
AWS Permission Toolkit - A tool for enumerating and exploring AWS permissions.
"""
import argparse
import os
import sys
import json
from core.permission_enum import enumerate_permissions, save_results
from core.further_enum import ask_for_further_enumeration
from core.policy_reader import process_policies
from core.s3_bucket_enum import enumerate_single_bucket

blue = '\033[94m'
green = '\033[92m'
red = '\033[91m'
bold = '\033[1m'
yellow = "\033[93m"
cyan = "\033[96m"
magenta = "\033[95m"
reset = "\033[0m"

def main():
    """Main entry point for AWS Permission Toolkit"""
    parser = argparse.ArgumentParser(
        description='AWS Permission Toolkit - A tool for enumerating and exploring AWS permissions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  # Use default operations with AWS profile
  python aws_scanner.py --profile dev
  
  # Scan with custom operations file
  python aws_scanner.py --profile dev --op_file custom_operations.json
  
  # Scan a specific region
  python aws_scanner.py --profile dev --region us-west-2
  
  # Enable verbose output
  python aws_scanner.py --profile dev --verbose

Note: By default this tool will do simple permissions check on 5 services: IAM, EC2, SQS, Lambda and Secretsmanager. If you want to scan for more services, leverage {yellow}"--op_file"{reset} flag.
'''
    )
    
    parser.add_argument('--profile', type=str, help='AWS profile name')
    parser.add_argument('--region', type=str, help='AWS region name (defaults to scanning all US regions)')
    parser.add_argument('--op_file', type=str, help='Path to operations file (JSON)')
    parser.add_argument('--output_dir', type=str, default='results', help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no_further', action='store_true', help='Disable further enumeration prompt')
    parser.add_argument('--no_policy', action='store_true', help='Disable policy processing')
    #parser.add_argument('--enum-bucket', type=str, help='Enumerate specific S3 bucket')
    #parser.add_argument('--save', action='store_true', help='Save results without prompting')
    #parser.add_argument('--no_save', action='store_true', help='Do not save results')
    #parser.add_argument('--detailed-objects', action='store_true', help='Show detailed list of objects when enumerating a bucket')
    
    # If no arguments provided, print help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
        
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create session parameters
    session_kwargs = {}
    if args.profile:
        session_kwargs['profile_name'] = args.profile
    if args.region:
        session_kwargs['region_name'] = args.region
    
    try:
        # Check if we're enumerating a specific S3 bucket
        if args.enum_bucket:
            print(f"\n{bold}=== S3 Bucket Enumeration ==={reset}")
            results = enumerate_single_bucket(
                args.enum_bucket,
                profile_name=args.profile,
                region_name=args.region,
                output_dir=args.output_dir if args.save else None,
                op_file=args.op_file
            )
            
            # If detailed objects flag is set, list objects
            if args.detailed_objects:
                from core.s3_bucket_enum import list_bucket_objects
                list_bucket_objects(
                    args.enum_bucket,
                    profile_name=args.profile,
                    region_name=args.region
                )
                
            return 0
        
        # Feature 1: AWS Permission Enumeration
        print(f"\n{bold}=== AWS Permission Enumeration ==={reset}")
        results, discovered_arns = enumerate_permissions(
            profile_name=args.profile,
            region_name=args.region,
            op_file=args.op_file,
            verbose=args.verbose
        )
        
        # Save enumeration results only if explicitly requested with --save flag
        if args.save:
            result_file = save_results(results, discovered_arns, args.output_dir)
            print(f"\nResults saved to: {result_file}")
        
        # Report discovered ARNs with highlighting
        if discovered_arns:
            print(f"\n{bold}{cyan}=== Discovered ARNs from error messages ==={reset}")
            for arn in sorted(discovered_arns):
                print(f"  {magenta}•{reset} {yellow}{arn}{reset}")
        
        # Feature 2: Further IAM Enumeration (if ARNs found and not disabled)
        if discovered_arns and not args.no_further:
            print(f"\n{bold}=== Further IAM Enumeration ==={reset}")
            further_results, policies = ask_for_further_enumeration(
                discovered_arns,
                profile_name=args.profile,
                region_name=args.region
            )
            
            # Feature 3: Policy Reader (if policies found and not disabled)
            if policies and not args.no_policy:
                print(f"\n{bold}=== Policy Reader ==={reset}")
                import boto3
                session = boto3.Session(**session_kwargs)
                
                policy_dir = os.path.join(args.output_dir, 'policies')
                
                # Always save policy files - this is what the user wants
                output_dir = policy_dir
                process_policies(policies, session, output_dir)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"\nError: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())