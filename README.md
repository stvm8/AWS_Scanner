# AWS Permission Toolkit

## Overview

The AWS Permission Toolkit is a Python-based tool designed to help security professionals, cloud administrators, and developers enumerate and analyze AWS permissions across different services. It provides a comprehensive approach to understanding the access rights and potential security risks in AWS environments.

## Features

### 1. Permission Enumeration
- Scan AWS services for accessible operations
- Supports custom operations via JSON configuration
- Identifies allowed and denied permissions
- Discovers hidden ARNs (Amazon Resource Names)

### 2. IAM Resource Exploration
- Further enumerate discovered IAM resources
- Extract detailed information about users, roles, and groups
- List attached and inline policies

### 3. Policy Analysis
- Read and explain IAM policies in human-readable format
- Highlight interesting and potentially risky permissions
- Save policy documents for further investigation

### 4. S3 Bucket Enumeration
- Enumerate specific S3 buckets
- List bucket operations and configurations
- Discover bucket accessibility and potential security issues

## Project Structure

```
aws_permission_toolkit/
│
├── aws_scanner.py          # Main entry point for the toolkit
│
├── config/                 # Configuration files
│   ├── custom_operations.json
│   ├── iam_operations.json
│   └── s3_operations.json
│
├── core/                   # Core functionality modules
│   ├── __init__.py
│   ├── arn_extractor.py    # ARN extraction utilities
│   ├── further_enum.py     # IAM resource enumeration
│   ├── permission_enum.py  # Permission scanning core
│   ├── policy_reader.py    # Policy document analysis
│   ├── s3_bucket_enum.py   # S3 bucket enumeration
│   └── utils.py            # Utility functions
│
└── README.md               # This documentation
```

## Installation

### Prerequisites
- Python 3.7+
- AWS CLI configured with appropriate credentials
- Required Python packages:
  - boto3
  - rich (optional, but recommended for better output)

### Setup
1. Clone the repository
2. Install dependencies:
   ```
   pip install boto3 rich
   ```

## Usage

### Basic Scanning
```bash
# Scan with default AWS profile
python aws_scanner.py --profile dev

# Scan with specific region
python aws_scanner.py --profile dev --region us-west-2

# Use custom operations file
python aws_scanner.py --profile dev --op_file config/custom_operations.json
```

### Advanced Options
- `--verbose`: Enable detailed output
- `--no_further`: Disable further IAM enumeration
- `--no_policy`: Disable policy processing
- `--output_dir`: Specify custom output directory

## Configuration

### Operations Configuration
Customize scanning by modifying JSON files in the `config/` directory:
- `custom_operations.json`: Define services and operations to scan
- `iam_operations.json`: Configure IAM resource enumeration
- `s3_operations.json`: Define S3 bucket enumeration operations

## Security Considerations
- Use the tool responsibly and only on environments you have explicit permission to test
- Ensure you have proper authorization before scanning
- The tool requires IAM permissions to perform enumeration

## Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Notes:
The tool is still under development to provide better result and also onboard more services.

## Disclaimer
This tool is for educational and authorized security testing purposes only. Unauthorized scanning of systems you do not own is illegal.
