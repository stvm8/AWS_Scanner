"""
Core functionality for AWS Permission Toolkit.
"""

# Import core modules for easier access
from .permission_enum import enumerate_permissions, save_results
from .further_enum import ask_for_further_enumeration
from .policy_reader import process_policies