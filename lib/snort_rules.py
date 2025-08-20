#!/usr/bin/env python3

import re
import os
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime
import shutil


class SnortRuleParser:
    """
    """
    def __init__(self, rule_dirs: List[str] = None):
        self.rule_dirs = rule_dirs or ['/etc/snort/rules', './rules']

        self.rule_pattern = re.compile(r'sid:(\d+);')
        self.gid_pattern = re.compile(r'gid:(\d+);')
        self.rev_pattern = re.compile(r'rev:(\d+);')
        self.soid_pattern = re.compile(r'soid:(\d+);')



    def find_rule_files(self) -> List[str]:
        """
        Find all rule files in the specified directories.

        Returns:
            List of rule file paths
        """
        rule_files = []

        for directory in self.rule_dirs:
            if os.path.isdir(directory):
                for file_path in Path(directory).rglob('*.rules'):
                    rule_files.append(str(file_path))
                # Also check for .rule files
                for file_path in Path(directory).rglob('*.rule'):
                    rule_files.append(str(file_path))

        return rule_files

    def comment_out_rule(self, file_path: str, line_num: int, dry_run: bool = False) -> bool:
        """
        Comment out a specific line in a rule file.

        Args:
            file_path: Path to the rule file
            line_num: Line number to comment out (1-indexed)
            dry_run: If True, don't actually modify the file

        Returns:
            True if successful, False otherwise
        """
        try:
            # Read the file
            with open(file_path, 'r') as f:
                lines = f.readlines()

            # Check if line is already commented
            if lines[line_num - 1].strip().startswith('#'):
                print(f"      Line {line_num} already commented")
                return True

            if dry_run:
                print(f"      [DRY RUN] Would comment out line {line_num}")
                return True

            # Create backup
            backup_path = f"{file_path}.bak"
            shutil.copy2(file_path, backup_path)

            # Comment out the line
            lines[line_num - 1] = f"# DISABLED DUE TO NEWER REVISION: {lines[line_num - 1]}"

            # Write back
            with open(file_path, 'w') as f:
                f.writelines(lines)

            print(f"      ✓ Commented out line {line_num}")
            return True

        except Exception as e:
            print(f"      ✗ Error modifying file: {e}")
            return False

    def handle_duplicate_rules(self, duplicate_rules: List[Dict], dry_run: bool = False):
        """
        Process duplicate rule errors and comment out older revisions.

        Args:
            duplicate_errors: List of duplicate rule errors
            dry_run: If True, don't actually modify files
        """

        # Find all rule files
        rule_files = self.find_rule_files()

        # Track which files we'll modify
        files_to_modify = set()

        for rule in duplicate_rules:
            sid = rule['sid']
            # Find all instances of this rule
            found_rules = self.find_duplicate_rules(sid, rule_files)

            if len(found_rules) < 2:
                print(f"  ⚠ Expected multiple instances but found {len(found_rules)}")
                continue

            # Sort by revision (highest first)
            found_rules.sort(key=lambda x: x['revision'], reverse=True)

            # Comment out older revisions
            for rule in found_rules[1:]:
                if not rule['is_commented']:
                    file_name = os.path.basename(rule['file_path'])

                    # Skip if it's pulledpork.rules (we don't want to modify that)
                    if 'pulledpork' in file_name.lower():
                        print(f"    ⚠ Skipping pulledpork.rules - should be handled by pulledpork config")
                        continue

                    self.comment_out_rule(rule['file_path'], rule['line_num'], dry_run)
