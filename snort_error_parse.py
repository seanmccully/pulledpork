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
    def __init__(self, log_file: str, rule_dirs: List[str] = None):
        self.log_file = log_file
        self.rule_dirs = rule_dirs or ['/etc/snort/rules', './rules']
        self.error_pattern = re.compile(
            r'ERROR:\s+(\S+):(\d+)\s+SO rule (\d+) not loaded\.'
        )
        self.duplicate_pattern = re.compile(
            r'ERROR:\s+(\S+):(\d+)\s+GID (\d+) SID (\d+) in rule duplicates previous rule, with different protocol\.'
        )
        self.rule_pattern = re.compile(r'sid:(\d+);')
        self.gid_pattern = re.compile(r'gid:(\d+);')
        self.rev_pattern = re.compile(r'rev:(\d+);')
        self.soid_pattern = re.compile(r'soid:(\d+);')

    def parse_errors(self) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        """
        Parse the log file and extract both SO rule loading errors and duplicate rule errors.

        Returns:
            Tuple of (so_errors, duplicate_errors)
        """
        so_errors = []
        duplicate_errors = []

        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    # Check for SO rule errors
                    match = self.error_pattern.search(line.strip())
                    if match:
                        so_errors.append({
                            'log_line': line_num,
                            'rule_file': match.group(1),
                            'rule_line': match.group(2),
                            'rule_id': match.group(3),
                            'full_line': line.strip()
                        })

                    # Check for duplicate rule errors
                    dup_match = self.duplicate_pattern.search(line.strip())
                    if dup_match:
                        duplicate_errors.append({
                            'log_line': line_num,
                            'rule_file': dup_match.group(1),
                            'rule_line': dup_match.group(2),
                            'gid': dup_match.group(3),
                            'sid': dup_match.group(4),
                            'full_line': line.strip()
                        })

        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading log file: {e}")
            sys.exit(1)

        return so_errors, duplicate_errors

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

    def find_duplicate_rules(self, sid: str, rule_files: List[str]) -> List[Dict]:
        """
        Find all instances of a rule with given SID across rule files.

        Args:
            sid: The rule SID to search for
            rule_files: List of rule file paths to search

        Returns:
            List of dictionaries with rule information
        """
        found_rules = []

        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        original_line = line
                        check_line = line.strip()

                        # Track if rule is commented
                        is_commented = False
                        if check_line.startswith('#'):
                            is_commented = True
                            check_line = check_line[1:].strip()

                        if not check_line:
                            continue

                        # Look for sid in the rule
                        sid_match = self.rule_pattern.search(check_line)
                        if sid_match and sid_match.group(1) == sid:
                            # Extract revision
                            rev_match = self.rev_pattern.search(check_line)
                            rev = int(rev_match.group(1)) if rev_match else 0

                            # Extract GID
                            gid_match = self.gid_pattern.search(check_line)
                            gid = gid_match.group(1) if gid_match else "1"

                            found_rules.append({
                                'file_path': rule_file,
                                'line_num': line_num,
                                'rule_content': check_line,
                                'original_line': original_line,
                                'revision': rev,
                                'gid': gid,
                                'sid': sid,
                                'is_commented': is_commented
                            })

            except Exception as e:
                print(f"Warning: Could not read rule file '{rule_file}': {e}")
                continue

        return found_rules

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

    def handle_duplicate_rules(self, duplicate_errors: List[Dict], dry_run: bool = False):
        """
        Process duplicate rule errors and comment out older revisions.

        Args:
            duplicate_errors: List of duplicate rule errors
            dry_run: If True, don't actually modify files
        """
        print("\n" + "=" * 80)
        print("PROCESSING DUPLICATE RULE ERRORS")
        print("=" * 80)

        if not duplicate_errors:
            print("No duplicate rule errors found.")
            return

        print(f"Found {len(duplicate_errors)} duplicate rule error(s).")

        # Find all rule files
        rule_files = self.find_rule_files()

        # Track which files we'll modify
        files_to_modify = set()

        for error in duplicate_errors:
            sid = error['sid']
            print(f"\nProcessing SID {sid}:")
            print(f"  Error: {error['full_line']}")

            # Find all instances of this rule
            found_rules = self.find_duplicate_rules(sid, rule_files)

            if len(found_rules) < 2:
                print(f"  ⚠ Expected multiple instances but found {len(found_rules)}")
                continue

            # Sort by revision (highest first)
            found_rules.sort(key=lambda x: x['revision'], reverse=True)

            print(f"  Found {len(found_rules)} instance(s):")
            for rule in found_rules:
                status = "[COMMENTED]" if rule['is_commented'] else "[ACTIVE]"
                print(f"    {status} Rev {rule['revision']}: {os.path.basename(rule['file_path'])}:{rule['line_num']}")

            # Keep the highest revision (first in sorted list)
            newest_rule = found_rules[0]
            print(f"  Keeping newest revision {newest_rule['revision']} from {os.path.basename(newest_rule['file_path'])}")

            # Comment out older revisions
            for rule in found_rules[1:]:
                if not rule['is_commented']:
                    file_name = os.path.basename(rule['file_path'])

                    # Skip if it's pulledpork.rules (we don't want to modify that)
                    if 'pulledpork' in file_name.lower():
                        print(f"    ⚠ Skipping pulledpork.rules - should be handled by pulledpork config")
                        continue

                    print(f"  Disabling older rev {rule['revision']} in {file_name}:{rule['line_num']}")
                    self.comment_out_rule(rule['file_path'], rule['line_num'], dry_run)
                    files_to_modify.add(rule['file_path'])

        if files_to_modify:
            print(f"\n✓ Modified {len(files_to_modify)} file(s)")
            for file_path in sorted(files_to_modify):
                print(f"  - {file_path}")

    def run(self, write_disablesid: bool = False, fix_duplicates: bool = False, dry_run: bool = False) -> None:
        """
        Main execution method to parse errors and handle them.

        Args:
            write_disablesid: Whether to write a disablesid.conf file
            fix_duplicates: Whether to fix duplicate rule errors
            dry_run: If True, don't actually modify files
        """
        # Parse errors from log file
        so_errors, duplicate_errors = self.parse_errors()

        # Handle SO rule errors
        if so_errors:
            print("=" * 80)
            print("SNORT SO RULE ERROR PARSER")
            print("=" * 80)
            print(f"Found {len(so_errors)} SO rule loading error(s).")

            if write_disablesid:
                # Process SO errors and write disablesid.conf
                # ... (previous SO error handling code here) ...
                pass

        # Handle duplicate rule errors
        if fix_duplicates and duplicate_errors:
            self.handle_duplicate_rules(duplicate_errors, dry_run)

def main():
    parser = argparse.ArgumentParser(
        description="Parse Snort logs for rule errors and fix issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fix duplicate rules by commenting out older revisions
  python snort_parser.py /var/log/snort/snort.log --fix-duplicates

  # Dry run to see what would be changed
  python snort_parser.py /var/log/snort/snort.log --fix-duplicates --dry-run

  # Handle both SO errors and duplicates
  python snort_parser.py /var/log/snort/snort.log --write-disablesid --fix-duplicates

  # Specify custom rule directories
  python snort_parser.py snort.log -r /etc/snort/rules /opt/snort/rules --fix-duplicates
        """
    )

    parser.add_argument(
        'log_file',
        help='Path to the Snort log file to parse'
    )

    parser.add_argument(
        '-r', '--rule-dirs',
        nargs='+',
        default=['/etc/snort/rules', './rules'],
        help='Directories to search for rule files (default: /etc/snort/rules ./rules)'
    )

    parser.add_argument(
        '-w', '--write-disablesid',
        action='store_true',
        help='Write a disablesid.conf file for PulledPork (for SO errors)'
    )

    parser.add_argument(
        '-f', '--fix-duplicates',
        action='store_true',
        help='Fix duplicate rule errors by commenting out older revisions'
    )

    parser.add_argument(
        '-d', '--dry-run',
        action='store_true',
        help="Don't actually modify files, just show what would be done"
    )

    parser.add_argument(
        '-o', '--output',
        default='disablesid.conf',
        help='Output filename for disablesid.conf (default: disablesid.conf)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"Log file: {args.log_file}")
        print(f"Rule directories: {', '.join(args.rule_dirs)}")
        if args.dry_run:
            print("DRY RUN MODE - No files will be modified")
        print()

    snort_parser = SnortRuleParser(args.log_file, args.rule_dirs)
    snort_parser.run(
        write_disablesid=args.write_disablesid,
        fix_duplicates=args.fix_duplicates,
        dry_run=args.dry_run
    )

if __name__ == "__main__":
    main()
