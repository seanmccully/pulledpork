from pathlib import Path
import os
from shutil import rmtree
from subprocess import Popen, PIPE
import tempfile


from . import logger


__all__ = ["WorkingDirectory", "convert_snort2_to_snort3_rules"]


################################################################################
# Logging
################################################################################

log = logger.Logger()


################################################################################
# WorkingDirectory - Temporary directory helper
################################################################################


class WorkingDirectory:

    __slots__ = [
        "temp_path",
        "dir_name",
        "path",
        "downloaded_path",
        "extracted_path",
        "so_rules_path",
        "cleanup_on_exit",
    ]

    def __init__(self, temp_path, dir_name, cleanup_on_exit=True):
        """
        Setup the working directory and structure
        """

        # Save the bits
        self.temp_path = Path(temp_path)
        self.dir_name = dir_name
        self.path = Path(self.temp_path).joinpath(self.dir_name)
        self.downloaded_path = self.path.joinpath("downloaded_rulesets")
        self.extracted_path = self.path.joinpath("extracted_rulesets")
        self.so_rules_path = self.path.joinpath("so_rules")
        self.cleanup_on_exit = cleanup_on_exit

        # Prepare things
        self._setup()

    def __repr__(self):
        return f"WorkingDirectory(path:{self.path}, cleanup_on_exit:{self.cleanup_on_exit})"

    def __del__(self):
        """
        Clean up the temprary folder if required
        """

        log.debug("---------------------------------")

        # Not cleaning up?
        if not self.cleanup_on_exit:
            log.verbose(f"Not deleting working directory: {self.path}")
            return

        log.verbose(f"Attempting to delete working directory: {self.path}")
        try:
            rmtree(self.path)
        except Exception as e:
            log.warning(f"Unable to delete working directory: {e}")
        else:
            log.verbose(" - Successfully deleted working directory")

    def _setup(self):
        """
        Create the directory structure we'll be using
        """

        log.verbose(f"Setting up the working directory structure in: {self.path}")

        # Create all the directories
        try:
            if not self.path.exists():
                self.path.mkdir(parents=True)
            self.downloaded_path.mkdir()
            self.extracted_path.mkdir()
            self.so_rules_path.mkdir()
        except Exception as e:
            log.error(f"Setup of the working directory failed: {e}")
        else:
            log.verbose(" - Successfully setup the working directory")

def convert_snort2_to_snort3_rules(rules_path, working_dir):
    """
    Convert Snort 2 rules to Snort 3 format using snort2lua

    Args:
        rules_path: Path containing Snort 2 format rules
        working_dir: Working directory for converted rules

    Returns:
        Path to converted rules directory
    """

    converted_path = working_dir.path.joinpath("converted_snort3_rules")
    converted_path.mkdir(exist_ok=True)

    log.info("Converting Emerging Threats Snort 2 rules to Snort 3 format")

    rules_path = Path(rules_path)
    converted_count = 0
    failed_count = 0
    total_rejected = 0

    for rule_file in rules_path.glob("*.rules"):
        output_file = converted_path / rule_file.name

        # Run snort2lua with correct syntax
        command = f"snort2lua -c {rule_file} -r {output_file}"
        log.verbose(f"Converting {rule_file.name} using snort2lua")

        try:
            process = Popen(
                command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
            )
            output, error = process.communicate()

            # snort2lua returns non-zero if there are rejected rules
            # but it still creates the output file with converted rules
            if output_file.exists() and output_file.stat().st_size > 0:
                converted_count += 1
                log.debug(f"  Converted: {rule_file.name}")

                # Check for rejected rules
                reject_file = Path("snort.rej")
                if reject_file.exists():
                    with reject_file.open("r") as f:
                        rejected_rules = f.readlines()
                    rejected_count = len([line for line in rejected_rules if line.strip() and not line.startswith("#")])
                    if rejected_count > 0:
                        log.warning(f"  {rejected_count} rules rejected from {rule_file.name}")
                        total_rejected += rejected_count
                    # Clean up reject file
                    reject_file.unlink()
            else:
                failed_count += 1
                log.warning(f"  Failed to convert: {rule_file.name}")
                if error:
                    log.debug(f"  Error: {error[:500]}")

        except Exception as e:
            failed_count += 1
            log.warning(f"Exception converting {rule_file.name}: {e}")

    log.info(
        f"Conversion complete: {converted_count} files converted, {failed_count} failed"
    )
    if total_rejected > 0:
        log.warning(f"Total rules rejected across all files: {total_rejected}")

    if converted_count == 0:
        log.error("No rules were successfully converted")
        return None

    return converted_path


def convert_rules_file_individually(input_file, output_file):
    """
    Convert a rules file line by line when bulk conversion fails

    Args:
        input_file: Path to input Snort 2 rules file
        output_file: Path to output Snort 3 rules file

    Returns:
        True if at least some rules were converted
    """
    import tempfile

    converted_rules = []
    temp_dir = Path(tempfile.gettempdir())

    with input_file.open("r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Create temp file with single rule
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".rules", delete=False, dir=temp_dir
            ) as tmp:
                tmp.write(line)
                tmp_path = Path(tmp.name)

            try:
                # Create temp output file
                temp_output = temp_dir / f"conv_{line_num}.rules"

                # Try to convert single rule
                command = f"snort2lua -c {tmp_path} -r {temp_output}"
                process = Popen(
                    command,
                    stdout=PIPE,
                    stderr=PIPE,
                    shell=True,
                    universal_newlines=True,
                )
                output, error = process.communicate()

                # Check if output file was created
                if temp_output.exists():
                    with temp_output.open("r") as f:
                        converted_rule = f.read().strip()
                        if converted_rule:
                            converted_rules.append(converted_rule)
                    temp_output.unlink()

                # Clean up reject file if it exists
                reject_file = Path("snort.rej")
                if reject_file.exists():
                    reject_file.unlink()

            finally:
                # Clean up temp file
                tmp_path.unlink(missing_ok=True)

    # Write successfully converted rules
    if converted_rules:
        with output_file.open("w") as f:
            for rule in converted_rules:
                f.write(rule + "\n")
        log.verbose(
            f"  Individually converted {len(converted_rules)} rules from {input_file.name}"
        )
        return True

    return False
