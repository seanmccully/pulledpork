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

    for rule_file in rules_path.glob("*.rules"):
        output_file = converted_path / rule_file.name

        # Run snort2lua for this file
        command = f"snort2lua -c {rule_file} -r {rule_file}"
        log.verbose(f"Converting {rule_file.name} using snort2lua")

        try:
            process = Popen(
                command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
            )
            output, error = process.communicate()

            if process.returncode == 0:
                # Parse the converted rules from stdout
                # snort2lua outputs to stdout by default
                with output_file.open("w") as f:
                    # Filter out non-rule lines from the output
                    for line in output.splitlines():
                        # Skip lua configuration lines, only keep actual rules
                        line = line.strip()
                        if not line.startswith("--") and not line.starswith("require"):
                            for _key in ("alert", "drop", "pass", "reject", "block"):
                                if _key in line:
                                    f.write(line + "\n")
                                    break
                converted_count += 1
                log.debug(f"  Converted: {rule_file.name}")
            else:
                log.warning(
                    f"Bulk conversion failed for {rule_file.name}, trying line-by-line"
                )
                if convert_rules_file_individually(rule_file, output_file):
                    converted_count += 1
                else:
                    failed_count += 1
                    log.warning(f"  Failed to convert: {rule_file.name}")
                    if error:
                        log.debug(f"  Error: {error}")

        except Exception as e:
            failed_count += 1
            log.warning(f"Exception converting {rule_file.name}: {e}")

    log.info(
        f"Conversion complete: {converted_count} files converted, {failed_count} failed"
    )

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
    converted_rules = []

    with input_file.open("r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Create temp file with single rule
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".rules", delete=False
            ) as tmp:
                tmp.write(line)
                tmp_path = tmp.name

            try:
                # Try to convert single rule
                command = f"snort2lua -c {tmp_path} -r {tmp_path}"
                process = Popen(
                    command,
                    stdout=PIPE,
                    stderr=PIPE,
                    shell=True,
                    universal_newlines=True,
                )
                output, error = process.communicate()

                if process.returncode == 0:
                    # Extract the converted rule from output
                    for out_line in output.splitlines():
                        out_line = out_line.strip()
                        if not out_line.startswith("--"):
                            for _key in ("alert", "drop"):
                                if _key in out_line:
                                    converted_rules.append(out_line)
                                    break
                else:
                    log.debug(f"    Line {line_num}: Could not convert")

            finally:
                # Clean up temp file
                os.unlink(tmp_path)

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
