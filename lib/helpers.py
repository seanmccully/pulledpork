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


def convert_snort2_to_snort3_rules(snort2lua_path, rules_path, working_dir):
    converted_path = working_dir.path.joinpath("converted_snort3_rules")
    converted_path.mkdir(exist_ok=True)

    # 0) sanity: make sure we’re calling the right tool
    try:
        p = Popen(f"{snort2lua_path} -V", stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
        out, err = p.communicate(timeout=5)
        log.verbose(f"snort2lua version: {out.strip() or err.strip()}")
    except Exception:
        pass

    log.info("Converting Emerging Threats Snort 2 rules to Snort 3 format")

    rules_path = Path(rules_path)
    converted_count = 0
    failed_count = 0
    total_rejected = 0

    # 1) Skip known-problematic ET rule files
    skip_names = {"deleted.rules", "scada.rules", "scada_special.rules"}

    # 2) run per file, but anchor the child cwd so snort.rej and snort.lua land where we expect
    for rule_file in rules_path.glob("*.rules"):
        if rule_file.name in skip_names:
            log.verbose(f"  Skipping known incompatible file: {rule_file.name}")
            continue

        output_file = converted_path / rule_file.name
        command = f"{snort2lua_path} -c {rule_file} -r {output_file}"
        log.verbose(f"Converting {rule_file.name} using snort2lua")

        try:
            process = Popen(
                command,
                stdout=PIPE,
                stderr=PIPE,
                shell=True,
                universal_newlines=True,
                cwd=str(converted_path)  # <-- critical: capture snort.rej & snort.lua here
            )
            output, error = process.communicate()

            # 3) if we got some output, count it; also capture rejects and thresholds
            if output_file.exists() and output_file.stat().st_size > 0:
                converted_count += 1
                log.debug(f"  Converted: {rule_file.name}")

                # rejected rules
                reject_file = converted_path / "snort.rej"
                if reject_file.exists():
                    with reject_file.open("r") as f:
                        rejected_rules = [
                            line for line in f.readlines()
                            if line.strip() and not line.startswith("#")
                        ]
                    if rejected_rules:
                        log.warning(f"  {len(rejected_rules)} rules rejected from {rule_file.name}")
                        total_rejected += len(rejected_rules)
                    reject_file.unlink(missing_ok=True)

                # thresholds/suppressions: snort2lua emits snort.lua; stash & append
                thresholds_src = converted_path / "snort.lua"
                if thresholds_src.exists():
                    thresholds_dst = converted_path / "et_thresholds.lua"
                    with thresholds_src.open("r") as src, thresholds_dst.open("a") as dst:
                        dst.write(f"\n-- thresholds from {rule_file.name}\n")
                        dst.write(src.read())
                    thresholds_src.unlink(missing_ok=True)

            else:
                # 4) fallback to per-line conversion to rescue partial content
                log.warning(f"  Bulk conversion failed for: {rule_file.name}. Trying line-by-line.")
                if convert_rules_file_individually(rule_file, output_file):
                    converted_count += 1
                else:
                    failed_count += 1
                    if error:
                        log.debug(f"  Error: {error[:500]}")

        except Exception as e:
            failed_count += 1
            log.warning(f"Exception converting {rule_file.name}: {e}")

    log.info(f"Conversion complete: {converted_count} files converted, {failed_count} failed")
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
                command = f"{snort2lua_path} -c {tmp_path} -r {temp_output}"
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
