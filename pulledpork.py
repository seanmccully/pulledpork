#!/usr/bin/env python3
"""
pulledpork3 v(whatever it says below!)

Copyright (C) 2021 Noah Dietrich, Colin Grady, Michael Shirk and the PulledPork Team!

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from argparse import ArgumentParser  # command line parameters parser
from json import load  # to load json in lightSPD
from os import environ, listdir, kill
from os.path import isfile, join, sep, abspath
from pathlib import Path
from platform import platform, version, uname, system, python_version, architecture
from re import search, sub, match, MULTILINE
from shutil import copy  # remove directory tree, python 3.4+
from string import Template

try:
    from signal import SIGHUP  # linux/bsd, not windows
except ImportError:
    # from ctypes import CDLL, c_raise,      # Windows reload process (not yet implemented)
    pass
from subprocess import Popen, PIPE  # to get Snort version from binary

# Our PulledPork3 internal libraries
from lib import config, helpers, logger
from lib.snort import Blocklist, Rules, Policies, RulesArchive, RulesetTypes


# -----------------------------------------------------------------------------
#   GLOBAL CONSTANTS
# -----------------------------------------------------------------------------

# Version is based on the following:
# First number will always be 3 (until Snort 4 or hell freezes over)
# Second number will be the major number (3.1.0.0 will be for a major updates only)
# Third number will be the minor number (3.0.1.0 for a number of bug fixes)
# Fourth number will be for any revisions between releases (to track builds)

__version__ = "3.1"

SCRIPT_NAME = "PulledPork"
TAGLINE = "Lowcountry yellow mustard bbq sauce is the best bbq sauce. Fight me."
VERSION_STR = f"{SCRIPT_NAME} v{__version__}"

# URLs for supported rulesets (replace <version> and <oinkcode> when downloading)
RULESET_URL_SNORT_COMMUNITY = (
    "https://snort.org/downloads/community/snort3-community-rules.tar.gz"
)
RULESET_URL_SNORT_REGISTERED = (
    "https://snort.org/rules/snortrules-snapshot-<VERSION>.tar.gz"
)
RULESET_URL_SNORT_LIGHTSPD = "https://snort.org/rules/Talos_LightSPD.tar.gz"

# TODO: Support for the ET Rulesets has not yet been implemented
RULESET_URL_ET_OPEN = Template(
    "https://rules.emergingthreats.net/open/snort-$version/emerging.rules.tar.gz"
)
RULESET_URL_ET_PRO = Template(
    "https://rules.emergingthreatspro.com/$oinkcode/snort-$version/etpro.rules.tar.gz"
)

# URLs for supported blocklists
SNORT_BLOCKLIST_URL = "https://snort.org/downloads/ip-block-list"
ET_BLOCKLIST_URL = "http://rules.emergingthreatspro.com/fwrules/emerging-Block-IPs.txt"

total_stats = {}

# -----------------------------------------------------------------------------
#   Prepare the logging and config
# -----------------------------------------------------------------------------

log = logger.Logger()
conf = config.Config()


# -----------------------------------------------------------------------------
#   MAIN FUNCTION - program execution starts here.
# -----------------------------------------------------------------------------
# Function to convert version string to comparable tuple
def version_to_tuple(version_str):
    """Convert version string like '3.1.0.0-0' to tuple (3,1,0,0,0) for comparison"""
    # Replace dash with dot and split
    parts = version_str.replace("-", ".").split(".")
    # Convert to integers, handling any non-numeric parts
    result = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    # Pad with zeros to ensure consistent length for comparison
    while len(result) < 5:
        result.append(0)
    return tuple(result)


def load_ruleset(working_dir, filename=None, url=None, oinkcode=None):
    """
    Load the specified ruleset, locally or from URL, and add to the rulesets list
    """

    log.verbose(f"Loading rules archive:\n - Source:  {filename or url}")

    # Attempt to load the file and get the type
    try:
        rules_archive = RulesArchive(filename=filename, url=url, oinkcode=oinkcode)
        ruleset_type = rules_archive.ruleset
    except Exception as e:
        log.warning(f"Unable to load rules archive:  {e}")
        return
    log.verbose(f" - Loaded as:  {ruleset_type.value}")

    # Save the ruleset
    try:
        written_file = rules_archive.write_file(working_dir.downloaded_path)
    except Exception as e:
        log.warning(f"Unable to save rules archive:  {e}")
        return
    log.verbose(f" - Saved as:  {written_file}")

    # Appends the loaded ruleset
    return rules_archive


# End helper


def main():
    conf = load_conf()

    target_dir = f"{SCRIPT_NAME}-{conf.start_time}"
    working_dir = helpers.WorkingDirectory(
        conf.temp_path, target_dir, conf.delete_temp_path
    )
    log.verbose(f"Working directory is:  {working_dir}")

    # Are we missing the Snort version in config?
    if not conf.defined("snort_version"):
        conf.snort_version = get_snort_version(conf.get("snort_path"))

    # we now have all required info to run, print the configuration to screen
    print_operational_settings()

    log.debug("---------------------------------")
    log.verbose("Loading rulesets")

    # The RulesArchive objects used for loading
    loaded_rulesets = []
    if conf.args.file:
        loaded_rulesets.append(load_ruleset(working_dir, filename=conf.args.file))

    if conf.args.folder:
        folder = Path(conf.args.folder)
        if folder.exists() and folder.is_dir():
            for path in folder.iterdir():
                full_path = folder.joinpath(path)
                if full_path.is_file():
                    loaded_rulesets.append(
                        load_ruleset(working_dir, filename=full_path)
                    )
    loaded_rulesets.extend(load_rulesets_extract(conf, working_dir))

    log.debug("---------------------------------")
    log.verbose("Processing rulesets")

    # Check if we're in update mode
    if conf.defined("update_mode"):
        if conf.update_mode == "update":
            if conf.defined("local_rules_folder"):
                update_mode(conf, loaded_rulesets, working_dir)

    else:
        # Original merge mode processing
        log.info("Running in MERGE mode - will create single rules file")
        log.debug("---------------------------------")
        log.verbose("Processing rulesets")

        pulled_pork_file_processing(conf, loaded_rulesets, working_dir)


# *****************************************************************************
# *****************************************************************************
#
#
#                       END OF MAIN FUNCTION
#
#
# *****************************************************************************
# *****************************************************************************


def load_conf():

    # parse our command-line args with ArgParse
    conf.args = parse_argv()

    # Setup logging as requested
    #   NOTE: For now all the args are permitted, but specifying more than one
    #         will override less verbose ones. Priority order:
    #               DEFAULT (info) < quiet < verbose < debug
    if conf.args.quiet:
        log.level = logger.Levels.WARNING
    if conf.args.verbose:
        log.level = logger.Levels.VERBOSE
    if conf.args.debug:
        log.level = logger.Levels.DEBUG

    # if the -V flag (version) was passed: Print the script Version and Exit
    if conf.args.version:
        print(VERSION_STR)
        flying_pig_banner()
        return

    # Always show pigs flying as the preamble, unless running in quiet mode
    if not conf.args.quiet:
        flying_pig_banner()

    # Print the env (will only print if verbose or debug)
    print_environment(conf)

    # Also setup halt on warn as requested
    log.halt_on_warn = not conf.args.ignore_warn

    # Save from args
    conf.delete_temp_path = not conf.args.keep_temp_dir

    # Load the configuration File from command line (-c FILENAME). Verify exists, and only 1 entry.
    if not conf.args.configuration:
        log.error("The following arguments are required: -c/--configuration <file>")
    if len(conf.args.configuration) > 1:
        log.warning(
            "Multiple entries passed as -c/--configuration.  Only a single entry permitted."
        )

    config_file = conf.args.configuration[0]  # this is a list of one element

    # load configuration file
    log.info(f"Loading configuration file:  {config_file}")
    try:
        conf.load(config_file)
    except Exception as e:
        log.error(f"Unable to load configuration file:  {e}")

    # Before we log the config, add hidden string for oinkcode
    if conf.oinkcode and not conf.args.print_oinkcode:
        log.add_hidden_string(conf.oinkcode)

    # Print the read config before validation
    conf.log_config()

    # Attempt to validate the config
    conf.validate()
    return conf


def update_mode(conf, loaded_rulesets, working_dir):
    log.info("Running in UPDATE mode - will update individual rule files")

    # Process each ruleset separately for update mode
    for loaded_ruleset in loaded_rulesets:
        ruleset_path = loaded_ruleset.extracted_path

        if loaded_ruleset.ruleset == RulesetTypes.REGISTERED:
            log.info("Processing Registered ruleset for updates")

            # Load rules with file tracking
            merge_rules_path(
                conf, conf.local_rules_folder, ruleset_path.joinpath("rules")
            )

        elif loaded_ruleset.ruleset == RulesetTypes.EMERGING_THREATS:

            log.info("Processing Emerging Threats ruleset for updates")
            merge_rules_path(
                conf, conf.local_rules_folder, ruleset_path.joinpath("rules")
            )

        elif loaded_ruleset.ruleset == RulesetTypes.LIGHTSPD:
            # Similar processing for LightSPD if needed
            log.info("Processing LightSPD ruleset for updates")
            lightspd_rules, lightspd_policies = process_rules_files(conf, ruleset_path)

            merge_rules_path_versions(
                conf,
                conf.local_rules_folder,
                ruleset_path.joinpath("lightspd", "rules"),
            )
            merge_rules_path_versions(
                conf,
                conf.local_builtins_folder,
                ruleset_path.joinpath("lightspd", "builtins"),
            )

        elif loaded_ruleset.ruleset == RulesetTypes.COMMUNITY:
            log.info("Processing Community ruleset for updates")
            # ... similar logic
            community_rules, _ = process_rules_files(
                conf, ruleset_path.joinpath("rules")
            )

    # Summary
    log.info("Update Summary:")
    total_updates = sum(s["updates"] for s in total_stats.values())
    total_additions = sum(s["additions"] for s in total_stats.values())
    log.info(f"  Total files modified: {len(total_stats)}")
    log.info(f"  Total rules updated: {total_updates}")
    log.info(f"  Total rules added: {total_additions}")


def load_rulesets_extract(conf, working_dir):
    loaded_rulesets = []
    if conf.community_ruleset:
        rulesets = load_ruleset(working_dir, url=RULESET_URL_SNORT_COMMUNITY)
        if not rulesets:
            log.error("No rulesets were loaded")
        else:
            loaded_rulesets.append(rulesets)
        extract_rulesets(loaded_rulesets, working_dir.extracted_path)
    if conf.emergingthreats_ruleset:
        et_vers = ["edge", "2.9.7.0"]  # Only two snort versions
        snort_version_tuple = version_to_tuple(conf.snort_version)
        url = RULESET_URL_ET_OPEN.substitute({"version": et_vers[0]})
        et_oinkcode = False
        if conf.defined("emergingthreats_oinkcode"):
            et_oinkcode = conf.emergingthreats_oinkcode
            url = RULESET_URL_ET_OPEN.substitute(
                {"version": et_vers[0], "oinkcode": et_oinkcode}
            )
        if snort_version_tuple[0] < 3:
            if et_oinkcode:
                url = RULESET_URL_ET_OPEN.substitute(
                    {"version": et_vers[1], "oinkcode": et_oinkcode}
                )
            else:
                url = RULESET_URL_ET_OPEN.substitute({"version": et_vers[1]})

        rulesets = load_ruleset(working_dir, url=url)
        if not rulesets:
            log.error("No rulesets were loaded")
        else:
            loaded_rulesets.append(rulesets)
        extract_rulesets(loaded_rulesets, working_dir.extracted_path)

    if conf.registered_ruleset:
        version = sub(
            r"[^a-zA-Z0-9]", "", "3.9.0.0"
        )  # version in URL is alphanumeric only
        reg_url = RULESET_URL_SNORT_REGISTERED.replace("<VERSION>", version)
        rulesets = load_ruleset(working_dir, url=reg_url, oinkcode=conf.oinkcode)
        if not rulesets:
            log.error("No rulesets were loaded")
        else:
            loaded_rulesets.append(rulesets)
        extract_rulesets(loaded_rulesets, working_dir.extracted_path)

    if conf.lightspd_ruleset:
        rulesets = load_ruleset(
            working_dir, url=RULESET_URL_SNORT_LIGHTSPD, oinkcode=conf.oinkcode
        )
        if not rulesets:
            log.error("No rulesets were loaded")
        else:
            loaded_rulesets.append(rulesets)
        extract_rulesets(loaded_rulesets, working_dir.extracted_path)

    return loaded_rulesets


def pulled_pork_file_processing(conf, loaded_rulesets, working_dir):
    all_new_rules = Rules()
    all_new_policies = Policies()

    for loaded_ruleset in loaded_rulesets:

        # Save the extracted path to a shorter named var
        ruleset_path = loaded_ruleset.extracted_path

        # determine ruleset type:
        if loaded_ruleset.ruleset == RulesetTypes.COMMUNITY:

            rules, policies = community_rules_processing(conf, ruleset_path)
            all_new_rules.extend(rules)
            all_new_policies.extend(policies)

        elif loaded_ruleset.ruleset == RulesetTypes.EMERGING_THREATS:
            rules = emerging_threats_rules_processing(conf, ruleset_path, working_dir)
            all_new_rules.extend(rules)

        elif loaded_ruleset.ruleset == RulesetTypes.REGISTERED:

            rules, policies = registered_rules_processing(
                conf, ruleset_path, working_dir
            )
            all_new_rules.extend(rules)
            all_new_policies.extend(policies)

        elif loaded_ruleset.ruleset == RulesetTypes.LIGHTSPD:
            rules, policies = lightspd_rules_processing(conf, ruleset_path, working_dir)
            all_new_rules.extend(rules)
            all_new_policies.extend(policies)
            log.verbose(
                "Preparing to apply policy " f"{conf.ips_policy} to LightSPD rules"
            )
            log.debug(f" - LightSPD rules before policy application:  {rules}")

            log.verbose("Finished processing LightSPD ruleset")
            log.verbose(f" - LightSPD Rules:  {rules}")
            log.verbose(f" - LightSPD Policies:  {policies}")

        else:
            log.warning("Unknown ruleset archive folder recieved.")
            # TODO: non-standard ruleset, we need to figure it out

    if len(conf.local_rules):
        load_local_rules(conf, all_new_rules, all_new_policies)

    log.info("Preparing to modify rules by sid file")

    log.info("Completed processing all rulesets and local rules:")
    log.info(f" - Collected Rules:  {all_new_rules}")
    rules_sid_mods(conf, all_new_rules)

    # if rule_mode is policy, and disabled rules should be written, we need to
    # enable all rules (but not modify the policy) so that all disabled rules
    # are written without a hash mark.
    if conf.rule_mode == "policy" and conf.include_disabled_rules:
        for rule in all_new_rules:
            rule.state = True

    # write rules to disk
    all_new_rules.write_file(
        conf.rule_path,
        conf.include_disabled_rules,
        create_policies(conf, all_new_policies),
    )

    # write the policy to disk
    if conf.rule_mode == "policy":
        log.info(f"Writing policy file to:  {conf.policy_path}")
        (all_new_policies[conf.ips_policy]).write_file(conf.policy_path)

    # copy .so rules from tempdir
    # todo: delete old rules
    if conf.defined("sorule_path"):
        src_files = listdir(working_dir.so_rules_path)
        for file_name in src_files:
            full_file_name = working_dir.so_rules_path.joinpath(file_name)
            if isfile(full_file_name):
                copy(full_file_name, conf.sorule_path)

    # -----------------------------------------------------------------------------
    # Download Blocklists

    download_blocklists(conf)
    # -----------------------------------------------------------------------------
    # Relad Snort

    reload_snort(conf)
    # Delete the working dir (if requested)
    del working_dir

    # -----------------------------------------------------------------------------
    # END Program Execution (main function)
    log.info("Program execution complete.")


def merge_rules_path_versions(conf, local_path, ruleset_path):
    rules_versions = ruleset_path.iterdir()
    snort_version_tuple = version_to_tuple(conf.snort_version)

    for rules_version in rules_versions:
        rules_version_tuple = version_to_tuple(rules_version.name)
        if snort_version_tuple >= rules_version_tuple:
            merge_rules_path(conf, local_path, ruleset_path.joinpath(rules_version))


def create_policies(conf, all_new_policies):
    log.info(" - Collected Policies:")
    for policy in all_new_policies:
        log.info(f"    - {policy}")

    # Prepare rules for output
    log.info(f"Writing rules to:  {conf.rule_path}")
    header = (
        "#-------------------------------------------------------------------\n"
        f"#  Rules file created by {SCRIPT_NAME}  at {conf.start_time}\n"
        "#  \n"
        "#  To Use this file: in your snort.lua, you need the following settings:\n"
        "#  ips =\n"
        "#  {{\n"
        f'#      include = "{conf.rule_path}",\n'
    )
    if conf.rule_mode == "policy":
        header += (
            f'#      states = "{conf.policy_path}",\n'
            "#      ...\n"
            "#  }}\n#\n"
            "#  detection=\n"
            "#  {{\n"
            "#      global_default_rule_state = false,\n"
        )
    header += "#      ...\n"
    header += "#  }}\n#\n"
    if conf.defined("sorule_path"):
        header += "# You have chosen to enable so rules.\n"
        header += "# To prevent errors when running snort, make sure to include\n"
        header += "# the following command-line option:\n"
        header += f'#    --plugin-path "{conf.sorule_path}"\n#\n'
    header += "#-------------------------------------------------------------------\n\n"
    return header


def rules_sid_mods(conf, all_new_rules):
    # Modify Rules based on sid files
    for s in conf.state_order:
        log.debug(f"- checking to see if {s} sid file is set in conf:")
        if s == "enable" and conf.defined("enablesid"):
            all_new_rules.load_sid_modification_file(conf.enablesid, "enable")
        elif s == "drop" and conf.defined("dropsid"):
            log.debug("dropsid is set in conf, will try to process.")
            all_new_rules.load_sid_modification_file(conf.dropsid, "drop")
        elif s == "disable" and conf.defined("disablesid"):
            all_new_rules.load_sid_modification_file(conf.disablesid, "disable")
        else:
            # errorout todo
            pass


def merge_rules_path(conf, local_path, ruleset_path):
    # Fix: Don't double the path
    update_rules = Rules(
        ruleset_path,  # Changed from ruleset_path.joinpath(ruleset_path)
        ignored_files=conf.ignored_files,
        track_files=True,
    )

    # Apply SID modifications before updating
    for s in conf.state_order:
        if s == "enable" and conf.defined("enablesid"):
            update_rules.load_sid_modification_file(conf.enablesid, "enable")
        elif s == "drop" and conf.defined("dropsid"):
            update_rules.load_sid_modification_file(conf.dropsid, "drop")
        elif s == "disable" and conf.defined("disablesid"):
            update_rules.load_sid_modification_file(conf.disablesid, "disable")

    # Update local files
    stats = update_rules.update_local_files(
        local_path, backup=(not conf.no_backup), dry_run=conf.dry_run
    )

    # Merge stats
    for file, file_stats in stats.items():
        if file not in total_stats:
            total_stats[file] = {"updates": 0, "additions": 0}
        total_stats[file]["updates"] += file_stats["updates"]
        total_stats[file]["additions"] += file_stats["additions"]


def load_local_rules(conf, all_new_rules, all_new_policies):

    log.verbose("Completed processing all rulesets before local rulesets:")
    log.verbose(f" - Collected Rules:  {all_new_rules}")
    log.verbose(" - Collected Policies:")
    for policy in all_new_policies:
        log.verbose(f"    - {policy}")

    for path in conf.local_rules:
        local_rules = Rules(path)
        log.info(f"loaded local rules file:  {local_rules} from {path}")
        all_new_rules.extend(local_rules)
        # local rules don't come with a policy file,
        # so create one (in case the rule_mode = policy)
        all_new_policies.extend(local_rules.policy_from_state(conf.ips_policy))


def lightspd_rules_processing(conf, ruleset_path, working_dir):
    lightspd_rules, lightspd_policies = process_lightspd_files(
        conf, ruleset_path, working_dir
    )

    text_rules, text_policies = process_rules_files(
        conf, ruleset_path.joinpath("lightspd", "rules")
    )
    lightspd_rules.extend(text_rules)
    lightspd_policies.extend(text_policies)

    builtin_rules, builtin_policies = process_rules_files(
        conf, ruleset_path.joinpath("lightspd", "builtin")
    )

    lightspd_rules.extend(builtin_rules)
    lightspd_policies.extend(builtin_policies)
    # apply the policy to these rules
    lightspd_rules.apply_policy(lightspd_policies[conf.ips_policy])

    return lightspd_rules, lightspd_policies


def emerging_threats_rules_processing(conf, ruleset_path, working_dir):
    log.info("Processing Emerging Threats ruleset")
    log.verbose(f" - Ruleset path:  {ruleset_path}")

    # Original rules path (Snort 2 format)
    text_rules_path = ruleset_path.joinpath("rules")

    # Check Snort version to determine if conversion is needed
    snort_version_tuple = version_to_tuple(conf.snort_version)

    if snort_version_tuple[0] >= 3:
        # Snort 3 - need to convert rules
        log.info("Detected Snort 3 - converting ET rules from Snort 2 format")

        # Convert the rules
        converted_path = helpers.convert_snort2_to_snort3_rules(text_rules_path, working_dir)

        if converted_path and converted_path.exists():
            # Use converted rules
            registered_rules = Rules(converted_path, conf.ignored_files)
            log.verbose(f" - Converted Rules:  {registered_rules}")
        else:
            log.error("Failed to convert ET rules to Snort 3 format")
            return Rules()  # Return empty Rules object
    else:
        # Snort 2 - use rules as-is
        registered_rules = Rules(text_rules_path, conf.ignored_files)
        log.verbose(f" - Text Rules:  {registered_rules}")

    # ET rules don't come with policies, so we don't process them
    log.debug(f" - Text Rules:  {registered_rules}")

    return registered_rules


def registered_rules_processing(conf, ruleset_path, working_dir):

    log.info("Processing Registered ruleset")
    log.verbose(f" - Ruleset path:  {ruleset_path}")

    # process text rules
    text_rules_path = ruleset_path.joinpath("rules")
    registered_rules = Rules(text_rules_path, conf.ignored_files)
    registered_policies = Policies(text_rules_path)

    log.debug(f" - Text Rules:  {registered_rules}")
    log.debug(f" - Text Policies:  {registered_policies}")

    # process builtin rules
    builtin_rules_path = ruleset_path.joinpath("builtins")
    builtin_rules = Rules(builtin_rules_path)
    builtin_policies = Policies(builtin_rules_path)

    log.debug(f" - Builtin Rules:  {builtin_rules}")
    log.debug(f" - Builtin Policies:  {builtin_policies}")

    registered_rules.extend(builtin_rules)
    registered_policies.extend(builtin_policies)

    # process so rules
    if conf.defined("sorule_path"):
        # copy files first to temp\so_rules
        # folder (we'll copy them all at the end, this checks for dupes)
        # todo: error handling
        so_src_folder = ruleset_path.joinpath("so_rules", "precompiled", conf.distro)
        src_files = listdir(so_src_folder)
        for file_name in src_files:
            full_file_name = so_src_folder.joinpath(file_name)
            if isfile(full_file_name):
                copy(full_file_name, working_dir.so_rules_path)

        # get SO rule stubs
        # todo: generate stubs if distro folder doesn't exist
        so_rules_path = ruleset_path.joinpath("so_rules")

        so_rules = Rules(so_rules_path)
        so_policies = Policies(so_rules_path)

        log.debug(f" - SO Rules:  {so_rules}")
        log.debug(f" - SO Policies:  {so_policies}")

        registered_rules.extend(so_rules)
        registered_policies.extend(so_policies)

    log.verbose(f"Preparing to apply policy {conf.ips_policy} to Registered rules")
    log.debug(f" - Registered rules before policy application:  {registered_rules}")

    # apply the policy to these rules
    registered_rules.apply_policy(registered_policies[conf.ips_policy])

    log.verbose("Finished processing Registered ruleset")
    log.verbose(f" - Registered Rules:  {registered_rules}")
    log.verbose(f" - Registered Policies:  {registered_policies}")

    return registered_rules, registered_policies


def community_rules_processing(conf, ruleset_path):
    log.info("Processing Community ruleset")
    log.verbose(f" - Ruleset path:  {ruleset_path}")

    # only simple rules to worry about
    # community rules have an extra folder to delve into
    rule_path = ruleset_path.joinpath("snort3-community-rules")

    # todo: wrap next line in try/catch
    community_rules = Rules(rule_path, conf.ignored_files)

    # Generate the community policy from the rules
    # commmunity rules don't come with a policy file
    # so create one (in case the rule_mode = policy)
    community_policy = community_rules.policy_from_state(conf.ips_policy)

    log.verbose("Finished processing Community ruleset")
    log.verbose(f" - Community Rules:  {community_rules}")
    log.verbose(f" - Community Policy:  {community_policy}")

    return community_rules, community_policy


def process_rules_files(conf, ruleset_path):

    rules_versions = ruleset_path.iterdir()
    snort_version_tuple = version_to_tuple(conf.snort_version)
    rules = Rules()
    policies = Policies()
    for rules_version in rules_versions:
        rule_version_tuple = version_to_tuple(rules_version.name)
        if rule_version_tuple <= snort_version_tuple:

            rule = Rules(ruleset_path.joinpath(rules_version), conf.ignored_files)
            policy = Policies(ruleset_path.joinpath(rules_version))

            log.debug(f" - Rules processed:  {rules}")
            log.debug(f" - Policies processed:  {policies}")

            rules.extend(rule)
            policies.extend(policy)
    return rules, policy


def process_lightspd_files(conf, ruleset_path, working_dir):
    log.info("Processing LightSPD ruleset")
    log.verbose(f" - Ruleset path:  {ruleset_path}")

    lightspd_rules = Rules()
    lightspd_policies = Policies()

    # load .so rules IFF sorule_path is configured.
    # if 'distro' is not configured, then we need to compile the rules ourself
    # right now: we only use the manifest.json file for processing .so rules
    if conf.defined("sorule_path") and conf.defined("distro"):
        log.debug("Trying to load precompiled so rules")
        json_manifest_file = ruleset_path.joinpath("lightspd", "manifest.json")

        # load json manifest file to identify .so rules location
        log.debug(f"Processing json manifest file {json_manifest_file}")
        with open(json_manifest_file) as f:
            manifest = load(f)

        # Get all available versions from manifest
        manifest_versions = list(manifest["snort versions"].keys())
        log.debug(
            f"Found {len(manifest_versions)} versions in manifest: {manifest_versions}"
        )

        # Convert our Snort version to tuple
        snort_version_tuple = version_to_tuple(conf.snort_version)
        log.debug(
            f"Snort version {conf.snort_version} converted to tuple: {snort_version_tuple}"
        )

        # Find the best matching version (highest version <= our Snort version)
        best_match = None
        best_match_tuple = (0, 0, 0, 0, 0)

        for manifest_version in manifest_versions:
            manifest_tuple = version_to_tuple(manifest_version)
            log.debug(
                f"Checking manifest version {manifest_version} (tuple: {manifest_tuple})"
            )

            # Check if this version is <= our Snort version and better than current best
            is_version = (
                manifest_tuple <= snort_version_tuple
                and manifest_tuple > best_match_tuple
            )
            if is_version:
                best_match = manifest_version
                best_match_tuple = manifest_tuple
                log.debug(f"  -> New best match: {best_match}")

        if best_match is None:
            log.warning(
                f"No compatible version found in LightSPD manifest for Snort {conf.snort_version}"
            )
            log.warning("Available versions: " + ", ".join(sorted(manifest_versions)))
        else:
            version_to_use = best_match
            log.info(
                f"Using LightSPD version {version_to_use} for Snort {conf.snort_version}"
            )

            # Get other data from manifest file for the selected version
            policies_path = manifest["snort versions"][version_to_use].get(
                "policies_path", ""
            )
            policies_path = policies_path.replace("/", sep)
            log.debug(f"policies_path from LightSPD Manifest: {policies_path}")

            # Check if architecture exists
            if conf.distro not in manifest["snort versions"][version_to_use].get(
                "architectures", {}
            ):
                ver = manifest["snort versions"][version_to_use]
                log.warning(
                    f"Architecture {conf.distro} not found for version {version_to_use}"
                )
                log.warning(
                    "Available architectures: "
                    f"{list(ver.get("architectures", {}).keys())}"
                )
            else:
                modules_path = manifest["snort versions"][version_to_use][
                    "architectures"
                ][conf.distro]["modules_path"]
                modules_path = modules_path.replace("/", sep)
                log.debug(f"modules_path from LightSPD Manifest: {modules_path}")

                # Check if we should compile from source
                if conf.defined("compile_lightspd") and conf.compile_lightspd:
                    log.info("Compiling SO rules from source with hybrid approach")
                    precompiled_base = ruleset_path.joinpath(
                        "lightspd", modules_path, "so_rules"
                    )
                    lightspd_rules, lightspd_policies = compile_so_rules_hybrid(
                        ruleset_path.joinpath("lightspd", "modules", "src"),
                        precompiled_base,
                        working_dir.so_rules_path,
                    )
                else:
                    # Copy precompiled SO files
                    so_src_folder = ruleset_path.joinpath(
                        "lightspd", modules_path, "so_rules"
                    )
                    if so_src_folder.exists():
                        for file_name in so_src_folder.glob("*"):
                            if file_name.is_file():
                                full_file_name = so_src_folder.joinpath(file_name)
                                if full_file_name.is_file():
                                    copy(full_file_name, working_dir.so_rules_path)
                                    log.debug(f"Copied precompiled SO: {file_name}")

                    # Load SO rule stubs
                    so_rules_path = ruleset_path.joinpath(
                        "lightspd", "modules", "stubs"
                    )
                    lightspd_rules = Rules(so_rules_path)
                    lightspd_policies = Policies(so_rules_path)

        log.debug(f" - SO Rules processed:  {lightspd_rules}")
        log.debug(f" - SO Policies processed:  {lightspd_policies}")

    elif conf.defined("sorule_path"):
        log.debug("Trying to compile .so rules (no distro specified)")
        lightspd_rules, lightspd_policies = compile_so_rules(
            ruleset_path.joinpath("lightspd", "modules", "src"),
            working_dir.so_rules_path,
        )

    else:
        log.debug("No so rules to process.")
    return lightspd_rules, lightspd_policies


def download_blocklists(conf):
    # Have a blocklist out file defined AND have a blocklist to download?
    if conf.defined("blocklist_path") and any(
        [conf.snort_blocklist, conf.et_blocklist, len(conf.blocklist_urls)]
    ):

        log.debug("---------------------------------")
        log.verbose("Processing blocklists")

        # Prepare an empty blocklist
        new_blocklist = Blocklist()

        # Downloading the Snort blocklist?
        if conf.snort_blocklist:
            log.verbose(" - Downloading the Snort blocklist")
            try:
                new_blocklist.load_url(SNORT_BLOCKLIST_URL)
            except Exception as e:
                log.warning(f"Unable to download the Snort blocklist:  {e}")

        # ET blocklist?
        if conf.et_blocklist:
            log.verbose(" - Downloading the ET blocklist")
            try:
                new_blocklist.load_url(ET_BLOCKLIST_URL)
            except Exception as e:
                log.warning(f"Unable to download the ET blocklist:  {e}")

        # Any other blocklists
        for bl_url in conf.blocklist_urls:
            log.verbose(f" - Downloading blocklist:  {bl_url}")
            try:
                new_blocklist.load_url(bl_url)
            except Exception as e:
                log.warning(f"Unable to download blocklist:  {e}")

        # Compose the blocklist header and write the blocklist file
        blocklist_header = (
            "#-------------------------------------------------------------------\n"
        )
        blocklist_header += (
            f"# BLOCKLIST CREATED BY {SCRIPT_NAME.upper()} ON {conf.start_time}\n#\n"
        )
        blocklist_header += (
            "# To Use this file, in your snort.lua, you need the following settings:\n"
        )
        blocklist_header += "# reputation = \n"
        blocklist_header += "# {{\n"
        blocklist_header += f'#     blocklist = "{conf.blocklist_path}",\n'
        blocklist_header += "#     ...\n"
        blocklist_header += "# }}\n"
        blocklist_header += "#\n#-------------------------------------------------------------------\n\n"

        log.info(f"Writing blocklist file to:  {conf.blocklist_path}")
        try:
            new_blocklist.write_file(conf.blocklist_path, blocklist_header)
        except Exception as e:
            log.warning(f"Unable to write blocklist:  {e}")


def reload_snort(conf):
    # Have a PID file defined?
    if conf.defined("pid_path"):
        log.verbose(f"Loading Snort PID file: {conf.pid_path}")
        pid = 0
        try:
            with open(conf.pid_path, "r") as f:
                pid = int(f.readline().strip())
        except Exception as e:
            log.warning(f"Error loading PID file {conf.pid_path}: {e}")

        if not pid:
            log.warning(f"Missing or invalid Snort PID: {pid}")
        else:
            log.info(f"Sending Snort process the reload signal (PID {pid}).")
            try:
                kill(pid, SIGHUP)
            except Exception as e:
                log.warning(f"Error sending SIGHUP to Snort3 process: {e}")

        # windows SIGHUP
        # import ctypes
        # ucrtbase = ctypes.CDLL('ucrtbase')
        # c_raise = ucrtbase['raise']
        # c_raise(some_signal)


def flying_pig_banner():
    """
    OMG We MUST HAVE FLYING PIGS! The community demands it.
    """

    # For now simple printing, will need to clean this up
    # Pig art by JJ Cummings
    print(
        f"""
    https://github.com/shirkdog/pulledpork3
      _____ ____
     `----,\\    )   {VERSION_STR}
      `--==\\\\  /    {TAGLINE}
       `--==\\\\/
     .-~~~~-.Y|\\\\_  Copyright (C) 2021 Noah Dietrich, Colin Grady, Michael Shirk
  @_/        /  66\\_  and the PulledPork Team!
    |    \\   \\   _(\")
     \\   /-| ||'--'   Rules give me wings!
      \\_\\  \\_\\\\
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"""
    )


def parse_argv():
    """
    Get command line arguments into global argparser variable
    """

    # Parse command-line arguments
    arg_parser = ArgumentParser(description=f"{VERSION_STR} - {TAGLINE}")

    # we want Quiet or Verbose (v, vv), can't have more than one (but we can have none)
    group_verbosity = arg_parser.add_mutually_exclusive_group()
    group_verbosity.add_argument(
        "-v", "--verbose", help="Increase output verbosity", action="store_true"
    )
    group_verbosity.add_argument(
        "-vv", "--debug", help="Really increase output verbosity", action="store_true"
    )
    group_verbosity.add_argument(
        "-q", "--quiet", help="Only display warnings and errors", action="store_true"
    )

    # input file or folder (optional)
    group_input = arg_parser.add_mutually_exclusive_group()
    group_input.add_argument(
        "-f", "--file", help="Use this file as source of rulesets", type=abspath
    )
    group_input.add_argument(
        "-F",
        "--folder",
        help="Use all the tgz file in this folder as source of rulesets",
        type=abspath,
    )

    # standard arguments
    arg_parser.add_argument(
        "-c",
        "--configuration",
        help="path to the configuration file",
        nargs=1,
        type=abspath,
    )
    arg_parser.add_argument(
        "-V", "--version", help="Print version number and exit", action="store_true"
    )
    arg_parser.add_argument(
        "-k",
        "--keep-temp-dir",
        help="Do not delete the temp directory when done",
        action="store_true",
    )
    arg_parser.add_argument(
        "-po",
        "--print-oinkcode",
        help="Do not obfuscate oinkcode in output.",
        action="store_true",
    )
    arg_parser.add_argument(
        "-i",
        "--ignore-warn",
        help="Ignore warnings and continue processing.",
        action="store_true",
    )

    return arg_parser.parse_args()


def print_operational_settings():
    """
    Print all the operational settings after parsing (what we will do)
    """

    log.verbose("---------------------------------")
    log.verbose(
        "After parsing the command line and configuration file, this is what I know:"
    )

    # halt-on-error
    if conf.args.ignore_warn:
        log.verbose(
            "Warnings will not cause this program to terminate (damn the torpedos, full speed ahead!)."
        )
    else:
        log.verbose("Program will terminate when encountering an error or warning.")

    # are we printing oinkcode?
    if conf.args.print_oinkcode:
        log.verbose(
            "Oinkcode will NOT be obfuscated in the output (do not share your oinkcode)."
        )
    else:
        log.verbose("Oinkcode will be obfuscated in the output (this is a good thing).")

    # Temp dir management
    log.verbose(f"Temporary directory is:  {conf.temp_path}")

    if conf.delete_temp_path:
        log.verbose("Temporary working directory will be deleted at the end.")
    else:
        log.verbose("Temporary working directory will not be deleted at the end.")

    # env. variables
    log.verbose(
        f"The Snort version number used for processing is:  {conf.snort_version}"
    )
    if conf.defined("distro"):
        log.verbose(f"The distro used for processing is: {conf.distro}")
    log.verbose(f"The ips policy used for processing is: {conf.ips_policy}")

    if conf.defined("sorule_path"):
        log.verbose("Pre-compiled (.so) rules will be processed.")
        log.verbose(f"Pre-compiled (.so) files will be saved to: {conf.sorule_path}")
    else:
        log.verbose("Pre-compiled (.so) rules will not be processed.")
    # ruelset locations
    if conf.args.file:
        log.verbose(
            "Rulesets will not be downloaded, they will be loaded from a single local file: \n\t {conf.args.file} "
        )
    elif conf.args.folder:
        log.verbose(
            "Rulesets will not be downloaded, "
            "they will be loaded from all files "
            f"in local folder: \n\t {conf.args.folder}"
        )
    else:
        log.verbose("Rulesets will be downloaded from: ")
        if conf.registered_ruleset:
            log.verbose("\tSnort Registered Ruleset")
        if conf.community_ruleset:
            log.verbose("\tSnort Community Ruleset")
        if conf.lightspd_ruleset:
            log.verbose("\tSnort LightSPD Ruleset")

    #   Rules
    if conf.ignored_files:
        log.verbose(
            f"The following rules files will not be included in rulesets:  {", ".join(conf.ignored_files)}"
        )

    log.verbose(f"Rule Output mode is:  {conf.rule_mode}")
    if conf.rule_mode == "policy":
        log.verbose(f"Policy file to write is: {conf.policy_path}")

    # local rules files
    for opt in conf.local_rules:
        log.verbose(f"Rules from Local rules file will be included: {opt}")

    log.verbose(f"All Rules will be written to a single file: {conf.rule_path}")
    if conf.include_disabled_rules:
        log.verbose("Disabled rules will be written to the rules file")
    else:
        log.verbose("Disabled rules will not be written to the rules file")

    # policys
    log.verbose(f"The rule_mode is:  {conf.rule_mode}")
    if conf.rule_mode == "policy":
        log.verbose(
            f"the policy file written (to specify enabled rules) is:  {conf.policy_path}"
        )

    # blocklists
    if conf.snort_blocklist:
        log.verbose("Snort blocklist will be downloaded")
    if conf.et_blocklist:
        log.verbose("ET blocklist will be downloaded")

    for bl in conf.blocklist_urls:
        log.verbose(f"Other blocklist will be downloaded: {bl}")

    if not any([conf.snort_blocklist, conf.et_blocklist, len(conf.blocklist_urls)]):
        log.verbose("No Blocklists will be downloaded.")
    else:
        log.verbose(f"Blocklist entries will be written to: {conf.blocklist_path}")

    # sid modification order
    log.verbose(f"The state_order is: {conf.state_order}")

    # sid files:
    # check the sid files exist if defined
    if conf.defined("enablesid"):
        log.verbose(f"enablesid path is:  {conf.enablesid}")

    if conf.defined("dropsid"):
        log.verbose(f"dropsid path is:  {conf.dropsid}")

    if conf.defined("disablesid"):
        log.verbose(f"disablesid path is:  {conf.disablesid}")

    if conf.defined("modifysid"):
        log.verbose(f"modifysid path is:  {conf.modifysid}")

    # reload snort
    if conf.defined("pid_path"):
        log.verbose(
            f"Snort will be reloaded with new configuration, Pid loaded from:  {conf.pid_path}"
        )
    else:
        log.verbose("Snort will NOT be reloaded with new configuration.")


def extract_rulesets(files, target_dir):
    """
    untar archives to folder,
    """
    if isinstance(target_dir, str):
        target_dir = Path(target_dir)

    log.verbose(f"Preparing to extract rulesets:\n - Target Path:  {target_dir}")
    for file in files:

        # get the filename
        if file.filename.endswith(".tgz"):
            out_dir = target_dir.joinpath(file.filename[:-4])
        elif file.filename.endswith(".tar.gz"):
            out_dir = target_dir.joinpath(file.filename[:-7])
        else:
            out_dir = target_dir.joinpath(file.filename)

        log.verbose(
            f" - Extracting archive:\n   - Filename: {file.filename}\n   - To: {out_dir}"
        )
        file.extract(out_dir)


def print_environment(gc):
    """
    Print environment Information
    """

    # todo: get distro
    # todo: convert print to 'log'
    log.debug(f"Start time:  {gc.start_time}")
    log.verbose(f"Log level:  {log.level.name}")
    log.debug("Parsed command-line arguments are (including defaults):")
    for k, v in sorted(vars(gc.args).items()):
        log.debug(f" - {k} = {v}")
    log.debug(f"Platform:  {platform()}; {version()}")
    log.debug(f"uname:  {uname()}")
    log.debug(f"System:  {system()}")
    log.debug(f"Architecture:  {architecture()[0]}")
    log.debug(f"Python version:  {python_version()}")
    log.debug(f'PWD:  {environ.get("PWD")}')
    log.debug(f'Shell:  {environ.get("SHELL")}')
    log.debug(f"OS direcotry separator:  {sep}")


def get_snort_version(snort_path=None):
    """
    Determine the Version of Snort
    """

    log.debug("Determining Snort version from executable")

    # Default to just "snort" if no path provided
    snort_path = snort_path or "snort"

    # Run snort to attempt to find the version
    command = f"{snort_path} -V"
    log.debug(f" - Running Snort using:  {command}")

    # call the snort binary with -V flag
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
        output, error = process.communicate()
    except Exception as e:
        log.error(f"Fatal error running Snort:  {e}")

    # check return call for error
    if error:
        log.error(f"Fatal error running Snort:  [{process.returncode}] {error.strip()}")

    # parse stdout from snort binary to determine version number
    log.debug(f" - Output from Snort: \n{output}")
    x = search(r"Version ([-\.\d\w]+)", str(output))
    if not x:
        log.error("Unable to grok version number from Snort output")
    log.verbose(f" - Snort version is: {x[1]}")
    return x[1]


def normalize_version_number(number):

    log.debug(f"entering function normalize_version_number with param {number}")
    ver = ""
    # check for a semi-normal number first (n.n.n.n-n)
    if match(r"^\d+\.\d+\.\d+\.\d+-\d+$", number):
        ver = number.replace("-", ".", 1)

    # check for a semi-normal number (n.n.n.n)
    elif match(r"^\d+\.\d+\.\d+\.\d+$", number):
        ver = number + ".0"

    # check for early releases with poor numbering (n.n.n-n)
    elif match(r"^\d+\.\d+\.\d+-\d+$", number):
        ver = number.replace("-", ".0.", 1)

    else:
        log.warning(f"Unknown version number format: {number}")

    log.debug(f"Normalized version number is {ver}")
    return ver


def version_equal_or_lesser(v1, v2):
    # returns true if v1 is equal or less than v2

    log.debug(
        f"Entering Function version_equal_or_lesser(v1,v2), Comparing version strings: {v1} to {v2}"
    )

    # This will split both the versions by '.'
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    n = len(arr1)
    m = len(arr2)

    # converts to integer from string
    arr1 = [int(i) for i in arr1]
    arr2 = [int(i) for i in arr2]

    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimeters)
    if n > m:
        for i in range(m, n):
            arr2.append(0)
    elif m > n:
        for i in range(n, m):
            arr1.append(0)

    for i in range(len(arr1)):
        if arr1[i] > arr2[i]:
            log.debug("- Returning True (lesser)")
            return True
        elif arr2[i] > arr1[i]:
            log.debug("- Returning False")
            return False

    log.debug("- Returning True (equal)")
    return True


def compile_so_rules(src_path, dst_path):
    log.debug(f"Entering function compile_so_rules with src_path: {src_path}")
    if isinstance(src_path, str):
        src_path = Path(src_path)
    # Make generate_category.sh executable
    gen_cat_script = Path(src_path).joinpath("generate_category.sh")
    log.debug(f"Changing permissions to 755 for {gen_cat_script}")
    try:
        gen_cat_script.chmod(0o755)
    except Exception as e:
        log.error(f"Unable to chmod {gen_cat_script}: {e}")

    # Get build parameters from pkg-config
    command = "pkg-config --variable=bindir snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        bindir, error = process.communicate()
    except Exception as e:
        log.error(f'Fatal error determining "bindir": {e}')

    bindir = bindir.strip()
    if not bindir:
        log.error('"bindir" could not be determined by pkg-config.')
    bindir = bindir.joinpath("snort")
    log.debug(f"bindir: {bindir}")

    # Get compiler flags
    command = "pkg-config --cflags snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        cflags, error = process.communicate()
    except Exception as e:
        log.error(f"Fatal error getting cflags: {e}")

    cflags = cflags.strip()
    if not cflags:
        log.error('"cflags" could not be determined by pkg-config.')
    log.debug(f"cflags: {cflags}")

    # Get library flags for linking
    command = "pkg-config --libs snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        ldflags, error = process.communicate()
    except Exception as e:
        log.warning(f"Could not get ldflags: {e}")
        ldflags = ""

    # Fix the Makefile
    makefile = src_path.joinpath("Makefile")
    log.debug(f"Modifying Makefile: {makefile}")

    with open(makefile, "r+") as f:
        text = f.read()

        # Replace hardcoded paths
        text = sub(
            r"CXXFLAGS \+= -I\$\(PREFIX\)/include/snort",
            f"CXXFLAGS += {cflags}",
            text,
            flags=MULTILINE,
        )
        text = sub(r"\$\(SNORT\)", bindir, text, flags=MULTILINE)

        # Add -fPIC for position-independent code (required for shared objects)
        if "-fPIC" not in text:
            text = sub(r"(CXXFLAGS \+=)", r"\1 -fPIC", text, count=1)

        # Add library flags if available
        if ldflags:
            text = sub(r"(LDFLAGS \+=)", f"\\1 {ldflags}", text, count=1)

        f.seek(0)
        f.write(text)
        f.truncate()

    # Run make to compile
    log.info("Compiling SO rules from source. This may take a few minutes...")
    try:
        # Add environment variables for compilation
        env = environ.copy()
        env["CXX"] = "g++"
        env["CC"] = "gcc"

        process = Popen(
            "make clean && make",
            stdout=PIPE,
            stderr=PIPE,
            shell=True,
            universal_newlines=True,
            cwd=src_path,
            env=env,
        )
        output, error = process.communicate()

        if process.returncode != 0:
            log.error(f"Make failed with return code {process.returncode}")
            log.error(f"Error output: {error}")
    except Exception as e:
        log.error(f"Fatal error running make: {e}")

    log.debug(f"Make output:\n{output}")

    # Copy compiled .so files
    so_files = src_path.glob("*.so")

    if not so_files:
        log.warning("No .so files were generated!")

    for so_file in so_files:
        if isfile(so_file):
            copy(so_file, dst_path)
            log.debug(f"Copied: {so_file} -> {dst_path}")

    # Load rules and policies
    lightspd_rules = Rules(src_path)
    lightspd_policies = Policies(join(src_path, "..", "stubs"))

    log.debug(f"SO Rules processed: {lightspd_rules}")
    log.debug(f"SO Policies processed: {lightspd_policies}")

    return lightspd_rules, lightspd_policies


def compile_so_rules_hybrid(src_path, precompiled_path, dst_path):
    """
    Compile SO rules from source where available, use precompiled for others
    """
    log.debug("Using hybrid SO rule compilation/copying approach")

    # First, compile from source
    compiled_files = set()
    if isinstance(src_path, str):
        dst_path = Path(src_path)
    if isinstance(dst_path, str):
        dst_path = Path(dst_path)
    if isinstance(precompiled_path, str):
        precompiled_path = Path(precompiled_path)

    # Make generate_category.sh executable
    gen_cat_script = Path(join(src_path, "generate_category.sh"))
    log.debug(f"Changing permissions to 755 for {gen_cat_script}")
    try:
        gen_cat_script.chmod(0o755)
    except Exception as e:
        log.error(f"Unable to chmod {gen_cat_script}: {e}")

    # Get build parameters from pkg-config
    command = "pkg-config --variable=bindir snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        bindir, error = process.communicate()
    except Exception as e:
        log.error(f'Fatal error determining "bindir": {e}')

    bindir = bindir.strip()
    if not bindir:
        log.error('"bindir" could not be determined by pkg-config.')
    bindir = join(bindir, "snort")
    log.debug(f"bindir: {bindir}")

    # Get compiler flags
    command = "pkg-config --cflags snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        cflags, error = process.communicate()
    except Exception as e:
        log.error(f"Fatal error getting cflags: {e}")

    cflags = cflags.strip()
    if not cflags:
        log.error('"cflags" could not be determined by pkg-config.')
    log.debug(f"cflags: {cflags}")

    # Get library flags for linking
    command = "pkg-config --libs snort"
    try:
        process = Popen(
            command, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True
        )
        ldflags, error = process.communicate()
    except Exception as e:
        log.warning(f"Could not get ldflags: {e}")
        ldflags = ""

    # Fix the Makefile
    makefile = join(src_path, "Makefile")
    log.debug(f"Modifying Makefile: {makefile}")

    with open(makefile, "r+") as f:
        text = f.read()

        # Replace hardcoded paths
        text = sub(
            r"CXXFLAGS \+= -I\$\(PREFIX\)/include/snort",
            f"CXXFLAGS += {cflags}",
            text,
            flags=MULTILINE,
        )
        text = sub(r"\$\(SNORT\)", bindir, text, flags=MULTILINE)

        # Add -fPIC for position-independent code (required for shared objects)
        if "-fPIC" not in text:
            text = sub(r"(CXXFLAGS \+=)", r"\1 -fPIC", text, count=1)

        # Add library flags if available
        if ldflags:
            text = sub(r"(LDFLAGS \+=)", f"\\1 {ldflags}", text, count=1)

        f.seek(0)
        f.write(text)
        f.truncate()

    # Run make to compile
    log.info("Compiling SO rules from source. This may take a few minutes...")
    try:
        # Add environment variables for compilation
        env = environ.copy()
        env["CXX"] = "g++"
        env["CC"] = "gcc"

        process = Popen(
            "make clean && make",
            stdout=PIPE,
            stderr=PIPE,
            shell=True,
            universal_newlines=True,
            cwd=src_path,
            env=env,
        )
        output, error = process.communicate()

        if process.returncode != 0:
            log.error(f"Make failed with return code {process.returncode}")
            log.error(f"Error output: {error}")
    except Exception as e:
        log.error(f"Fatal error running make: {e}")

    log.debug(f"Make output:\n{output}")

    # Copy compiled .so files
    so_files = Path(src_path).glob("*.so")
    if not so_files:
        log.warning("No .so files were generated!")

    for so_file in so_files:
        filename = so_file.name
        compiled_files.add(filename)
        copy(so_file, dst_path)
        log.debug(f"Using compiled: {filename}")

    # List of ALL expected SO files (from stubs directory)
    stub_files = src_path.joinpath("..", "stubs").glob("*.rules")
    expected_so_files = set()
    for stub in stub_files:
        basename = stub.name
        if basename != "includes.rules" and not basename.startswith("rulestates"):
            so_name = basename.replace(".rules", ".so")
            expected_so_files.add(so_name)

    # Find what's missing
    missing_files = expected_so_files - compiled_files

    if missing_files:
        log.info(f'Using precompiled binaries for: {", ".join(missing_files)}')

        # Try multiple architecture paths
        # arch_paths = [
        #    'ubuntu-x64/3.0.0.0-0/so_rules',
        #    'debian-x64/3.0.0.0-0/so_rules',
        #    'centos-x64/3.0.0.0-0/so_rules'
        # ]
        for so_file in missing_files:
            file = precompiled_path.joinpath(so_file)
            if file.exists():
                copy(file, dst_path)
                log.debug(f"Using precompiled: {file} from {precompiled_path.parent}")
            else:
                log.debug(f"Using precompiled: {file} Doesn't exist")

    # Load rules and policies
    lightspd_rules = Rules(src_path.joinpath("..", "stubs"))
    lightspd_policies = Policies(src_path.joinpath("..", "stubs"))

    return lightspd_rules, lightspd_policies


if __name__ == "__main__":
    main()
