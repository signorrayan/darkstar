"""
WordPress-specific Nuclei vulnerability scanner for the Darkstar framework.

This module provides specialized scanning for WordPress installations to
detect vulnerabilities using Nuclei's template-based approach.
"""

import logging
import subprocess
import yaml
from typing import Optional

from common.db_helper import insert_vulnerability_to_database
from core.models.vulnerability import Vulnerability
from scanners.nuclei.base import BaseNucleiScanner
from common.logger import setup_logger

setup_logger()
logger = logging.getLogger(__name__)


class WordPressNucleiScanner(BaseNucleiScanner):
    """
    Specialized Nuclei scanner for WordPress vulnerabilities.

    Provides methods to scan WordPress installations for known
    vulnerabilities using specialized Nuclei templates.

    Attributes:
        domains (str): WordPress domains to scan
        org_name (str): Organization name for database storage
    """

    def __init__(self, domains: str, org_name: str):
        super().__init__(org_name)
        self.domains = domains

    def find_first_path_with_nuclei(self, pattern: str) -> Optional[str]:
        """
        Find a Nuclei template file based on a hash pattern.

        Args:
            pattern: Template hash to search for

        Returns:
            Path to the template file, or None if not found
        """
        # Build the find command
        command = ["find", "/", "-name", f"*{pattern}*"]
        # Run the command; stderr is suppressed to mimic 2>/dev/null
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        logger.debug(f"Find result: {result}")

        # Split the output by newline to get a list of paths
        paths = result.stdout.strip().split("\n") if result.stdout else []

        # Iterate over paths and return the first one containing "nuclei"
        for path in paths:
            if "nuclei" in path:
                return path
        return None

    def scan_nuclei(self) -> None:
        """
        Execute WordPress-specific Nuclei scan and process results.

        Runs Nuclei against WordPress domains, using template information
        to extract detailed vulnerability data.
        """
        logger.info(f"Running Nuclei WordPress scan against {self.domains}")

        nuclei_command = f'nuclei -u "{self.domains}" -s low,medium,high,critical,unknown -t github -bs 400 -rl 4000'
        logger.debug(f"Command: {nuclei_command}")

        process = subprocess.Popen(
            nuclei_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
        )

        while True:
            output_line = process.stdout.readline()
            if not output_line and process.poll() is not None:
                break

            if output_line:
                if any(keyword in output_line for keyword in self.keywords):
                    logger.debug(f"Output Line: {output_line}")

                    # Extract URL and domain
                    url = self.extract_url_from_output(output_line)
                    domain = self.extract_host_from_url(url)

                    # Get first element of output line
                    vuln = output_line.split(" ")[0]
                    logger.debug(f"Raw vuln: {vuln}")

                    # Extract template hash for detailed info
                    template_hash_value = (
                        vuln.rstrip("]").lstrip("[").split("-")[-1].split(":")[0]
                    )
                    template_hash_value = self.remove_ansi_codes(template_hash_value)

                    formatted_vuln = (
                        vuln.replace(f"-{template_hash_value}", "")
                        .strip("[")
                        .strip("]")
                    )
                    formatted_vuln = self.remove_ansi_codes(formatted_vuln).split(":")[
                        0
                    ]
                    logger.debug(f"Formatted vuln: {formatted_vuln}")

                    # Default values
                    references = []
                    vuln_title = formatted_vuln
                    severity = self.extract_severity(output_line)

                    # Try to get additional data from the template file
                    logger.debug(f"Template hash: {template_hash_value}")
                    template_path = self.find_first_path_with_nuclei(
                        template_hash_value
                    )
                    logger.debug(f"Template path: {template_path}")

                    # Extract detailed info if template found
                    if template_path is not None:
                        try:
                            with open(template_path, "r") as f:
                                template_data = yaml.safe_load(f)

                            if template_data and "info" in template_data:
                                references = template_data["info"].get("reference", [])
                                vuln_title = template_data["info"].get(
                                    "name", formatted_vuln
                                )
                                severity = template_data["info"].get(
                                    "severity", severity
                                )
                        except Exception as e:
                            logger.error(
                                f"Error parsing template file {template_path}: {e}"
                            )

                    # Determine if this is a CVE
                    cve_number = None
                    if "CVE" in formatted_vuln or "cve" in formatted_vuln:
                        cve_number = formatted_vuln

                    logger.info(f"Vulnerability: {vuln_title}")

                    # Create and store vulnerability
                    finding_object = Vulnerability(
                        title=vuln_title,
                        affected_item=url,
                        tool="nuclei_wordpress",
                        confidence=97,
                        severity=severity,
                        host=domain,
                        cve_number=cve_number,
                        references=references,
                        poc=url,
                    )

                    # Add to database
                    logger.info(f"Adding to database: {finding_object}")
                    insert_vulnerability_to_database(
                        vuln=finding_object, org_name=self.org_name
                    )

        logger.info("WordPress Nuclei scan completed")
