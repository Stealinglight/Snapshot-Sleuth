"""
Evidence Miner Tool - Forensic artifact extraction and analysis

Extracts and analyzes forensic artifacts from mounted snapshots:
- User enumeration and password analysis
- Login history and session data
- SSH keys and configuration
- Service configurations (SSH, nginx, httpd)
- Cron jobs and automated tasks
- Startup scripts and persistence mechanisms
- IAM credentials and AWS configuration
- Hidden directories and suspicious files

Produces normalized findings for:
- Credential exposure
- Persistence mechanisms
- Privilege escalation opportunities
- Configuration issues
"""

import hashlib
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

# Import from forensics-base
import sys
sys.path.insert(0, '/app/src')

from snapshot_reader import EBSMountReader, FileEntry
from progress import ProgressReporter, PhaseInfo
from result_handler import (
    ResultHandler,
    NormalizedResult,
    Finding,
    FindingType,
    Severity,
    create_finding_id,
)

logger = structlog.get_logger(__name__)


class EvidenceMinerTool:
    """
    Evidence Miner forensic artifact extraction tool.

    Analyzes mounted snapshot for security-relevant artifacts and
    produces normalized findings.
    """

    # Paths to exclude from hidden directory analysis
    EXCLUDED_HIDDEN_PATHS = {
        ".cargo", ".npm", ".cache", ".rustup", ".config",
        ".local", ".mozilla", ".gnupg", ".pki",
        ".snapshots", ".build-id", ".git", ".svn",
        ".X11-unix", ".font-unix", ".XIM-unix", ".ICE-unix",
    }

    # AWS credential patterns
    AWS_ACCESS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')
    AWS_SECRET_KEY_PATTERN = re.compile(r'[A-Za-z0-9/+=]{40}')

    def __init__(
        self,
        config,
        reader: EBSMountReader,
        progress: ProgressReporter,
        result_handler: ResultHandler,
    ):
        self.config = config
        self.reader = reader
        self.progress = progress
        self.result_handler = result_handler
        self._logger = logger.bind(tool="evidence-miner", case_id=config.case_id)

        # Analysis results
        self._users: dict = {}
        self._password_hashes: list = []
        self._sudoers: list = []
        self._login_history: list = []
        self._ssh_keys: dict = {}
        self._services: dict = {}
        self._cron_jobs: list = []
        self._startup_scripts: list = []
        self._iam_credentials: dict = {}
        self._hidden_dirs: list = []
        self._instance_id: str = "unknown"

    def run(self) -> NormalizedResult:
        """Execute evidence mining on the mounted snapshot."""
        start_time = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors_count = 0

        # Define processing phases
        self.progress.define_phases([
            PhaseInfo("users", weight=0.15, description="Enumerating users"),
            PhaseInfo("logins", weight=0.10, description="Analyzing login history"),
            PhaseInfo("ssh", weight=0.15, description="Extracting SSH artifacts"),
            PhaseInfo("services", weight=0.10, description="Reviewing services"),
            PhaseInfo("automation", weight=0.15, description="Finding automation/persistence"),
            PhaseInfo("credentials", weight=0.15, description="Searching for credentials"),
            PhaseInfo("hidden", weight=0.10, description="Finding hidden directories"),
            PhaseInfo("upload", weight=0.10, description="Uploading results"),
        ])

        try:
            # Get instance ID
            self._get_instance_id()

            # Phase 1: User enumeration
            with self.progress.phase("users"):
                user_findings = self._enumerate_users()
                findings.extend(user_findings)

            # Phase 2: Login history
            with self.progress.phase("logins"):
                login_findings = self._analyze_login_history()
                findings.extend(login_findings)

            # Phase 3: SSH artifacts
            with self.progress.phase("ssh"):
                ssh_findings = self._extract_ssh_artifacts()
                findings.extend(ssh_findings)

            # Phase 4: Service configuration
            with self.progress.phase("services"):
                service_findings = self._review_services()
                findings.extend(service_findings)

            # Phase 5: Automation and persistence
            with self.progress.phase("automation"):
                automation_findings = self._find_automation()
                findings.extend(automation_findings)

            # Phase 6: Credential search
            with self.progress.phase("credentials"):
                cred_findings = self._search_credentials()
                findings.extend(cred_findings)

            # Phase 7: Hidden directories
            with self.progress.phase("hidden"):
                hidden_findings = self._find_hidden_directories()
                findings.extend(hidden_findings)

            # Phase 8: Upload results
            with self.progress.phase("upload"):
                self._upload_raw_results()

            status = "success"

        except Exception as e:
            self._logger.error("Evidence mining failed", error=str(e))
            status = "failed"
            errors_count += 1

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        return NormalizedResult(
            tool_name="evidence-miner",
            case_id=self.config.case_id,
            snapshot_id=self.config.snapshot_id,
            status=status,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            findings=findings,
            files_scanned=0,  # Not applicable for artifact extraction
            bytes_scanned=0,
            errors_count=errors_count,
            tool_version="2.0.0",
            metadata={
                "instance_id": self._instance_id,
                "users_found": len(self._users),
                "ssh_keys_found": sum(len(keys) for keys in self._ssh_keys.values()),
                "cron_jobs_found": len(self._cron_jobs),
            },
        )

    def _get_instance_id(self) -> None:
        """Try to determine EC2 instance ID from cloud-init."""
        try:
            cloud_instances = "/var/lib/cloud/instances/"
            if self.reader.is_directory(cloud_instances):
                entries = self.reader.list_directory(cloud_instances)
                for entry in entries:
                    if entry.name.startswith("i-") and entry.is_directory:
                        self._instance_id = entry.name
                        self._logger.info("Found instance ID", instance_id=self._instance_id)
                        return
        except Exception as e:
            self._logger.warning("Could not determine instance ID", error=str(e))

    def _enumerate_users(self) -> list[Finding]:
        """Enumerate users from passwd/shadow files."""
        findings = []

        # Parse /etc/passwd
        try:
            passwd_content = self.reader.read_file("/etc/passwd").decode("utf-8", errors="ignore")
            for line in passwd_content.splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    username, _, uid, gid, gecos, home, shell = parts[:7]
                    # Skip system accounts with nologin shells
                    if shell not in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/dev/null"]:
                        self._users[username] = {
                            "uid": uid,
                            "gid": gid,
                            "home": home,
                            "shell": shell,
                        }
        except Exception as e:
            self._logger.warning("Could not parse passwd", error=str(e))

        # Parse /etc/shadow for password hashes
        try:
            shadow_content = self.reader.read_file("/etc/shadow").decode("utf-8", errors="ignore")
            for line in shadow_content.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    password_hash = parts[1]

                    # Check for set passwords (not locked/disabled)
                    if password_hash and password_hash[0] not in ["!", "*", "x"]:
                        self._password_hashes.append(username)

                        # Finding: User has password set
                        findings.append(Finding(
                            id=create_finding_id("evidence-miner", "password-set", username),
                            type=FindingType.CREDENTIAL,
                            severity=Severity.INFO,
                            title=f"User '{username}' has password authentication enabled",
                            description=f"The user account '{username}' has a password hash set in /etc/shadow",
                            file_path="/etc/shadow",
                            tool_name="evidence-miner",
                            rule_name="password-set",
                            metadata={"username": username},
                        ))
        except Exception as e:
            self._logger.warning("Could not parse shadow", error=str(e))

        # Parse sudoers
        try:
            sudoers_content = self.reader.read_file("/etc/sudoers").decode("utf-8", errors="ignore")
            for line in sudoers_content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "ALL=" in line:
                    self._sudoers.append(line)

                    # Finding: Sudoers entry
                    if "NOPASSWD" in line:
                        findings.append(Finding(
                            id=create_finding_id("evidence-miner", "sudoers-nopasswd", line[:50]),
                            type=FindingType.PRIVILEGE_ESCALATION,
                            severity=Severity.MEDIUM,
                            title="NOPASSWD sudo access configured",
                            description=f"Passwordless sudo access found: {line}",
                            file_path="/etc/sudoers",
                            tool_name="evidence-miner",
                            rule_name="sudoers-nopasswd",
                            mitre_tactic="TA0004",
                            mitre_technique="T1548.003",
                        ))
        except Exception as e:
            self._logger.debug("Could not parse sudoers", error=str(e))

        self._logger.info("Users enumerated", count=len(self._users))
        return findings

    def _analyze_login_history(self) -> list[Finding]:
        """Analyze login history from wtmp."""
        findings = []

        try:
            # Use 'last' command to parse wtmp
            wtmp_files = ["/var/log/wtmp"]

            for wtmp in wtmp_files:
                if self.reader.exists(wtmp):
                    # Read wtmp and run last command
                    mount_path = self.reader.get_access_path()
                    full_path = os.path.join(mount_path, wtmp.lstrip("/"))

                    result = subprocess.run(
                        ["last", "-f", full_path],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode == 0:
                        self._login_history = result.stdout.splitlines()

                        # Look for suspicious patterns
                        for line in self._login_history:
                            # Root login from remote
                            if line.startswith("root") and "pts/" in line:
                                findings.append(Finding(
                                    id=create_finding_id("evidence-miner", "root-remote-login", line[:50]),
                                    type=FindingType.SUSPICIOUS_FILE,
                                    severity=Severity.MEDIUM,
                                    title="Root login from remote session",
                                    description=f"Root user logged in via pseudo-terminal: {line}",
                                    file_path="/var/log/wtmp",
                                    tool_name="evidence-miner",
                                    rule_name="root-remote-login",
                                    mitre_tactic="TA0001",
                                    mitre_technique="T1078",
                                ))
        except Exception as e:
            self._logger.warning("Could not analyze login history", error=str(e))

        return findings

    def _extract_ssh_artifacts(self) -> list[Finding]:
        """Extract SSH keys and configuration."""
        findings = []

        # Check each user's .ssh directory
        for username, user_info in self._users.items():
            home = user_info["home"]
            ssh_dir = f"{home}/.ssh"

            if not self.reader.exists(ssh_dir):
                continue

            try:
                ssh_files = self.reader.list_directory(ssh_dir)
                user_keys = {}

                for entry in ssh_files:
                    if not entry.is_file:
                        continue

                    try:
                        content = self.reader.read_file(entry.path).decode("utf-8", errors="ignore")
                        user_keys[entry.name] = content[:1000]  # Truncate for storage

                        # Finding: Private key without passphrase
                        if entry.name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]:
                            if "ENCRYPTED" not in content:
                                findings.append(Finding(
                                    id=create_finding_id("evidence-miner", "unencrypted-key", entry.path),
                                    type=FindingType.CREDENTIAL,
                                    severity=Severity.HIGH,
                                    title=f"Unencrypted SSH private key for '{username}'",
                                    description=f"SSH private key without passphrase protection found at {entry.path}",
                                    file_path=entry.path,
                                    tool_name="evidence-miner",
                                    rule_name="unencrypted-ssh-key",
                                    mitre_tactic="TA0006",
                                    mitre_technique="T1552.004",
                                ))

                        # Finding: Authorized keys
                        if entry.name == "authorized_keys":
                            key_count = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
                            findings.append(Finding(
                                id=create_finding_id("evidence-miner", "authorized-keys", entry.path),
                                type=FindingType.PERSISTENCE,
                                severity=Severity.INFO,
                                title=f"SSH authorized_keys for '{username}' ({key_count} keys)",
                                description=f"Found {key_count} authorized SSH keys for user {username}",
                                file_path=entry.path,
                                tool_name="evidence-miner",
                                rule_name="authorized-keys",
                                metadata={"key_count": key_count},
                            ))

                    except Exception:
                        pass

                self._ssh_keys[username] = user_keys

            except Exception as e:
                self._logger.warning("Could not read SSH dir", user=username, error=str(e))

        # Check global SSH config
        try:
            sshd_config = self.reader.read_file("/etc/ssh/sshd_config").decode("utf-8", errors="ignore")

            # Check for insecure settings
            if re.search(r"^\s*PermitRootLogin\s+yes", sshd_config, re.MULTILINE):
                findings.append(Finding(
                    id=create_finding_id("evidence-miner", "sshd-root-login", "/etc/ssh/sshd_config"),
                    type=FindingType.CONFIGURATION_ISSUE,
                    severity=Severity.MEDIUM,
                    title="SSH root login enabled",
                    description="SSH daemon configured to allow direct root login",
                    file_path="/etc/ssh/sshd_config",
                    tool_name="evidence-miner",
                    rule_name="sshd-root-login",
                ))

            if re.search(r"^\s*PasswordAuthentication\s+yes", sshd_config, re.MULTILINE):
                findings.append(Finding(
                    id=create_finding_id("evidence-miner", "sshd-password-auth", "/etc/ssh/sshd_config"),
                    type=FindingType.CONFIGURATION_ISSUE,
                    severity=Severity.LOW,
                    title="SSH password authentication enabled",
                    description="SSH daemon configured to allow password authentication",
                    file_path="/etc/ssh/sshd_config",
                    tool_name="evidence-miner",
                    rule_name="sshd-password-auth",
                ))

        except Exception:
            pass

        return findings

    def _review_services(self) -> list[Finding]:
        """Review service configurations."""
        findings = []

        # Check nginx
        try:
            if self.reader.exists("/etc/nginx/nginx.conf"):
                self._services["nginx"] = True
        except Exception:
            pass

        # Check httpd/apache
        try:
            if self.reader.exists("/etc/httpd/conf/httpd.conf"):
                self._services["httpd"] = True
        except Exception:
            pass

        return findings

    def _find_automation(self) -> list[Finding]:
        """Find cron jobs, systemd services, and startup scripts."""
        findings = []

        # System crontabs
        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
        ]

        for cron_path in cron_paths:
            try:
                if self.reader.is_directory(cron_path):
                    entries = self.reader.list_directory(cron_path)
                    for entry in entries:
                        if entry.is_file:
                            content = self.reader.read_file(entry.path).decode("utf-8", errors="ignore")
                            self._cron_jobs.append({"path": entry.path, "content": content})

                            # Look for suspicious patterns
                            if any(s in content.lower() for s in ["curl", "wget", "nc ", "bash -i", "/dev/tcp"]):
                                findings.append(Finding(
                                    id=create_finding_id("evidence-miner", "suspicious-cron", entry.path),
                                    type=FindingType.PERSISTENCE,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious cron job: {entry.name}",
                                    description=f"Cron job contains potentially malicious commands",
                                    file_path=entry.path,
                                    tool_name="evidence-miner",
                                    rule_name="suspicious-cron",
                                    mitre_tactic="TA0003",
                                    mitre_technique="T1053.003",
                                ))

                elif self.reader.is_file(cron_path):
                    content = self.reader.read_file(cron_path).decode("utf-8", errors="ignore")
                    self._cron_jobs.append({"path": cron_path, "content": content})

            except Exception:
                pass

        # Systemd services
        systemd_paths = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
        ]

        for systemd_path in systemd_paths:
            try:
                if self.reader.is_directory(systemd_path):
                    entries = self.reader.list_directory(systemd_path)
                    for entry in entries:
                        if entry.is_file and entry.name.endswith(".service"):
                            content = self.reader.read_file(entry.path).decode("utf-8", errors="ignore")

                            # Look for suspicious ExecStart
                            if "ExecStart=" in content:
                                exec_match = re.search(r"ExecStart=(.+)", content)
                                if exec_match:
                                    exec_cmd = exec_match.group(1)
                                    if any(s in exec_cmd.lower() for s in ["/tmp/", "/dev/shm/", "curl", "wget"]):
                                        findings.append(Finding(
                                            id=create_finding_id("evidence-miner", "suspicious-service", entry.path),
                                            type=FindingType.PERSISTENCE,
                                            severity=Severity.HIGH,
                                            title=f"Suspicious systemd service: {entry.name}",
                                            description=f"Service executes from suspicious location: {exec_cmd[:100]}",
                                            file_path=entry.path,
                                            tool_name="evidence-miner",
                                            rule_name="suspicious-systemd-service",
                                            mitre_tactic="TA0003",
                                            mitre_technique="T1543.002",
                                        ))
            except Exception:
                pass

        # rc.local and init scripts
        startup_paths = ["/etc/rc.local", "/etc/rc.d/rc.local"]
        for startup_path in startup_paths:
            try:
                if self.reader.exists(startup_path):
                    content = self.reader.read_file(startup_path).decode("utf-8", errors="ignore")
                    self._startup_scripts.append({"path": startup_path, "content": content})

                    # Check for non-default content
                    if len(content.strip().splitlines()) > 3:  # More than just comments
                        findings.append(Finding(
                            id=create_finding_id("evidence-miner", "rc-local-modified", startup_path),
                            type=FindingType.PERSISTENCE,
                            severity=Severity.MEDIUM,
                            title="Modified rc.local startup script",
                            description="The rc.local startup script contains custom commands",
                            file_path=startup_path,
                            tool_name="evidence-miner",
                            rule_name="rc-local-modified",
                            mitre_tactic="TA0003",
                            mitre_technique="T1037.004",
                        ))
            except Exception:
                pass

        return findings

    def _search_credentials(self) -> list[Finding]:
        """Search for AWS credentials and other sensitive data."""
        findings = []

        # Check common credential locations
        credential_paths = [
            "/root/.aws/credentials",
            "/root/.aws/config",
        ]

        # Add user home directories
        for username, user_info in self._users.items():
            home = user_info["home"]
            credential_paths.extend([
                f"{home}/.aws/credentials",
                f"{home}/.aws/config",
                f"{home}/.boto",
            ])

        for cred_path in credential_paths:
            try:
                if self.reader.exists(cred_path):
                    content = self.reader.read_file(cred_path).decode("utf-8", errors="ignore")

                    # Look for access keys
                    access_keys = self.AWS_ACCESS_KEY_PATTERN.findall(content)

                    if access_keys:
                        self._iam_credentials[cred_path] = access_keys

                        findings.append(Finding(
                            id=create_finding_id("evidence-miner", "aws-credentials", cred_path),
                            type=FindingType.CREDENTIAL,
                            severity=Severity.CRITICAL,
                            title=f"AWS credentials found: {cred_path}",
                            description=f"Found {len(access_keys)} AWS access key(s) in credential file",
                            file_path=cred_path,
                            tool_name="evidence-miner",
                            rule_name="aws-credentials",
                            indicators=[f"Access Key: {k[:8]}..." for k in access_keys],
                            mitre_tactic="TA0006",
                            mitre_technique="T1552.001",
                        ))

            except Exception:
                pass

        # Search for hardcoded credentials in common config files
        config_paths = [
            "/etc/environment",
            "/etc/profile",
            "/etc/profile.d",
        ]

        for config_path in config_paths:
            try:
                if self.reader.is_directory(config_path):
                    entries = self.reader.list_directory(config_path)
                    for entry in entries:
                        if entry.is_file:
                            self._check_file_for_credentials(entry.path, findings)
                elif self.reader.is_file(config_path):
                    self._check_file_for_credentials(config_path, findings)
            except Exception:
                pass

        return findings

    def _check_file_for_credentials(self, file_path: str, findings: list[Finding]) -> None:
        """Check a file for hardcoded credentials."""
        try:
            content = self.reader.read_file(file_path).decode("utf-8", errors="ignore")

            # AWS access keys
            access_keys = self.AWS_ACCESS_KEY_PATTERN.findall(content)
            if access_keys:
                findings.append(Finding(
                    id=create_finding_id("evidence-miner", "hardcoded-aws-key", file_path),
                    type=FindingType.CREDENTIAL,
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded AWS key in {Path(file_path).name}",
                    description=f"AWS access key found in configuration file",
                    file_path=file_path,
                    tool_name="evidence-miner",
                    rule_name="hardcoded-aws-key",
                    mitre_tactic="TA0006",
                    mitre_technique="T1552.001",
                ))

        except Exception:
            pass

    def _find_hidden_directories(self) -> list[Finding]:
        """Find hidden directories that might indicate compromise."""
        findings = []

        suspicious_locations = ["/tmp", "/var/tmp", "/dev/shm", "/root"]

        for location in suspicious_locations:
            try:
                if not self.reader.is_directory(location):
                    continue

                entries = self.reader.list_directory(location)
                for entry in entries:
                    if entry.is_directory and entry.name.startswith("."):
                        # Skip known safe directories
                        if entry.name in self.EXCLUDED_HIDDEN_PATHS:
                            continue

                        self._hidden_dirs.append(entry.path)

                        # Hidden directory in /tmp or /dev/shm is more suspicious
                        if location in ["/tmp", "/dev/shm", "/var/tmp"]:
                            findings.append(Finding(
                                id=create_finding_id("evidence-miner", "hidden-dir", entry.path),
                                type=FindingType.SUSPICIOUS_FILE,
                                severity=Severity.MEDIUM,
                                title=f"Hidden directory in {location}",
                                description=f"Found hidden directory '{entry.name}' in temporary location",
                                file_path=entry.path,
                                tool_name="evidence-miner",
                                rule_name="hidden-directory",
                                mitre_tactic="TA0005",
                                mitre_technique="T1564.001",
                            ))

            except Exception as e:
                self._logger.warning("Could not scan for hidden dirs", location=location, error=str(e))

        return findings

    def _upload_raw_results(self) -> None:
        """Upload raw evidence miner output."""
        import json

        raw_data = {
            "instance_id": self._instance_id,
            "users": self._users,
            "password_hashes_users": self._password_hashes,
            "sudoers": self._sudoers,
            "login_history": self._login_history[:100],  # Limit size
            "ssh_keys": {k: list(v.keys()) for k, v in self._ssh_keys.items()},
            "services": self._services,
            "cron_jobs": [{"path": c["path"]} for c in self._cron_jobs],
            "startup_scripts": [{"path": s["path"]} for s in self._startup_scripts],
            "iam_credential_locations": list(self._iam_credentials.keys()),
            "hidden_directories": self._hidden_dirs,
        }

        self.result_handler.upload_raw_output(
            json.dumps(raw_data, indent=2).encode("utf-8"),
            "artifacts.json",
            "application/json"
        )

        self._logger.info("Raw results uploaded")
