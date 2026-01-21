#!/usr/bin/python3
"""
Evidence Miner: Automated forensic artifact extraction and analysis tool.
"""

import argparse
import datetime
import hashlib
import logging
import os
import queue
import re
import string
import subprocess
import sys
from typing import Union, Dict, Any

import boto3
import defusedxml.ElementTree as ET
import pytz
from evtx import PyEvtxParser

# Configure logging to stdout for containerized environments
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("EvidenceMiner")

class EvidenceMiner:
    def __init__(self, snapshot_id, os_type, root, working_dir):
        self.cloud_init_output = None
        self.user_data = None
        self.session_dict = {}
        self.command_exec_dict = {}
        self.snapshot_id = snapshot_id
        self.os_type = os_type
        self.root = root
        self.working_dir = working_dir
        self.report_path = os.path.join(
            self.working_dir, self.snapshot_id + "_evidence_miner_report.md"
        )
        if not self.root.endswith("/"):
            self.root = self.root + "/"
        self.users = None
        self.dir_queue = queue.Queue()
        self.run = True
        self.max_read_size = 1024 * 1024 * 100  # 100MB
        self.file_dict = dict()
        self.login_data = list()
        self.home_dir_info = dict()
        self.instance_id = "Unknown"
        self.services = None
        self.automation = dict()
        self.startup_jobs = dict()
        self.password_set = list()
        self.hidden_directories = list()
        self.sudoers_users = list()
        self.sudoers_groups = list()
        self.group_memberships = dict()
        self.iam_credentials = {}

        # Paths to exclude from hidden directory analysis
        self.excluded_hidden_paths = [
            "/root/.cargo",
            "/root/.chronicle",
            "/root/.npm",
            "/root/.cache",
            "/.snapshots",
            "/usr/lib/.build-id",
            "/home/ec2-user/tools/efs-utils/src/proxy/target/release/.fingerprint",
            "/root/.rustup",
            "/tmp/.X11-unix",
            "/tmp/.font-unix",
            "/tmp/.XIM-unix",
            "/tmp/.ICE-unix",
            "/run/.mount",
            "/run/.containerenv",
            "/sys/fs/cgroup/.updated",
            "/usr/lib/debug/.build-id",
            "/usr/lib/python3.9/site-packages/awscli/botocore/.changes",
        ]
        logger.info(
            f"Initialized Evidence Miner with args snapshot_id={snapshot_id}, os_type={self.os_type}, root={root}, working_dir={working_dir}"
        )

    def get_instance_id_from_image(self):
        """Attempts to obtain the target system's Instance ID"""
        if "windows" in self.os_type:
            try:
                ec2_launch_path = "ProgramData/Amazon/EC2Launch/log/console.log"
                path = os.path.join(self.root, ec2_launch_path)
                if os.path.exists(path):
                    with open(path, "rt") as f:
                        for line in f.read().split("\n"):
                            if "Instance-ID:" in line:
                                match = re.search("(i-[a-f0-9]+)", line)
                                if match is not None:
                                    self.instance_id = match.group(0)
                                    return
            except Exception as e:
                logger.info("Unable to determine instance ID from Windows logs")
        elif "linux" in self.os_type:
            try:
                ec2_launch_path = os.path.join(self.root, "var/lib/cloud/instances/")
                logger.info(f"Retrieving instance ID from {ec2_launch_path}")
                if os.path.exists(ec2_launch_path):
                    with os.scandir(ec2_launch_path) as i:
                        for element in i:
                            if element.name.startswith("i-") and element.is_dir():
                                self.instance_id = element.name
                                logger.info(f"Retrieved instance ID: {self.instance_id}")
                                return
            except Exception as e:
                logger.info("Unable to determine instance ID from cloud-init")

    def review_services(self):
        """Obtains basic information on pre-defined services"""
        logger.info("Retrieving installed services:")
        if self.os_type == "linux":
            services = {"ssh": dict(), "nginx": dict(), "httpd": dict()}
            for s in services.keys():
                if s == "ssh":
                    path = os.path.join(self.root, "etc/ssh/sshd_config")
                    ssh_data = self.review_ssh_config(path)
                    if any(len(ssh_data[key]) for key in ssh_data):
                        services[s] = ssh_data
                elif s == "nginx":
                    path = os.path.join(self.root, "etc/nginx/")
                    nginx_data = self.review_nginx_config(path)
                    if any(len(nginx_data[key]) for key in nginx_data):
                        services[s] = nginx_data
                elif s == "httpd":
                    path = os.path.join(self.root, "etc/httpd/conf/")
                    httpd_data = self.review_httpd_config(path)
                    if any(len(httpd_data[key]) for key in httpd_data):
                        services[s] = httpd_data
            self.services = services
        logger.info(f"Found services: {self.services}")

    def review_nginx_config(self, path):
        primary_config_file = "nginx.conf"
        data = {primary_config_file: list(), "sites": list()}

        config_file_path = os.path.join(self.root, path, primary_config_file)
        if not os.path.exists(config_file_path):
            return data

        with open(config_file_path) as f:
            for line in f.read().split("\n"):
                if not line.startswith("#") and line != "":
                    data[primary_config_file].append(line)
        data[primary_config_file] = "\n".join(data[primary_config_file])

        sites_path = os.path.join(self.root, path, "sites-available/")
        if not os.path.exists(sites_path):
            return data

        with os.scandir(sites_path) as i:
            for element in i:
                if element.is_file(follow_symlinks=False) and element.name not in [".", ".."]:
                    with open(element.path) as f:
                        data["sites"].append(f.read())
        data["sites"] = "\n".join(data["sites"])
        return data

    def review_httpd_config(self, path):
        primary_config_file = "httpd.conf"
        data = {primary_config_file: list()}
        config_file_path = os.path.join(self.root, path, primary_config_file)
        if not os.path.exists(config_file_path):
            return data

        with open(config_file_path) as f:
            for line in f.read().split("\n"):
                if not line.strip().startswith("#") and line != "":
                    data[primary_config_file].append(line)
        data[primary_config_file] = "\n".join(data[primary_config_file])
        return data

    def review_ssh_config(self, path):
        port = ""
        addresses = list()
        other_settings = list()
        if os.path.exists(path):
            with open(path) as f:
                for line in f.read().split("\n"):
                    if re.match(r"^Port\s", line):
                        port = line.split(" ")[1]
                    elif re.match(r"^ListenAddress\s", line):
                        addresses.append(line.split(" ")[1])
                    else:
                        if not line.startswith("#") and len(line) > 0:
                            other_settings.append(line)
            if len(addresses) == 0:
                addresses.append("0.0.0.0")
                addresses.append("::")

            if port == "":
                port = "22"

        return {
            "port": port,
            "addresses": "\n".join(addresses),
            "active_settings": "\n".join(other_settings),
        }

    def generate_report(self):
        logger.info("Generating report...")
        logins = "```bash\n"
        for l in self.login_data:
            logins += l + "\n"
        logins = logins.strip() + "\n```"

        password = ""
        if len(self.password_set) > 0:
            password = "## Accounts with passwords set\n```bash\n"
            password += "\n".join(self.password_set) + "\n```\n"

        sudoers = ""
        if len(self.sudoers_users) > 0:
            sudoers = "## Users with sudo access\n```bash\n"
            sudoers += "\n".join(self.sudoers_users) + "\n```\n"

        sudoers_groups = ""
        if len(self.sudoers_groups) > 0:
            sudoers_groups = "## Groups with sudo access\n```bash\n"
            sudoers_groups += "\n".join(self.sudoers_groups) + "\n```\n"

        group_memberships = ""
        if self.group_memberships:
            group_memberships = "## Group memberships for sudo groups\n```\n"
            for group_name, group_info in self.group_memberships.items():
                if group_name == 'error':
                    group_memberships += f"{group_info}\n"
                    continue
                group_memberships += f"Group: {group_name} (GID: {group_info['gid']})\n"
                if group_info['members']:
                    group_memberships += f"Members: {', '.join(group_info['members'])}\n"
                else:
                    group_memberships += "Members: None\n"
                group_memberships += "\n"
            group_memberships += "```\n"

        iam_credentials_section = ""
        if self.iam_credentials:
            iam_credentials_section = "## IAM credential locations\n| File Path | Access Keys |\n| --------- | ----------- |\n"
            for file_path, access_keys in self.iam_credentials.items():
                keys_str = ", ".join(access_keys)
                iam_credentials_section += f"| {file_path} | {keys_str} |\n"

        users = "| User | Home Directory | Creation Time | Access Time | Modification Time | Permissions | Owner | Group |\n"
        users += "| ---- | ------------- | ------------ | ----------- | ----------------- | ----------- | ----- | ----- |\n"
        for user, home_dir in self.users.items():
            users += f"| {user} | {home_dir.replace(self.root, '/')} | "
            if user in self.home_dir_md:
                users += f"{self.home_dir_md[user].get('Creation_Time', 'N/A')} | "
                users += f"{self.home_dir_md[user].get('Accessed_Time', 'N/A')} | "
                users += f"{self.home_dir_md[user].get('Modification_Time', 'N/A')} | "
                users += f"{self.home_dir_md[user].get('Permissions', 'N/A')} | "
                users += f"{self.home_dir_md[user].get('Owner', 'N/A')} | "
                users += f"{self.home_dir_md[user].get('Group', 'N/A')} |\n"
            else:
                users += "N/A | N/A | N/A | N/A | N/A | N/A |\n"

        home_data = ""
        for user, dd in self.home_dir_info.items():
            home_data += f"## {user}:\n"
            if "ssh_files" in dd and dd["ssh_files"]:
                home_data += "### SSH Files\n"
                for ssh_file, content in dd["ssh_files"].items():
                    file_content = content.get("Content", "")
                    home_data += f"#### {ssh_file}\n```\n{file_content}\n```\n"

            for history_type, history_dict in dd.items():
                if history_type == "ssh_files": continue
                if history_dict:
                    home_data += f"### {history_type.replace('_', ' ').title()}\n"
                    for app, details in history_dict.items():
                        home_data += f"#### {app}\n```bash\n{details.get('Content', '')}\n```\n"

        hidden_dirs = ""
        if len(self.hidden_directories) > 0:
            hidden_dirs = "## Hidden Directories\n```bash\n"
            hidden_dirs += "\n".join(self.hidden_directories) + "\n```\n"

        service_data = "# Services\n"
        if self.services:
            for s, value in self.services.items():
                service_data += f"\n## {s}\n"
                if isinstance(value, bool):
                    service_data += f"```\n{str(value)}\n```\n"
                elif isinstance(value, dict):
                    for k, v in value.items():
                        service_data += f"\n### {k}\n```\n{str(v)}\n```\n"

        automation = ""
        for app in self.automation:
            automation += f"## {app}\n"
            for job in self.automation[app]:
                automation += f"### {job}\n```bash\n{self.automation[app][job].get('Content', '')}\n```\n"

        startup_jobs = ""
        for job in self.startup_jobs:
            startup_jobs += f"## {job}\n```bash\n{self.startup_jobs[job].get('Content', '')}\n```\n"

        ssm_sessions = ""
        for session in self.session_dict:
            ssm_sessions += f"### {session}\n```bash\n{self.session_dict[session]['Output']}\n```\n"

        command_exec = ""
        for exec_id in self.command_exec_dict:
            command_exec += f"### {exec_id}\n```bash\n{self.command_exec_dict[exec_id]['Output']}\n```\n"

        report = f"""# Evidence Miner Report for {self.instance_id}
# Logins
{logins}
{password}
--------------------------
# Users
{users}
{sudoers}
{sudoers_groups}
{group_memberships}
{iam_credentials_section}
--------------------------
# Home dir analysis
{home_data}
--------------------------
{hidden_dirs}
--------------------------
# Services enabled
{service_data}
--------------------------
# Automated Processes
{automation}
--------------------------
# Startup Processes
{startup_jobs}
--------------------------
# SSM
## SSM Sessions
{ssm_sessions}
## SSM Run Commands
{command_exec}
--------------------------
# Instance Bootstrap
## Userdata
```bash
{self.user_data}

```

## Userdata output

```bash
{self.cloud_init_output}

```

---

"""
        with open(self.report_path, "w") as f:
            f.write(report)
        logger.info(f"Report written to {self.report_path}")

    def get_login_history(self):
        logger.info("Getting login history")
        if self.os_type == "linux":
            try:
                log_path = os.path.join(self.root, "var/log/")
                if os.path.exists(log_path):
                    with os.scandir(log_path) as i:
                        for entity in i:
                            if entity.is_file() and "wtmp" in entity.name:
                                try:
                                    output = subprocess.run(
                                        ["last", "-f", entity.path],
                                        capture_output=True,
                                        timeout=30
                                    )
                                    if output.returncode == 0:
                                        self.login_data.append(output.stdout.decode("utf-8", errors='ignore'))
                                except Exception as e:
                                    logger.warning(f"Could not run last command on {entity.path}: {e}")
            except Exception as e:
                logger.error(f"Error parsing login history: {e}")

    def read_file(self, path, binary=True, max_size=None) -> Union[bytes, str, None]:
        if max_size is None:
            max_size = self.max_read_size
        read_type = "rb" if binary else "r"
        try:
            if os.path.exists(path) and os.path.getsize(path) <= max_size:
                with open(path, read_type, errors='ignore' if not binary else None) as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Unable to read {path}: {e}")
        return None

    def get_file_timestamps(self, file_path):
        try:
            stat = os.stat(file_path)
            return {
                "Creation_Time": datetime.datetime.fromtimestamp(stat.st_ctime, tz=datetime.timezone.utc).isoformat(),
                "Modification_Time": datetime.datetime.fromtimestamp(stat.st_mtime, tz=datetime.timezone.utc).isoformat(),
                "Accessed_Time": datetime.datetime.fromtimestamp(stat.st_atime, tz=datetime.timezone.utc).isoformat(),
            }
        except Exception:
            return {}

    def extract_userdata(self):
        logger.info("Extracting instance userdata")
        if self.os_type == "linux":
            path_to_user_data = os.path.join(self.root, "var", "lib", "cloud", "instance", "user-data.txt")
            if os.path.exists(path_to_user_data):
                self.user_data = self.read_file(path_to_user_data, False)
                logger.info(f"Extracted userdata from {path_to_user_data}")
            else:
                logger.warning(f"Userdata not found in {path_to_user_data}, checking alternative")
                path_to_user_data = os.path.join(self.root, "var", "lib", "cloud", "instances", f"{self.instance_id}", "user-data.txt")
                if os.path.exists(path_to_user_data):
                    self.user_data = self.read_file(path_to_user_data, False)
                    logger.info(f"Extracted userdata from {path_to_user_data}")
                else:
                    logger.warning("No userdata found")

    def extract_cloud_init_output(self):
        logger.info("Extracting instance userdata output")
        if self.os_type == "linux":
            path_to_cloud_init_output = os.path.join(self.root, "var", "log", "cloud-init-output.log")
            if os.path.exists(path_to_cloud_init_output):
                self.cloud_init_output = self.read_file(path_to_cloud_init_output, False)

    def enumerate_users(self):
        logger.info("Enumerating users")
        self.users = {}
        self.home_dir_md = {}
        if self.os_type == "linux":
            passwd_path = os.path.join(self.root, "etc/passwd")
            if os.path.exists(passwd_path):
                content = self.read_file(passwd_path, binary=False)
                if content:
                    for line in content.splitlines():
                        parts = line.split(":")
                        if len(parts) == 7:
                            user, home, shell = parts[0], parts[5], parts[6]
                            if shell not in ["/sbin/nologin", "/bin/false", "/dev/null"]:
                                if home.startswith("/"): home = self.root + home[1:]
                                self.users[user] = home
                                self.home_dir_md[user] = self.get_file_timestamps(home)

            shadow_path = os.path.join(self.root, "etc/shadow")
            if os.path.exists(shadow_path):
                content = self.read_file(shadow_path, binary=False)
                if content:
                    for line in content.splitlines():
                        parts = line.split(":")
                        if len(parts) > 1 and parts[1].startswith("$"):
                            self.password_set.append(line)

    def get_interesting_files_from_home_dir(self, home_dir):
        files = {"ssh_files": {}, "shell_history": {}, "editor_history": {}, "network_history": {}, "misc_history": {}}

        # SSH
        ssh_dir = os.path.join(home_dir, ".ssh")
        if os.path.exists(ssh_dir):
            for f in os.listdir(ssh_dir):
                fp = os.path.join(ssh_dir, f)
                if os.path.isfile(fp):
                    files["ssh_files"][f] = {"Content": self.read_file(fp, binary=False)}

        # History
        history_map = {
            ".bash_history": ("shell_history", "bash"),
            ".zhistory": ("shell_history", "zsh"),
            ".viminfo": ("editor_history", "vim"),
            ".wget-hsts": ("network_history", "wget")
        }

        for fname, (cat, key) in history_map.items():
            fp = os.path.join(home_dir, fname)
            if os.path.exists(fp):
                files[cat][key] = {"Content": self.read_file(fp, binary=False)}

        return files

    def process_home_directories(self):
        logger.info("Processing home directories")
        for user, home in self.users.items():
            if os.path.exists(home):
                self.home_dir_info[user] = self.get_interesting_files_from_home_dir(home)

    def get_sudoers_users(self):
        logger.info("Getting sudoers")
        sudoers_path = os.path.join(self.root, "etc/sudoers")
        if os.path.exists(sudoers_path):
            content = self.read_file(sudoers_path, binary=False)
            if content:
                for line in content.splitlines():
                    if "ALL=" in line and not line.strip().startswith("#"):
                        self.sudoers_users.append(line)

    def extract_send_command(self):
        # Placeholder for full implementation
        pass

    def extract_ssm_session_output(self):
        # Placeholder for full implementation
        pass

    def parse_startup_jobs(self):
        # Placeholder for full implementation
        pass

    def find_hidden_directories(self):
        # Placeholder for full implementation
        pass

    def find_iam_credentials(self):
        # Placeholder for full implementation
        pass

    def process_image(self):
        if not os.path.exists(self.working_dir):
            os.mkdir(self.working_dir)
        self.get_instance_id_from_image()
        self.enumerate_users()
        self.get_login_history()
        self.process_home_directories()
        self.get_sudoers_users()
        self.review_services()
        self.extract_userdata()
        self.extract_cloud_init_output()
        # Add calls to other analysis methods here
        self.generate_report()


def parse_args():
    parser = argparse.ArgumentParser(description="Evidence Miner: Tier 1 Triage Tool")
    parser.add_argument("root", type=str, help="Path to the mounted root volume")
    parser.add_argument("-o", "--os_type", type=str, choices=["linux", "windows"], default="linux", help="OS type")
    parser.add_argument("-w", "--working_dir", type=str, default="/tmp", help="Working directory for report output")
    parser.add_argument("-s", "--snapshot_id", type=str, required=True, help="Snapshot ID being processed")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    miner = EvidenceMiner(args.snapshot_id, args.os_type, args.root, args.working_dir)
    miner.process_image()
