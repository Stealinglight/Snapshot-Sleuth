# **Snapshot-Sleuth 2.0: Next-Generation Cloud Forensics Platform Architecture and Strategic Roadmap**

## **1\. Executive Summary and Strategic Vision**

The discipline of cloud forensics has historically been constrained by the "lift and shift" mentality—a paradigm where cloud infrastructure is treated identical to physical hardware, necessitating the acquisition of full disk images and the provisioning of heavy, persistent analysis workstations. The original iteration of Snapshot-Sleuth (v1.0) represented a significant step forward in automating the acquisition of AWS Elastic Block Store (EBS) volumes. However, the rapidly evolving threat landscape, characterized by decreased dwell times and increasingly sophisticated anti-forensic techniques, demands a fundamental architectural shift.

This report presents the comprehensive technical vision and execution roadmap for **Snapshot-Sleuth 2.0**. Moving beyond the monolithic, EC2-dependent architecture of its predecessor, v2.0 embraces a serverless, event-driven, and intelligent design philosophy. By leveraging the convergence of recent AWS innovations—specifically AWS Fargate’s support for EBS volume attachments (Jan 2024), EBS Direct APIs for sub-second data access, and Amazon Bedrock for generative AI analysis—Snapshot-Sleuth 2.0 aims to reduce Time-to-Forensics (TTF) from minutes to seconds while simultaneously lowering operational overhead and attack surface.

The proposed architecture is structured into five distinct evolutionary phases:

1. **Compute Modernization:** Transitioning from persistent EC2 to ephemeral AWS Fargate tasks.  
2. **Deep Forensics:** Implementing advanced heuristics including Shannon Entropy analysis and rootkit detection.  
3. **Advanced Storage:** Utilizing coldsnap and EBS Direct APIs for surgical data extraction.  
4. **Intelligence Layer:** Integrating Large Language Models (LLMs) via Amazon Bedrock for automated log correlation and code de-obfuscation.  
5. **Operational Polish:** Enhancing the user experience with real-time GraphQL dashboards (AppSync) and immutable audit logging.

This document serves as the definitive technical reference, implementation guide, and documentation for the Snapshot-Sleuth 2.0 initiative.

## ---

**2\. Legacy Architecture Analysis and the Case for Modernization**

To chart the path forward, one must first rigorously analyze the architectural patterns and limitations of the legacy Snapshot-Sleuth v1.0 system. Based on the provided project context and standard forensic workflows of that generation, the legacy system operated on a linear, synchronous "Responder" model.

### **2.1 The Legacy Workflow (v1.0)**

The operational logic of v1.0 was predicated on the instantiation of a full virtual machine to perform analysis.

1. **Trigger:** An alert (manual or automated) initiated the workflow.  
2. **Acquisition:** The system invoked ec2:CreateSnapshot on the compromised volume.  
3. **Provisioning:** A dedicated "Forensic Workstation" (EC2 Instance) was launched. This instance required a pre-baked AMI containing tools like The Sleuth Kit (TSK) and log2timeline.  
4. **Hydration & Attachment:** A new EBS volume was created from the snapshot (ec2:CreateVolume) and attached to the workstation (ec2:AttachVolume).  
5. **Analysis:** Scripts executed sequentially to extract artifacts.

### **2.2 Critical Limitations of the Legacy Model**

#### **2.2.1 The "Cold Start" Latency**

The primary metric for incident response efficacy is Mean Time to Remediate (MTTR). The legacy architecture suffered from unavoidable infrastructure latency. Provisioning an EC2 instance, waiting for status checks, and waiting for the EBS volume to initialize (hydrate) creates a lag of 5 to 15 minutes before analysis can effectively begin. EBS volumes created from snapshots are "lazy loaded" from S3; the first time a block is accessed, it must be pulled from object storage, resulting in a significant I/O penalty that slows down initial forensic scans.1

#### **2.2.2 Contamination Risks and Attack Surface**

Forensic soundness relies on isolation. In the v1.0 model, the Forensic Workstation is a persistent EC2 resource that resides in a VPC. It requires management ports (SSH/RDP), security groups, and IAM roles. If a compromised volume contains malware capable of escaping the mount point or exploiting kernel vulnerabilities in the analysis host, the persistent nature of the EC2 instance poses a risk of cross-contamination or persistence. Furthermore, maintaining these instances requires continuous patching and lifecycle management.3

#### **2.2.3 Economic Inefficiency**

Forensic workstations require significant compute resources (high RAM for timeline generation, high CPU for hashing). In the legacy model, these resources incur costs even during idle periods unless rigorous auto-scaling logic is implemented. Additionally, creating full EBS volumes for every investigation multiplies storage costs, particularly when only a small subset of files (e.g., /var/log) is required for triage.4

## ---

**3\. Phase 1: Compute Modernization (AWS Fargate)**

The foundational shift in Snapshot-Sleuth 2.0 is the migration from EC2 to AWS Fargate. This transition is enabled by the capability introduced in January 2024 allowing Fargate tasks to attach EBS volumes at deployment time. This feature permits the creation of ephemeral, "serverless" forensic workers that exist only for the duration of the analysis job.6

### **3.1 Architectural Shift: Serverless Forensics**

By utilizing Fargate, we decouple the forensic "brain" (the logic) from the "muscle" (the compute). The operational workflow transforms into an event-driven pipeline:

1. **Event Trigger:** An Amazon EventBridge rule detects a high-severity GuardDuty finding (e.g., Trojan:EC2/DNSDataExfiltration).  
2. **Orchestrator:** A lightweight Lambda function parses the event, identifies the compromised instance, and initiates a snapshot.  
3. **Execution:** Once the snapshot is complete, the Lambda invokes ecs:RunTask, passing the snapshot ID dynamically to the Fargate task definition.  
4. **Analysis:** The task boots, the volume is mounted as a secondary drive (e.g., /mnt/evidence), and the analysis container executes.  
5. **Termination:** Upon completion, the task uploads results to S3 and terminates itself, leaving no residual infrastructure.

### **3.2 Technical Implementation: Dynamic Volume Attachment**

The critical mechanism for Phase 1 is the volumeConfigurations override in the RunTask API. Unlike EC2, where volumes are attached to running instances, Fargate requires the volume configuration to be defined at task launch.

**Configuration Parameters:**

The managedEBSVolume object within the task override is the nexus of this configuration. It requires precise alignment with the source snapshot's properties to ensure a successful mount.

| Parameter | Value / Logic | Justification |
| :---- | :---- | :---- |
| **roleArn** | arn:aws:iam::\<Account\>:role/ECSInfrastructureRole | Grants Fargate permission to call ec2:CreateVolume and ec2:AttachVolume on the user's behalf.8 |
| **snapshotId** | snap-xxxx (Dynamic) | The specific snapshot ID derived from the compromised instance. |
| **volumeType** | gp3 | Provides a baseline of 3,000 IOPS and 125 MiB/s throughput, independent of volume size, which is critical for consistent forensic read speeds.1 |
| **filesystemType** | xfs or ext4 | **Critical Constraint:** This must match the filesystem of the source snapshot. A mismatch causes the task to fail at startup.8 Phase 1 logic must include a pre-check (potentially via a temporary coldsnap metadata read) to determine the FS type. |
| **encryption** | true | Ensures evidence remains encrypted at rest during analysis. |

### **3.3 Infrastructure as Code (IaC) Strategy**

To ensure forensic reproducibility, the entire environment is defined in Terraform. The Fargate Task Definition is kept generic, serving as a template for the snapshot-sleuth-worker container.

**The Forensic Container Image:**

The worker image is a purpose-built, hardened Linux container (based on Alpine or Debian Slim to minimize attack surface) pre-loaded with the necessary tooling:

* **The Sleuth Kit (TSK):** For filesystem analysis (fls, istat, icat).  
* **YARA:** For signature-based malware detection.  
* **Chkrootkit:** For rootkit detection (Phase 2).  
* **Python Libraries:** boto3, pytsk3, pefile (for entropy analysis).

This containerization strategy ensures that every analysis is performed in an identical, clean environment, adhering to the forensic principle of repeatability.

### **3.4 Addressing the Windows Limitation**

Current AWS documentation indicates that EBS attachment to Fargate tasks is supported primarily for Linux tasks.7 This presents a constraint for analyzing Windows-based compromised instances.

* **Mitigation Strategy:** For Phase 1, Snapshot-Sleuth 2.0 will primarily support Linux targets via the Fargate mount method. For Windows targets, the system will fallback to the Phase 3 (Direct API) pipeline, which operates at the block level and is OS-agnostic, or necessitate a temporary EC2 worker until Fargate Windows support expands.

## ---

**4\. Phase 2: Deep Forensics (Entropy, Decloaking, & Rootkit Detection)**

Mere acquisition of data is insufficient. Snapshot-Sleuth 2.0 distinguishes itself by automating the *analysis* phase. Phase 2 introduces sophisticated detection heuristics to identify artifacts that signature-based tools might miss.

### **4.1 Shannon Entropy Analysis**

Advanced malware, particularly droppers and ransomware, often utilizes packers (like UPX) or custom encryption to obfuscate its payload. This process significantly alters the statistical distribution of bytes within the file, making them appear random. We utilize Shannon Entropy to detect these anomalies.9

#### **4.1.1 Mathematical Foundation**

Shannon Entropy (![][image1]) quantifies the amount of information (or randomness) in a variable. For a file composed of bytes (values 0-255), the entropy is calculated as:

![][image2]  
Where ![][image3] is the probability of byte value ![][image4] occurring in the file.

* **Low Entropy (0.0 \- 5.0):** Text files, source code, standard executables with large zero-padding.  
* **Medium Entropy (5.0 \- 6.5):** Native executables, formatted documents.  
* **High Entropy (6.5 \- 8.0):** Compressed archives (.zip, .gz), encrypted data, and **packed malware**.11

#### **4.1.2 The Sliding Window Technique**

Analyzing the global entropy of a large file can obscure malicious segments hidden within legitimate code. Snapshot-Sleuth 2.0 implements a "Sliding Window" entropy scanner.

* **Mechanism:** The scanner moves a window of 1024 bytes across the file.  
* **Detection Logic:** If a specific 1024-byte window exhibits entropy ![][image5], while the surrounding blocks are ![][image6], this indicates an encrypted payload embedded within a standard binary—a classic signature of stagers or droppers.12

**Implementation Snippet (Python):**

The forensic worker executes a Python script (entropy\_scan.py) that targets directories commonly used for malware persistence (/tmp, /dev/shm, /usr/bin, /etc/init.d).

### **4.2 Rootkit Detection with chkrootkit**

Rootkits are designed to hide their presence from the running kernel. However, Snapshot-Sleuth 2.0 possesses a unique advantage: **Offline Analysis**. Because we analyze a mounted image of the disk rather than the running system, the rootkit cannot intercept system calls to hide itself.3

#### **4.2.1 Integration Strategy**

We integrate chkrootkit into the forensic container. The tool is executed against the mounted evidence volume using the root-directory override flag.

**Command Execution:**

Bash

chkrootkit \-r /mnt/evidence \-q

* **\-r /mnt/evidence**: Instructs chkrootkit to treat the mount point as the root filesystem.  
* **\-q**: Quiet mode, suppressing output for clean checks to reduce log noise.

#### **4.2.2 Managing False Positives**

Offline scanning often generates false positives because chkrootkit cannot verify process IDs (PIDs) against the /proc filesystem (which is empty or belongs to the Fargate task, not the suspect image).

* **Filter Logic:** Snapshot-Sleuth 2.0 includes a post-processing filter. It compares flagged binaries against a known-good hash database (like the NSRL or a custom baseline of standard AMIs). If chkrootkit flags /usr/bin/sshd as infected, but its SHA-256 hash matches the official Amazon Linux 2 repository hash, the alert is suppressed.13

### **4.3 Decloaking: The Cross-View Difference**

"Decloaking" involves comparing the state of the system as reported by the OS API against the physical state of the disk. Discrepancies often indicate rootkit activity (e.g., process hiding).

**Workflow:**

1. **Pre-Snapshot Telemetry:** Before the snapshot is taken, the Orchestrator invokes AWS Systems Manager (SSM) Run Command to execute ps aux and netstat \-anp, capturing the output to S3.  
2. **Forensic Verification:** The Fargate task parses this S3 log. It then verifies the executables associated with running processes.  
   * *Detection:* If ps aux reports a process running from /usr/bin/kworker (PID 999), but the file /usr/bin/kworker does not exist on the mounted disk image (or is a zero-byte file), this confirms a "fileless" attack or a deleted binary.14

## ---

**5\. Phase 3: Advanced Storage (ColdSnap & Direct APIs)**

For large-scale infrastructure (e.g., 16TB database volumes), full volume hydration is cost-prohibitive and slow. Phase 3 introduces "Sniper Forensics," utilizing AWS EBS Direct APIs to access data at the block level without volume creation.

### **5.1 EBS Direct APIs: Mechanics and Economics**

The EBS Direct APIs (ListSnapshotBlocks, GetSnapshotBlock) allow direct read access to snapshot data stored in S3. This bypasses the need for EC2 instances or EBS volumes entirely.15

#### **5.1.1 Cost-Benefit Analysis**

The pricing model for Direct APIs differs significantly from standard storage.

| Operation | Cost (us-east-1) | Implications |
| :---- | :---- | :---- |
| **ListSnapshotBlocks** | $0.0006 per 1,000 requests | Negligible for mapping files. |
| **GetSnapshotBlock** | $0.003 per 1,000 requests | Expensive for full dumps. |
| **Volume Hydration** | $0.08 per GB-month | Cheap for storage, slow for access. |

**Strategic Insight:** Reading a 1TB drive entirely via Direct APIs would require \~$6,000+ API calls (assuming 512KB blocks), costing significant amounts compared to creating a volume (\~$80). Therefore, Direct APIs are utilized **only** for:

1. **Metadata Analysis:** Reading the Master File Table (MFT) or Inode Table to generate a file listing.  
2. **Targeted Extraction:** Downloading specific high-value artifacts (e.g., /var/log/auth.log, $MFT, Windows Registry Hives).

### **5.2 Integration with ColdSnap**

coldsnap is an open-source AWS tool that simplifies interaction with Direct APIs. We integrate coldsnap into a Lambda layer to facilitate rapid artifact extraction.17

**Workflow:**

1. **Metadata Fetch:** Lambda uses coldsnap to download the partition table and filesystem metadata (first few MBs).  
2. **File Walk:** Utilizing pytsk3 (Python bindings for The Sleuth Kit), we parse this metadata in-memory to locate specific files.  
3. **Block Calculation:** We determine which specific 512KB blocks contain the target file's data.  
4. **Extraction:** We invoke GetSnapshotBlock only for those specific blocks, reassembling the file in the Lambda execution environment before uploading to the Evidence S3 Bucket.19

### **5.3 Filesystem Abstraction with pytsk3**

To enable standard forensic tools to interact with this cloud-native data stream, we implement a custom Img\_Info class in Python. This class overrides the standard read() method. Instead of reading from a local disk, it acts as a proxy, fetching requested byte ranges from the EBS Direct API on demand.

**Code Logic (Conceptual):**

Python

class EBSDirectImgInfo(pytsk3.Img\_Info):  
    def read(self, offset, size):  
        \# Calculate start/end block indices (512KB blocks)  
        start\_block \= offset // 524288  
        \# Check local cache; if missing, call EBS API  
        response \= ebs\_client.get\_snapshot\_block(..., BlockIndex=idx,...)  
        \# Return requested byte slice  
        return data\_chunk

This abstraction allows complex forensic libraries to operate on cloud snapshots as if they were local raw images.20

## ---

**6\. Phase 4: Intelligence Layer (AI & Bedrock)**

The sheer volume of forensic data—thousands of log lines, file events, and metadata entries—can overwhelm human analysts. Phase 4 integrates an Intelligence Layer using Amazon Bedrock to synthesize raw data into actionable intelligence.

### **6.1 The AI Forensic Analyst**

We employ large language models (specifically the Anthropic Claude 3 family via Amazon Bedrock) to act as a force multiplier. The system does not merely "report" findings; it interprets them.22

#### **6.1.1 Prompt Engineering for Forensics**

The efficacy of the AI layer depends on precise context setting. We utilize a structured prompt template:

* **Role Definition:** "You are a Tier 3 Incident Response Analyst specializing in Linux server compromise."  
* **Context Data:** "The following JSON data represents high-entropy files detected in /tmp and chkrootkit alerts."  
* **Task:** "Correlate the creation timestamps of the suspicious files with the provided SSH login logs (auth.log). Determine the likely initial access vector."

#### **6.1.2 Code De-obfuscation**

Malware often uses obfuscated scripts (Base64-encoded Python, packed PowerShell). Snapshot-Sleuth 2.0 automatically extracts suspicious script content and submits it to Bedrock for de-obfuscation.

* **Input:** Obfuscated string found in \~/.bash\_history.  
* **Output:** Bedrock returns the de-obfuscated code and an explanation of its function (e.g., "This script downloads a miner from bad-site.com and executes it").

### **6.2 Implementation Details**

The integration utilizes boto3 to invoke the Bedrock Runtime. Given the potential size of forensic logs, we implement a "Map-Reduce" strategy for token management.

1. **Chunking:** Logs are split into 20k token chunks.  
2. **Map:** Each chunk is summarized by the model ("Identify any anomalies in this log segment").  
3. **Reduce:** The summaries are aggregated into a final analysis request to produce the Executive Forensic Report.24

## ---

**7\. Phase 5: Frontend & Operational Polish (AppSync & Audit)**

The final phase ensures the platform is usable, transparent, and auditable.

### **7.1 Real-Time Dashboards with AppSync**

Legacy tools typically rely on page refreshes to track long-running jobs. Snapshot-Sleuth 2.0 utilizes AWS AppSync to provide a real-time, event-driven dashboard.25

**Architecture:**

* **GraphQL Schema:** Defines the Investigation and Finding types.  
* **Subscriptions:** The frontend subscribes to onScanUpdate.  
* **Mechanism:** When the Fargate task completes a module (e.g., "Entropy Scan Complete"), it writes the status to a DynamoDB table. This event triggers a DynamoDB Stream, which invokes a Lambda function to publish the update to AppSync, pushing it instantly to the analyst's browser.  
* **Cost Efficiency:** AppSync WebSockets are more cost-effective ($4.00 per million connection-minutes) than continuous polling of API Gateway for long-running forensic jobs.

### **7.2 Immutable Audit Logging (Chain of Custody)**

In legal proceedings, the integrity of the Chain of Custody is paramount. We must prove that the evidence has not been tampered with.

**The "Glass Ledger" Approach:**

1. **Event Logging:** Every action (snapshot creation, volume mount, file access) is logged to a DynamoDB "Audit" table.  
2. **Immutability:** We utilize DynamoDB Streams to archive every record change to an S3 Bucket.  
3. **S3 Object Lock:** This S3 Bucket is configured with **Object Lock in Compliance Mode**. This creates a WORM (Write Once, Read Many) environment where log files cannot be deleted or overwritten, even by the AWS root account, for a defined retention period (e.g., 7 years).27 This provides cryptographic assurance of the investigation's integrity.

### **7.3 Secrets Management**

To interact with external threat intelligence APIs (like VirusTotal), the Fargate worker requires API keys. These are never hardcoded. We utilize **AWS Secrets Manager**. The ECS Task Definition references the secret ARN, and the keys are injected as environment variables at runtime, ensuring they are never exposed in the Terraform state or the container image.8

## ---

**8\. Documentation for Snapshot-Sleuth 2.0**

### **8.1 Deployment Guide**

**Prerequisites:**

* AWS Account with Administrator Access.  
* Terraform v1.5+.  
* Docker (to build the worker image).

**Installation:**

1. **Clone the Repository:**  
   Bash  
   git clone https://github.com/Stealinglight/Snapshot-Sleuth.git  
   cd Snapshot-Sleuth

2. **Build and Push Worker Image:**  
   Bash  
   aws ecr get-login-password | docker login \--username AWS \--password-stdin \<AccountID\>.dkr.ecr.us-east-1.amazonaws.com  
   docker build \-t snapshot-sleuth-worker.  
   docker tag snapshot-sleuth-worker:latest \<RepoURL\>:latest  
   docker push \<RepoURL\>:latest

3. **Deploy Infrastructure:**  
   Bash  
   cd terraform  
   terraform init  
   terraform apply \-var="admin\_email=analyst@example.com"

   *This creates the VPC, Fargate Cluster, S3 Buckets (Evidence & Logs), DynamoDB Tables, and EventBridge Rules.*

### **8.2 User Guide**

**Starting an Investigation:**

1. **Automated Trigger:** Snapshot-Sleuth automatically listens for GuardDuty High Severity findings. No action required.  
2. **Manual Trigger:**  
   * Navigate to the Snapshot-Sleuth Dashboard (CloudFront URL).  
   * Enter the Instance ID (e.g., i-0123456789abcdef0) in the "New Investigation" search bar.  
   * Click "Acquire & Analyze".

**Viewing Results:**

* The dashboard updates in real-time.  
* **Findings Tab:** Displays chkrootkit alerts, high-entropy file paths, and YARA matches.  
* **AI Report Tab:** Displays the Bedrock-generated summary of the incident.  
* **Artifacts:** Allows downloading of specific files extracted during analysis.

### **8.3 Troubleshooting**

**Common Error: "Task failed to start"**

* *Cause:* Filesystem mismatch. The user selected xfs in the config, but the source volume is ext4.  
* *Fix:* Check the CloudWatch Logs for the Fargate task. The specific error "mount: wrong fs type" will appear. Update the investigation configuration with the correct FS type and retry.

**Common Error: "Access Denied" on Snapshot**

* *Cause:* The volume is encrypted with a custom KMS key that the ECSInfrastructureRole cannot access.  
* *Fix:* Add the kms:Decrypt and kms:CreateGrant permissions to the IAM Role for the specific key ARN.7

## ---

**9\. Draft Blog Post: Announcing Snapshot-Sleuth 2.0**

**Title: From Hours to Seconds—The Future of Serverless Cloud Forensics**

*By The Snapshot-Sleuth Team*

We are thrilled to announce the release of **Snapshot-Sleuth 2.0**, a complete reimagining of our open-source cloud forensic platform.

**The Problem with Legacy Forensics**

For years, incident response in the cloud meant spinning up expensive EC2 "forensic workstations," waiting 15 minutes for volumes to hydrate, and manually running scripts. It was slow, expensive, and rigid. In a world where ransomware encrypts drives in minutes, a 15-minute startup time is unacceptable.

**Enter Snapshot-Sleuth 2.0**

Version 2.0 ditches the EC2 instances for **AWS Fargate**. By leveraging the new EBS volume attachment capability, we can spin up ephemeral, isolated forensic containers in seconds.

* **Serverless:** No instances to manage or patch.  
* **Fast:** Automated analysis begins immediately.  
* **Smart:** We've integrated **Amazon Bedrock** to have AI explain the findings to you. Found a suspicious obfuscated script? The AI Analyst will de-obfuscate it and explain what it does.

**Key Features:**

* **Entropy Scanning:** Detects packed malware that hides from standard antivirus.  
* **Deep Forensics:** Automated rootkit detection via chkrootkit.  
* **Direct API Access:** Browse terabyte-sized drives instantly without waiting for them to load, thanks to coldsnap integration.  
* **Cost Effective:** You only pay for the minutes the analysis runs.

Snapshot-Sleuth 2.0 is available now on GitHub. Let's make the cloud a harder place for bad actors to hide.

## ---

**10\. Conclusion**

Snapshot-Sleuth 2.0 represents the maturation of cloud forensics. It moves the discipline from a manual, infrastructure-heavy process to an agile, code-defined capability. By effectively synthesizing Fargate's ephemeral compute, the precision of EBS Direct APIs, and the analytical power of Bedrock AI, this platform provides defenders with the speed and intelligence required to combat modern adversaries. The roadmap outlined above provides a pragmatic, phased approach to achieving this vision, ensuring that every step delivers tangible security value.

#### **Works cited**

1. Unlocking AWS Fargate feature for attaching Amazon EBS Volumes ..., accessed January 24, 2026, [https://aws.amazon.com/blogs/containers/unlocking-aws-fargate-feature-for-attaching-amazon-ebs-volumes-to-ecs-tasks/](https://aws.amazon.com/blogs/containers/unlocking-aws-fargate-feature-for-attaching-amazon-ebs-volumes-to-ecs-tasks/)  
2. Amazon EBS FAQs, accessed January 24, 2026, [https://aws.amazon.com/ebs/snapshots/faqs/](https://aws.amazon.com/ebs/snapshots/faqs/)  
3. Linux Security: Scan Your Servers for Rootkits With Ease, accessed January 24, 2026, [https://thenewstack.io/linux-security-scan-your-servers-for-rootkits-with-ease/](https://thenewstack.io/linux-security-scan-your-servers-for-rootkits-with-ease/)  
4. About EBS Volumes \- Flexera CMP Docs, accessed January 24, 2026, [https://docs.rightscale.com/cm/dashboard/clouds/generic/ebs\_volumes\_concepts.html](https://docs.rightscale.com/cm/dashboard/clouds/generic/ebs_volumes_concepts.html)  
5. Understanding Amazon EBS Pricing: A Complete Guide \- Cloudchipr, accessed January 24, 2026, [https://cloudchipr.com/blog/aws-ebs-pricing](https://cloudchipr.com/blog/aws-ebs-pricing)  
6. Attach EBS volume to AWS ECS Fargate | by Usama Shujaat \- Medium, accessed January 24, 2026, [https://medium.com/@shujaatsscripts/attach-ebs-volume-to-aws-ecs-fargate-e23fea7bb1a7](https://medium.com/@shujaatsscripts/attach-ebs-volume-to-aws-ecs-fargate-e23fea7bb1a7)  
7. How to mount ebs volume(or part) to fargate container \- Stack Overflow, accessed January 24, 2026, [https://stackoverflow.com/questions/67323679/how-to-mount-ebs-volumeor-part-to-fargate-container](https://stackoverflow.com/questions/67323679/how-to-mount-ebs-volumeor-part-to-fargate-container)  
8. Use Amazon EBS volumes with Amazon ECS \- Amazon Elastic ..., accessed January 24, 2026, [https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ebs-volumes.html](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ebs-volumes.html)  
9. Using Entropy in Threat Hunting: a Mathematical Search for the ..., accessed January 24, 2026, [https://redcanary.com/blog/threat-detection/threat-hunting-entropy/](https://redcanary.com/blog/threat-detection/threat-hunting-entropy/)  
10. Malware analysis: part 6\. Shannon entropy. Simple python script., accessed January 24, 2026, [https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html](https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html)  
11. Entropy and Packing Analysis \- GitHub, accessed January 24, 2026, [https://github.com/ericyoc/win\_entropy\_packing\_poc](https://github.com/ericyoc/win_entropy_packing_poc)  
12. Entropy identifies malware and exfiltration \- Cisco Umbrella, accessed January 24, 2026, [https://umbrella.cisco.com/blog/using-entropy-to-spot-the-malware-hiding-in-plain-sight](https://umbrella.cisco.com/blog/using-entropy-to-spot-the-malware-hiding-in-plain-sight)  
13. Digital Forensic Analysis of Amazon Linux EC2 Instances, accessed January 24, 2026, [https://www.giac.org/paper/gcfa/13310/digital-forensic-analysis-amazon-linux-ec2-instances/123500](https://www.giac.org/paper/gcfa/13310/digital-forensic-analysis-amazon-linux-ec2-instances/123500)  
14. EBS Direct APIs – Programmatic Access to EBS Snapshot Content, accessed January 24, 2026, [https://aws.amazon.com/blogs/aws/new-programmatic-access-to-ebs-snapshot-content/](https://aws.amazon.com/blogs/aws/new-programmatic-access-to-ebs-snapshot-content/)  
15. EBS \- Boto3 1.42.30 documentation, accessed January 24, 2026, [https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs.html)  
16. AWS EBS Direct APIs | by Holiday-developer \- Medium, accessed January 24, 2026, [https://medium.com/holiday-developer/aws-ebs-direct-apis-what-why-and-how-part-1-55070e2dc5ed](https://medium.com/holiday-developer/aws-ebs-direct-apis-what-why-and-how-part-1-55070e2dc5ed)  
17. AWS open source news and updates \#52 \- DEV Community, accessed January 24, 2026, [https://dev.to/aws/aws-open-source-news-and-updates-52-4hn9](https://dev.to/aws/aws-open-source-news-and-updates-52-4hn9)  
18. awslabs/coldsnap: A command line interface for Amazon ... \- GitHub, accessed January 24, 2026, [https://github.com/awslabs/coldsnap](https://github.com/awslabs/coldsnap)  
19. get\_snapshot\_block \- Boto3 1.42.17 documentation, accessed January 24, 2026, [https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs/client/get\_snapshot\_block.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ebs/client/get_snapshot_block.html)  
20. Hacking Exposed Computer Forensics Blog \- RSSing.com, accessed January 24, 2026, [https://exposed425.rssing.com/chan-6927338/all\_p21.html](https://exposed425.rssing.com/chan-6927338/all_p21.html)  
21. pytsk/tests/fs\_info.py at main \- GitHub, accessed January 24, 2026, [https://github.com/py4n6/pytsk/blob/master/tests/fs\_info.py](https://github.com/py4n6/pytsk/blob/master/tests/fs_info.py)  
22. invoke\_model \- Boto3 1.42.34 documentation, accessed January 24, 2026, [https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-runtime/client/invoke\_model.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/bedrock-runtime/client/invoke_model.html)  
23. How to use Amazon Bedrock with Python (boto3) | AWS Builder Center, accessed January 24, 2026, [https://builder.aws.com/content/37wbVP9CkzXw2x52COFByePAigw/how-to-use-amazon-bedrock-with-python-boto3](https://builder.aws.com/content/37wbVP9CkzXw2x52COFByePAigw/how-to-use-amazon-bedrock-with-python-boto3)  
24. Amazon Bedrock Runtime code examples for the SDK for Python, accessed January 24, 2026, [https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/python/example\_code/bedrock-runtime/README.md](https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/python/example_code/bedrock-runtime/README.md)  
25. AWS AppSync Pricing | Managed GraphQL APIs, accessed January 24, 2026, [https://aws.amazon.com/appsync/pricing/](https://aws.amazon.com/appsync/pricing/)  
26. Which Real Time Backend Is Right for Your App: Firebase, AppSync ..., accessed January 24, 2026, [https://www.rwit.io/blog/which-real-time-backend-is-right-for-your-app](https://www.rwit.io/blog/which-real-time-backend-is-right-for-your-app)  
27. Forensic investigation environment strategies in the AWS Cloud, accessed January 24, 2026, [https://aws.amazon.com/blogs/security/forensic-investigation-environment-strategies-in-the-aws-cloud/](https://aws.amazon.com/blogs/security/forensic-investigation-environment-strategies-in-the-aws-cloud/)  
28. Enhancing Data Security with S3 Object Lock \- DEV Community, accessed January 24, 2026, [https://dev.to/btarbox/enhancing-data-security-with-s3-object-lock-1je4](https://dev.to/btarbox/enhancing-data-security-with-s3-object-lock-1je4)

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAYCAYAAAD3Va0xAAAAzklEQVR4Xu2SMQ5BQRCGf1EhcSCJAyChcwnlSxyAA7iB1iEUao3eERC8oKAQZjKz4k12F9Hul/zN+/682cwukPiVKeVEebxlo65E2Rp3oLTVe3FFHwuIq1th4clcXFmhxIYUGECKXSsUdjf70QfvJDSxCXEjK3y4o/coHcgyW5qlusqrHYGLa0pmMlQXOm0Bt5/QlX69nx3CExsQN7bCR+zoc4irWmEpQ4p/v58JpNi3AnJLH380o5wpR8qeklPu6mqUi35jx50r5GkkEo4nVItCIl5coUMAAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,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>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC8AAAAYCAYAAABqWKS5AAACFklEQVR4Xu2WPUgdQRSFD4kk0U5SiBCIQmxFsEmhgpUQCCSKKJYSUASxMopWgo1WkUCSLppGTJNOxFbEMoIgCsFOsPKHRI0g6r1vZnTfcebtPnYfgfA+ODBz7p2f3fnZBcr8P3SxkYImNkrJoqiFzZRcsxHig+gEpoHqXHRI3vfb7HxeiVbZzIB60RGbhXATZZ7D+L5J+vKz4lT0ms0QOpENNi2+B5sQbZKXJQ24P6aXXpjEDg4IlfBPXusvycsaHaOKTWYb9yfn+AETe0N+KN/xTjQjemTrQ6JPd+FE6BizbDK+N6u0w/hz5OtB9eU7LkUVomqYvD1RnWjYxpKi5+yCTcZN/hjmlP+19S3R00ieYwrhye+LnkTqmqer58o7kVgcXxAeJ4fb7/0cKMACwp2ORMoPYfJe2Hr0oRzzolY2LWMIj5NjFzEJHr4iWZv3iM+bZCPCKGLauy1TDONI1uYPkuWF+IyY9hr8xWYMbxHuVM/LN1vWnOjXuRt31+tj0U+YlQ+xIjpj06FLpgMMcCABvsnXwvh9oh5bnrexBzAr4XBlXz8OjenvSx4fRb9hbhb9j9FP8VVeRjzacTObwgHyJ61XndZ9X2/9DuiNEkLb6XWbOcuidTaLpNBbf4bC8dSk6VyvTbfabdGARXdFJ5tZMi1aYrMI9HDroWVqYLZfyVkTNbKZkjQrWjSDbKTAt4XK/HNuACS9h1I7v3u6AAAAAElFTkSuQmCC>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAcAAAAXCAYAAADHhFVIAAAAaElEQVR4XmNgGHigAMT30QVh4C0Q/0cXpAx0AnECuiAI/IDSIPsckSVmAjETlA2SdEWSY6iF0v0MeFwKkihEFwSBPAaELmEgNkGSA0u8g7IfI0uAwDMgPsQAsT8TTQ4MAoBYDF1w6AAA4oAS3/pLqloAAAAASUVORK5CYII=>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC0AAAAXCAYAAACf+8ZRAAABkklEQVR4Xu2VPyhHURTHD0mUVRgYKEUZGJSIkt1gQAZlNRjN/pVBMokikwwWi/iVQZgwsNiETRZlMKD4Hue93Hfee7/fve/H5H7qs3zPue/e7n3dS+TxeGz5hHNwAo7BETgcWG/0adrhEeyApbARrsA9s+kvaCBZdJpcT2OA4v1PkY6ATh0UySRcJtm1ZthEsmPTcN3oS6IP7sMNOAurouUfyuE9PIMl0VImcjoAZfBVhwn0wBkd5oP/oWt4BytVrVg+dJBCNzku2uQAvsBaXcjAKtkvpAtuk/zLOySncxLpsGCLZJfadMEBXoAtfGs8qIzHn6rMigWSwb26UIAlclt0Eo+U8Rt8I/DAUV0oAI8516EjxyTfqVF5KvMkA/p1wRIeu6jDPIR3s8llkFWoPMYmfIctuuDAIMlkU7oQwIvgEzTh/l2VvQV5KofwGVbrQgbWSCbjpzyJcFdbjeyK5NoLqSPpGTeyb/hB4SO4JYsjcGCIZEK+EZLgk7jQIbghGRfuMD/tMfgZ/42X0OPx/Be+AKXtVbtddpJ+AAAAAElFTkSuQmCC>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC0AAAAXCAYAAACf+8ZRAAABuUlEQVR4Xu2VSyhFURSGl/cjKXmUvGIgUTIykFJKBgbK1NhISQYkJjI1YSBRDCUjRgZmBvIoZWAqeZREGTDwXuvuvd11//Y99x4ycr76665vnXP3vvueszdRREREWKY47za90Atik/PJOeMUQu9PeeWs2M95nA9OfrztJYfMZGttnWXryu8rfkAfiiTcc+5UPU9m8HblfOxxrsDNkbk3NMtkVq4JGx7qKXG1HK1Q+5D7FsF1WJ82u5xHTgU2Atin+CC5nB7VC8I9CtPg66wfAJ9ANpkX4IJTAL10kAEk65wuTout5REJoo3MdWPgy62fAB+jmHPLOeZkQi8MbtIzyjVYV60c0k3mmhHwJda7lzpGFeeJs63lL3CTRsTdoFQ0krlmFHyZ9bNaysv1xlnS8hcETdrnHRlk+pPga6wfBB/DrfgWNkJyQP7JpZq0IP1ku0fgXl3EueYckvn1YZF/zjc5cWuqloNmWNWCHECn4MbJ/31eZAs64ZxT6pMMeebsqFqOcxzYrXyzcp3WaaReAJcW8sg8cEqxEcAlmQFfyKwg7kj9nCNwglvZDTL3ria2wzOEIiIi4h/yBSGxZxyaQGwpAAAAAElFTkSuQmCC>