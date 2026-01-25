# **Snapshot-Sleuth 2.0: Architecting Serverless Forensic Analysis & Multi-Agent Intelligence**

## **1\. Executive Context: The Crisis of Cloud Forensics**

The trajectory of cloud-native incident response is currently colliding with a fundamental architectural barrier: the disconnect between the scale of modern infrastructure and the capabilities of legacy forensic tooling. For the past decade, Digital Forensics and Incident Response (DFIR) in the cloud has largely been a "lift and shift" exercise—replicating the physical forensic lab within virtual machines. Analysts capture full disk images, transfer them to analysis instances, and process them using monolithic software suites. This linear, I/O-intensive workflow is proving unsustainable against the velocity of ephemeral threats and the sheer volume of petabyte-scale storage environments.

Snapshot-Sleuth 1.0 represented an initial attempt to break this paradigm by introducing serverless concepts to forensic acquisition. By leveraging AWS Lambda, it demonstrated the potential for event-driven, automated snapshots. However, operational realities have revealed significant limitations in this first-generation approach. The "Lambda Ceiling"—defined by strict 15-minute execution timeouts, limited ephemeral storage, and memory constraints—has rendered deep forensic analysis of complex artifacts (such as Master File Tables or extensive Event Logs) unreliable.1 A timeline reconstruction that terminates prematurely due to a timeout is not merely inefficient; it is forensically unsound, potentially truncating critical evidence of lateral movement or persistence.

Snapshot-Sleuth 2.0 addresses these systemic failures through a radical re-architecture. This report details the strategic pivot from a Function-as-a-Service (FaaS) model to a Container-as-a-Service (CaaS) model using AWS Fargate (Phase 3), and the integration of a Multi-Agent Intelligence Layer (Phase 4). The analysis necessitates a rigorous examination of the feasibility of "mounting" versus "extraction" in restricted container environments, ultimately proposing a third way—Virtual Forensic Streaming—that leverages Amazon EBS Direct APIs to bypass the limitations of both traditional approaches. Furthermore, the report outlines the deployment of a Map-Reduce cognitive architecture utilizing advanced Large Language Models (LLMs)—specifically referencing the capabilities of 'Claude Sonnet 4.5' and 'Haiku 4.5'—to automate the synthesis of raw log data into coherent, verifiable forensic narratives.3

## **2\. Phase 3 Re-Architecture: The Migration to Fargate and the Access Paradox**

The transition from AWS Lambda to AWS Fargate is not merely a change in compute environments; it is a shift in the operational philosophy of the forensic extraction engine, ColdSnap. While Lambda optimization focuses on millisecond-latency for lightweight triggers, forensic analysis requires sustained computational throughput and predictable I/O performance over extended periods. Fargate provides this stability while retaining the serverless abstraction that eliminates the overhead of managing EC2 fleets.

### **2.1 The "Mounting" vs. "Extraction" Feasibility Analysis**

The user query specifically demands a resolution to the "mounting" versus "extraction" debate within the context of Fargate containers. This dichotomy has long plagued containerized forensics. Traditionalists favor mounting to utilize standard POSIX tools, while modernists favor extraction to work with API-native formats. The analysis indicates that in the specific context of AWS Fargate Platform Version 1.4+, both approaches face critical, and often prohibitive, challenges.

#### **2.1.1 The FUSE/Mounting Barrier in Fargate**

The concept of "mounting" an S3 bucket or an EBS snapshot directly into a container typically relies on Filesystem in Userspace (FUSE) technologies (e.g., s3fs, mount-s3, or rclone). In a standard Docker environment running on a self-managed EC2 instance, an administrator can grant the container the necessary privileges to perform these operations. specifically, the container requires access to the /dev/fuse device and the CAP\_SYS\_ADMIN Linux capability.5

However, AWS Fargate enforces a strict, multi-tenant security model designed to isolate workloads running on shared hardware. To achieve this, Fargate tasks run within Firecracker microVMs, and the platform explicitly denies the addition of privileged capabilities such as CAP\_SYS\_ADMIN to task definitions.5 This restriction is not a configuration error but a fundamental security feature of the platform. Consequently, standard FUSE-based mounting solutions are architecturally incompatible with Fargate. While AWS has introduced persistent storage options like Amazon EFS, these require the data to already reside on an EFS file system, which does not solve the problem of accessing raw block data residing in an EBS snapshot.7

Attempts to circumvent this via "privileged" flags in Fargate task definitions will result in deployment failures or runtime errors, as the underlying container runtime prohibits the escalation of privileges required to manipulate the kernel's mount namespace.10 Therefore, a roadmap dependent on "mounting" snapshots via FUSE in Fargate is non-viable.

#### **2.1.2 The Extraction Bottleneck**

The alternative—full extraction—involves downloading the entire disk image from the snapshot to the container's local storage before analysis begins. This approach faces two hurdles: storage capacity and time-to-evidence.

First, while Fargate has increased its ephemeral storage limits (configurable up to 200 GB for Platform Version 1.4), this is often insufficient for modern forensic targets.11 A compromised database server or file server may easily have a boot volume exceeding 1 TB. To analyze such a volume via extraction, the architecture would require attaching an external EFS volume to the Fargate task.8 While technically feasible, EFS introduces significant cost premiums ($0.30/GB-month for standard storage) and I/O latency compared to local NVMe storage.12

Second, and more critically, is the latency introduced by the download process. Transferring 1 TB of data from S3 (where snapshots are stored) to the Fargate container saturates the network interface and delays the start of analysis by hours. In a high-velocity incident response scenario, waiting three hours for a "download" to complete before the first artifact can be parsed is operationally unacceptable. The "Extraction" model essentially recreates the inefficiencies of the legacy forensic lab in the cloud.13

### **2.2 The Strategic Pivot: Virtual Forensic Streaming**

Given the impossibility of FUSE mounting and the inefficiency of full extraction, Phase 3 of the Snapshot-Sleuth 2.0 roadmap introduces a third methodology: **Virtual Forensic Streaming**. This approach leverages the Amazon EBS Direct APIs (ListSnapshotBlocks, GetSnapshotBlock) to perform sparse, random-access reads of the snapshot data directly from the application layer, without ever hydrating a volume or mounting a filesystem.14

#### **2.2.1 Architecture of the Virtual Stream**

The Virtual Forensic Streaming architecture relies on a custom Python wrapper (the EBSDirectFile class) that emulates a standard file object (io.RawIOBase). When a forensic parser (such as dissect or libtsk) requests to read a specific byte range—for example, the first 1024 bytes of the Master File Table—the wrapper intercepts this call. Instead of reading from a local disk, the wrapper mathematically calculates which 512 KiB snapshot blocks contain the requested data. It then issues a GetSnapshotBlock API call to AWS, retrieves only the necessary chunks, extracts the relevant bytes, and returns them to the parser.15

This methodology aligns perfectly with the access patterns of digital forensics. Forensic tools rarely read a disk linearly from start to finish. They perform "sparse" reads: jumping to the partition table, then to the file system boot record, then to the MFT, and finally to specific file clusters. By fetching only the blocks requested by the parser, Virtual Streaming creates a scenario where analyzing a 1 TB drive might only require downloading 500 MB of metadata. This reduces data transfer costs by orders of magnitude and allows analysis to begin milliseconds after the Fargate task initializes.17

#### **2.2.2 The Role of the dissect Framework**

The success of this architecture depends on the forensic tooling's ability to accept a Python file-like object rather than a physical file path. The dissect framework, developed by Fox-IT, is uniquely suited for this purpose. Unlike legacy tools that wrap C libraries and demand OS-level file handles, dissect is a pure Python implementation of various filesystem parsers (NTFS, EXT4, etc.) designed to operate on abstract streams.19 This compatibility allows Snapshot-Sleuth 2.0 to plug the EBSDirectFile stream directly into dissect.ntfs, enabling sophisticated artifact parsing within the unprivileged Fargate container.

### **2.3 Cost Governance and Performance Metrics**

The shift to Virtual Streaming fundamentally alters the cost structure of forensic acquisition. Traditional volume restoration requires paying for provisioned storage (e.g., GP3 volumes) and the I/O operations required to initialize the volume. For a short-term forensic instance, the minimum billing increments and the time spent waiting for volume initialization ("hydration") represent wasted resources.22

**Table 1: Comparative Cost and Latency Analysis of Forensic Access Methods**

| Metric | Full Volume Restore (Legacy) | Full Image Download (Extraction) | Virtual Forensic Streaming (Phase 3\) |
| :---- | :---- | :---- | :---- |
| **Startup Latency** | High (Minutes to Hours for Initialization) | High (Hours for Transfer) | **Near-Zero** (Milliseconds) |
| **Storage Cost** | High (Provisioned Volume Capacity) | Medium (Ephemeral/EFS Storage) | **Zero** (In-Memory Processing) |
| **Data Transfer Cost** | Low (Intra-Region) | High (Full Size Transfer) | **Optimized** (Sparse Data Only) |
| **Compute Environment** | EC2 Only (Requires Device Attachment) | EC2 or Fargate (High Storage) | **Fargate Compatible** (Low Storage) |
| **Security Posture** | Medium (Volume Management Risk) | Medium (Data Residency Risk) | **High** (Read-Only API Access) |
| **API Cost** | Standard EBS Pricing | Standard S3/EBS Pricing | **Per-Block API Fees** (See Section 5\) |

The table illustrates that Virtual Forensic Streaming is the only viable path for a truly serverless, scalable architecture. It decouples the forensic process from the size of the evidence; analyzing a 10 TB drive takes roughly the same time as analyzing a 100 GB drive if the number of artifacts (MFT records, Event Logs) is similar. This "O(artifacts)" complexity replaces the "O(disk\_size)" complexity of traditional imaging.15

## **3\. Phase 4 Re-Architecture: The Multi-Agent Intelligence Layer**

While Phase 3 solves the data access and runtime problems, Phase 4 addresses the "cognitive bottleneck." The output of dissect and other parsers is typically a deluge of structured data—millions of JSON lines representing file system entries, registry keys, and event logs. A human analyst cannot manually correlate this volume of data at the speed of cloud compromise. Phase 4 introduces a Multi-Agent Intelligence Layer designed to automate this reasoning process.

### **3.1 The Necessity of Agentic Workflows**

Current LLM integrations in forensics often rely on simple "summarization" prompts: pasting a log snippet into a model and asking "is this bad?" This approach fails at scale due to context window limitations and the lack of temporal correlation. A single log entry is rarely malicious in isolation; it is the *sequence* of events—a login, followed by a registry change, followed by a file execution—that constitutes an Indicator of Compromise (IoC). To detect these patterns across gigabytes of logs, Snapshot-Sleuth 2.0 employs a **Map-Reduce** architecture implemented via **LangGraph**.3

### **3.2 Model Selection: The Cognitive Hierarchy**

The user request specifies the use of 'Claude Sonnet 4.5' and 'Haiku 4.5'. These models (representing the next generation of anthropic reasoning) are architected into a hierarchy based on their performance profiles:

* **'Haiku 4.5' (The Triage Scout):** This model is optimized for extreme speed and low cost per token. In the "Map" phase of the architecture, it acts as a high-throughput filter. It does not perform deep reasoning; instead, it scans raw log chunks for statistical anomalies, known attack signatures, and deviations from baselines. Its massive context window allows it to ingest large swathes of logs (e.g., 10MB chunks) and output structured JSON objects containing potential leads.4  
* **'Claude Sonnet 4.5' (The Forensic Lead):** This model is optimized for complex reasoning and nuance. In the "Reduce" phase, it consumes the aggregated leads from the Haiku scouts. It is responsible for constructing the narrative, identifying causal relationships between seemingly disparate events (e.g., correlating a network connection found by Scout A with a process execution found by Scout B), and generating the final forensic timeline. It serves as the synthesis engine, prioritizing accuracy over raw throughput.4

### **3.3 LangGraph Map-Reduce Architecture**

The technical implementation of this hierarchy relies on LangGraph, a library for building stateful, multi-actor applications with LLMs. The workflow is modeled not as a linear chain, but as a cyclic graph that allows for iteration and self-correction.

#### **3.3.1 The Graph Topology**

The forensic analysis process is defined by a StateGraph consisting of distinct nodes, each representing a specific unit of work or an agentic behavior.

1. **The Distributor Node:** This entry point accepts the location of the raw artifacts (produced by Phase 3). It partitions the data into logical chunks—for example, splitting 24 hours of Event Logs into 1-hour segments. It calculates the optimal chunk size to maximize the context utilization of the 'Haiku' models without risking token overflow.  
2. **The Mapper Nodes (Haiku):** Leveraging LangGraph's Send() API, the Distributor spawns multiple parallel execution branches. Each branch runs a 'Haiku' agent on a specific log chunk. This parallelism is critical; it allows the system to analyze terabytes of logs in the time it takes to analyze a single chunk.3 The output of each Mapper is a list of SuspiciousEvent objects, strictly typed to ensure consistency.  
3. **The Reducer Node (Sonnet):** This node acts as the synchronization point. It receives the list of SuspiciousEvent objects from all completed Mapper nodes. The 'Sonnet' agent then performs temporal sorting, deduplication, and cross-correlation. It looks for "chains" of evidence that span across the time chunks handled by different Mappers.  
4. **The Verifier Node:** A critical addition to the roadmap is the Verifier. This node takes the draft report generated by the Reducer and performs a citation check. For every claim made in the report (e.g., "Attacker moved laterally via RDP at 14:00"), the Verifier checks if there is a corresponding raw log entry in the state object that supports this claim. If a hallucination is detected, the graph loops back to the Reducer for correction.28

**Table 2: Operational Specifications of the Multi-Agent Layer**

| Component | Agent / Model | Function | Input Data | Output Artifact |
| :---- | :---- | :---- | :---- | :---- |
| **LogSplitter** | Deterministic Script | Partitioning | Raw JSONL Logs | List |
| **MapScan** | **Haiku 4.5** | Anomaly Detection | Single Log Chunk | List |
| **TimelineBuilder** | **Sonnet 4.5** | Correlation | Aggregated Events | DraftNarrative |
| **CitationAudit** | **Sonnet 4.5** | Verification | Draft \+ Source Data | VerifiedReport |

### **3.4 Handling Large Context Windows**

A persistent challenge in LLM forensics is the "Lost in the Middle" phenomenon, where models struggle to recall information in the center of a massive context window. The Map-Reduce pattern mitigates this by ensuring that the 'Haiku' agents operate on manageable, bite-sized chunks where signal density is high. The 'Sonnet' agent, in turn, receives a *condensed* stream of high-relevance events rather than raw noise. This hierarchical compression preserves the semantic integrity of the investigation while circumventing the token limits of even the most advanced models.26

Furthermore, LangGraph's state management capabilities allow for the persistence of the investigation state. If the 'Sonnet' agent identifies a gap in the timeline (e.g., "Missing logs between 02:00 and 03:00"), it can modify the graph state to request a re-extraction or a targeted search, effectively enabling a "Human-in-the-Loop" workflow where the AI requests clarification or additional data access.30

## **4\. Technical Implementation Strategies**

### **4.1 Developing the EBSDirectFile Wrapper**

The core enabler of Phase 3 is the EBSDirectFile Python class. This class must implement the read(), seek(), and tell() methods of the standard library's io module to ensure compatibility with forensic tools.

* **Block Alignment Logic:** EBS Direct APIs return data in 512 KiB blocks. A read request for 4 KiB of data at offset 100 must be translated into a request for Block 0, followed by an extraction of the byte range \[100:4196\]. The wrapper must handle edge cases where a read request spans across two or more blocks.15  
* **Caching Strategy:** To optimize performance and cost, the wrapper must implement a Least Recently Used (LRU) cache. Forensic parsers frequently re-read metadata structures (like the MFT header). Serving these requests from a local RAM cache avoids redundant API calls and reduces the likelihood of throttling.15  
* **Sparse Block Handling:** EBS snapshots are sparse; blocks that have never been written to are not stored. The GetSnapshotBlock API may return a specific error or token for these blocks. The wrapper must interpret this signal and return a buffer of null bytes (\\x00) to the parser, maintaining the illusion of a continuous linear disk.14

### **4.2 Fargate Task Configuration**

The Fargate task definition for ColdSnap must be tuned for network throughput and memory buffering rather than disk storage.

* **Resource Sizing:** A configuration of 2 vCPU and 4 GB RAM is recommended. The CPU is needed for the Python Global Interpreter Lock (GIL) overhead during parsing, while the RAM is essential for the LRU block cache and holding parsed data structures.32  
* **Networking:** The task must run in a private subnet with a VPC Endpoint for EBS and S3. This keeps the forensic traffic entirely within the AWS internal network, reducing data egress costs and improving security posture.17

### **4.3 FinOps and Cost Governance**

Implementing this roadmap requires a strict FinOps approach to prevent runaway costs associated with API usage and LLM tokens.

**Table 3: Cost Governance Model**

| Cost Driver | Pricing Unit | Risk Factor | Mitigation Strategy |
| :---- | :---- | :---- | :---- |
| **EBS Direct API** | $0.003 / 1k blocks | High (Looping Reads) | Implement LRU Caching in the Python wrapper. |
| **Fargate Compute** | vCPU/Hour | Low | Set strict timeouts on task execution (e.g., 24h). |
| **LLM Inference** | Per Million Tokens | High (Verbose Logs) | Use 'Haiku' for bulk reading; use 'Sonnet' only for synthesis. |
| **Data Transfer** | GB Processed | Medium | Use VPC Endpoints; process data in the same region as the snapshot. |

The cost analysis reveals that for typical forensic triage—which accesses only about 5-10% of a disk's sectors—the Virtual Streaming method is significantly cheaper than full volume restoration. The API costs for reading 500 MB of metadata (\~$0.003) are negligible compared to the cost of provisioning a 1 TB GP3 volume for even a single hour.15

## **5\. Operational Governance & Security Considerations**

The shift to an automated, agentic forensic architecture introduces new security vectors that must be managed through rigorous governance.

### **5.1 Least Privilege & Data Integrity**

The Fargate execution role must effectively function as a "Read-Only" entity. The IAM policy should explicitly allow ebs:ListSnapshotBlocks and ebs:GetSnapshotBlock while explicitly denying ebs:PutSnapshotBlock and ebs:StartSnapshot. This cryptographic enforcement ensures that the forensic tool cannot alter the evidence, preserving the chain of custody. Furthermore, the dissect framework operates in memory without creating temporary files, minimizing the risk of data residue persisting on the container host.36

### **5.2 The "Hallucination" Risk in Forensic Reporting**

The introduction of Generative AI into legal and forensic workflows carries the risk of hallucination—the generation of plausible but false facts. The LangGraph architecture addresses this via the Citation Verification mechanism. By forcing the 'Sonnet' model to reference specific EventIDs in its final report, and having a deterministic code node verify these references against the source data, Snapshot-Sleuth 2.0 establishes a "trust but verify" loop. A report cannot be finalized unless every assertion is mathematically linked to a piece of evidence extracted in Phase 3\.28

### **5.3 Network Isolation and Exfiltration Prevention**

Fargate tasks should be deployed in a "Forensic VPC" with no Internet Gateway. Access to the necessary AWS APIs (EBS, S3, Bedrock/Anthropic) should be mediated strictly through VPC Endpoints. Security Groups must act as a firewall, permitting outbound traffic only to these specific endpoints on port 443\. This isolation ensures that even if the forensic container were compromised by a malicious payload within the snapshot (a rare but theoretical risk in dynamic analysis, though less so in static parsing), the attacker cannot exfiltrate data to an external C2 server.1

## **6\. Implementation Roadmap and Future Outlook**

The realization of Snapshot-Sleuth 2.0 requires a phased execution plan that prioritizes the stability of the extraction engine before layering on the cognitive intelligence.

* **Phase 3 Implementation (Weeks 1-6):** Focus on the EBSDirectFile wrapper. Success criteria include the ability to parse a 1 TB NTFS volume's MFT in under 5 minutes using Fargate, with zero disk hydration.  
* **Phase 4 Implementation (Weeks 7-12):** Deployment of the LangGraph infrastructure. Initial testing should focus on "Golden Datasets"—known forensic images with verified attack paths—to tune the prompt engineering of the 'Haiku' and 'Sonnet' agents.  
* **Integration & Hardening (Weeks 13-16):** End-to-end integration where an EventBridge alert (e.g., GuardDuty finding) triggers the Fargate task, which streams artifacts to S3, which automatically triggers the LangGraph analysis.

### **6.1 Future Outlook: The Autonomous SOC**

Snapshot-Sleuth 2.0 lays the foundation for the Autonomous Security Operations Center (SOC). By demonstrating that heavy forensic lifting can be decoupled from heavy infrastructure, it paves the way for "Forensics as Code." Future iterations could expand the Multi-Agent layer to include "Interrogator" agents that can query other data sources (CloudTrail, VPC Flow Logs) to corroborate findings from the disk image, effectively creating a synthetic Tier-3 analyst capable of operating at machine speed.

The architecture proposed herein—Fargate-based Virtual Streaming coupled with Map-Reduce Agentic Intelligence—represents the state-of-the-art in cloud forensics. It solves the immediate technical debt of the Lambda era while positioning the platform to leverage the exponential advancements in generative AI, ultimately reducing the Mean Time to Response (MTTR) from hours to minutes.

#### **Works cited**

1. Fargate security considerations for Amazon ECS, accessed January 24, 2026, [https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html)  
2. Downloading and Exploring AWS EBS Snapshots, accessed January 24, 2026, [https://rhinosecuritylabs.com/aws/exploring-aws-ebs-snapshots/](https://rhinosecuritylabs.com/aws/exploring-aws-ebs-snapshots/)  
3. Map-Reduce with the Send() API in LangGraph \- Medium, accessed January 24, 2026, [https://medium.com/ai-engineering-bootcamp/map-reduce-with-the-send-api-in-langgraph-29b92078b47d](https://medium.com/ai-engineering-bootcamp/map-reduce-with-the-send-api-in-langgraph-29b92078b47d)  
4. Multi-Agent collaboration patterns with Strands Agents and Amazon ..., accessed January 24, 2026, [https://aws.amazon.com/blogs/machine-learning/multi-agent-collaboration-patterns-with-strands-agents-and-amazon-nova/](https://aws.amazon.com/blogs/machine-learning/multi-agent-collaboration-patterns-with-strands-agents-and-amazon-nova/)  
5. How to mount a FUSE-based filesystem on docker container running ..., accessed January 24, 2026, [https://stackoverflow.com/questions/68709395/how-to-mount-a-fuse-based-filesystem-on-docker-container-running-on-aws](https://stackoverflow.com/questions/68709395/how-to-mount-a-fuse-based-filesystem-on-docker-container-running-on-aws)  
6. AWS Fargate Supports Container Workloads Regulated By ISO, PCI ..., accessed January 24, 2026, [https://www.reddit.com/r/aws/comments/828r0q/aws\_fargate\_supports\_container\_workloads/](https://www.reddit.com/r/aws/comments/828r0q/aws_fargate_supports_container_workloads/)  
7. Demystifying EFS-Claim not bound on AWS Fargate with Amazon EKS, accessed January 24, 2026, [https://repost.aws/articles/ARvp6j-8c4Q4W9Zg7Zw3o\_4g/demystifying-efs-claim-not-bound-on-aws-fargate-with-amazon-eks](https://repost.aws/articles/ARvp6j-8c4Q4W9Zg7Zw3o_4g/demystifying-efs-claim-not-bound-on-aws-fargate-with-amazon-eks)  
8. AWS Fargate Scanner with EFS \- Documentation \- APIsec, accessed January 24, 2026, [https://docs.apisec.ai/efs-fargate-scanner/](https://docs.apisec.ai/efs-fargate-scanner/)  
9. Mount Amazon EFS file systems on Amazon ECS containers or ..., accessed January 24, 2026, [https://repost.aws/knowledge-center/ecs-fargate-mount-efs-containers-tasks](https://repost.aws/knowledge-center/ecs-fargate-mount-efs-containers-tasks)  
10. ECS Task with Fargate and EBS volume fails to deploy | AWS re:Post, accessed January 24, 2026, [https://repost.aws/questions/QUAbH6SPI5QVO9epR\_C2BIMw/ecs-task-with-fargate-and-ebs-volume-fails-to-deploy](https://repost.aws/questions/QUAbH6SPI5QVO9epR_C2BIMw/ecs-task-with-fargate-and-ebs-volume-fails-to-deploy)  
11. AWS Fargate Security: A Comprehensive Guide: Upwind, accessed January 24, 2026, [https://www.upwind.io/glossary/the-basics-of-aws-fargate](https://www.upwind.io/glossary/the-basics-of-aws-fargate)  
12. AWS EFS (Elastic File System) vs. AWS EBS (Elastic Block Store), accessed January 24, 2026, [https://n2ws.com/blog/aws-ebs-snapshot/aws-fast-storage-efs-vs-ebs](https://n2ws.com/blog/aws-ebs-snapshot/aws-fast-storage-efs-vs-ebs)  
13. Restoring on-premises applications to AWS from Amazon EBS ..., accessed January 24, 2026, [https://aws.amazon.com/blogs/storage/restoring-on-premises-applications-to-aws-from-amazon-ebs-snapshots-created-by-ebs-direct-apis/](https://aws.amazon.com/blogs/storage/restoring-on-premises-applications-to-aws-from-amazon-ebs-snapshots-created-by-ebs-direct-apis/)  
14. EBS — Boto3 Docs 1.17.49 documentation, accessed January 24, 2026, [https://boto3.amazonaws.com/v1/documentation/api/1.17.49/reference/services/ebs.html](https://boto3.amazonaws.com/v1/documentation/api/1.17.49/reference/services/ebs.html)  
15. GetSnapshotBlock \- EBS direct APIs \- AWS Documentation, accessed January 24, 2026, [https://docs.aws.amazon.com/ebs/latest/APIReference/API\_GetSnapshotBlock.html](https://docs.aws.amazon.com/ebs/latest/APIReference/API_GetSnapshotBlock.html)  
16. 2019-02-09-working-with-large-s3-objects.md \- GitHub, accessed January 24, 2026, [https://github.com/alexwlchan/alexwlchan.net/blob/main/src/\_posts/2019/2019-02-09-working-with-large-s3-objects.md](https://github.com/alexwlchan/alexwlchan.net/blob/main/src/_posts/2019/2019-02-09-working-with-large-s3-objects.md)  
17. Reduce time to recovery with Amazon EBS direct APIs & flexible ..., accessed January 24, 2026, [https://d1.awsstatic.com/events/Summits/reinvent2022/STG404\_Reduce-time-to-recovery-with-Amazon-EBS-direct-APIs-and-flexible-snapshot-proxy.pdf](https://d1.awsstatic.com/events/Summits/reinvent2022/STG404_Reduce-time-to-recovery-with-Amazon-EBS-direct-APIs-and-flexible-snapshot-proxy.pdf)  
18. Concepts for EBS direct APIs \- AWS Documentation, accessed January 24, 2026, [https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-elements.html](https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-elements.html)  
19. dissect.ntfs \- PyPI, accessed January 24, 2026, [https://pypi.org/project/dissect.ntfs/](https://pypi.org/project/dissect.ntfs/)  
20. dissect.ntfs \- Dissect 3.21-1-g6a5cbe8 documentation, accessed January 24, 2026, [https://docs.dissect.tools/en/latest/api/dissect/ntfs/index.html](https://docs.dissect.tools/en/latest/api/dissect/ntfs/index.html)  
21. dissect.ntfs \- Dissect 3.21-2-g57f99f6 documentation, accessed January 24, 2026, [https://docs.dissect.tools/en/latest/projects/dissect.ntfs/index.html](https://docs.dissect.tools/en/latest/projects/dissect.ntfs/index.html)  
22. 5 AWS EBS Volume Types: Cost-Performance Based Comparison ..., accessed January 24, 2026, [https://n2ws.com/blog/aws-ebs-snapshot/which-ebs-volume-types-do-you-need-a-cost-performance-based-comparison](https://n2ws.com/blog/aws-ebs-snapshot/which-ebs-volume-types-do-you-need-a-cost-performance-based-comparison)  
23. Amazon EBS pricing, accessed January 24, 2026, [https://aws.amazon.com/ebs/pricing/](https://aws.amazon.com/ebs/pricing/)  
24. Thinking in LangGraph \- Docs by LangChain, accessed January 24, 2026, [https://docs.langchain.com/oss/python/langgraph/thinking-in-langgraph](https://docs.langchain.com/oss/python/langgraph/thinking-in-langgraph)  
25. LangGraph 101: Let's Build A Deep Research Agent, accessed January 24, 2026, [https://towardsdatascience.com/langgraph-101-lets-build-a-deep-research-agent/](https://towardsdatascience.com/langgraph-101-lets-build-a-deep-research-agent/)  
26. Leveraging Map-Reduce & LLMs for Network Detection \- Corelight, accessed January 24, 2026, [https://corelight.com/blog/map-reduce-llms-cybersecurity-network-detection](https://corelight.com/blog/map-reduce-llms-cybersecurity-network-detection)  
27. How to Use LLMs for Log File Analysis: Examples, Workflows, and ..., accessed January 24, 2026, [https://www.splunk.com/en\_us/blog/learn/log-file-analysis-llms.html](https://www.splunk.com/en_us/blog/learn/log-file-analysis-llms.html)  
28. LLM-driven Provenance Forensics for Threat Intelligence and ... \- arXiv, accessed January 24, 2026, [https://arxiv.org/html/2508.21323v2](https://arxiv.org/html/2508.21323v2)  
29. Advancing Cyber Incident Timeline Analysis Through Rule-Based AI ..., accessed January 24, 2026, [https://arxiv.org/html/2409.02572v3](https://arxiv.org/html/2409.02572v3)  
30. LangGraph Best Practices \- Swarnendu De, accessed January 24, 2026, [https://www.swarnendu.de/blog/langgraph-best-practices/](https://www.swarnendu.de/blog/langgraph-best-practices/)  
31. LLM-based-Digital-Forensic-Timeline-Analysis.pdf, accessed January 24, 2026, [https://forensicsandsecurity.com/papers/LLM-based-Digital-Forensic-Timeline-Analysis.pdf](https://forensicsandsecurity.com/papers/LLM-based-Digital-Forensic-Timeline-Analysis.pdf)  
32. AWS ECS Fargate \- Langfuse Handbook, accessed January 24, 2026, [https://langfuse.com/handbook/product-engineering/infrastructure/ecs](https://langfuse.com/handbook/product-engineering/infrastructure/ecs)  
33. Amazon ECS task definition parameters for Fargate, accessed January 24, 2026, [https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task\_definition\_parameters.html](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html)  
34. Amazon EBS Direct API Backups \- Commvault Documentation, accessed January 24, 2026, [https://documentation.commvault.com/v11/commcell-console/amazon\_ebs\_direct\_api\_backups.html](https://documentation.commvault.com/v11/commcell-console/amazon_ebs_direct_api_backups.html)  
35. The Guide to AWS EBS Pricing \- CloudBolt Software, accessed January 24, 2026, [https://www.cloudbolt.io/guide-to-aws-cost-optimization/aws-ebs-pricing/](https://www.cloudbolt.io/guide-to-aws-cost-optimization/aws-ebs-pricing/)  
36. AWS EBS Direct APIs | by Holiday-developer \- Medium, accessed January 24, 2026, [https://medium.com/holiday-developer/aws-ebs-direct-apis-what-why-and-how-part-1-55070e2dc5ed](https://medium.com/holiday-developer/aws-ebs-direct-apis-what-why-and-how-part-1-55070e2dc5ed)