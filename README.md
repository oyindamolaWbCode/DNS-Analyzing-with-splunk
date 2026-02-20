

DNS Traffic Assessment Using Splunk


 Overview

This project focuses on analyzing DNS logs within Splunk to identify potential indicators of suspicious behavior, including Domain Generation Algorithms (DGA), DNS tunneling, and beaconing activity.

The dataset consists of DNS log entries containing source IPs, destination IPs, query types, FQDNs, and response information.

 Objectives

Identify hosts generating excessive NXDOMAIN responses

Detect abnormal DNS query patterns

Analyze unique domain counts per host

Identify long or random-looking FQDNs

Investigate potential DNS beaconing behavior

🛠 Tools Used

Splunk Enterprise

SPL (Search Processing Language)

Kali Linux Lab Environment

 Key Detection Queries
1. High NXDOMAIN Activity
index=dns_assessment sourcetype=dns_assessment "NXDOMAIN"
| stats count by src_ip
| sort - count

Purpose: Detect potential DGA or failed domain resolution patterns.

2. Unique Domain Count per Host
index=dns_assessment sourcetype=dns_assessment
| stats dc(fqdn) as unique_domains count by src_ip
| sort - unique_domains

Purpose: Identify hosts querying an unusually high number of domains.

3. Long Domain Detection
index=dns_assessment sourcetype=dns_assessment
| eval domain_length=len(fqdn)
| where domain_length > 70
| stats count by src_ip, fqdn
| sort - count

Purpose: Detect potential DNS tunneling or encoded subdomains.

 Findings

Multiple hosts generated high NXDOMAIN responses.

Domains analyzed were legitimate services (e.g., common APIs and vendor services).

No confirmed DGA or DNS tunneling activity identified.

High NXDOMAIN likely due to lab DNS configuration or simulated traffic.

🧠 Key Takeaways

DNS anomaly detection requires contextual validation.

High NXDOMAIN alone does not indicate compromise.

Domain reputation and pattern analysis are critical.

Effective field filtering in Splunk improves detection accuracy.
