# AWS IAM Access Advisor Analyzer (Least Privilege Auditor)

[![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue.svg)](https://www.python.org/)
[![SDK](https://img.shields.io/badge/SDK-Boto3-orange.svg)](https://aws.amazon.com/pythonsdk/)
[![Framework](https://img.shields.io/badge/Security-Least%20Privilege-red.svg)](https://aws.amazon.com/iam/)

## 📋 Operational Overview

This repository contains an enterprise-grade Python automation script that leverages the **AWS IAM Access Advisor API** to programmatic identify and report on over-permissioned IAM identities. 

In large-scale production environments, engineers frequently attach broad managed policies to service roles and user profiles. This tool programmatically queries the last-accessed timestamp for every single service permission granted to an IAM principal, flags permissions that have gone unused for more than 90 days, and outputs an actionable remediation report to trim down the attack surface.
┌─────────────────────────┐      1. List IAM Principals     ┌────────────────────────┐
│  Auditor Script Engine  ├────────────────────────────────►│      AWS IAM API       │
│        (Python)         │◄────────────────────────────────┤   (Users & Roles)      │
└───────────┬─────────────┘    2. Return Identities List    └────────────────────────┘
│
│ 3. Generate Service Last Accessed Details
▼
┌─────────────────────────┐      4. Query Job Progress      ┌────────────────────────┐
│   Access Advisor Job    ├────────────────────────────────►│  IAM Credential Report │
│   Tracking Loop         │◄────────────────────────────────┤     Data Plane         │
└───────────┬─────────────┘       5. Return Job Results     └────────────────────────┘
│
▼ 6. Parse Data against Max Age Threshold (90 Days)
┌────────────────────────────────────────────────────────────────────────────────────┐
│ OUTPUT: Comprehensive JSON Compliance Report & Local Markdown Remediation Playbook │
└────────────────────────────────────────────────────────────────────────────────────┘

## 🛡️ Core Security CapabilitiesDeploys

* **Dynamic Asynchronous Job Evaluation:** Uses `generate_service_last_accessed_details` to launch background processing jobs on AWS infrastructure, continuously tracking execution status through a managed backoff loop.
* **Granular Privilege Analysis:** Analyzes individual service tracking metadata to identify exactly which configured services have zero recorded transactions within the defined retention period.
* **Actionable Remediation Outlining:** Flags highly sensitive, high-privilege services (such as `iam`, `kms`, `s3`) that are currently unutilized but actively attached to live enterprise workloads.

## 📂 Repository Structural Mapping

```text
aws-iam-access-advisor-analyzer/
├── README.md                      # Technical summary and architectural workflow
├── iam_advisor_auditor.py         # Main Python automation execution engine
├── requirements.txt               # Documented script dependencies
└── remediation_report.json        # Output target blueprint file
