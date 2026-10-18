# 🛡️ Enterprise Secure Cloud Backup & IAM Platform

> An end-to-end, production-ready cloud backup solution incorporating automated anomaly detection, machine learning-driven Role-Based Access Control (RBAC), cryptographic audit logging, and AWS S3 integration.

---

## 📸 Key Features & Architecture

* **Interactive Security Dashboard**: Streamlit-powered UI providing real-time operational visibility into active backups, access logs, and system anomalies.
* **Rule-Based Anomaly Detection Engine**: Identifies suspicious user behavior (e.g., off-hours access spikes, rapid mass deletions, unauthorized IP ranges).
* **AI Access Role Optimization**: Unsupervised Machine Learning (`K-Means` via Scikit-learn) analyzing access patterns to recommend minimal-privilege roles.
* **Tamper-Evident Audit Trail**: Cryptographically chained hashing (SHA-256) embedded inside SQLite to guarantee immutable logging integrity.
* **Cloud Storage Adapter**: Cloud-native integration leveraging `boto3` for isolated S3 backup, retrieval, and bucket lifecycle operations.

---

## 🛠️ System Architecture & Tech Stack

| Layer | Component / Tool | Primary Purpose |
| :--- | :--- | :--- |
| **Interface** | Streamlit | Executive & operational dashboarding |
| **Backend / ML** | Python 3.11+, Scikit-learn, Pandas | Anomaly evaluation & cluster analysis |
| **Database** | SQLite (`logs/backups.db`) | Hash-chained log persistence |
| **Cloud Storage**| AWS S3 via Boto3 | Secure remote backup management |
| **Testing** | Pytest | Automated test coverage (55 tests) |

---
![App Dashboard Preview](dashboard_preview.png)

## 🚀 Getting Started

### Prerequisites
* Python 3.11 or higher
* Virtual Environment activated (`.venv`)

### Installation & Execution

1. **Activate Environment**
   ```powershell
   .\.venv\Scripts\Activate.ps1



   
