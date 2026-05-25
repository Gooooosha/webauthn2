"""
WebAuthn 2FA Demo
Run: uvicorn main:app --reload
Open: http://localhost:8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticatorAttestationResponse,
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
import hashlib
import base64
import json
import secrets
import time
import bcrypt

app = FastAPI(title="WebAuthn 2FA Demo")

RP_ID = "9336-50-7-157-226.ngrok-free.app"
RP_NAME = "WebAuthn 2FA Demo"
ORIGIN = "https://9336-50-7-157-226.ngrok-free.app"

def _hash_password(password: str) -> str:
    # Pre-hash with SHA-256 (44 bytes base64) before bcrypt to handle any length
    digest = base64.b64encode(hashlib.sha256(password.encode()).digest())
    return bcrypt.hashpw(digest, bcrypt.gensalt()).decode()


def _verify_password(password: str, hashed: str) -> bool:
    digest = base64.b64encode(hashlib.sha256(password.encode()).digest())
    return bcrypt.checkpw(digest, hashed.encode())

# In-memory storage (demo only — restart resets everything)
users: dict = {}        # username -> {id, password_hash, credentials}
pending_reg: dict = {}  # reg_token  -> {username, challenge, expires_at}
pending_auth: dict = {} # session_id -> {username, challenge, expires_at}


# ── Pydantic request models ──────────────────────────────────────────────────

class RegisterBeginReq(BaseModel):
    username: str
    password: str

class RegisterCompleteReq(BaseModel):
    reg_token: str
    credential: dict

class LoginBeginReq(BaseModel):
    username: str
    password: str

class LoginCompleteReq(BaseModel):
    session_id: str
    credential: dict


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_reg_credential(cred: dict) -> RegistrationCredential:
    r = cred["response"]
    return RegistrationCredential(
        id=cred["id"],
        raw_id=base64url_to_bytes(cred["rawId"]),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(r["clientDataJSON"]),
            attestation_object=base64url_to_bytes(r["attestationObject"]),
        ),
    )


def _build_auth_credential(cred: dict) -> AuthenticationCredential:
    r = cred["response"]
    return AuthenticationCredential(
        id=cred["id"],
        raw_id=base64url_to_bytes(cred["rawId"]),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(r["clientDataJSON"]),
            authenticator_data=base64url_to_bytes(r["authenticatorData"]),
            signature=base64url_to_bytes(r["signature"]),
            user_handle=base64url_to_bytes(r["userHandle"]) if r.get("userHandle") else None,
        ),
    )


# ── Registration ─────────────────────────────────────────────────────────────

@app.post("/api/register/begin")
async def register_begin(req: RegisterBeginReq):
    if not req.username.strip() or not req.password:
        raise HTTPException(400, "Username and password are required")
    if req.username in users:
        raise HTTPException(400, "Username already taken")

    user_id = secrets.token_bytes(16)
    users[req.username] = {
        "id": user_id,
        "password_hash": _hash_password(req.password),
        "credentials": [],
    }

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=req.username,
        user_display_name=req.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=60000,
    )

    options_dict = json.loads(webauthn.options_to_json(options))
    reg_token = secrets.token_urlsafe(32)
    pending_reg[reg_token] = {
        "username": req.username,
        "challenge": options.challenge,  # raw bytes
        "expires_at": time.time() + 300,
    }

    return {"reg_token": reg_token, "options": options_dict}


@app.post("/api/register/complete")
async def register_complete(req: RegisterCompleteReq):
    session = pending_reg.pop(req.reg_token, None)
    if not session or time.time() > session["expires_at"]:
        raise HTTPException(400, "Invalid or expired registration token")

    user = users.get(session["username"])
    if not user:
        raise HTTPException(400, "User not found")

    try:
        parsed = _build_reg_credential(req.credential)
        verification = webauthn.verify_registration_response(
            credential=parsed,
            expected_challenge=session["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(400, f"Biometric verification failed: {exc}")

    user["credentials"].append({
        "id": bytes_to_base64url(verification.credential_id),
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    })

    return {"ok": True, "message": "Account created. Biometric registered successfully!"}


# ── Authentication ────────────────────────────────────────────────────────────

@app.post("/api/login/begin")
async def login_begin(req: LoginBeginReq):
    user = users.get(req.username)
    if not user or not _verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    if not user["credentials"]:
        raise HTTPException(400, "No biometric registered — please register first")

    allow_creds = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
        for c in user["credentials"]
    ]

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_creds,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    options_dict = json.loads(webauthn.options_to_json(options))
    session_id = secrets.token_urlsafe(32)
    pending_auth[session_id] = {
        "username": req.username,
        "challenge": options.challenge,
        "expires_at": time.time() + 300,
    }

    return {"session_id": session_id, "options": options_dict}


@app.post("/api/login/complete")
async def login_complete(req: LoginCompleteReq):
    session = pending_auth.pop(req.session_id, None)
    if not session or time.time() > session["expires_at"]:
        raise HTTPException(401, "Invalid or expired session")

    user = users.get(session["username"])
    if not user:
        raise HTTPException(401, "User not found")

    stored = next(
        (c for c in user["credentials"] if c["id"] == req.credential.get("id")),
        None,
    )
    if not stored:
        raise HTTPException(401, "Unrecognized credential")

    try:
        parsed = _build_auth_credential(req.credential)
        verification = webauthn.verify_authentication_response(
            credential=parsed,
            expected_challenge=session["challenge"],
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(401, f"Biometric verification failed: {exc}")

    stored["sign_count"] = verification.new_sign_count

    return {
        "ok": True,
        "username": session["username"],
        "message": f"Welcome back, {session['username']}! 2FA passed.",
    }


# Serve frontend — must come AFTER API routes
app.mount("/", StaticFiles(directory="static", html=True), name="static")
