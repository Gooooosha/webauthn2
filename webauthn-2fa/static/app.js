// ── Binary helpers ──────────────────────────────────────────────────────────

function toBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function fromBase64url(b64url) {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + (4 - (b64.length % 4)) % 4, "=");
    const raw = atob(padded);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf.buffer;
}

// ── WebAuthn option adapters ─────────────────────────────────────────────────

// Convert JSON options from server → navigator.credentials.create() format
function toCreationOptions(opts) {
    return {
        ...opts,
        challenge: fromBase64url(opts.challenge),
        user: { ...opts.user, id: fromBase64url(opts.user.id) },
        excludeCredentials: (opts.excludeCredentials || []).map((c) => ({
            ...c,
            id: fromBase64url(c.id),
        })),
    };
}

// Convert JSON options from server → navigator.credentials.get() format
function toRequestOptions(opts) {
    return {
        ...opts,
        challenge: fromBase64url(opts.challenge),
        allowCredentials: (opts.allowCredentials || []).map((c) => ({
            ...c,
            id: fromBase64url(c.id),
        })),
    };
}

// Serialize PublicKeyCredential (registration) → plain JSON for server
function serializeRegistration(cred) {
    return {
        id: cred.id,
        rawId: toBase64url(cred.rawId),
        type: cred.type,
        response: {
            clientDataJSON: toBase64url(cred.response.clientDataJSON),
            attestationObject: toBase64url(cred.response.attestationObject),
        },
    };
}

// Serialize PublicKeyCredential (authentication) → plain JSON for server
function serializeAuthentication(assertion) {
    return {
        id: assertion.id,
        rawId: toBase64url(assertion.rawId),
        type: assertion.type,
        response: {
            clientDataJSON: toBase64url(assertion.response.clientDataJSON),
            authenticatorData: toBase64url(assertion.response.authenticatorData),
            signature: toBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle
                ? toBase64url(assertion.response.userHandle)
                : null,
        },
    };
}

// ── API helpers ──────────────────────────────────────────────────────────────

async function post(url, body) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Request failed");
    return data;
}

// ── UI helpers ───────────────────────────────────────────────────────────────

const $status     = document.getElementById("status");
const $statusText = document.getElementById("status-text");
const $result     = document.getElementById("result");
const $resultIcon = document.getElementById("result-icon");
const $resultText = document.getElementById("result-text");

function showStatus(text) {
    $result.classList.add("hidden");
    $statusText.textContent = text;
    $status.classList.remove("hidden");
}

function showResult(ok, message) {
    $status.classList.add("hidden");
    $result.className = `result ${ok ? "ok" : "err"}`;
    $resultIcon.textContent = ok ? "✓" : "✕";
    $resultText.textContent = message;
    $result.classList.remove("hidden");
}

function withButton(btn, fn) {
    return async (...args) => {
        btn.disabled = true;
        try {
            await fn(...args);
        } finally {
            btn.disabled = false;
        }
    };
}

// ── Registration flow ────────────────────────────────────────────────────────

async function register(username, password) {
    if (!window.PublicKeyCredential) {
        showResult(false, "WebAuthn is not supported in this browser.");
        return;
    }

    showStatus("Creating account…");
    const { reg_token, options } = await post("/api/register/begin", { username, password });

    showStatus("Touch your fingerprint sensor (factor 2)…");
    const cred = await navigator.credentials.create({ publicKey: toCreationOptions(options) });

    showStatus("Verifying biometric…");
    const result = await post("/api/register/complete", {
        reg_token,
        credential: serializeRegistration(cred),
    });

    showResult(true, result.message);
}

// ── Login flow ───────────────────────────────────────────────────────────────

async function login(username, password) {
    if (!window.PublicKeyCredential) {
        showResult(false, "WebAuthn is not supported in this browser.");
        return;
    }

    showStatus("Verifying password (factor 1)…");
    const { session_id, options } = await post("/api/login/begin", { username, password });

    showStatus("Touch your fingerprint sensor (factor 2)…");
    const assertion = await navigator.credentials.get({ publicKey: toRequestOptions(options) });

    showStatus("Verifying biometric…");
    const result = await post("/api/login/complete", {
        session_id,
        credential: serializeAuthentication(assertion),
    });

    showResult(true, result.message);
}

// ── Event wiring ─────────────────────────────────────────────────────────────

// Tab switching
document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(btn.dataset.tab).classList.add("active");
        $result.classList.add("hidden");
        $status.classList.add("hidden");
    });
});

// Register form
const regBtn = document.querySelector("#register-form button");
document.getElementById("register-form").addEventListener(
    "submit",
    withButton(regBtn, async (e) => {
        e.preventDefault();
        const username = document.getElementById("reg-username").value.trim();
        const password = document.getElementById("reg-password").value;
        if (!username || !password) return showResult(false, "Fill in all fields.");
        try {
            await register(username, password);
        } catch (err) {
            showResult(false, err.message);
        }
    }),
);

// Login form
const loginBtn = document.querySelector("#login-form button");
document.getElementById("login-form").addEventListener(
    "submit",
    withButton(loginBtn, async (e) => {
        e.preventDefault();
        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value;
        if (!username || !password) return showResult(false, "Fill in all fields.");
        try {
            await login(username, password);
        } catch (err) {
            showResult(false, err.message);
        }
    }),
);
