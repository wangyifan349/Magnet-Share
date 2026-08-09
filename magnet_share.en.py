"""
Magnet Share - single-file FastAPI application

Run:
    pip install fastapi uvicorn
    python magnet_share_single_file.py

Database:
    magnet_share.db  (created automatically beside this file)

Notes:
- Frontend HTML/CSS/JS is embedded in this single Python file.
- Passwords intentionally use unsalted SHA-512 because that was explicitly requested.
  For a public production service, use Argon2id/scrypt/bcrypt instead.
"""

import base64
import hashlib
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, field_validator


APP_DIRECTORY = Path(__file__).resolve().parent
DATABASE_PATH = APP_DIRECTORY / "magnet_share.db"

BOOTSTRAP_CSS = (
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
)
BOOTSTRAP_CSS_INTEGRITY = (
    "sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB"
)
BOOTSTRAP_JS = (
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"
)
BOOTSTRAP_JS_INTEGRITY = (
    "sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI"
)


# -----------------------------
# Database
# -----------------------------

def get_database():
    database = sqlite3.connect(DATABASE_PATH)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys = ON")
    try:
        yield database
    finally:
        database.close()


def initialize_database():
    with sqlite3.connect(DATABASE_PATH) as database:
        database.execute("PRAGMA foreign_keys = ON")
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS magnets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                magnet TEXT NOT NULL,
                infohash TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (user_id, infohash)
            );

            CREATE INDEX IF NOT EXISTS index_magnets_infohash
            ON magnets(infohash);

            CREATE INDEX IF NOT EXISTS index_magnets_user_id
            ON magnets(user_id);
            """
        )


# -----------------------------
# Reusable core logic
# -----------------------------

def sha512_text(value: str) -> str:
    return hashlib.sha512(value.encode("utf-8")).hexdigest()


def canonical_infohash(infohash: str) -> str:
    """Return a canonical lowercase hexadecimal BTIH for de-duplication."""
    infohash = infohash.strip()

    if re.fullmatch(r"[0-9a-fA-F]{40}", infohash):
        return infohash.lower()

    if re.fullmatch(r"[A-Z2-7a-z]{32}", infohash):
        return base64.b32decode(infohash.upper()).hex()

    return infohash.casefold()


def extract_infohash(magnet_link: str) -> str:
    magnet_link = magnet_link.strip()

    if not magnet_link.lower().startswith("magnet:?"):
        raise ValueError("The Magnet URI must start with magnet:?")

    query_parameters = parse_qs(urlparse(magnet_link).query)

    for exact_topic in query_parameters.get("xt", []):
        if not exact_topic.lower().startswith("urn:btih:"):
            continue

        infohash = exact_topic[9:]

        if re.fullmatch(r"[0-9a-fA-F]{40}", infohash):
            return infohash.lower()

        if re.fullmatch(r"[A-Z2-7a-z]{32}", infohash):
            return infohash.upper()

        raise ValueError("BTIH must be either 40 hexadecimal characters or 32 Base32 characters")

    raise ValueError("The Magnet URI is missing xt=urn:btih:...")


def longest_common_subsequence_score(search_text: str, candidate_text: str) -> float:
    """
    LCS fuzzy-search score.

    Score is based on how much of the search text can be found in order
    inside the candidate. 1.0 means the whole search text is a subsequence.
    Memory usage is O(min(m, n)).
    """
    search_text = search_text.casefold()
    candidate_text = candidate_text.casefold()

    if not search_text or not candidate_text:
        return 0.0

    if len(search_text) <= len(candidate_text):
        shorter_text = search_text
        longer_text = candidate_text
    else:
        shorter_text = candidate_text
        longer_text = search_text

    previous_row = [0] * (len(shorter_text) + 1)

    for longer_character in longer_text:
        current_row = [0]

        for column_index, shorter_character in enumerate(shorter_text, start=1):
            if longer_character == shorter_character:
                current_value = previous_row[column_index - 1] + 1
            else:
                current_value = max(
                    previous_row[column_index],
                    current_row[column_index - 1],
                )

            current_row.append(current_value)

        previous_row = current_row

    longest_length = previous_row[-1]
    return min(1.0, longest_length / len(search_text))


def require_logged_in_user(
    authorization: str | None = Header(default=None),
    database: sqlite3.Connection = Depends(get_database),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Please sign in first")

    raw_token = authorization.removeprefix("Bearer ").strip()
    token_hash = sha512_text(raw_token)

    session = database.execute(
        """
        SELECT
            login_sessions.expires_at,
            users.id,
            users.username,
            users.created_at
        FROM login_sessions
        JOIN users ON users.id = login_sessions.user_id
        WHERE login_sessions.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if session is None:
        raise HTTPException(status_code=401, detail="Invalid login session")

    expiration_time = datetime.fromisoformat(session["expires_at"])

    if expiration_time <= datetime.now(timezone.utc):
        database.execute(
            "DELETE FROM login_sessions WHERE token_hash = ?",
            (token_hash,),
        )
        database.commit()
        raise HTTPException(status_code=401, detail="Your login session has expired")

    return {
        "id": session["id"],
        "username": session["username"],
        "created_at": session["created_at"],
    }


# -----------------------------
# Request models
# -----------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_must_not_be_empty(cls, username: str):
        if not username.strip():
            raise ValueError("Username cannot be empty")
        return username.strip()

    @field_validator("password")
    @classmethod
    def password_must_not_be_empty(cls, password: str):
        if password == "":
            raise ValueError("Password cannot be empty")
        return password


class LoginRequest(BaseModel):
    username: str
    password: str


class MagnetRequest(BaseModel):
    title: str
    description: str = ""
    magnet: str

    @field_validator("title")
    @classmethod
    def title_must_not_be_empty(cls, title: str):
        if not title.strip():
            raise ValueError("Title cannot be empty")
        return title.strip()

    @field_validator("description")
    @classmethod
    def trim_description(cls, description: str):
        return description.strip()

    @field_validator("magnet")
    @classmethod
    def magnet_must_be_valid(cls, magnet: str):
        magnet = magnet.strip()
        extract_infohash(magnet)
        return magnet


# -----------------------------
# Embedded frontend
# -----------------------------

GLOBAL_STYLE = """
<style>
:root {
    --orange-primary: #ff5a00;
    --orange-dark: #b83200;
    --orange-soft: #ffb000;
    --page-background: #170900;
    --card-background: #241000;
    --card-background-soft: #321600;
    --border-color: #7a2c00;
    --text-main: #fff2df;
    --text-muted: #d7aa7a;
    --user-red: #e50000;
    --magnet-green: #159600;

    --bs-primary: var(--orange-primary);
    --bs-primary-rgb: 255, 90, 0;
    --bs-link-color: var(--orange-soft);
    --bs-link-hover-color: #ff6b00;
    --bs-body-bg: var(--page-background);
    --bs-body-color: var(--text-main);
    --bs-border-color: var(--border-color);
}

body {
    min-height: 100vh;
    background:
        radial-gradient(circle at top right, #451700 0, transparent 32rem),
        var(--page-background);
    color: var(--text-main);
}

.navbar,
.card,
.modal-content,
.dropdown-menu {
    background-color: var(--card-background) !important;
    border-color: var(--border-color) !important;
}

.form-control,
.form-select {
    color: var(--text-main);
    background-color: var(--card-background-soft);
    border-color: var(--border-color);
}

.form-control:focus,
.form-select:focus {
    color: var(--text-main);
    background-color: var(--card-background-soft);
    border-color: var(--orange-primary);
    box-shadow: 0 0 0 .25rem rgba(255, 90, 0, .25);
}

.form-control::placeholder {
    color: var(--text-muted);
}

.btn-primary {
    --bs-btn-bg: var(--orange-primary);
    --bs-btn-border-color: var(--orange-primary);
    --bs-btn-hover-bg: #d94800;
    --bs-btn-hover-border-color: #d94800;
    --bs-btn-active-bg: #b83200;
    --bs-btn-active-border-color: #b83200;
}

.btn-outline-primary {
    --bs-btn-color: #ff7a00;
    --bs-btn-border-color: #ff7a00;
    --bs-btn-hover-bg: #ff5a00;
    --bs-btn-hover-border-color: #ff5a00;
    --bs-btn-hover-color: #170900;
}

.text-secondary,
.form-text {
    color: var(--text-muted) !important;
}

.brand-mark {
    color: var(--orange-primary);
}

.result-user {
    border-left: .35rem solid var(--user-red) !important;
}

.result-magnet {
    border-left: .35rem solid var(--magnet-green) !important;
}

.badge-user {
    background: var(--user-red);
    color: white;
}

.badge-magnet {
    background: var(--magnet-green);
    color: white;
}

.user-link {
    color: #ff3b00;
    font-weight: 700;
    text-decoration: none;
}

.user-link:hover {
    color: #ff6a00;
}

.magnet-title {
    color: #43c000;
}

code {
    color: #ff9a00;
}

.table {
    --bs-table-bg: transparent;
    --bs-table-color: var(--text-main);
    --bs-table-border-color: var(--border-color);
}

.alert-custom {
    color: #fff0d6;
    background: #3a1500;
    border: 1px solid #8d3200;
}

.search-score {
    color: #ffad00;
}
</style>
"""

FRONTEND_JAVASCRIPT = """
<script>
const tokenStorageKey = "magnet_share_token";

async function apiRequest(url, options = {}) {
    const token = localStorage.getItem(tokenStorageKey);
    const requestHeaders = { ...(options.headers || {}) };

    if (token) {
        requestHeaders.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(url, {
        ...options,
        headers: requestHeaders
    });

    if (response.status === 204) {
        return null;
    }

    let responseData = null;

    try {
        responseData = await response.json();
    } catch {
        responseData = null;
    }

    if (!response.ok) {
        throw new Error(responseData?.detail || `HTTP ${response.status}`);
    }

    return responseData;
}

function createTextElement(tagName, text, className = "") {
    const element = document.createElement(tagName);
    element.textContent = text;

    if (className) {
        element.className = className;
    }

    return element;
}

async function loadCurrentUser() {
    if (!localStorage.getItem(tokenStorageKey)) {
        return null;
    }

    try {
        return await apiRequest("/api/auth/me");
    } catch {
        localStorage.removeItem(tokenStorageKey);
        return null;
    }
}

async function renderNavigation() {
    const navigation = document.getElementById("navigation");

    if (!navigation) {
        return;
    }

    const currentUser = await loadCurrentUser();
    navigation.replaceChildren();

    const homeLink = createTextElement("a", "Search", "btn btn-outline-primary btn-sm");
    homeLink.href = "/";
    navigation.appendChild(homeLink);

    const exportLink = createTextElement(
        "a",
        "Export TXT",
        "btn btn-outline-primary btn-sm"
    );
    exportLink.href = "/api/export/magnets";
    exportLink.download = "magnet-share-all.txt";
    navigation.appendChild(exportLink);

    if (!currentUser) {
        const loginLink = createTextElement("a", "Sign In", "btn btn-outline-primary btn-sm");
        loginLink.href = "/login";

        const registerLink = createTextElement("a", "Sign Up", "btn btn-primary btn-sm");
        registerLink.href = "/register";

        navigation.append(loginLink, registerLink);
        return;
    }

    const managementLink = createTextElement(
        "a",
        "My List",
        "btn btn-outline-primary btn-sm"
    );
    managementLink.href = "/me";

    const profileLink = createTextElement(
        "a",
        `@${currentUser.username}`,
        "btn btn-outline-primary btn-sm"
    );
    profileLink.href = `/user/${currentUser.id}`;

    const logoutButton = createTextElement(
        "button",
        "Sign Out",
        "btn btn-outline-primary btn-sm"
    );

    logoutButton.addEventListener("click", async () => {
        try {
            await apiRequest("/api/auth/logout", { method: "POST" });
        } catch {}

        localStorage.removeItem(tokenStorageKey);
        location.href = "/";
    });

    navigation.append(managementLink, profileLink, logoutButton);
}

function createMagnetCard(searchResult, allowDelete = false, onDeleted = null) {
    const magnet = searchResult.item || searchResult;
    const card = document.createElement("div");
    card.className = "card result-magnet shadow-sm mb-3";

    const cardBody = document.createElement("div");
    cardBody.className = "card-body";

    const badge = createTextElement("span", "Magnet", "badge badge-magnet mb-2");
    const title = createTextElement("h5", magnet.title, "card-title magnet-title");

    const ownerLine = document.createElement("div");
    ownerLine.className = "small text-secondary mb-2";
    ownerLine.append("Created by: ");

    const ownerLink = createTextElement("a", `@${magnet.username}`, "user-link");
    ownerLink.href = `/user/${magnet.user_id}`;
    ownerLine.appendChild(ownerLink);

    cardBody.append(badge, title, ownerLine);

    if (magnet.description) {
        cardBody.appendChild(
            createTextElement("p", magnet.description, "card-text")
        );
    }

    cardBody.appendChild(
        createTextElement(
            "div",
            `Infohash: ${magnet.infohash}`,
            "small text-secondary text-break"
        )
    );

    if (searchResult.score !== undefined) {
        cardBody.appendChild(
            createTextElement(
                "div",
                `LCS similarity ${(searchResult.score * 100).toFixed(2)}% · matched field ${searchResult.match_field}`,
                "small search-score mt-1"
            )
        );
    }

    const buttonArea = document.createElement("div");
    buttonArea.className = "d-flex flex-wrap gap-2 mt-3";

    const openLink = createTextElement("a", "Open Magnet", "btn btn-primary btn-sm");
    openLink.href = magnet.magnet;

    const copyButton = createTextElement(
        "button",
        "Copy Magnet",
        "btn btn-outline-primary btn-sm"
    );

    copyButton.addEventListener("click", async () => {
        await navigator.clipboard.writeText(magnet.magnet);
        copyButton.textContent = "Copied";
    });

    buttonArea.append(openLink, copyButton);

    if (allowDelete) {
        const deleteButton = createTextElement(
            "button",
            "Delete",
            "btn btn-outline-danger btn-sm"
        );

        deleteButton.addEventListener("click", async () => {
            if (!confirm(`Are you sure you want to delete "${magnet.title}"?`)) {
                return;
            }

            await apiRequest(`/api/magnets/${magnet.id}`, {
                method: "DELETE"
            });

            if (onDeleted) {
                await onDeleted();
            }
        });

        buttonArea.appendChild(deleteButton);
    }

    cardBody.appendChild(buttonArea);
    card.appendChild(cardBody);

    return card;
}
</script>
"""

NAVBAR_HTML = """
<nav class="navbar navbar-expand-lg border-bottom mb-4">
    <div class="container py-2">
        <a class="navbar-brand fw-bold text-light" href="/">
            <span class="brand-mark">🧲</span> Magnet Share
        </a>
        <div id="navigation" class="d-flex flex-wrap gap-2"></div>
    </div>
</nav>
"""


def build_html_page(title: str, page_content: str, page_script: str = "") -> str:
    """
    One useful frontend helper: every page shares the same Bootstrap import,
    orange-red theme, navigation and common JavaScript.
    """
    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <link
        href="{BOOTSTRAP_CSS}"
        rel="stylesheet"
        integrity="{BOOTSTRAP_CSS_INTEGRITY}"
        crossorigin="anonymous"
    >
    {GLOBAL_STYLE}
</head>
<body>
    {NAVBAR_HTML}
    {page_content}
    <script
        src="{BOOTSTRAP_JS}"
        integrity="{BOOTSTRAP_JS_INTEGRITY}"
        crossorigin="anonymous"
    ></script>
    {FRONTEND_JAVASCRIPT}
    <script>
        renderNavigation();
    </script>
    {page_script}
</body>
</html>"""


HOME_PAGE = build_html_page(
    "Search - Magnet Share",
    """
    <main class="container pb-5">
        <div class="card shadow-lg mb-4">
            <div class="card-body p-4">
                <h1 class="h3 mb-3">LCS Search</h1>
                <p class="text-secondary">
                    Search by username, Magnet URI, Infohash, or title.
                    <span class="badge badge-user">Red = User</span>
                    <span class="badge badge-magnet">Green = Magnet</span>
                </p>

                <div class="row g-2">
                    <div class="col-lg-8">
                        <input
                            id="searchText"
                            class="form-control"
                            placeholder="Enter a username, title, magnet:?xt=urn:btih:..., or infohash"
                        >
                    </div>

                    <div class="col-lg-2">
                        <select id="searchType" class="form-select">
                            <option value="all">All</option>
                            <option value="user">User</option>
                            <option value="magnet">Magnet</option>
                            <option value="title">Title</option>
                        </select>
                    </div>

                    <div class="col-lg-2 d-grid">
                        <button id="searchButton" class="btn btn-primary">
                            Search
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div id="searchResults"></div>
    </main>
    """,
    """
    <script>
    async function performSearch() {
        const searchText = document.getElementById("searchText").value.trim();
        const searchType = document.getElementById("searchType").value;
        const resultArea = document.getElementById("searchResults");

        if (!searchText) {
            resultArea.innerHTML =
                '<div class="alert alert-custom">Enter something to search for.</div>';
            return;
        }

        resultArea.innerHTML =
            '<div class="alert alert-custom">Calculating Longest Common Subsequence similarity...</div>';

        try {
            const result = await apiRequest(
                `/api/search?q=${encodeURIComponent(searchText)}&type=${searchType}`
            );

            resultArea.replaceChildren();

            if (!result.users.length && !result.magnets.length) {
                resultArea.innerHTML =
                    '<div class="alert alert-custom">No results found.</div>';
                return;
            }

            for (const userResult of result.users) {
                const userCard = document.createElement("div");
                userCard.className = "card result-user shadow-sm mb-3";

                const cardBody = document.createElement("div");
                cardBody.className = "card-body";

                const userBadge = createTextElement(
                    "span",
                    "User",
                    "badge badge-user mb-2"
                );

                const userLink = createTextElement(
                    "a",
                    `@${userResult.username}`,
                    "user-link fs-5 d-block mb-2"
                );
                userLink.href = `/user/${userResult.user_id}`;

                const details = createTextElement(
                    "div",
                    `${userResult.magnet_count}  magnets · LCS similarity ${(userResult.score * 100).toFixed(2)}%`,
                    "small text-secondary"
                );

                cardBody.append(userBadge, userLink, details);
                userCard.appendChild(cardBody);
                resultArea.appendChild(userCard);
            }

            for (const magnetResult of result.magnets) {
                resultArea.appendChild(createMagnetCard(magnetResult));
            }
        } catch (error) {
            resultArea.innerHTML =
                `<div class="alert alert-danger">${error.message}</div>`;
        }
    }

    document.getElementById("searchButton").addEventListener(
        "click",
        performSearch
    );

    document.getElementById("searchText").addEventListener(
        "keydown",
        event => {
            if (event.key === "Enter") {
                performSearch();
            }
        }
    );
    </script>
    """,
)


LOGIN_PAGE = build_html_page(
    "Sign In - Magnet Share",
    """
    <main class="container" style="max-width: 560px">
        <div class="card shadow-lg">
            <div class="card-body p-4">
                <h1 class="h3 mb-4">Sign In</h1>

                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input
                        id="username"
                        class="form-control"
                        autocomplete="username"
                    >
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input
                        id="password"
                        type="password"
                        class="form-control"
                        autocomplete="current-password"
                    >
                </div>

                <div class="d-grid gap-2">
                    <button id="loginButton" class="btn btn-primary">
                        Sign In
                    </button>
                    <a href="/register" class="btn btn-outline-primary">
                        No account? Sign up
                    </a>
                </div>

                <div id="loginMessage" class="mt-3"></div>
            </div>
        </div>
    </main>
    """,
    """
    <script>
    document.getElementById("loginButton").addEventListener(
        "click",
        async () => {
            const loginMessage = document.getElementById("loginMessage");
            loginMessage.textContent = "Signing in...";

            try {
                const result = await apiRequest("/api/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        username: document.getElementById("username").value,
                        password: document.getElementById("password").value
                    })
                });

                localStorage.setItem(tokenStorageKey, result.token);
                location.href = "/me";
            } catch (error) {
                loginMessage.innerHTML =
                    `<div class="alert alert-danger">${error.message}</div>`;
            }
        }
    );
    </script>
    """,
)


REGISTER_PAGE = build_html_page(
    "Sign Up - Magnet Share",
    """
    <main class="container" style="max-width: 560px">
        <div class="card shadow-lg">
            <div class="card-body p-4">
                <h1 class="h3 mb-3">Sign Up</h1>

                <div class="alert alert-custom">
                    Username and password have no application-level maximum length. Passwords use unsalted
                    SHA-512 storage, as requested by this project.
                </div>

                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input
                        id="username"
                        class="form-control"
                        autocomplete="username"
                    >
                </div>

                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input
                        id="password"
                        type="password"
                        class="form-control"
                        autocomplete="new-password"
                    >
                </div>

                <div class="d-grid gap-2">
                    <button id="registerButton" class="btn btn-primary">
                        Create Account
                    </button>
                    <a href="/login" class="btn btn-outline-primary">
                        Already have an account? Sign in
                    </a>
                </div>

                <div id="registerMessage" class="mt-3"></div>
            </div>
        </div>
    </main>
    """,
    """
    <script>
    document.getElementById("registerButton").addEventListener(
        "click",
        async () => {
            const registerMessage =
                document.getElementById("registerMessage");
            registerMessage.textContent = "Creating account...";

            try {
                const result = await apiRequest("/api/auth/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        username: document.getElementById("username").value,
                        password: document.getElementById("password").value
                    })
                });

                localStorage.setItem(tokenStorageKey, result.token);
                location.href = "/me";
            } catch (error) {
                registerMessage.innerHTML =
                    `<div class="alert alert-danger">${error.message}</div>`;
            }
        }
    );
    </script>
    """,
)


MANAGEMENT_PAGE = build_html_page(
    "My List - Magnet Share",
    """
    <main class="container pb-5">
        <div class="row g-4">
            <div class="col-lg-5">
                <div class="card shadow-lg">
                    <div class="card-body p-4">
                        <h1 class="h3">Create Magnet</h1>
                        <p id="currentUserName" class="text-secondary"></p>

                        <div class="mb-3">
                            <label for="magnetTitle" class="form-label">
                                Title
                            </label>
                            <input id="magnetTitle" class="form-control">
                        </div>

                        <div class="mb-3">
                            <label for="magnetDescription" class="form-label">
                                Description
                            </label>
                            <textarea
                                id="magnetDescription"
                                class="form-control"
                                rows="4"
                            ></textarea>
                        </div>

                        <div class="mb-3">
                            <label for="magnetLink" class="form-label">
                                Magnet
                            </label>
                            <textarea
                                id="magnetLink"
                                class="form-control"
                                rows="5"
                                placeholder="magnet:?xt=urn:btih:..."
                            ></textarea>
                        </div>

                        <button id="createMagnetButton" class="btn btn-primary">
                            Create
                        </button>

                        <div id="createMessage" class="mt-3"></div>
                    </div>
                </div>
            </div>

            <div class="col-lg-7">
                <h2 class="h4 mb-3">My Magnets</h2>
                <div id="myMagnetList"></div>
            </div>
        </div>
    </main>
    """,
    """
    <script>
    async function loadMyMagnets() {
        const magnetList = document.getElementById("myMagnetList");
        magnetList.innerHTML =
            '<div class="alert alert-custom">Loading...</div>';

        try {
            const magnets = await apiRequest("/api/magnets/mine");
            magnetList.replaceChildren();

            if (!magnets.length) {
                magnetList.innerHTML =
                    '<div class="alert alert-custom">You have not created any magnets yet.</div>';
                return;
            }

            for (const magnet of magnets) {
                magnetList.appendChild(
                    createMagnetCard(
                        magnet,
                        true,
                        loadMyMagnets
                    )
                );
            }
        } catch (error) {
            magnetList.innerHTML =
                `<div class="alert alert-danger">${error.message}</div>`;
        }
    }

    (async () => {
        const currentUser = await loadCurrentUser();

        if (!currentUser) {
            location.href = "/login";
            return;
        }

        document.getElementById("currentUserName").textContent =
            `Current account: @${currentUser.username}`;

        await loadMyMagnets();
    })();

    document.getElementById("createMagnetButton").addEventListener(
        "click",
        async () => {
            const createMessage = document.getElementById("createMessage");
            createMessage.textContent = "Creating...";

            try {
                await apiRequest("/api/magnets", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        title: document.getElementById("magnetTitle").value,
                        description:
                            document.getElementById("magnetDescription").value,
                        magnet: document.getElementById("magnetLink").value
                    })
                });

                document.getElementById("magnetTitle").value = "";
                document.getElementById("magnetDescription").value = "";
                document.getElementById("magnetLink").value = "";

                createMessage.innerHTML =
                    '<div class="alert alert-success">Created successfully.</div>';

                await loadMyMagnets();
            } catch (error) {
                createMessage.innerHTML =
                    `<div class="alert alert-danger">${error.message}</div>`;
            }
        }
    );
    </script>
    """,
)


USER_PAGE = build_html_page(
    "User Profile - Magnet Share",
    """
    <main class="container pb-5">
        <div class="card result-user shadow-lg mb-4">
            <div class="card-body p-4">
                <span class="badge badge-user mb-2">User</span>
                <h1 id="profileName" class="h3"></h1>
                <div id="profileInformation" class="text-secondary"></div>
            </div>
        </div>

        <h2 class="h4 mb-3">All Magnets Created by This User</h2>
        <div id="profileMagnets"></div>
    </main>
    """,
    """
    <script>
    (async () => {
        const pathParts = location.pathname.split("/").filter(Boolean);
        const userId = Number(pathParts[pathParts.length - 1]);
        const profileMagnets = document.getElementById("profileMagnets");

        try {
            const user = await apiRequest(`/api/users/${userId}`);
            const magnets = await apiRequest(`/api/users/${userId}/magnets`);
            const currentUser = await loadCurrentUser();

            document.getElementById("profileName").textContent =
                `@${user.username}`;

            document.getElementById("profileInformation").textContent =
                `Joined: ${new Date(user.created_at).toLocaleString()}`;

            profileMagnets.replaceChildren();

            if (!magnets.length) {
                profileMagnets.innerHTML =
                    '<div class="alert alert-custom">This user has not created any magnets yet.</div>';
                return;
            }

            const allowDelete =
                currentUser !== null && currentUser.id === user.id;

            for (const magnet of magnets) {
                profileMagnets.appendChild(
                    createMagnetCard(
                        magnet,
                        allowDelete,
                        async () => location.reload()
                    )
                );
            }
        } catch (error) {
            profileMagnets.innerHTML =
                `<div class="alert alert-danger">${error.message}</div>`;
        }
    })();
    </script>
    """,
)


# -----------------------------
# Page routes
# -----------------------------

page_router = APIRouter()


@page_router.get("/", response_class=HTMLResponse, include_in_schema=False)
def search_page():
    return HOME_PAGE


@page_router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page():
    return LOGIN_PAGE


@page_router.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page():
    return REGISTER_PAGE


@page_router.get("/me", response_class=HTMLResponse, include_in_schema=False)
def management_page():
    return MANAGEMENT_PAGE


@page_router.get(
    "/user/{user_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def user_page(user_id: int):
    return USER_PAGE


# -----------------------------
# Authentication API routes
# -----------------------------

auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@auth_router.post("/register")
def register(
    request: RegisterRequest,
    database: sqlite3.Connection = Depends(get_database),
):
    existing_user = database.execute(
        "SELECT id FROM users WHERE username = ?",
        (request.username,),
    ).fetchone()

    if existing_user is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    created_at = datetime.now(timezone.utc).isoformat()

    cursor = database.execute(
        """
        INSERT INTO users (username, password_hash, created_at)
        VALUES (?, ?, ?)
        """,
        (
            request.username,
            sha512_text(request.password),
            created_at,
        ),
    )

    user_id = cursor.lastrowid
    raw_token = secrets.token_urlsafe(48)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=30)
    ).isoformat()

    database.execute(
        """
        INSERT INTO login_sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
        """,
        (
            sha512_text(raw_token),
            user_id,
            expires_at,
        ),
    )
    database.commit()

    return {
        "token": raw_token,
        "user": {
            "id": user_id,
            "username": request.username,
            "created_at": created_at,
        },
    }


@auth_router.post("/login")
def login(
    request: LoginRequest,
    database: sqlite3.Connection = Depends(get_database),
):
    user = database.execute(
        """
        SELECT id, username, password_hash, created_at
        FROM users
        WHERE username = ?
        """,
        (request.username.strip(),),
    ).fetchone()

    if user is None or user["password_hash"] != sha512_text(request.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    raw_token = secrets.token_urlsafe(48)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=30)
    ).isoformat()

    database.execute(
        """
        INSERT INTO login_sessions (token_hash, user_id, expires_at)
        VALUES (?, ?, ?)
        """,
        (
            sha512_text(raw_token),
            user["id"],
            expires_at,
        ),
    )
    database.commit()

    return {
        "token": raw_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "created_at": user["created_at"],
        },
    }


@auth_router.get("/me")
def current_user(user=Depends(require_logged_in_user)):
    return user


@auth_router.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
    database: sqlite3.Connection = Depends(get_database),
):
    if authorization and authorization.startswith("Bearer "):
        raw_token = authorization.removeprefix("Bearer ").strip()

        database.execute(
            "DELETE FROM login_sessions WHERE token_hash = ?",
            (sha512_text(raw_token),),
        )
        database.commit()

    return {"ok": True}


# -----------------------------
# Magnet API routes
# -----------------------------

magnet_router = APIRouter(prefix="/api/magnets", tags=["Magnets"])


@magnet_router.post("")
def create_magnet(
    request: MagnetRequest,
    user=Depends(require_logged_in_user),
    database: sqlite3.Connection = Depends(get_database),
):
    infohash = extract_infohash(request.magnet)

    existing_magnet = database.execute(
        """
        SELECT id
        FROM magnets
        WHERE user_id = ? AND infohash = ?
        """,
        (user["id"], infohash),
    ).fetchone()

    if existing_magnet is not None:
        raise HTTPException(
            status_code=409,
            detail="You have already created this magnet",
        )

    created_at = datetime.now(timezone.utc).isoformat()

    cursor = database.execute(
        """
        INSERT INTO magnets (
            title,
            description,
            magnet,
            infohash,
            user_id,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request.title,
            request.description,
            request.magnet,
            infohash,
            user["id"],
            created_at,
        ),
    )
    database.commit()

    return {
        "id": cursor.lastrowid,
        "title": request.title,
        "description": request.description,
        "magnet": request.magnet,
        "infohash": infohash,
        "user_id": user["id"],
        "username": user["username"],
        "created_at": created_at,
    }


@magnet_router.get("/mine")
def my_magnets(
    user=Depends(require_logged_in_user),
    database: sqlite3.Connection = Depends(get_database),
):
    magnet_rows = database.execute(
        """
        SELECT
            magnets.id,
            magnets.title,
            magnets.description,
            magnets.magnet,
            magnets.infohash,
            magnets.user_id,
            magnets.created_at,
            users.username
        FROM magnets
        JOIN users ON users.id = magnets.user_id
        WHERE magnets.user_id = ?
        ORDER BY magnets.id DESC
        """,
        (user["id"],),
    ).fetchall()

    return [dict(row) for row in magnet_rows]


@magnet_router.delete("/{magnet_id}", status_code=204)
def delete_magnet(
    magnet_id: int,
    user=Depends(require_logged_in_user),
    database: sqlite3.Connection = Depends(get_database),
):
    magnet = database.execute(
        "SELECT id, user_id FROM magnets WHERE id = ?",
        (magnet_id,),
    ).fetchone()

    if magnet is None:
        raise HTTPException(status_code=404, detail="Magnet not found")

    if magnet["user_id"] != user["id"]:
        raise HTTPException(
            status_code=403,
            detail="You can only delete magnets that you created",
        )

    database.execute(
        "DELETE FROM magnets WHERE id = ?",
        (magnet_id,),
    )
    database.commit()

    return None


# -----------------------------
# User API routes
# -----------------------------

user_router = APIRouter(prefix="/api/users", tags=["Users"])


@user_router.get("/{user_id}")
def get_user(
    user_id: int,
    database: sqlite3.Connection = Depends(get_database),
):
    user = database.execute(
        """
        SELECT id, username, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return dict(user)


@user_router.get("/{user_id}/magnets")
def get_user_magnets(
    user_id: int,
    database: sqlite3.Connection = Depends(get_database),
):
    user = database.execute(
        "SELECT id FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    magnet_rows = database.execute(
        """
        SELECT
            magnets.id,
            magnets.title,
            magnets.description,
            magnets.magnet,
            magnets.infohash,
            magnets.user_id,
            magnets.created_at,
            users.username
        FROM magnets
        JOIN users ON users.id = magnets.user_id
        WHERE magnets.user_id = ?
        ORDER BY magnets.id DESC
        """,
        (user_id,),
    ).fetchall()

    return [dict(row) for row in magnet_rows]


# -----------------------------
# Export API route
# -----------------------------

export_router = APIRouter(prefix="/api/export", tags=["Export"])


@export_router.get("/magnets", response_class=PlainTextResponse)
def export_all_magnets(
    database: sqlite3.Connection = Depends(get_database),
):
    """Export all unique Magnet URIs as a plain-text file."""
    magnet_rows = database.execute(
        """
        SELECT id, magnet, infohash
        FROM magnets
        ORDER BY id ASC
        """
    ).fetchall()

    exported_magnets = []
    seen_infohashes = set()

    for magnet_row in magnet_rows:
        normalized_infohash = canonical_infohash(magnet_row["infohash"])

        if normalized_infohash in seen_infohashes:
            continue

        seen_infohashes.add(normalized_infohash)
        exported_magnets.append(magnet_row["magnet"].strip())

    file_content = "\n".join(exported_magnets)

    if file_content:
        file_content += "\n"

    return PlainTextResponse(
        content=file_content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition":
                'attachment; filename="magnet-share-all.txt"'
        },
    )


# -----------------------------
# Search API route
# -----------------------------

search_router = APIRouter(prefix="/api/search", tags=["Search"])


@search_router.get("")
def search(
    q: str = Query(min_length=1, max_length=4096),
    type: str = Query(default="all", pattern="^(all|user|magnet|title)$"),
    database: sqlite3.Connection = Depends(get_database),
):
    search_text = q.strip()

    user_results = []
    magnet_results = []

    if type in {"all", "user"}:
        user_rows = database.execute(
            """
            SELECT
                users.id,
                users.username,
                COUNT(magnets.id) AS magnet_count
            FROM users
            LEFT JOIN magnets ON magnets.user_id = users.id
            GROUP BY users.id
            """
        ).fetchall()

        for user_row in user_rows:
            score = longest_common_subsequence_score(
                search_text,
                user_row["username"],
            )

            if score == 0:
                continue

            user_results.append(
                {
                    "user_id": user_row["id"],
                    "username": user_row["username"],
                    "magnet_count": user_row["magnet_count"],
                    "score": round(score, 6),
                }
            )

        user_results.sort(
            key=lambda item: (-item["score"], item["username"].casefold())
        )

    if type in {"all", "magnet", "title"}:
        magnet_rows = database.execute(
            """
            SELECT
                magnets.id,
                magnets.title,
                magnets.description,
                magnets.magnet,
                magnets.infohash,
                magnets.user_id,
                magnets.created_at,
                users.username
            FROM magnets
            JOIN users ON users.id = magnets.user_id
            """
        ).fetchall()

        for magnet_row in magnet_rows:
            searchable_fields = []

            if type in {"all", "title"}:
                searchable_fields.append(("title", magnet_row["title"]))

            if type in {"all", "magnet"}:
                searchable_fields.append(("magnet", magnet_row["magnet"]))
                searchable_fields.append(("infohash", magnet_row["infohash"]))

            best_field = ""
            best_score = 0.0

            for field_name, field_value in searchable_fields:
                field_score = longest_common_subsequence_score(
                    search_text,
                    field_value,
                )

                if field_score > best_score:
                    best_score = field_score
                    best_field = field_name

            if best_score == 0:
                continue

            magnet_results.append(
                {
                    "score": round(best_score, 6),
                    "match_field": best_field,
                    "item": dict(magnet_row),
                }
            )

        magnet_results.sort(
            key=lambda item: (
                -item["score"],
                item["item"]["title"].casefold(),
            )
        )

    return {
        "users": user_results[:50],
        "magnets": magnet_results[:50],
    }


# -----------------------------
# Application
# -----------------------------

initialize_database()

app = FastAPI(
    title="Magnet Share",
    version="1.0.0",
    description="Single-file FastAPI + SQLite magnet index.",
)

app.include_router(page_router)
app.include_router(auth_router)
app.include_router(magnet_router)
app.include_router(user_router)
app.include_router(export_router)
app.include_router(search_router)


if __name__ == "__main__":
    print('❤️ If you find this project useful or support open and P2P technologies such as BitTorrent / Magnet, voluntary sponsorships are welcome.')
    print('₿ Bitcoin (BTC): bc1qxqfhumpqtnxrznkx9r4xsp8m6zsedtgusjns7p')
    print('Ł Litecoin (LTC): ltc1qx60jqksl8pa38zmqjxau0vy04rqpjgfpn0xgw3')
    print('◆ Ethereum (ETH): 0x2d92f9e4d8ac7effa9cd7cd5eccd364cac7c201b')
    print()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
    )
