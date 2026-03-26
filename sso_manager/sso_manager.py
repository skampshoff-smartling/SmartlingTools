import os
import pathlib
import secrets
from functools import wraps

import requests
from flask import Flask, Response, jsonify, render_template_string, request, session

app = Flask(__name__)

_key_file = pathlib.Path(__file__).with_name(".sso_secret_key")
if _key_file.exists():
    app.secret_key = _key_file.read_text().strip()
else:
    app.secret_key = secrets.token_hex(32)
    _key_file.write_text(app.secret_key)

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE = "https://api.smartling.com"
AUTH_URL = f"{BASE}/auth-api/v2/authenticate/user"
IDP_BASE = f"{BASE}/idp-api/v2"


_BASIC_AUTH_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")

def require_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not _BASIC_AUTH_PASSWORD:
            return f(*args, **kwargs)  # skip if no password configured
        if not auth or auth.password != _BASIC_AUTH_PASSWORD:
            return Response(
                "Unauthorized", 401,
                {"WWW-Authenticate": 'Basic realm="SSO Manager"'}
            )
        return f(*args, **kwargs)
    return decorated


def get_token():
    return request.headers.get("X-Access-Token") or session.get("access_token")


def api_call(method, url, **kwargs):
    try:
        resp = requests.request(
            method, url,
            headers={"Authorization": f"Bearer {get_token()}"},
            **kwargs,
        )
        try:
            return resp.json(), resp.status_code
        except ValueError:
            return {"error": resp.text}, resp.status_code
    except requests.RequestException as e:
        return {"error": str(e)}, 500


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Smartling SSO Manager</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: sans-serif; background: #f4f4f5; min-height: 100vh; }

    /* Auth overlay */
    #auth-overlay {
      position: fixed; inset: 0; background: #f4f4f5;
      display: flex; align-items: center; justify-content: center; z-index: 100;
    }
    #auth-overlay.hidden { display: none; }
    .auth-card {
      background: white; border-radius: 8px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.12); padding: 32px; width: 420px;
    }
    .auth-card h1 { font-size: 1.2rem; font-weight: 700; margin-bottom: 6px; color: #111; }
    .auth-card p { font-size: 0.8rem; color: #6b7280; margin-bottom: 24px; }
    .auth-error { color: #dc2626; font-size: 0.8rem; margin-top: 10px; display: none; }

    /* Main app */
    #main { display: none; min-height: 100vh; }
    #main.visible { display: block; }
    .topbar {
      background: #6366f1; color: white; padding: 12px 24px;
      display: flex; align-items: center; justify-content: space-between;
    }
    .topbar h1 { font-size: 1rem; font-weight: 600; }
    .topbar-right { display: flex; align-items: center; gap: 14px; }
    .topbar-user { font-size: 0.8rem; opacity: 0.85; }
    .topbar-btn {
      background: rgba(255,255,255,0.18); border: none; color: white;
      padding: 5px 14px; border-radius: 4px; cursor: pointer; font-size: 0.8rem;
    }
    .topbar-btn:hover { background: rgba(255,255,255,0.28); }

    /* Tabs */
    .tabs {
      background: white; border-bottom: 1px solid #e5e7eb;
      padding: 0 24px; display: flex;
    }
    .tab-btn {
      padding: 13px 18px; border: none; background: none; cursor: pointer;
      font-size: 0.875rem; font-weight: 500; color: #6b7280;
      border-bottom: 2px solid transparent; margin-bottom: -1px;
    }
    .tab-btn:hover { color: #374151; }
    .tab-btn.active { color: #6366f1; border-bottom-color: #6366f1; }

    /* Content */
    .content { padding: 24px; max-width: 1100px; margin: 0 auto; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    /* Accordion sections */
    .section {
      background: white; border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 12px; overflow: hidden;
    }
    .section-hdr {
      padding: 13px 18px; cursor: pointer; display: flex;
      align-items: center; justify-content: space-between;
      user-select: none;
    }
    .section-hdr:hover { background: #fafafa; }
    .section-hdr-left { display: flex; align-items: center; gap: 10px; }
    .section-hdr h3 { font-size: 0.875rem; font-weight: 600; color: #374151; }
    .method-badge {
      font-size: 0.68rem; font-weight: 700; padding: 2px 7px;
      border-radius: 3px; font-family: monospace; white-space: nowrap;
    }
    .badge-get  { background: #d1fae5; color: #065f46; }
    .badge-post { background: #dbeafe; color: #1e40af; }
    .badge-del  { background: #fee2e2; color: #991b1b; }
    .chevron { color: #9ca3af; font-size: 0.75rem; transition: transform 0.18s; }
    .chevron.open { transform: rotate(180deg); }
    .section-body { padding: 18px 20px; display: none; }
    .section-body.open { display: block; }

    /* Form elements */
    label {
      display: block; font-size: 0.8rem; font-weight: 600;
      color: #374151; margin-bottom: 4px;
    }
    label .opt { font-weight: 400; color: #9ca3af; font-size: 0.75rem; }
    input[type="text"], input[type="password"], select, textarea {
      width: 100%; padding: 7px 10px; border: 1px solid #d1d5db;
      border-radius: 5px; font-size: 0.85rem; margin-bottom: 13px;
      background: white; font-family: inherit;
    }
    input:focus, select:focus, textarea:focus {
      outline: none; border-color: #6366f1;
      box-shadow: 0 0 0 2px rgba(99,102,241,0.15);
    }
    textarea { resize: vertical; min-height: 80px; font-family: monospace; font-size: 0.8rem; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .two-col > div { display: flex; flex-direction: column; }
    .two-col > div input,
    .two-col > div select { margin-bottom: 0; }
    .two-col { margin-bottom: 13px; }

    /* Buttons */
    .btn {
      padding: 8px 18px; border: none; border-radius: 5px;
      font-size: 0.85rem; font-weight: 600; cursor: pointer;
    }
    .btn-primary { background: #6366f1; color: white; }
    .btn-primary:hover { background: #4f46e5; }
    .btn-danger { background: #ef4444; color: white; }
    .btn-danger:hover { background: #dc2626; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }

    /* Auth form button (full-width) */
    .btn-auth {
      width: 100%; padding: 10px; background: #6366f1; color: white;
      border: none; border-radius: 6px; font-size: 0.9rem; font-weight: 600; cursor: pointer;
    }
    .btn-auth:hover { background: #4f46e5; }
    .btn-auth:disabled { opacity: 0.6; cursor: not-allowed; }

    /* Auth form fields */
    .auth-field { margin-bottom: 16px; }
    .auth-field label { display: block; font-size: 0.8rem; font-weight: 600; color: #374151; margin-bottom: 4px; }
    .auth-field input {
      width: 100%; padding: 8px 12px; border: 1px solid #d1d5db;
      border-radius: 6px; font-size: 0.9rem;
    }
    .auth-field input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 2px rgba(99,102,241,0.2); }

    /* Result box */
    .result-box { margin-top: 14px; border-radius: 6px; overflow: hidden; border: 1px solid #e5e7eb; display: none; }
    .result-box.visible { display: block; }
    .result-hdr {
      padding: 7px 13px; font-size: 0.75rem; font-weight: 600;
      display: flex; align-items: center; gap: 6px;
    }
    .result-hdr.ok  { background: #f0fdf4; color: #15803d; border-bottom: 1px solid #bbf7d0; }
    .result-hdr.err { background: #fef2f2; color: #b91c1c; border-bottom: 1px solid #fecaca; }
    .result-hdr.loading { background: #f9fafb; color: #6b7280; border-bottom: 1px solid #e5e7eb; }
    .result-body {
      background: #f9fafb; padding: 13px; font-family: monospace;
      font-size: 0.78rem; line-height: 1.55; white-space: pre-wrap;
      word-break: break-all; max-height: 320px; overflow-y: auto;
    }

    /* Description text */
    .desc { font-size: 0.8rem; color: #6b7280; margin-bottom: 14px; }

    /* Dynamic account rows */
    .account-row {
      border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px 12px 0;
      margin-bottom: 10px; position: relative;
    }
    .account-row .rm-row {
      position: absolute; top: 8px; right: 10px; background: none; border: none;
      color: #9ca3af; cursor: pointer; font-size: 1rem; line-height: 1; padding: 0;
    }
    .account-row .rm-row:hover { color: #ef4444; }
    .add-row-btn {
      background: none; border: 1px dashed #d1d5db; border-radius: 5px;
      color: #6b7280; padding: 7px; font-size: 0.8rem; cursor: pointer;
      width: 100%; margin-bottom: 13px;
    }
    .add-row-btn:hover { border-color: #6366f1; color: #6366f1; }

    hr.divider { border: none; border-top: 1px solid #f3f4f6; margin: 14px 0; }

    /* Table layout */
    .table-section-hdr {
      padding: 13px 18px; display: flex; align-items: center;
      justify-content: space-between; border-bottom: 1px solid #f3f4f6;
    }
    .table-section-hdr h3 { font-size: 0.875rem; font-weight: 600; color: #374151; }
    .table-wrapper { overflow-x: auto; }
    .provider-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
    .provider-table th {
      text-align: left; padding: 8px 14px; background: #f9fafb;
      border-bottom: 2px solid #e5e7eb; font-size: 0.74rem; font-weight: 600;
      color: #6b7280; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap;
    }
    .provider-table td { padding: 10px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }
    .provider-table tbody tr:last-child td { border-bottom: none; }
    .provider-table .col-trunc { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .status-on  { display:inline-block; background:#d1fae5; color:#065f46; padding:2px 8px; border-radius:9999px; font-size:0.75rem; font-weight:600; }
    .status-off { display:inline-block; background:#f3f4f6; color:#6b7280; padding:2px 8px; border-radius:9999px; font-size:0.75rem; font-weight:600; }
    .btn-sm { padding:4px 10px; font-size:0.78rem; font-weight:600; border:none; border-radius:4px; cursor:pointer; }
    .btn-edit { background:#e0e7ff; color:#4338ca; }
    .btn-edit:hover { background:#c7d2fe; }
    .btn-del-sm { background:#fee2e2; color:#b91c1c; margin-left:5px; }
    .btn-del-sm:hover { background:#fecaca; }
    .btn-refresh { background:#f3f4f6; color:#374151; border:1px solid #e5e7eb; }
    .btn-refresh:hover { background:#e5e7eb; }
    .btn-secondary { background:#f3f4f6; color:#374151; border:1px solid #e5e7eb; }
    .btn-secondary:hover { background:#e5e7eb; }
    .btn-create { background:#6366f1; color:white; }
    .btn-create:hover { background:#4f46e5; }

    /* Filter input */
    input.filter-input {
      padding:5px 10px; border:1px solid #d1d5db; border-radius:5px;
      font-size:0.82rem; width:200px; margin-bottom:0;
    }
    input.filter-input:focus { outline:none; border-color:#6366f1; box-shadow:0 0 0 2px rgba(99,102,241,0.15); }

    /* Modal */
    .modal-overlay {
      position:fixed; inset:0; background:rgba(0,0,0,0.45); z-index:200;
      display:flex; align-items:center; justify-content:center;
    }
    .modal-overlay.hidden { display:none; }
    .modal-card {
      background:white; border-radius:8px; box-shadow:0 4px 24px rgba(0,0,0,0.18);
      width:620px; max-width:calc(100vw - 32px); max-height:calc(100vh - 64px);
      display:flex; flex-direction:column; overflow:hidden;
    }
    .modal-hdr {
      padding:15px 20px; border-bottom:1px solid #e5e7eb;
      display:flex; align-items:center; justify-content:space-between; flex-shrink:0;
    }
    .modal-hdr h2 { font-size:1rem; font-weight:600; color:#111; }
    .modal-close {
      background:none; border:none; font-size:1.1rem; color:#6b7280;
      cursor:pointer; padding:2px 7px; border-radius:4px; line-height:1;
    }
    .modal-close:hover { background:#f3f4f6; color:#374151; }
    .modal-body { padding:20px; overflow-y:auto; }
    .modal-footer { padding:12px 20px; border-top:1px solid #e5e7eb; display:flex; gap:8px; align-items:center; }
    .empty-cell { text-align:center; color:#9ca3af; padding:28px !important; font-size:0.85rem; }
    .edit-row > td { padding:0 !important; background:#f8f7ff; }
    .inline-form { padding:16px 18px; border-left:3px solid #6366f1; }
    .inline-actions { display:flex; align-items:flex-start; gap:8px; margin-top:4px; flex-wrap:wrap; }
    .inline-actions .result-box { flex:1; min-width:200px; margin-top:0; }
  </style>
</head>
<body>

<!-- ===== AUTH OVERLAY ===== -->
<div id="auth-overlay">
  <div class="auth-card">
    <h1>Smartling SSO Manager</h1>
    <p>Sign in with your Smartling API credentials to continue.</p>
    <div class="auth-field">
      <label>User Identifier</label>
      <input type="text" id="auth-id" autocomplete="off">
    </div>
    <div class="auth-field">
      <label>User Secret</label>
      <input type="password" id="auth-secret">
    </div>
    <button class="btn-auth" id="auth-btn" onclick="doAuth()">Sign In</button>
    <div class="auth-error" id="auth-error"></div>
  </div>
</div>

<!-- ===== MAIN APP ===== -->
<div id="main">
  <div class="topbar">
    <h1>Smartling SSO Manager</h1>
    <div class="topbar-right">
      <span class="topbar-user" id="topbar-user"></span>
      <button class="topbar-btn" onclick="doLogout()">Sign Out</button>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('oidc',this)">OIDC</button>
    <button class="tab-btn" onclick="switchTab('saml',this)">SAML</button>
    <button class="tab-btn" onclick="switchTab('users',this)">Users</button>
    <button class="tab-btn" onclick="switchTab('autoreg',this)">Auto-Registration</button>
    <button class="tab-btn" onclick="switchTab('domains',this)">Domains</button>
  </div>

  <div class="content">

    <!-- ========== OIDC TAB ========== -->
    <div class="tab-panel active" id="tab-oidc">

      <div class="section">
        <div class="table-section-hdr">
          <input type="text" class="filter-input" placeholder="Filter by alias…" oninput="filterOidcTable(this.value)">
          <div style="display:flex;gap:6px;">
            <button class="btn-sm btn-create" onclick="openModal('modal-oidc-create')">+ Create</button>
            <button class="btn-sm btn-refresh" onclick="loadOidcList()">&#8635; Refresh</button>
          </div>
        </div>
        <div class="table-wrapper">
          <table class="provider-table">
            <thead>
              <tr>
                <th>Alias</th>
                <th>Enabled</th>
                <th>Client ID</th>
                <th>Issuer</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="oidc-tbody">
              <tr><td colspan="5" class="empty-cell">Loading…</td></tr>
            </tbody>
          </table>
        </div>
      </div>

    </div><!-- /tab-oidc -->

    <!-- ========== SAML TAB ========== -->
    <div class="tab-panel" id="tab-saml">

      <div class="section">
        <div class="table-section-hdr">
          <input type="text" class="filter-input" placeholder="Filter by alias…" oninput="filterSamlTable(this.value)">
          <div style="display:flex;gap:6px;">
            <button class="btn-sm btn-create" onclick="openModal('modal-saml-create')">+ Create</button>
            <button class="btn-sm btn-refresh" onclick="loadSamlList()">&#8635; Refresh</button>
          </div>
        </div>
        <div class="table-wrapper">
          <table class="provider-table">
            <thead>
              <tr>
                <th>Alias</th>
                <th>Enabled</th>
                <th>SSO URL</th>
                <th>Name ID Format</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="saml-tbody">
              <tr><td colspan="5" class="empty-cell">Click Refresh to load providers.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

    </div><!-- /tab-saml -->

    <!-- ========== USERS TAB ========== -->
    <div class="tab-panel" id="tab-users">

      <!-- Remove user link -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-del">DELETE</span>
            <h3>Remove Identity Provider Link for User</h3>
          </div>
          <span class="chevron open">▼</span>
        </div>
        <div class="section-body open">
          <p class="desc">Removes any association that a user has with the given identity provider.</p>
          <div class="two-col">
            <div>
              <label>Account UID</label>
              <input type="text" id="user-rm-account">
            </div>
            <div>
              <label>IDP Alias</label>
              <input type="text" id="user-rm-alias">
            </div>
          </div>
          <label>User Email</label>
          <input type="text" id="user-rm-email">
          <button class="btn btn-danger" onclick="userRemoveLink()">Remove Link</button>
          <div class="result-box" id="r-user-remove"></div>
        </div>
      </div>

      <!-- Break users link -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-post">POST</span>
            <h3>Break Users Link with Identity Provider</h3>
          </div>
          <span class="chevron">▼</span>
        </div>
        <div class="section-body">
          <p class="desc">Unlinks <strong>all users</strong> from the specified identity provider. Use when migrating to a different IDP.</p>
          <label>IDP Alias</label>
          <input type="text" id="user-unlink-alias">
          <button class="btn btn-danger" onclick="userUnlink()">Break All Links</button>
          <div class="result-box" id="r-user-unlink"></div>
        </div>
      </div>

    </div><!-- /tab-users -->

    <!-- ========== AUTO-REGISTRATION TAB ========== -->
    <div class="tab-panel" id="tab-autoreg">

      <!-- Get auto-reg -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-get">GET</span>
            <h3>Get User Auto-Registration Info</h3>
          </div>
          <span class="chevron open">▼</span>
        </div>
        <div class="section-body open">
          <label>IDP Alias</label>
          <input type="text" id="ar-get-alias">
          <button class="btn btn-primary" onclick="arGet()">Fetch</button>
          <div class="result-box" id="r-ar-get"></div>
        </div>
      </div>

      <!-- Set auto-reg -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-post">POST</span>
            <h3>Set / Update User Auto-Registration</h3>
          </div>
          <span class="chevron">▼</span>
        </div>
        <div class="section-body">
          <p class="desc">Enables user auto-creation as a specified role on first IDP login. Supported roles: Requester and Project Manager.</p>
          <label>IDP Alias</label>
          <input type="text" id="ar-set-alias">
          <hr class="divider">
          <label style="margin-bottom:10px;">Account Configurations</label>
          <div id="ar-accounts"></div>
          <button class="add-row-btn" onclick="addAccountRow()">+ Add Account</button>
          <button class="btn btn-primary" onclick="arSet()">Save</button>
          <div class="result-box" id="r-ar-set"></div>
        </div>
      </div>

      <!-- Disable auto-reg -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-del">DELETE</span>
            <h3>Disable User Auto-Registration</h3>
          </div>
          <span class="chevron">▼</span>
        </div>
        <div class="section-body">
          <p class="desc">Disables user auto-creation on first IDP login.</p>
          <label>IDP Alias</label>
          <input type="text" id="ar-disable-alias">
          <button class="btn btn-danger" onclick="arDisable()">Disable</button>
          <div class="result-box" id="r-ar-disable"></div>
        </div>
      </div>

    </div><!-- /tab-autoreg -->

    <!-- ========== DOMAINS TAB ========== -->
    <div class="tab-panel" id="tab-domains">

      <!-- List domains -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-get">GET</span>
            <h3>Get Domains Bound to Identity Provider</h3>
          </div>
          <span class="chevron open">▼</span>
        </div>
        <div class="section-body open">
          <label>IDP Alias</label>
          <input type="text" id="dom-list-alias">
          <button class="btn btn-primary" onclick="domList()">Fetch</button>
          <div class="result-box" id="r-dom-list"></div>
        </div>
      </div>

      <!-- Add domain -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-post">POST</span>
            <h3>Add Domain to Identity Provider</h3>
          </div>
          <span class="chevron">▼</span>
        </div>
        <div class="section-body">
          <div class="two-col">
            <div>
              <label>IDP Alias</label>
              <input type="text" id="dom-add-alias">
            </div>
            <div>
              <label>Domain</label>
              <input type="text" id="dom-add-domain" placeholder="e.g. example.com">
            </div>
          </div>
          <button class="btn btn-primary" onclick="domAdd()">Add Domain</button>
          <div class="result-box" id="r-dom-add"></div>
        </div>
      </div>

      <!-- Delete domain -->
      <div class="section">
        <div class="section-hdr" onclick="toggle(this)">
          <div class="section-hdr-left">
            <span class="method-badge badge-del">POST</span>
            <h3>Delete Domain from Identity Provider</h3>
          </div>
          <span class="chevron">▼</span>
        </div>
        <div class="section-body">
          <div class="two-col">
            <div>
              <label>IDP Alias</label>
              <input type="text" id="dom-del-alias">
            </div>
            <div>
              <label>Domain</label>
              <input type="text" id="dom-del-domain">
            </div>
          </div>
          <button class="btn btn-danger" onclick="domDelete()">Delete Domain</button>
          <div class="result-box" id="r-dom-delete"></div>
        </div>
      </div>

    </div><!-- /tab-domains -->

  </div><!-- /content -->
</div><!-- /main -->

<!-- ===== OIDC CREATE MODAL ===== -->
<div class="modal-overlay hidden" id="modal-oidc-create" onclick="if(event.target===this)closeModal('modal-oidc-create')">
  <div class="modal-card">
    <div class="modal-hdr">
      <h2>Create OIDC Identity Provider</h2>
      <button class="modal-close" onclick="closeModal('modal-oidc-create')">&#10005;</button>
    </div>
    <div class="modal-body">
      <div class="two-col">
        <div>
          <label>IDP Alias</label>
          <input type="text" id="oidc-c-alias" placeholder="e.g. shopify">
        </div>
        <div>
          <label>Account UIDs <span class="opt">(comma-separated)</span></label>
          <input type="text" id="oidc-c-accounts" placeholder="e.g. 68d30a959, abc123">
        </div>
      </div>
      <div class="two-col">
        <div>
          <label>Client ID</label>
          <input type="text" id="oidc-c-client-id">
        </div>
        <div>
          <label>Client Secret</label>
          <input type="password" id="oidc-c-client-secret">
        </div>
      </div>
      <label>OIDC Well-Known Endpoint</label>
      <input type="text" id="oidc-c-endpoint" placeholder="https://.../.well-known/openid-configuration">
      <div class="result-box" id="r-oidc-create"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-primary" onclick="oidcCreate()">Create</button>
      <button class="btn btn-secondary" onclick="closeModal('modal-oidc-create')">Cancel</button>
    </div>
  </div>
</div>

<!-- ===== SAML CREATE MODAL ===== -->
<div class="modal-overlay hidden" id="modal-saml-create" onclick="if(event.target===this)closeModal('modal-saml-create')">
  <div class="modal-card">
    <div class="modal-hdr">
      <h2>Create SAML Identity Provider</h2>
      <button class="modal-close" onclick="closeModal('modal-saml-create')">&#10005;</button>
    </div>
    <div class="modal-body">
      <div class="two-col">
        <div>
          <label>IDP Alias</label>
          <input type="text" id="saml-c-alias">
        </div>
        <div>
          <label>Account UIDs <span class="opt">(comma-separated)</span></label>
          <input type="text" id="saml-c-accounts">
        </div>
      </div>
      <label>Single Sign-On Service URL</label>
      <input type="text" id="saml-c-sso-url">
      <label>Single Logout Service URL <span class="opt">(optional)</span></label>
      <input type="text" id="saml-c-slo-url">
      <div class="two-col">
        <div>
          <label>Name ID Policy Format</label>
          <select id="saml-c-nameid">
            <option value="EMAIL">EMAIL</option>
            <option value="UNSPECIFIED">UNSPECIFIED</option>
            <option value="KERBEROS">KERBEROS</option>
            <option value="PERSISTENT">PERSISTENT</option>
          </select>
        </div>
        <div>
          <label>Signature Algorithm</label>
          <select id="saml-c-sig-alg">
            <option value="RSA_SHA256">RSA_SHA256</option>
            <option value="RSA_SHA512">RSA_SHA512</option>
            <option value="RSA_SHA1">RSA_SHA1</option>
            <option value="DSA_SHA1">DSA_SHA1</option>
          </select>
        </div>
      </div>
      <div class="two-col">
        <div>
          <label>Backchannel Supported</label>
          <select id="saml-c-backchannel">
            <option value="false">False</option>
            <option value="true">True</option>
          </select>
        </div>
        <div>
          <label>Want AuthnRequests Signed</label>
          <select id="saml-c-want-signed">
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </div>
      </div>
      <div class="two-col">
        <div>
          <label>Post Binding AuthnRequest</label>
          <select id="saml-c-post-authn">
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </div>
        <div>
          <label>Post Binding Response</label>
          <select id="saml-c-post-resp">
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </div>
      </div>
      <div class="two-col" style="margin-bottom:13px;">
        <div>
          <label>Validate Signature</label>
          <select id="saml-c-validate-sig">
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </div>
      </div>
      <label>Signing Certificate (PEM) <span class="opt">(optional)</span></label>
      <textarea id="saml-c-cert" placeholder="Paste PEM certificate content here..."></textarea>
      <div class="result-box" id="r-saml-create"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-primary" onclick="samlCreate()">Create</button>
      <button class="btn btn-secondary" onclick="closeModal('modal-saml-create')">Cancel</button>
    </div>
  </div>
</div>

<script>
  // ── Auth ──────────────────────────────────────────────────────────────────
  document.getElementById('auth-secret').addEventListener('keydown', e => {
    if (e.key === 'Enter') doAuth();
  });

  let _token = localStorage.getItem('sso_token') || '';
  function authHeaders() {
    return {'Content-Type': 'application/json', 'X-Access-Token': _token};
  }

  function enterApp(userIdentifier) {
    localStorage.setItem('sso_user', userIdentifier);
    document.getElementById('auth-overlay').classList.add('hidden');
    document.getElementById('main').classList.add('visible');
    document.getElementById('topbar-user').textContent = userIdentifier;
    if (!document.getElementById('ar-accounts').children.length) addAccountRow();
    loadOidcList();
  }

  // Restore session from localStorage — no network round-trip needed
  const _savedUser = localStorage.getItem('sso_user');
  if (_savedUser && _token) { enterApp(_savedUser); }

  async function doAuth() {
    const id  = document.getElementById('auth-id').value.trim();
    const sec = document.getElementById('auth-secret').value;
    const btn = document.getElementById('auth-btn');
    const err = document.getElementById('auth-error');
    btn.disabled = true; btn.textContent = 'Signing in…'; err.style.display = 'none';
    try {
      const r = await fetch('https://connect.smartling.com/api/v2/auth-api/v2/authenticate/user', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({userIdentifier: id, userSecret: sec})
      });
      const d = await r.json();
      const token = d?.response?.data?.accessToken;
      if (!r.ok || !token) {
        err.textContent = d?.response?.errors?.[0]?.message || 'Authentication failed.';
        err.style.display = 'block';
      } else {
        _token = token;
        localStorage.setItem('sso_token', _token);
        enterApp(id);
      }
    } catch (e) { err.textContent = 'Network error: ' + e.message; err.style.display = 'block'; }
    btn.disabled = false; btn.textContent = 'Sign In';
  }

  async function doLogout() {
    await fetch('/logout', {method: 'POST'});
    _token = '';
    localStorage.removeItem('sso_token');
    localStorage.removeItem('sso_user');
    document.getElementById('main').classList.remove('visible');
    document.getElementById('auth-overlay').classList.remove('hidden');
    document.getElementById('auth-secret').value = '';
  }

  // ── Tabs ──────────────────────────────────────────────────────────────────
  const _tabLoaded = {};
  function switchTab(name, btn) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + name).classList.add('active');
    if (name === 'saml' && !_tabLoaded.saml) { _tabLoaded.saml = true; loadSamlList(); }
  }

  // ── Accordion ─────────────────────────────────────────────────────────────
  function toggle(hdr) {
    const body = hdr.nextElementSibling;
    const ch   = hdr.querySelector('.chevron');
    body.classList.toggle('open');
    ch.classList.toggle('open');
  }

  // ── Generic API call ──────────────────────────────────────────────────────
  async function call(method, url, body, resultId) {
    const box = document.getElementById(resultId);
    box.className = 'result-box visible';
    box.innerHTML = '<div class="result-hdr loading">Loading…</div>';
    try {
      const opts = {method, headers: authHeaders()};
      if (body) opts.body = JSON.stringify(body);
      const r = await fetch(url, opts);
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      const ok = r.ok && d?.response?.code === 'SUCCESS';
      box.innerHTML =
        '<div class="result-hdr ' + (ok ? 'ok' : 'err') + '">' +
          (ok ? '✓ Success' : '✗ Error') + ' — HTTP ' + r.status +
        '</div>' +
        '<div class="result-body">' + escHtml(JSON.stringify(d, null, 2)) + '</div>';
    } catch (e) {
      box.innerHTML = '<div class="result-hdr err">✗ Network error</div><div class="result-body">' + escHtml(e.message) + '</div>';
    }
  }

  function escHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function showLogin() {
    _token = '';
    localStorage.removeItem('sso_token');
    localStorage.removeItem('sso_user');
    document.getElementById('main').classList.remove('visible');
    document.getElementById('auth-overlay').classList.remove('hidden');
  }

  function v(id) { return document.getElementById(id).value.trim(); }
  function bv(id) { return document.getElementById(id).value === 'true'; }
  function splitUids(s) { return s.split(',').map(x => x.trim()).filter(Boolean); }

  // ── OIDC ──────────────────────────────────────────────────────────────────
  let oidcProviders = {};

  async function loadOidcList() {
    const tbody = document.getElementById('oidc-tbody');
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Loading\u2026</td></tr>';
    try {
      const r = await fetch('/api/oidc/list', {headers: authHeaders()});
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      renderOidcTable(d?.response?.data?.items || []);
    } catch(e) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Error: ' + escHtml(e.message) + '</td></tr>';
    }
  }

  function renderOidcTable(items) {
    items = [...items].sort((a, b) => a.idpAlias.localeCompare(b.idpAlias));
    oidcProviders = {};
    const tbody = document.getElementById('oidc-tbody');
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No OIDC providers found.</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const p of items) {
      oidcProviders[p.idpAlias] = p;
      const tr = document.createElement('tr');
      tr.id = 'oidc-row-' + p.idpAlias;
      tr.className = 'provider-row';
      tr.dataset.alias = p.idpAlias;
      tr.innerHTML =
        '<td><strong>' + escHtml(p.idpAlias) + '</strong></td>' +
        '<td>' + (p.enabled ? '<span class="status-on">Yes</span>' : '<span class="status-off">No</span>') + '</td>' +
        '<td class="col-trunc">' + escHtml(p.clientId) + '</td>' +
        '<td class="col-trunc">' + escHtml(p.issuer) + '</td>' +
        '<td style="white-space:nowrap">' +
          '<button class="btn-sm btn-edit" onclick="toggleOidcEdit(' + JSON.stringify(p.idpAlias).replace(/"/g,'&quot;') + ')">Edit</button>' +
          '<button class="btn-sm btn-del-sm" onclick="deleteOidcRow(' + JSON.stringify(p.idpAlias).replace(/"/g,'&quot;') + ')">Delete</button>' +
        '</td>';
      tbody.appendChild(tr);
    }
  }

  function toggleOidcEdit(alias) {
    const existing = document.getElementById('oidcedit-' + alias);
    if (existing) { existing.remove(); return; }
    const p = oidcProviders[alias];
    const dataRow = document.getElementById('oidc-row-' + alias);
    const editTr = document.createElement('tr');
    editTr.id = 'oidcedit-' + alias;
    editTr.className = 'edit-row';
    editTr.innerHTML =
      '<td colspan="5"><div class="inline-form">' +
        '<div class="two-col">' +
          '<div><label>Client ID</label><input type="text" id="oe-cid-' + alias + '"></div>' +
          '<div><label>Client Secret</label><input type="password" id="oe-sec-' + alias + '" placeholder="(leave blank to keep current)"></div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div><label>Enabled</label><select id="oe-en-' + alias + '"><option value="true">True</option><option value="false">False</option></select></div>' +
          '<div><label>Issuer <span class="opt">(optional)</span></label><input type="text" id="oe-iss-' + alias + '"></div>' +
        '</div>' +
        '<label>Authorization Endpoint</label><input type="text" id="oe-auth-' + alias + '">' +
        '<label>Token Endpoint</label><input type="text" id="oe-tok-' + alias + '">' +
        '<label>User Info Endpoint <span class="opt">(optional)</span></label><input type="text" id="oe-ui-' + alias + '">' +
        '<label>End Session Endpoint <span class="opt">(optional)</span></label><input type="text" id="oe-es-' + alias + '">' +
        '<label>JWKS URI</label><input type="text" id="oe-jwks-' + alias + '">' +
        '<div class="inline-actions">' +
          '<button class="btn btn-primary" id="oe-save-' + alias + '">Save Changes</button>' +
          '<button class="btn btn-secondary" id="oe-cancel-' + alias + '">Cancel</button>' +
          '<div class="result-box" id="oe-result-' + alias + '"></div>' +
        '</div>' +
      '</div></td>';
    dataRow.after(editTr);
    // Set values safely without HTML injection
    document.getElementById('oe-cid-'  + alias).value = p.clientId || '';
    document.getElementById('oe-en-'   + alias).value = String(p.enabled);
    document.getElementById('oe-iss-'  + alias).value = p.issuer || '';
    document.getElementById('oe-auth-' + alias).value = p.authorizationEndPoint || '';
    document.getElementById('oe-tok-'  + alias).value = p.tokenEndPoint || '';
    document.getElementById('oe-ui-'   + alias).value = p.userInfoEndPoint || '';
    document.getElementById('oe-es-'   + alias).value = p.endSessionEndPoint || '';
    document.getElementById('oe-jwks-' + alias).value = p.jwksUri || '';
    document.getElementById('oe-save-'   + alias).onclick = () => saveOidcEdit(alias);
    document.getElementById('oe-cancel-' + alias).onclick = () => editTr.remove();
  }

  async function saveOidcEdit(alias) {
    const btn = document.getElementById('oe-save-' + alias);
    const box = document.getElementById('oe-result-' + alias);
    btn.disabled = true;
    const body = {
      idpAlias:              alias,
      clientId:              document.getElementById('oe-cid-'  + alias).value.trim(),
      clientSecret:          document.getElementById('oe-sec-'  + alias).value,
      enabled:               document.getElementById('oe-en-'   + alias).value === 'true',
      authorizationEndPoint: document.getElementById('oe-auth-' + alias).value.trim(),
      tokenEndPoint:         document.getElementById('oe-tok-'  + alias).value.trim(),
      jwksUri:               document.getElementById('oe-jwks-' + alias).value.trim(),
    };
    const iss = document.getElementById('oe-iss-'  + alias).value.trim();
    const ui  = document.getElementById('oe-ui-'   + alias).value.trim();
    const es  = document.getElementById('oe-es-'   + alias).value.trim();
    if (iss) body.issuer             = iss;
    if (ui)  body.userInfoEndPoint   = ui;
    if (es)  body.endSessionEndPoint = es;
    box.className = 'result-box visible';
    box.innerHTML = '<div class="result-hdr loading">Saving\u2026</div>';
    try {
      const r = await fetch('/api/oidc/update', {
        method: 'POST', headers: authHeaders(), body: JSON.stringify(body)
      });
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      const ok = r.ok && d?.response?.code === 'SUCCESS';
      box.innerHTML =
        '<div class="result-hdr ' + (ok ? 'ok' : 'err') + '">' + (ok ? '\u2713 Saved' : '\u2717 Error') + ' \u2014 HTTP ' + r.status + '</div>' +
        '<div class="result-body">' + escHtml(JSON.stringify(d, null, 2)) + '</div>';
      if (ok) loadOidcList();
    } catch(e) {
      box.innerHTML = '<div class="result-hdr err">\u2717 Network error</div><div class="result-body">' + escHtml(e.message) + '</div>';
    }
    btn.disabled = false;
  }

  async function deleteOidcRow(alias) {
    if (!confirm('Delete OIDC provider "' + alias + '"? This cannot be undone.')) return;
    try {
      const r = await fetch('/api/oidc/delete', {
        method: 'POST', headers: authHeaders(), body: JSON.stringify({idpAlias: alias})
      });
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      if (r.ok && d?.response?.code === 'SUCCESS') {
        document.getElementById('oidc-row-'  + alias)?.remove();
        document.getElementById('oidcedit-'  + alias)?.remove();
        delete oidcProviders[alias];
      } else {
        alert('Delete failed: ' + JSON.stringify(d));
      }
    } catch(e) { alert('Network error: ' + e.message); }
  }

  async function oidcCreate() {
    const alias    = v('oidc-c-alias');
    const accounts = v('oidc-c-accounts');
    const clientId = v('oidc-c-client-id');
    const secret   = document.getElementById('oidc-c-client-secret').value;
    const endpoint = v('oidc-c-endpoint');
    if (!alias || !accounts || !clientId || !secret || !endpoint)
      return alert('All fields are required.');
    await call('POST', '/api/oidc/create', {
      idpAlias: alias,
      accountUids: splitUids(accounts),
      clientId, clientSecret: secret,
      oidcWellKnownEndpoint: endpoint
    }, 'r-oidc-create');
    const box = document.getElementById('r-oidc-create');
    if (box.querySelector('.result-hdr.ok')) {
      closeModal('modal-oidc-create');
      loadOidcList();
    }
  }

  // ── SAML ──────────────────────────────────────────────────────────────────
  let samlProviders = {};

  async function loadSamlList() {
    const tbody = document.getElementById('saml-tbody');
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Loading\u2026</td></tr>';
    try {
      const r = await fetch('/api/saml/list', {headers: authHeaders()});
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      renderSamlTable(d?.response?.data?.items || []);
    } catch(e) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Error: ' + escHtml(e.message) + '</td></tr>';
    }
  }

  function renderSamlTable(items) {
    items = [...items].sort((a, b) => a.idpAlias.localeCompare(b.idpAlias));
    samlProviders = {};
    const tbody = document.getElementById('saml-tbody');
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No SAML providers found.</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    for (const p of items) {
      samlProviders[p.idpAlias] = p;
      const tr = document.createElement('tr');
      tr.id = 'saml-row-' + p.idpAlias;
      tr.className = 'provider-row';
      tr.dataset.alias = p.idpAlias;
      tr.innerHTML =
        '<td><strong>' + escHtml(p.idpAlias) + '</strong></td>' +
        '<td>' + (p.enabled ? '<span class="status-on">Yes</span>' : '<span class="status-off">No</span>') + '</td>' +
        '<td class="col-trunc">' + escHtml(p.singleSignOnServiceUrl) + '</td>' +
        '<td>' + escHtml(p.nameIdPolicyFormat) + '</td>' +
        '<td style="white-space:nowrap">' +
          '<button class="btn-sm btn-edit" onclick="toggleSamlEdit(' + JSON.stringify(p.idpAlias).replace(/"/g,'&quot;') + ')">Edit</button>' +
          '<button class="btn-sm btn-del-sm" onclick="deleteSamlRow(' + JSON.stringify(p.idpAlias).replace(/"/g,'&quot;') + ')">Delete</button>' +
        '</td>';
      tbody.appendChild(tr);
    }
  }

  function sel(opts, val) {
    return opts.map(o => '<option value="' + o + '"' + (o === String(val) ? ' selected' : '') + '>' + o + '</option>').join('');
  }
  function bsel(val) { return sel(['true','false'], String(val)); }

  function toggleSamlEdit(alias) {
    const existing = document.getElementById('samledit-' + alias);
    if (existing) { existing.remove(); return; }
    const p = oidcProviders[alias] || samlProviders[alias];
    const sp = samlProviders[alias];
    const dataRow = document.getElementById('saml-row-' + alias);
    const editTr = document.createElement('tr');
    editTr.id = 'samledit-' + alias;
    editTr.className = 'edit-row';
    editTr.innerHTML =
      '<td colspan="5"><div class="inline-form">' +
        '<div class="two-col">' +
          '<div><label>Enabled</label><select id="se-en-' + alias + '">' + bsel(sp.enabled) + '</select></div>' +
          '<div><label>Trust Email</label><select id="se-te-' + alias + '">' + bsel(sp.trustEmail) + '</select></div>' +
        '</div>' +
        '<label>Single Sign-On Service URL</label><input type="text" id="se-sso-' + alias + '">' +
        '<label>Single Logout Service URL <span class="opt">(optional)</span></label><input type="text" id="se-slo-' + alias + '">' +
        '<div class="two-col">' +
          '<div><label>Name ID Policy Format</label><select id="se-nid-' + alias + '">' + sel(['EMAIL','UNSPECIFIED','KERBEROS','PERSISTENT'], sp.nameIdPolicyFormat) + '</select></div>' +
          '<div><label>Signature Algorithm</label><select id="se-sig-' + alias + '">' + sel(['RSA_SHA256','RSA_SHA512','RSA_SHA1','DSA_SHA1'], sp.signatureAlgorithm) + '</select></div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div><label>Backchannel Supported</label><select id="se-bc-' + alias + '">' + bsel(sp.backchannelSupported) + '</select></div>' +
          '<div><label>Want AuthnRequests Signed</label><select id="se-ws-' + alias + '">' + bsel(sp.wantAuthnRequestsSigned) + '</select></div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div><label>Post Binding AuthnRequest</label><select id="se-pa-' + alias + '">' + bsel(sp.postBindingAuthnRequest) + '</select></div>' +
          '<div><label>Post Binding Response</label><select id="se-pr-' + alias + '">' + bsel(sp.postBindingResponse) + '</select></div>' +
        '</div>' +
        '<div class="two-col">' +
          '<div><label>Validate Signature</label><select id="se-vs-' + alias + '">' + bsel(sp.validateSignature) + '</select></div>' +
        '</div>' +
        '<label>Signing Certificate (PEM) <span class="opt">(optional)</span></label><textarea id="se-cert-' + alias + '"></textarea>' +
        '<div class="inline-actions">' +
          '<button class="btn btn-primary" id="se-save-' + alias + '">Save Changes</button>' +
          '<button class="btn btn-secondary" id="se-cancel-' + alias + '">Cancel</button>' +
          '<div class="result-box" id="se-result-' + alias + '"></div>' +
        '</div>' +
      '</div></td>';
    dataRow.after(editTr);
    document.getElementById('se-sso-'  + alias).value = sp.singleSignOnServiceUrl || '';
    document.getElementById('se-slo-'  + alias).value = sp.singleLogoutServiceUrl || '';
    document.getElementById('se-cert-' + alias).value = sp.signingCertificate || '';
    document.getElementById('se-save-'   + alias).onclick = () => saveSamlEdit(alias);
    document.getElementById('se-cancel-' + alias).onclick = () => editTr.remove();
  }

  async function saveSamlEdit(alias) {
    const btn = document.getElementById('se-save-' + alias);
    const box = document.getElementById('se-result-' + alias);
    btn.disabled = true;
    const g = id => document.getElementById(id + alias);
    const body = {
      idpAlias:               alias,
      enabled:                g('se-en-').value  === 'true',
      trustEmail:             g('se-te-').value  === 'true',
      singleSignOnServiceUrl: g('se-sso-').value.trim(),
      nameIdPolicyFormat:     g('se-nid-').value,
      backchannelSupported:   g('se-bc-').value  === 'true',
      wantAuthnRequestsSigned:g('se-ws-').value  === 'true',
      signatureAlgorithm:     g('se-sig-').value,
      postBindingAuthnRequest:g('se-pa-').value  === 'true',
      postBindingResponse:    g('se-pr-').value  === 'true',
      validateSignature:      g('se-vs-').value  === 'true',
    };
    const slo  = g('se-slo-').value.trim();
    const cert = g('se-cert-').value.trim();
    if (slo)  body.singleLogoutServiceUrl = slo;
    if (cert) body.signingCertificate     = cert;
    box.className = 'result-box visible';
    box.innerHTML = '<div class="result-hdr loading">Saving\u2026</div>';
    try {
      const r = await fetch('/api/saml/update', {
        method: 'POST', headers: authHeaders(), body: JSON.stringify(body)
      });
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      const ok = r.ok && d?.response?.code === 'SUCCESS';
      box.innerHTML =
        '<div class="result-hdr ' + (ok ? 'ok' : 'err') + '">' + (ok ? '\u2713 Saved' : '\u2717 Error') + ' \u2014 HTTP ' + r.status + '</div>' +
        '<div class="result-body">' + escHtml(JSON.stringify(d, null, 2)) + '</div>';
      if (ok) loadSamlList();
    } catch(e) {
      box.innerHTML = '<div class="result-hdr err">\u2717 Network error</div><div class="result-body">' + escHtml(e.message) + '</div>';
    }
    btn.disabled = false;
  }

  async function deleteSamlRow(alias) {
    if (!confirm('Delete SAML provider "' + alias + '"? This cannot be undone.')) return;
    try {
      const r = await fetch('/api/saml/delete', {
        method: 'POST', headers: authHeaders(), body: JSON.stringify({idpAlias: alias})
      });
      if (r.status === 401) { showLogin(); return; }
      const d = await r.json();
      if (r.ok && d?.response?.code === 'SUCCESS') {
        document.getElementById('saml-row-' + alias)?.remove();
        document.getElementById('samledit-' + alias)?.remove();
        delete samlProviders[alias];
      } else {
        alert('Delete failed: ' + JSON.stringify(d));
      }
    } catch(e) { alert('Network error: ' + e.message); }
  }

  async function samlCreate() {
    const alias    = v('saml-c-alias');
    const accounts = v('saml-c-accounts');
    const ssoUrl   = v('saml-c-sso-url');
    if (!alias || !accounts || !ssoUrl)
      return alert('IDP Alias, Account UIDs, and SSO URL are required.');
    const body = {
      idpAlias: alias,
      accountUids: splitUids(accounts),
      singleSignOnServiceUrl: ssoUrl,
      nameIdPolicyFormat:     v('saml-c-nameid'),
      signatureAlgorithm:     v('saml-c-sig-alg'),
      backchannelSupported:   bv('saml-c-backchannel'),
      wantAuthnRequestsSigned:bv('saml-c-want-signed'),
      postBindingAuthnRequest:bv('saml-c-post-authn'),
      postBindingResponse:    bv('saml-c-post-resp'),
      validateSignature:      bv('saml-c-validate-sig'),
    };
    const slo  = v('saml-c-slo-url');
    const cert = document.getElementById('saml-c-cert').value.trim();
    if (slo)  body.singleLogoutServiceUrl = slo;
    if (cert) body.signingCertificate     = cert;
    await call('POST', '/api/saml/create', body, 'r-saml-create');
    const box = document.getElementById('r-saml-create');
    if (box.querySelector('.result-hdr.ok')) {
      closeModal('modal-saml-create');
      loadSamlList();
    }
  }

  // ── Modal helpers ─────────────────────────────────────────────────────────
  function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
  function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

  // ── Table filters ──────────────────────────────────────────────────────────
  function filterOidcTable(q) {
    q = q.toLowerCase();
    document.querySelectorAll('#oidc-tbody .provider-row').forEach(tr => {
      const match = tr.dataset.alias.toLowerCase().includes(q);
      tr.style.display = match ? '' : 'none';
      const edit = document.getElementById('oidcedit-' + tr.dataset.alias);
      if (edit) edit.style.display = match ? '' : 'none';
    });
  }
  function filterSamlTable(q) {
    q = q.toLowerCase();
    document.querySelectorAll('#saml-tbody .provider-row').forEach(tr => {
      const match = tr.dataset.alias.toLowerCase().includes(q);
      tr.style.display = match ? '' : 'none';
      const edit = document.getElementById('samledit-' + tr.dataset.alias);
      if (edit) edit.style.display = match ? '' : 'none';
    });
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  function userRemoveLink() {
    const accountUid = v('user-rm-account');
    const idpAlias   = v('user-rm-alias');
    const email      = v('user-rm-email');
    if (!accountUid || !idpAlias || !email) return alert('All fields are required.');
    if (!confirm('Remove IDP link for ' + email + '?')) return;
    call('DELETE', '/api/user/remove-link', {accountUid, idpAlias, email}, 'r-user-remove');
  }

  function userUnlink() {
    const idpAlias = v('user-unlink-alias');
    if (!idpAlias) return alert('IDP Alias is required.');
    if (!confirm('Break ALL user links for IDP "' + idpAlias + '"? This affects every linked user.')) return;
    call('POST', '/api/user/unlink-users', {idpAlias}, 'r-user-unlink');
  }

  // ── Auto-registration ─────────────────────────────────────────────────────
  function addAccountRow() {
    const ctr = document.getElementById('ar-accounts');
    const id  = 'ar-row-' + Date.now();
    const div = document.createElement('div');
    div.className = 'account-row'; div.id = id;
    div.innerHTML =
      '<button class="rm-row" onclick="document.getElementById(\\'' + id + '\\').remove()">✕</button>' +
      '<div class="two-col">' +
        '<div><label>Account UID</label><input type="text" class="ar-uid" placeholder="e.g. 68d30a959"></div>' +
        '<div><label>Role</label><select class="ar-role">' +
          '<option value="ROLE_REQUESTER">Requester</option>' +
          '<option value="ROLE_PROJECT_MANAGER">Project Manager</option>' +
        '</select></div>' +
      '</div>' +
      '<label>Project UIDs <span class="opt">(comma-separated)</span></label>' +
      '<input type="text" class="ar-puids" placeholder="e.g. a1b2c3d4e5">';
    ctr.appendChild(div);
  }

  function arGet() {
    const alias = v('ar-get-alias');
    if (!alias) return alert('IDP Alias is required.');
    call('GET', '/api/auto-reg/get/' + encodeURIComponent(alias), null, 'r-ar-get');
  }

  function arSet() {
    const alias = v('ar-set-alias');
    if (!alias) return alert('IDP Alias is required.');
    const rows = document.querySelectorAll('#ar-accounts .account-row');
    if (!rows.length) return alert('At least one account configuration is required.');
    const accounts = [];
    for (const row of rows) {
      const accountUid   = row.querySelector('.ar-uid').value.trim();
      const role         = row.querySelector('.ar-role').value;
      const projectUids  = row.querySelector('.ar-puids').value
        .split(',').map(s => s.trim()).filter(Boolean);
      if (!accountUid || !projectUids.length)
        return alert('Each account row requires an Account UID and at least one Project UID.');
      accounts.push({accountUid, projectUids, role});
    }
    call('POST', '/api/auto-reg/set', {idpAlias: alias, accounts}, 'r-ar-set');
  }

  function arDisable() {
    const alias = v('ar-disable-alias');
    if (!alias) return alert('IDP Alias is required.');
    if (!confirm('Disable auto-registration for IDP "' + alias + '"?')) return;
    call('DELETE', '/api/auto-reg/disable', {idpAlias: alias}, 'r-ar-disable');
  }

  // ── Domains ───────────────────────────────────────────────────────────────
  function domList() {
    const alias = v('dom-list-alias');
    if (!alias) return alert('IDP Alias is required.');
    call('GET', '/api/domains/list/' + encodeURIComponent(alias), null, 'r-dom-list');
  }

  function domAdd() {
    const alias  = v('dom-add-alias');
    const domain = v('dom-add-domain');
    if (!alias || !domain) return alert('IDP Alias and Domain are required.');
    call('POST', '/api/domains/add', {idpAlias: alias, domain}, 'r-dom-add');
  }

  function domDelete() {
    const alias  = v('dom-del-alias');
    const domain = v('dom-del-domain');
    if (!alias || !domain) return alert('IDP Alias and Domain are required.');
    if (!confirm('Delete domain "' + domain + '" from IDP "' + alias + '"?')) return;
    call('POST', '/api/domains/delete', {idpAlias: alias, domain}, 'r-dom-delete');
  }
</script>
</body>
</html>
"""


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/")
@require_basic_auth
def index():
    return render_template_string(HTML)


@app.route("/auth", methods=["POST"])
def authenticate():
    data = request.json
    try:
        resp = requests.post(AUTH_URL, json={
            "userIdentifier": data["userIdentifier"],
            "userSecret": data["userSecret"],
        })
        if resp.status_code == 401:
            return jsonify({"error": "Authentication failed: invalid credentials."}), 401
        resp.raise_for_status()
        token = resp.json()["response"]["data"]["accessToken"]
        session["access_token"] = token
        session["user_identifier"] = data["userIdentifier"]
        return jsonify({"success": True, "accessToken": token})
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


# ── OIDC routes ───────────────────────────────────────────────────────────────

@app.route("/api/oidc/list")
def oidc_list():
    data, status = api_call("GET", f"{IDP_BASE}/jwks/list")
    return jsonify(data), status


@app.route("/api/oidc/get/<idp_alias>")
def oidc_get(idp_alias):
    data, status = api_call("GET", f"{IDP_BASE}/idp/{idp_alias}")
    return jsonify(data), status


@app.route("/api/oidc/create", methods=["POST"])
def oidc_create():
    data, status = api_call("POST", f"{IDP_BASE}/jwks/create", json=request.json)
    return jsonify(data), status


@app.route("/api/oidc/update", methods=["POST"])
def oidc_update():
    data, status = api_call("POST", f"{IDP_BASE}/jwks/update", json=request.json)
    return jsonify(data), status


@app.route("/api/oidc/delete", methods=["POST"])
def oidc_delete():
    data, status = api_call("POST", f"{IDP_BASE}/jwks/delete", json=request.json)
    return jsonify(data), status


# ── SAML routes ───────────────────────────────────────────────────────────────

@app.route("/api/saml/list")
def saml_list():
    data, status = api_call("GET", f"{IDP_BASE}/saml/list")
    return jsonify(data), status


@app.route("/api/saml/create", methods=["POST"])
def saml_create():
    data, status = api_call("POST", f"{IDP_BASE}/saml/create", json=request.json)
    return jsonify(data), status


@app.route("/api/saml/update", methods=["POST"])
def saml_update():
    data, status = api_call("POST", f"{IDP_BASE}/saml/update", json=request.json)
    return jsonify(data), status


@app.route("/api/saml/delete", methods=["POST"])
def saml_delete():
    data, status = api_call("POST", f"{IDP_BASE}/saml/delete", json=request.json)
    return jsonify(data), status


# ── User management routes ────────────────────────────────────────────────────

@app.route("/api/user/remove-link", methods=["DELETE"])
def user_remove_link():
    body = request.json
    account_uid = body["accountUid"]
    idp_alias   = body["idpAlias"]
    email       = body["email"]
    data, status = api_call(
        "DELETE",
        f"{IDP_BASE}/accounts/{account_uid}/idp/{idp_alias}/user/{email}",
    )
    return jsonify(data), status


@app.route("/api/user/unlink-users", methods=["POST"])
def user_unlink():
    idp_alias = request.json["idpAlias"]
    data, status = api_call("POST", f"{IDP_BASE}/idp/{idp_alias}/unlink-users", json={})
    return jsonify(data), status


# ── Auto-registration routes ──────────────────────────────────────────────────

@app.route("/api/auto-reg/get/<idp_alias>")
def auto_reg_get(idp_alias):
    data, status = api_call("GET", f"{IDP_BASE}/idp/{idp_alias}/user-auto-registration")
    return jsonify(data), status


@app.route("/api/auto-reg/set", methods=["POST"])
def auto_reg_set():
    body      = request.json
    idp_alias = body["idpAlias"]
    data, status = api_call(
        "POST",
        f"{IDP_BASE}/idp/{idp_alias}/user-auto-registration",
        json={"accounts": body["accounts"]},
    )
    return jsonify(data), status


@app.route("/api/auto-reg/disable", methods=["DELETE"])
def auto_reg_disable():
    idp_alias = request.json["idpAlias"]
    data, status = api_call("DELETE", f"{IDP_BASE}/idp/{idp_alias}/user-auto-registration")
    return jsonify(data), status


# ── Domain management routes ──────────────────────────────────────────────────

@app.route("/api/domains/list/<idp_alias>")
def domains_list(idp_alias):
    data, status = api_call("GET", f"{IDP_BASE}/idp/{idp_alias}/domains/list")
    return jsonify(data), status


@app.route("/api/domains/add", methods=["POST"])
def domains_add():
    body      = request.json
    idp_alias = body["idpAlias"]
    data, status = api_call(
        "POST",
        f"{IDP_BASE}/idp/{idp_alias}/domains/add",
        json={"domain": body["domain"]},
    )
    return jsonify(data), status


@app.route("/api/domains/delete", methods=["POST"])
def domains_delete():
    body      = request.json
    idp_alias = body["idpAlias"]
    data, status = api_call(
        "POST",
        f"{IDP_BASE}/idp/{idp_alias}/domains/delete",
        json={"domain": body["domain"]},
    )
    return jsonify(data), status


if __name__ == "__main__":
    app.run(debug=True, threaded=True, port=5001)
