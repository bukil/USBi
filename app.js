/**
 * EJEC License Generator
 * Pure vanilla JS — no external dependencies, no build step.
 * Uses Web Crypto API (crypto.subtle + crypto.getRandomValues) exclusively.
 *
 * Security notes:
 *  - Plaintext keys are held only in JS memory (the `session` array).
 *  - Nothing is written to localStorage, sessionStorage, or URL params.
 *  - All user-supplied strings are escaped via textContent / DOM construction.
 *  - innerHTML is never used with user data.
 *  - Imported JSON is validated strictly before being accepted.
 */

"use strict";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Unambiguous alphanumeric alphabet — no 0, O, 1, I */
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const KEY_LENGTH = 25;          // normalised character count
const GROUP_SIZE = 5;           // characters per display group
const GROUP_COUNT = 5;          // number of display groups
const HASH_HEX_LENGTH = 64;     // SHA-256 → 32 bytes → 64 hex chars
const MAX_IMPORT_BYTES = 1_048_576; // 1 MiB
const GITHUB_CONTENTS_URL = "https://api.github.com/repos/bukil/USBi/contents/licenses.json";
const GITHUB_BRANCH = "main";

// ---------------------------------------------------------------------------
// In-memory session state
// ---------------------------------------------------------------------------

/**
 * Holds plaintext keys generated this session.
 * Each entry: { key: string, hash: string, customerName: string,
 *               customerEmail: string, reference: string, createdAt: string }
 * This array is never persisted — it is cleared on "Clear Results".
 */
let session = [];

/**
 * Current working allowlist — merged from any imported licenses.json plus
 * newly generated entries (hashes only, no plaintext).
 * Each entry mirrors the licenses.json schema.
 */
let allowlist = [];

// ---------------------------------------------------------------------------
// Cryptographic utilities
// ---------------------------------------------------------------------------

/**
 * Generate a single cryptographically random product key (25 chars, normalised).
 * Uses crypto.getRandomValues — never Math.random.
 * @returns {string} 25-character key from ALPHABET
 */
function generateRawKey() {
  const alphabetLen = ALPHABET.length; // 32
  const result = new Array(KEY_LENGTH);
  // Use rejection sampling to avoid modulo bias.
  // ALPHABET length is 32 (power of 2), so bias is zero, but we keep the
  // pattern correct for future changes.
  const buf = new Uint8Array(KEY_LENGTH * 2); // extra headroom for rejection
  let filled = 0;
  while (filled < KEY_LENGTH) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && filled < KEY_LENGTH; i++) {
      // Accept values that fall within the largest multiple of alphabetLen ≤ 256
      const limit = Math.floor(256 / alphabetLen) * alphabetLen;
      if (buf[i] < limit) {
        result[filled++] = ALPHABET[buf[i] % alphabetLen];
      }
    }
  }
  return result.join("");
}

/**
 * Format a 25-character raw key into XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
 * @param {string} rawKey
 * @returns {string}
 */
function formatKey(rawKey) {
  const groups = [];
  for (let i = 0; i < GROUP_COUNT; i++) {
    groups.push(rawKey.slice(i * GROUP_SIZE, (i + 1) * GROUP_SIZE));
  }
  return groups.join("-");
}

/**
 * Normalise a product key before hashing:
 *  1. Remove hyphens and whitespace.
 *  2. Convert to uppercase.
 *  3. Confirm exactly 25 characters remain.
 * @param {string} key
 * @returns {string} normalised key
 * @throws {Error} if the result is not exactly 25 chars
 */
function normaliseKey(key) {
  const norm = key.replace(/[-\s]/g, "").toUpperCase();
  if (norm.length !== KEY_LENGTH) {
    throw new Error(
      `Normalised key must be exactly ${KEY_LENGTH} characters; got ${norm.length}.`
    );
  }
  return norm;
}

/**
 * Compute the lowercase SHA-256 hex digest of a normalised product key.
 * @param {string} normKey  — must already be normalised
 * @returns {Promise<string>} 64-character lowercase hex string
 */
async function sha256Hex(normKey) {
  const encoded = new TextEncoder().encode(normKey);
  const buffer = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/**
 * Return true if `s` is a valid 64-char lowercase hex string.
 * @param {string} s
 */
function isValidHash(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

/**
 * Return true if `s` is exactly "active" or "revoked".
 * @param {string} s
 */
function isValidStatus(s) {
  return s === "active" || s === "revoked";
}

/**
 * Validate and parse an imported licenses.json file.
 * Returns { ok: true, data } or { ok: false, error: string }.
 * @param {string} text
 */
function validateLicensesJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "File is not valid JSON." };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "Root must be a JSON object." };
  }
  if (parsed.version !== 1) {
    return { ok: false, error: `Expected version 1; got ${JSON.stringify(parsed.version)}.` };
  }
  if (!Array.isArray(parsed.licenses)) {
    return { ok: false, error: '"licenses" must be an array.' };
  }
  const seenHashes = new Set();
  for (let i = 0; i < parsed.licenses.length; i++) {
    const entry = parsed.licenses[i];
    if (typeof entry !== "object" || entry === null) {
      return { ok: false, error: `licenses[${i}] must be an object.` };
    }
    if (!isValidHash(entry.hash)) {
      return {
        ok: false,
        error: `licenses[${i}].hash must be a 64-character lowercase hex string.`,
      };
    }
    if (!isValidStatus(entry.status)) {
      return {
        ok: false,
        error: `licenses[${i}].status must be "active" or "revoked".`,
      };
    }
    if (seenHashes.has(entry.hash)) {
      return { ok: false, error: `Duplicate hash at licenses[${i}].` };
    }
    seenHashes.add(entry.hash);
  }
  return { ok: true, data: parsed };
}

/**
 * Escape a string for safe use in CSV cells.
 * Wraps in double quotes if the value contains comma, double-quote, or newline.
 * @param {string} val
 * @returns {string}
 */
function csvEscape(val) {
  const s = String(val ?? "");
  if (s.includes('"') || s.includes(",") || s.includes("\n") || s.includes("\r")) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

// ---------------------------------------------------------------------------
// Allowlist merge helpers
// ---------------------------------------------------------------------------

/**
 * Merge a new set of entries into the allowlist.
 * Existing entries are preserved; duplicate hashes are skipped.
 * @param {Array} newEntries — hash-only entries (no plaintext)
 */
function mergeIntoAllowlist(newEntries) {
  const existingHashes = new Set(allowlist.map((e) => e.hash));
  for (const entry of newEntries) {
    if (!existingHashes.has(entry.hash)) {
      allowlist.push(entry);
      existingHashes.add(entry.hash);
    }
  }
}

// Load the currently published allowlist before permitting new generation.
// This prevents a newly downloaded licenses.json from accidentally dropping
// licenses that were already published.
async function loadPublishedAllowlist() {
  if (typeof location === "undefined" || location.protocol === "file:") return;

  const generateButton = document.getElementById("gen-btn");
  const statusElement = document.getElementById("import-status");
  generateButton.disabled = true;
  generateButton.textContent = "Loading licenses…";

  try {
    const response = await fetch(GITHUB_CONTENTS_URL, {
      cache: "no-store",
      headers: {
        Accept: "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!response.ok) {
      throw new Error(`licenses.json returned HTTP ${response.status}.`);
    }

    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_IMPORT_BYTES) {
      throw new Error("licenses.json is larger than 1 MiB.");
    }

    const result = validateLicensesJson(text);
    if (!result.ok) throw new Error(result.error);

    mergeIntoAllowlist(result.data.licenses);
    renderAllowlistTable();
    showMessage(
      statusElement,
      `Loaded ${result.data.licenses.length} published license${result.data.licenses.length === 1 ? "" : "s"}.`
    );
    generateButton.disabled = false;
    generateButton.textContent = "Generate";
  } catch (error) {
    showMessage(
      statusElement,
      `Could not load the published allowlist: ${error.message} Generation is disabled to protect existing licenses.`,
      true
    );
    generateButton.textContent = "Allowlist unavailable";
  }
}

// ---------------------------------------------------------------------------
// DOM utilities (safe — never use innerHTML with user data)
// ---------------------------------------------------------------------------

/** Create an element with optional class and text content. */
function el(tag, opts = {}) {
  const node = document.createElement(tag);
  if (opts.cls) node.className = opts.cls;
  if (opts.text != null) node.textContent = opts.text;
  if (opts.id) node.id = opts.id;
  if (opts.type) node.type = opts.type;
  if (opts.attrs) {
    for (const [k, v] of Object.entries(opts.attrs)) {
      node.setAttribute(k, v);
    }
  }
  return node;
}

/** Display a transient status message in the given container. */
function showMessage(container, text, isError = false) {
  container.textContent = text;
  container.className = isError ? "message message-error" : "message message-success";
  container.removeAttribute("hidden");
  clearTimeout(container._timer);
  container._timer = setTimeout(() => {
    container.setAttribute("hidden", "");
    container.textContent = "";
  }, 6000);
}

/** Dismiss a status message immediately. */
function clearMessage(container) {
  clearTimeout(container._timer);
  container.setAttribute("hidden", "");
  container.textContent = "";
}

// ---------------------------------------------------------------------------
// Copy-to-clipboard helper
// ---------------------------------------------------------------------------

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.disabled = true;
    setTimeout(() => {
      btn.textContent = orig;
      btn.disabled = false;
    }, 1800);
  } catch {
    // Fallback for environments where clipboard API is not available
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    const orig = btn.textContent;
    btn.textContent = "Copied ✓";
    setTimeout(() => { btn.textContent = orig; }, 1800);
  }
}

// ---------------------------------------------------------------------------
// Download helpers
// ---------------------------------------------------------------------------

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Build the updated licenses.json (hashes only — NO plaintext keys)
// ---------------------------------------------------------------------------

function buildLicensesJson() {
  const out = {
    version: 1,
    licenses: allowlist.map((entry) => ({
      hash: entry.hash,
      status: entry.status,
      createdAt: entry.createdAt,
      customerName: entry.customerName ?? "",
      customerEmail: entry.customerEmail ?? "",
      reference: entry.reference ?? "",
    })),
  };
  return JSON.stringify(out, null, 2);
}

// Paranoia check: assert no plaintext key appears in a licenses.json string.
function assertNoPlaintext(json) {
  for (const s of session) {
    if (json.includes(s.key)) {
      throw new Error("SECURITY: plaintext key found in export — aborting.");
    }
  }
}

function decodeGitHubContent(value) {
  const binary = atob(value.replace(/\s/g, ""));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function encodeGitHubContent(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function githubRequest(url, token, options = {}) {
  const response = await fetch(url, {
    ...options,
    cache: "no-store",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    let message = `GitHub returned HTTP ${response.status}.`;
    try {
      const body = await response.json();
      if (typeof body.message === "string") message = body.message;
    } catch {
      // Keep the generic HTTP error when GitHub does not return JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

async function handlePublish() {
  const tokenInput = document.getElementById("github-token");
  const statusElement = document.getElementById("publish-status");
  const publishButton = document.getElementById("publish-btn");
  const token = tokenInput.value.trim();

  clearMessage(statusElement);
  if (!token) {
    showMessage(statusElement, "Enter a fine-grained GitHub token before publishing.", true);
    tokenInput.focus();
    return false;
  }
  if (allowlist.length === 0) {
    showMessage(statusElement, "There are no licenses to publish.", true);
    return false;
  }

  publishButton.disabled = true;
  publishButton.textContent = "Publishing…";

  try {
    const currentFile = await githubRequest(
      `${GITHUB_CONTENTS_URL}?ref=${encodeURIComponent(GITHUB_BRANCH)}`,
      token
    );
    if (currentFile.encoding !== "base64" || typeof currentFile.content !== "string") {
      throw new Error("GitHub returned an unsupported licenses.json representation.");
    }

    const currentAllowlist = validateLicensesJson(decodeGitHubContent(currentFile.content));
    if (!currentAllowlist.ok) {
      throw new Error(`Published licenses.json is invalid: ${currentAllowlist.error}`);
    }
    mergeIntoAllowlist(currentAllowlist.data.licenses);

    const json = buildLicensesJson();
    assertNoPlaintext(json);
    await githubRequest(GITHUB_CONTENTS_URL, token, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: `Update EJEC licenses (${new Date().toISOString()})`,
        content: encodeGitHubContent(json),
        sha: currentFile.sha,
        branch: GITHUB_BRANCH,
      }),
    });

    renderAllowlistTable();
    showMessage(
      statusElement,
      "Published successfully. GitHub Pages should update within a few minutes."
    );
    return true;
  } catch (error) {
    showMessage(statusElement, `Publishing failed: ${error.message}`, true);
    return false;
  } finally {
    tokenInput.value = "";
    publishButton.disabled = false;
    publishButton.textContent = "Publish Current Allowlist";
  }
}

// ---------------------------------------------------------------------------
// Build the private CSV (plaintext keys — NEVER commit this file)
// ---------------------------------------------------------------------------

function buildPrivateCsv() {
  const header = "license,hash,customerName,customerEmail,reference,createdAt";
  const rows = session.map((s) =>
    [
      csvEscape(s.key),
      csvEscape(s.hash),
      csvEscape(s.customerName),
      csvEscape(s.customerEmail),
      csvEscape(s.reference),
      csvEscape(s.createdAt),
    ].join(",")
  );
  return [header, ...rows].join("\r\n");
}

// ---------------------------------------------------------------------------
// Results table
// ---------------------------------------------------------------------------

function renderResultsTable() {
  const tbody = document.getElementById("results-tbody");
  tbody.textContent = ""; // safe clear

  if (session.length === 0) {
    const tr = el("tr");
    const td = el("td", { text: "No keys generated this session.", attrs: { colspan: "4" } });
    td.className = "empty-cell";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const entry of session) {
    const tr = document.createElement("tr");

    // Key cell
    const tdKey = document.createElement("td");
    const codeEl = el("code", { text: entry.key, cls: "key-display" });
    tdKey.appendChild(codeEl);
    tr.appendChild(tdKey);

    // Hash (shortened) cell
    const tdHash = el("td");
    const shortHash = el("code", { text: entry.hash.slice(0, 12) + "…", cls: "hash-short" });
    shortHash.title = entry.hash;
    tdHash.appendChild(shortHash);
    tr.appendChild(tdHash);

    // Customer cell
    const tdCustomer = el("td", {
      text: [entry.customerName, entry.customerEmail].filter(Boolean).join(" / ") || "—",
    });
    tr.appendChild(tdCustomer);

    // Actions cell
    const tdActions = document.createElement("td");
    tdActions.className = "actions-cell";

    const copyBtn = el("button", { text: "Copy", cls: "btn btn-sm btn-secondary" });
    copyBtn.addEventListener("click", () => copyText(entry.key, copyBtn));
    tdActions.appendChild(copyBtn);

    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  }

  // Show/hide bulk-action buttons
  document.getElementById("bulk-actions").removeAttribute("hidden");
}

// ---------------------------------------------------------------------------
// Allowlist management table
// ---------------------------------------------------------------------------

function renderAllowlistTable() {
  const tbody = document.getElementById("allowlist-tbody");
  tbody.textContent = "";

  if (allowlist.length === 0) {
    const tr = el("tr");
    const td = el("td", {
      text: "No licenses imported or generated yet.",
      attrs: { colspan: "7" },
    });
    td.className = "empty-cell";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (let i = 0; i < allowlist.length; i++) {
    const entry = allowlist[i];
    const tr = document.createElement("tr");

    // Short hash
    const tdHash = document.createElement("td");
    const hashEl = el("code", { text: entry.hash.slice(0, 12) + "…", cls: "hash-short" });
    hashEl.title = entry.hash;
    tdHash.appendChild(hashEl);
    tr.appendChild(tdHash);

    // Status badge
    const tdStatus = document.createElement("td");
    const badge = el("span", {
      text: entry.status,
      cls: entry.status === "active" ? "badge badge-active" : "badge badge-revoked",
    });
    tdStatus.appendChild(badge);
    tr.appendChild(tdStatus);

    // Customer name
    tr.appendChild(el("td", { text: entry.customerName || "—" }));

    // Customer email
    tr.appendChild(el("td", { text: entry.customerEmail || "—" }));

    // Reference
    tr.appendChild(el("td", { text: entry.reference || "—" }));

    // Created at
    const created = entry.createdAt
      ? new Date(entry.createdAt).toLocaleString()
      : "—";
    tr.appendChild(el("td", { text: created }));

    // Actions
    const tdAct = document.createElement("td");
    tdAct.className = "actions-cell";

    const toggleBtn = document.createElement("button");
    if (entry.status === "active") {
      toggleBtn.textContent = "Revoke";
      toggleBtn.className = "btn btn-sm btn-danger";
    } else {
      toggleBtn.textContent = "Reactivate";
      toggleBtn.className = "btn btn-sm btn-warning";
    }
    toggleBtn.addEventListener("click", () => {
      allowlist[i].status = entry.status === "active" ? "revoked" : "active";
      renderAllowlistTable();
    });

    const removeBtn = el("button", { text: "Remove", cls: "btn btn-sm btn-danger-outline" });
    removeBtn.addEventListener("click", () => {
      if (confirm("Remove this entry from the allowlist? This cannot be undone in this session.")) {
        allowlist.splice(i, 1);
        renderAllowlistTable();
      }
    });

    tdAct.appendChild(toggleBtn);
    tdAct.appendChild(removeBtn);
    tr.appendChild(tdAct);

    tbody.appendChild(tr);
  }
}

// ---------------------------------------------------------------------------
// Main generation workflow
// ---------------------------------------------------------------------------

async function handleGenerate() {
  const statusEl = document.getElementById("gen-status");
  clearMessage(statusEl);

  const quantityEl = document.getElementById("qty");
  const qty = parseInt(quantityEl.value, 10);
  if (!Number.isFinite(qty) || qty < 1 || qty > 100) {
    showMessage(statusEl, "Quantity must be between 1 and 100.", true);
    return;
  }

  const customerName = document.getElementById("customer-name").value.trim();
  const customerEmail = document.getElementById("customer-email").value.trim();
  const reference = document.getElementById("reference").value.trim();
  const now = new Date().toISOString();

  const existingHashes = new Set(allowlist.map((e) => e.hash));

  const genBtn = document.getElementById("gen-btn");
  genBtn.disabled = true;
  genBtn.textContent = "Generating…";

  try {
    const newSessionEntries = [];
    const newAllowlistEntries = [];

    for (let i = 0; i < qty; i++) {
      const rawKey = generateRawKey();
      const formatted = formatKey(rawKey);
      const norm = normaliseKey(formatted);
      const hash = await sha256Hex(norm);

      // Collision check (astronomically unlikely but handle it)
      if (existingHashes.has(hash)) {
        // Try once more
        const rawKey2 = generateRawKey();
        const formatted2 = formatKey(rawKey2);
        const norm2 = normaliseKey(formatted2);
        const hash2 = await sha256Hex(norm2);
        if (existingHashes.has(hash2)) {
          showMessage(statusEl, "Hash collision detected (extremely rare). Please try again.", true);
          return;
        }
      }

      existingHashes.add(hash);

      const sessionEntry = {
        key: formatted,
        hash,
        customerName,
        customerEmail,
        reference,
        createdAt: now,
      };
      newSessionEntries.push(sessionEntry);

      // Allowlist entry — no plaintext key
      newAllowlistEntries.push({
        hash,
        status: "active",
        createdAt: now,
        customerName,
        customerEmail,
        reference,
      });
    }

    session.push(...newSessionEntries);
    mergeIntoAllowlist(newAllowlistEntries);

    renderResultsTable();
    renderAllowlistTable();
    showMessage(
      statusEl,
      `${qty} key${qty > 1 ? "s" : ""} generated. Save the private key${qty > 1 ? "s" : ""} before leaving this page.`
    );
    if (document.getElementById("auto-publish").checked) {
      await handlePublish();
    }
  } catch (err) {
    showMessage(statusEl, `Error: ${err.message}`, true);
  } finally {
    genBtn.disabled = false;
    genBtn.textContent = "Generate";
  }
}

// ---------------------------------------------------------------------------
// Import existing licenses.json
// ---------------------------------------------------------------------------

function handleImport(file) {
  const statusEl = document.getElementById("import-status");
  clearMessage(statusEl);

  if (file.size > MAX_IMPORT_BYTES) {
    showMessage(statusEl, "File is too large (maximum 1 MiB).", true);
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    const result = validateLicensesJson(e.target.result);
    if (!result.ok) {
      showMessage(statusEl, `Import failed: ${result.error}`, true);
      return;
    }

    const incoming = result.data.licenses;
    const before = allowlist.length;
    mergeIntoAllowlist(incoming);
    const added = allowlist.length - before;

    renderAllowlistTable();
    showMessage(
      statusEl,
      `Imported ${incoming.length} entr${incoming.length === 1 ? "y" : "ies"}; ${added} new, ${incoming.length - added} duplicate(s) skipped.`
    );
    // Reset the file input so the same file can be re-imported after changes
    document.getElementById("import-file").value = "";
  };
  reader.onerror = () => {
    showMessage(statusEl, "Could not read the file.", true);
  };
  reader.readAsText(file);
}

// ---------------------------------------------------------------------------
// Download handlers
// ---------------------------------------------------------------------------

function handleDownloadCsv() {
  if (session.length === 0) {
    const statusEl = document.getElementById("gen-status");
    showMessage(statusEl, "No keys in this session to export.", true);
    return;
  }
  const csv = buildPrivateCsv();
  downloadText("ejec-private-keys.csv", csv);
}

function handleDownloadJson() {
  if (allowlist.length === 0) {
    const statusEl = document.getElementById("gen-status");
    showMessage(statusEl, "Allowlist is empty — generate or import licenses first.", true);
    return;
  }
  const json = buildLicensesJson();
  // Security assertion
  try {
    assertNoPlaintext(json);
  } catch (err) {
    alert(err.message);
    return;
  }
  downloadText("licenses.json", json);
}

// ---------------------------------------------------------------------------
// Clear session results
// ---------------------------------------------------------------------------

function handleClearResults() {
  if (session.length > 0) {
    const confirmed = confirm(
      "Clear all plaintext keys from this session?\n\n" +
      "WARNING: If you have not downloaded the CSV, these keys will be permanently lost. " +
      "The corresponding hashes remain in the allowlist table below."
    );
    if (!confirmed) return;
  }
  session = [];
  renderResultsTable();
  document.getElementById("bulk-actions").setAttribute("hidden", "");
  const statusEl = document.getElementById("gen-status");
  showMessage(statusEl, "Session results cleared. Plaintext keys have been removed from memory.");
}

// ---------------------------------------------------------------------------
// Initialise event listeners
// ---------------------------------------------------------------------------

function init() {
  // Generate form
  document.getElementById("gen-form").addEventListener("submit", (event) => {
    event.preventDefault();
    handleGenerate();
  });

  // Publish directly through GitHub's repository contents API.
  document.getElementById("publish-btn").addEventListener("click", handlePublish);

  // Copy All button
  document.getElementById("copy-all-btn").addEventListener("click", async (e) => {
    const keys = session.map((s) => s.key).join("\n");
    await copyText(keys, e.currentTarget);
  });

  // Download CSV
  document.getElementById("download-csv-btn").addEventListener("click", handleDownloadCsv);

  // Download licenses.json
  document.getElementById("download-json-btn").addEventListener("click", handleDownloadJson);

  // Download updated licenses.json (from allowlist section)
  document.getElementById("download-json-btn-2").addEventListener("click", handleDownloadJson);

  // Clear results
  document.getElementById("clear-btn").addEventListener("click", handleClearResults);

  // Import file input
  const importFile = document.getElementById("import-file");
  importFile.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) handleImport(file);
  });

  // Import drag-and-drop on the import zone
  const importZone = document.getElementById("import-zone");
  importZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    importZone.classList.add("drag-over");
  });
  importZone.addEventListener("dragleave", () => {
    importZone.classList.remove("drag-over");
  });
  importZone.addEventListener("drop", (e) => {
    e.preventDefault();
    importZone.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (file) handleImport(file);
  });
  // Initial renders
  renderResultsTable();
  renderAllowlistTable();
  void loadPublishedAllowlist();
}

// Run after DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

// ---------------------------------------------------------------------------
// Export test surface (accessed by tests/license-tests.js via window)
// ---------------------------------------------------------------------------
window.__ejec__ = {
  ALPHABET,
  KEY_LENGTH,
  GROUP_SIZE,
  GROUP_COUNT,
  HASH_HEX_LENGTH,
  generateRawKey,
  formatKey,
  normaliseKey,
  sha256Hex,
  isValidHash,
  isValidStatus,
  validateLicensesJson,
  csvEscape,
  mergeIntoAllowlist,
  buildLicensesJson,
  buildPrivateCsv,
  assertNoPlaintext,
  // Expose live state references for test inspection
  getSession: () => session,
  getAllowlist: () => allowlist,
  resetState: () => { session = []; allowlist = []; },
};
