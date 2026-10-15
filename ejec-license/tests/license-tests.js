/**
 * EJEC License Generator — Browser Test Suite
 * Pure vanilla JS, no external test frameworks.
 * Run by opening tests/license-tests.html in any modern browser.
 *
 * Tests cover every requirement listed in the specification.
 */

"use strict";

// ---------------------------------------------------------------------------
// Mini test runner
// ---------------------------------------------------------------------------

const results = [];

/**
 * Assert `condition` is truthy; record pass or fail.
 * @param {string} name
 * @param {boolean|Promise<boolean>} condition
 * @param {string} [detail]
 */
async function test(name, condition, detail = "") {
  let passed;
  try {
    const resolved = await condition;
    passed = !!resolved;
  } catch (err) {
    passed = false;
    detail = detail || err.message;
  }
  results.push({ name, passed, detail });
}

/**
 * Render all recorded results into the page.
 */
function renderResults() {
  const api = window.__ejec__;
  const container = document.getElementById("results");
  if (!container) return;

  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;

  const summary = document.createElement("div");
  summary.className = failed === 0 ? "summary summary-pass" : "summary summary-fail";
  summary.textContent = `${passed} / ${total} tests passed${failed > 0 ? ` — ${failed} FAILED` : " ✓"}`;
  container.appendChild(summary);

  for (const r of results) {
    const row = document.createElement("div");
    row.className = r.passed ? "test-row pass" : "test-row fail";

    const icon = document.createElement("span");
    icon.className = "test-icon";
    icon.textContent = r.passed ? "✓" : "✗";
    row.appendChild(icon);

    const label = document.createElement("span");
    label.className = "test-label";
    label.textContent = r.name;
    row.appendChild(label);

    if (!r.passed && r.detail) {
      const detail = document.createElement("span");
      detail.className = "test-detail";
      detail.textContent = ` — ${r.detail}`;
      row.appendChild(detail);
    }

    container.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Helpers used only in tests
// ---------------------------------------------------------------------------

/** Check that every character in `s` is in ALPHABET. */
function allCharsInAlphabet(s, alphabet) {
  return [...s].every((c) => alphabet.includes(c));
}

/** Check that none of the ambiguous characters appear in `s`. */
function noAmbiguousChars(s) {
  return !["0", "O", "1", "I"].some((c) => s.includes(c));
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

async function runTests() {
  const api = window.__ejec__;
  if (!api) {
    document.getElementById("results").textContent =
      "Error: app.js not loaded. Open this page via license-tests.html.";
    return;
  }

  // Reset in-memory state before tests
  api.resetState();

  // =========================================================================
  // 1. Key structure tests
  // =========================================================================

  // 1a. Normalised key is exactly 25 characters
  const rawKey1 = api.generateRawKey();
  await test(
    "Normalised key contains exactly 25 characters",
    rawKey1.length === api.KEY_LENGTH,
    `Got ${rawKey1.length}`
  );

  // 1b. Formatted key has five groups of five (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)
  const formatted1 = api.formatKey(rawKey1);
  const parts = formatted1.split("-");
  await test(
    "Formatted key has five groups of five separated by hyphens",
    parts.length === 5 && parts.every((p) => p.length === 5),
    `Formatted: ${formatted1}`
  );

  // 1c. Total display length is 29 (25 chars + 4 hyphens)
  await test(
    "Formatted key display length is 29 characters",
    formatted1.length === 29,
    `Got ${formatted1.length}`
  );

  // 1d. Only approved alphabet is used
  await test(
    "Only approved alphabet characters are used",
    allCharsInAlphabet(rawKey1, api.ALPHABET),
    `Key: ${rawKey1}`
  );

  // 1e. Ambiguous characters (0, O, 1, I) never appear
  await test(
    "Ambiguous characters (0, O, 1, I) never appear",
    noAmbiguousChars(rawKey1),
    `Key: ${rawKey1}`
  );

  // 1f. Generate many keys — all pass alphabet + no-ambiguous checks
  const sampleSize = 200;
  let allPass = true;
  for (let i = 0; i < sampleSize; i++) {
    const k = api.generateRawKey();
    if (
      k.length !== api.KEY_LENGTH ||
      !allCharsInAlphabet(k, api.ALPHABET) ||
      !noAmbiguousChars(k)
    ) {
      allPass = false;
      break;
    }
  }
  await test(
    `${sampleSize} random keys all pass alphabet and no-ambiguous-char checks`,
    allPass
  );

  // =========================================================================
  // 2. Normalisation tests
  // =========================================================================

  // 2a. normaliseKey strips hyphens
  const withHyphens = "ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2";
  const normed = api.normaliseKey(withHyphens);
  await test(
    "normaliseKey strips hyphens",
    !normed.includes("-"),
    `Result: ${normed}`
  );

  // 2b. normaliseKey converts to uppercase
  const lower = "abcde-fghjk-lmnpq-rstuv-wxyz2";
  const normedLower = api.normaliseKey(lower);
  await test(
    "normaliseKey converts to uppercase",
    normedLower === normedLower.toUpperCase(),
    `Result: ${normedLower}`
  );

  // 2c. normaliseKey strips whitespace
  const withSpaces = "ABCDE FGHJK LMNPQ RSTUV WXYZ2";
  const normedSpaces = api.normaliseKey(withSpaces);
  await test(
    "normaliseKey strips whitespace",
    !normedSpaces.includes(" "),
    `Result: ${normedSpaces}`
  );

  // 2d. normaliseKey throws if result is not 25 chars
  let threw = false;
  try { api.normaliseKey("TOOSHORT"); } catch { threw = true; }
  await test(
    "normaliseKey throws when normalised result ≠ 25 characters",
    threw
  );

  // =========================================================================
  // 3. Hash tests
  // =========================================================================

  // 3a. sha256Hex returns exactly 64 lowercase hex characters
  const hash1 = await api.sha256Hex("ABCDEFGHJKLMNPQRSTUVWXYZ2");
  await test(
    "SHA-256 hash is exactly 64 lowercase hex characters",
    api.isValidHash(hash1),
    `Hash: ${hash1}`
  );

  // 3b. Hashing ignores hyphens — formatted and raw keys produce the same hash
  const raw = "ABCDEFGHJKLMNPQRSTUVWXYZ2";
  const fmt = "ABCDE-FGHJK-LMNPQ-RSTUV-WXY Z2".replace(/\s/g,"");// 25 chars with hyphen
  const fmtFormatted = "ABCDE-FGHJK-LMNPQ-RSTUV-WXY";  // wrong length for illustration
  // Use a proper 25-char formatted version
  const rawForHash = "ABCDEFGHJKLMNPQRSTUVWXYZ2";
  const fmtForHash = "ABCDE-FGHJK-LMNPQ-RSTUV-WXY Z2"; // still 25 chars after normalise
  const hashRaw = await api.sha256Hex(api.normaliseKey(rawForHash));
  const hashFmt = await api.sha256Hex(api.normaliseKey("ABCDE-FGHJK-LMNPQ-RSTU-VWXYZ2".slice(0,29)));
  // Simpler: hash of raw == hash of formatted version
  const rawK = "ABCDEFGHJKLMNPQRSTUVWXYZ2"; // 25
  const fmtK = "ABCDE-FGHJK-LMNPQ-RSTU-VWX"; // NOT same chars—use formatKey instead
  const rawK2 = api.generateRawKey();
  const fmtK2 = api.formatKey(rawK2);
  const hashOfRaw = await api.sha256Hex(rawK2);
  const hashOfFmt = await api.sha256Hex(api.normaliseKey(fmtK2));
  await test(
    "SHA-256 of raw key equals SHA-256 of its formatted (hyphenated) version",
    hashOfRaw === hashOfFmt,
    `raw hash: ${hashOfRaw}\nfmt hash: ${hashOfFmt}`
  );

  // 3c. Same key always produces the same hash (determinism)
  const fixedKey = "ABCDEFGHJKLMNPQRSTUVWXYZ2";
  const h1 = await api.sha256Hex(fixedKey);
  const h2 = await api.sha256Hex(fixedKey);
  await test(
    "Same key always produces the same SHA-256 hash (deterministic)",
    h1 === h2,
    `h1: ${h1} h2: ${h2}`
  );

  // 3d. Different keys produce different hashes
  const keyA = api.generateRawKey();
  const keyB = api.generateRawKey();
  const hashA = await api.sha256Hex(keyA);
  const hashB = await api.sha256Hex(keyB);
  await test(
    "Different keys produce different SHA-256 hashes",
    hashA !== hashB,
    `keyA: ${keyA} keyB: ${keyB}`
  );

  // 3e. Known SHA-256 test vector
  // SHA-256("ABC") = b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78
  const knownHash = await api.sha256Hex("ABC");
  await test(
    "SHA-256 test vector: SHA-256('ABC') is correct",
    knownHash === "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
    `Got: ${knownHash}`
  );

  // =========================================================================
  // 4. Merge / allowlist tests
  // =========================================================================

  api.resetState();

  const entry1 = {
    hash: "a".repeat(64),
    status: "active",
    createdAt: "2026-01-01T00:00:00.000Z",
    customerName: "Alice",
    customerEmail: "alice@example.com",
    reference: "REF-1",
  };
  const entry2 = {
    hash: "b".repeat(64),
    status: "revoked",
    createdAt: "2026-01-02T00:00:00.000Z",
    customerName: "Bob",
    customerEmail: "bob@example.com",
    reference: "REF-2",
  };

  api.mergeIntoAllowlist([entry1, entry2]);
  await test(
    "Existing allowlist entries survive merging",
    api.getAllowlist().length === 2
  );

  // 4a. Duplicate hashes are rejected
  api.mergeIntoAllowlist([entry1]); // duplicate
  await test(
    "Duplicate hashes are rejected on merge",
    api.getAllowlist().length === 2, // still 2
    `Length after re-merge: ${api.getAllowlist().length}`
  );

  // 4b. New unique entries are appended
  const entry3 = { hash: "c".repeat(64), status: "active",
    createdAt: "2026-01-03T00:00:00.000Z", customerName: "", customerEmail: "", reference: "" };
  api.mergeIntoAllowlist([entry3]);
  await test(
    "New unique entries are appended to the allowlist",
    api.getAllowlist().length === 3
  );

  // =========================================================================
  // 5. JSON validation tests
  // =========================================================================

  // 5a. Valid empty file
  const validEmpty = JSON.stringify({ version: 1, licenses: [] });
  await test(
    "Valid empty licenses.json is accepted",
    api.validateLicensesJson(validEmpty).ok
  );

  // 5b. Valid file with entries
  const validWithEntries = JSON.stringify({
    version: 1,
    licenses: [
      { hash: "d".repeat(64), status: "active", createdAt: "", customerName: "", customerEmail: "", reference: "" },
    ],
  });
  await test(
    "Valid licenses.json with entries is accepted",
    api.validateLicensesJson(validWithEntries).ok
  );

  // 5c. Wrong version
  const wrongVersion = JSON.stringify({ version: 2, licenses: [] });
  await test(
    "File with version ≠ 1 is rejected",
    !api.validateLicensesJson(wrongVersion).ok
  );

  // 5d. Missing licenses array
  const noLicenses = JSON.stringify({ version: 1 });
  await test(
    "File missing 'licenses' array is rejected",
    !api.validateLicensesJson(noLicenses).ok
  );

  // 5e. Invalid hash (not 64 chars)
  const badHash = JSON.stringify({
    version: 1,
    licenses: [{ hash: "abc", status: "active" }],
  });
  await test(
    "Entry with hash shorter than 64 hex chars is rejected",
    !api.validateLicensesJson(badHash).ok
  );

  // 5f. Invalid hash (uppercase)
  const upperHash = JSON.stringify({
    version: 1,
    licenses: [{ hash: "A".repeat(64), status: "active" }],
  });
  await test(
    "Entry with uppercase hash characters is rejected",
    !api.validateLicensesJson(upperHash).ok
  );

  // 5g. Invalid status
  const badStatus = JSON.stringify({
    version: 1,
    licenses: [{ hash: "e".repeat(64), status: "pending" }],
  });
  await test(
    "Entry with status other than 'active' or 'revoked' is rejected",
    !api.validateLicensesJson(badStatus).ok
  );

  // 5h. Duplicate hash in import
  const dupHash = JSON.stringify({
    version: 1,
    licenses: [
      { hash: "f".repeat(64), status: "active" },
      { hash: "f".repeat(64), status: "revoked" },
    ],
  });
  await test(
    "File with duplicate hashes is rejected",
    !api.validateLicensesJson(dupHash).ok
  );

  // 5i. Invalid JSON
  await test(
    "Non-JSON text is rejected",
    !api.validateLicensesJson("not-json").ok
  );

  // =========================================================================
  // 6. Export tests
  // =========================================================================

  api.resetState();

  // Synthesise a session entry and allowlist entry for export tests.
  // We cannot call the real generate workflow in tests without async key gen,
  // so we directly push into state via the exposed reset + merge.
  const testHash = "9".repeat(64);
  api.mergeIntoAllowlist([{
    hash: testHash,
    status: "active",
    createdAt: "2026-10-15T12:00:00.000Z",
    customerName: "Test User",
    customerEmail: "test@example.com",
    reference: "TEST-001",
  }]);

  // 6a. Downloaded licenses.json contains no plaintext key
  // We manually add a fake session entry to test the assertion
  // (session is normally private; __ejec__.getSession() gives access)
  const fakeKey = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";
  api.getSession().push({
    key: fakeKey,
    hash: testHash,
    customerName: "Test User",
    customerEmail: "test@example.com",
    reference: "TEST-001",
    createdAt: "2026-10-15T12:00:00.000Z",
  });

  const jsonOut = api.buildLicensesJson();

  await test(
    "Plaintext key never appears in exported licenses.json",
    !jsonOut.includes(fakeKey.replace(/-/g, "")) && !jsonOut.includes(fakeKey),
    `JSON snippet: ${jsonOut.slice(0, 200)}`
  );

  // 6b. assertNoPlaintext does not throw when no key is in the JSON
  const safeJson = JSON.stringify({ version: 1, licenses: [{ hash: testHash, status: "active" }] });
  let assertPassed = true;
  try { api.assertNoPlaintext(safeJson); } catch { assertPassed = false; }
  await test(
    "assertNoPlaintext passes when JSON contains only hashes",
    assertPassed
  );

  // 6c. Exported JSON is valid licenses.json
  const parseResult = api.validateLicensesJson(jsonOut);
  await test(
    "Exported licenses.json passes validation",
    parseResult.ok,
    parseResult.error || ""
  );

  // 6d. Revoked entries remain revoked after export
  api.getAllowlist()[0].status = "revoked";
  const jsonRevoked = api.buildLicensesJson();
  const parsedRevoked = JSON.parse(jsonRevoked);
  await test(
    "Revoked entries remain revoked in exported licenses.json",
    parsedRevoked.licenses[0].status === "revoked"
  );

  // =========================================================================
  // 7. CSV escaping tests
  // =========================================================================

  await test(
    "csvEscape: plain value is unchanged",
    api.csvEscape("hello") === "hello"
  );

  await test(
    "csvEscape: value with comma is quoted",
    api.csvEscape("Acme, Inc.") === '"Acme, Inc."'
  );

  await test(
    "csvEscape: value with double-quote is escaped",
    api.csvEscape('say "hello"') === '"say ""hello"""'
  );

  await test(
    "csvEscape: value with newline is quoted",
    api.csvEscape("line1\nline2") === '"line1\nline2"'
  );

  await test(
    "csvEscape: value with carriage return is quoted",
    api.csvEscape("line1\rline2") === '"line1\rline2"'
  );

  await test(
    "csvEscape: empty string is unchanged",
    api.csvEscape("") === ""
  );

  await test(
    "csvEscape: null/undefined coerces to empty string",
    api.csvEscape(null) === "" && api.csvEscape(undefined) === ""
  );

  // =========================================================================
  // 8. isValidHash / isValidStatus tests
  // =========================================================================

  await test("isValidHash: 64 lowercase hex chars passes", api.isValidHash("a".repeat(64)));
  await test("isValidHash: 63 chars fails", !api.isValidHash("a".repeat(63)));
  await test("isValidHash: 65 chars fails", !api.isValidHash("a".repeat(65)));
  await test("isValidHash: uppercase hex fails", !api.isValidHash("A".repeat(64)));
  await test("isValidHash: non-hex chars fail", !api.isValidHash("g".repeat(64)));

  await test("isValidStatus: 'active' passes", api.isValidStatus("active"));
  await test("isValidStatus: 'revoked' passes", api.isValidStatus("revoked"));
  await test("isValidStatus: 'pending' fails", !api.isValidStatus("pending"));
  await test("isValidStatus: empty string fails", !api.isValidStatus(""));

  // =========================================================================
  // Render
  // =========================================================================
  renderResults();
}

// Run when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", runTests);
} else {
  runTests();
}
