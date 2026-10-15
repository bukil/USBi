/**
 * Node.js test runner for EJEC license logic.
 * Node v26 has several read-only globalThis properties (crypto, navigator).
 * Use Object.defineProperty to override them safely.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TextEncoder } from "node:util";
import path from "node:path";

// ------ Shim browser globals ------
const noop = () => {};
const fakeElement = () => ({
  textContent: "",
  className: "",
  style: {},
  title: "",
  disabled: false,
  hidden: false,
  value: "",
  files: [],
  addEventListener: noop,
  removeAttribute: noop,
  setAttribute: noop,
  removeEventListener: noop,
  appendChild: noop,
  classList: { add: noop, remove: noop },
  _timer: null,
});

// Node 26 locks window, navigator — use defineProperty
Object.defineProperty(globalThis, "window", { value: globalThis, writable: true, configurable: true });
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: async () => {} } },
  writable: true, configurable: true,
});

globalThis.TextEncoder = TextEncoder;
globalThis.document = {
  readyState: "complete",
  getElementById: () => fakeElement(),
  createElement: () => fakeElement(),
  addEventListener: noop,
  body: { appendChild: noop },
};
globalThis.confirm = () => false;
globalThis.alert = noop;
globalThis.setTimeout = (fn, ms) => {}; // prevent timer side-effects
globalThis.clearTimeout = noop;
// Stub Blob + URL.createObjectURL for download helpers
globalThis.Blob = class { constructor(parts, opts) {} };
globalThis.URL = { createObjectURL: () => "blob:fake", revokeObjectURL: noop };

// Load app.js via eval — it uses "use strict" but no ES module syntax
const __dir = path.dirname(fileURLToPath(import.meta.url));
const appSrc = readFileSync(path.join(__dir, "..", "app.js"), "utf8");
eval(appSrc);

const api = globalThis.__ejec__;

// ------ Mini test runner ------
let passed = 0, failed = 0;
const failures = [];

async function test(name, conditionFn) {
  try {
    const result = await conditionFn();
    if (result) {
      passed++;
      process.stdout.write(`  ✓ ${name}\n`);
    } else {
      failed++;
      failures.push(name);
      process.stdout.write(`  ✗ ${name}\n`);
    }
  } catch (err) {
    failed++;
    failures.push(`${name}: ${err.message}`);
    process.stdout.write(`  ✗ ${name} [THREW: ${err.message}]\n`);
  }
}

function allCharsInAlphabet(s, alphabet) {
  return [...s].every((c) => alphabet.includes(c));
}
function noAmbiguousChars(s) {
  return !["0", "O", "1", "I"].some((c) => s.includes(c));
}

console.log("\n🧪 EJEC License Generator — Node.js Test Runner\n");

// 1. Key structure
api.resetState();
const rawKey1 = api.generateRawKey();
await test("Normalised key is exactly 25 characters", () => rawKey1.length === 25);

const fmt = api.formatKey(rawKey1);
const parts = fmt.split("-");
await test("Formatted key has 5 groups of 5", () => parts.length === 5 && parts.every(p => p.length === 5));
await test("Formatted key display length is 29", () => fmt.length === 29);
await test("All chars in approved alphabet", () => allCharsInAlphabet(rawKey1, api.ALPHABET));
await test("No ambiguous characters (0,O,1,I)", () => noAmbiguousChars(rawKey1));

// 200-key bulk check
let allPass = true;
for (let i = 0; i < 200; i++) {
  const k = api.generateRawKey();
  if (k.length !== 25 || !allCharsInAlphabet(k, api.ALPHABET) || !noAmbiguousChars(k)) {
    allPass = false; break;
  }
}
await test("200 random keys all pass format+alphabet checks", () => allPass);

// 2. Normalisation
await test("normaliseKey strips hyphens", () => !api.normaliseKey("ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2").includes("-"));
await test("normaliseKey uppercases", () => {
  const n = api.normaliseKey("abcde-fghjk-lmnpq-rstuv-wxyz2");
  return n === n.toUpperCase();
});
await test("normaliseKey strips whitespace", () => !api.normaliseKey("ABCDE FGHJK LMNPQ RSTUV WXYZ2").includes(" "));
await test("normaliseKey throws for wrong length", () => {
  try { api.normaliseKey("TOOSHORT"); return false; } catch { return true; }
});

// 3. Hashing
const h = await api.sha256Hex("ABCDEFGHJKLMNPQRSTUVWXYZ2");
await test("SHA-256 hash is 64 lowercase hex chars", () => api.isValidHash(h));

const rawK = api.generateRawKey();
const hashRaw = await api.sha256Hex(rawK);
const hashFmt = await api.sha256Hex(api.normaliseKey(api.formatKey(rawK)));
await test("Hash of raw key == hash of formatted version", () => hashRaw === hashFmt);

await test("SHA-256 is deterministic", async () => {
  const a = await api.sha256Hex("ABCDEFGHJKLMNPQRSTUVWXYZ2");
  const b = await api.sha256Hex("ABCDEFGHJKLMNPQRSTUVWXYZ2");
  return a === b;
});
await test("Different keys produce different hashes", async () => {
  const hA = await api.sha256Hex(api.generateRawKey());
  const hB = await api.sha256Hex(api.generateRawKey());
  return hA !== hB;
});
await test("SHA-256 known vector: SHA-256('ABC')", async () => {
  const got = await api.sha256Hex("ABC");
  return got === "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78";
});

// 4. Merge
api.resetState();
const e1 = { hash: "a".repeat(64), status: "active", createdAt: "", customerName: "", customerEmail: "", reference: "" };
const e2 = { hash: "b".repeat(64), status: "revoked", createdAt: "", customerName: "", customerEmail: "", reference: "" };
api.mergeIntoAllowlist([e1, e2]);
await test("Entries survive merge", () => api.getAllowlist().length === 2);
api.mergeIntoAllowlist([e1]);
await test("Duplicate hashes are rejected on merge", () => api.getAllowlist().length === 2);
const e3 = { hash: "c".repeat(64), status: "active", createdAt: "", customerName: "", customerEmail: "", reference: "" };
api.mergeIntoAllowlist([e3]);
await test("New unique entries are appended", () => api.getAllowlist().length === 3);

// 5. JSON validation
await test("Valid empty JSON accepted", () => api.validateLicensesJson(JSON.stringify({ version: 1, licenses: [] })).ok);
await test("Wrong version rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 2, licenses: [] })).ok);
await test("Missing licenses array rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 1 })).ok);
await test("Bad hash (short) rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 1, licenses: [{ hash: "abc", status: "active" }] })).ok);
await test("Uppercase hash rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 1, licenses: [{ hash: "A".repeat(64), status: "active" }] })).ok);
await test("Bad status rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 1, licenses: [{ hash: "e".repeat(64), status: "pending" }] })).ok);
await test("Duplicate hashes in import rejected", () => !api.validateLicensesJson(JSON.stringify({ version: 1, licenses: [{ hash: "f".repeat(64), status: "active" }, { hash: "f".repeat(64), status: "revoked" }] })).ok);
await test("Non-JSON rejected", () => !api.validateLicensesJson("not-json").ok);

// 6. Export safety
api.resetState();
const testHash = "9".repeat(64);
api.mergeIntoAllowlist([{ hash: testHash, status: "active", createdAt: "", customerName: "", customerEmail: "", reference: "" }]);
const fakeKey = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";
api.getSession().push({ key: fakeKey, hash: testHash, customerName: "", customerEmail: "", reference: "", createdAt: "" });

const jsonOut = api.buildLicensesJson();
await test("Plaintext key never appears in exported licenses.json", () => !jsonOut.includes("AAAAA") && !jsonOut.includes("BBBBB"));

let assertPassed = true;
try { api.assertNoPlaintext(JSON.stringify({ version: 1, licenses: [{ hash: testHash }] })); } catch { assertPassed = false; }
await test("assertNoPlaintext passes for hash-only JSON", () => assertPassed);

const parsed = api.validateLicensesJson(jsonOut);
await test("Exported JSON passes validation", () => parsed.ok);

api.getAllowlist()[0].status = "revoked";
const jsonRevoked = JSON.parse(api.buildLicensesJson());
await test("Revoked entry stays revoked after export", () => jsonRevoked.licenses[0].status === "revoked");

// 7. CSV escaping
await test("csvEscape: plain value unchanged", () => api.csvEscape("hello") === "hello");
await test("csvEscape: comma triggers quoting", () => api.csvEscape("Acme, Inc.") === '"Acme, Inc."');
await test("csvEscape: double-quote escaped", () => api.csvEscape('say "hello"') === '"say ""hello"""');
await test("csvEscape: newline triggers quoting", () => api.csvEscape("a\nb") === '"a\nb"');
await test("csvEscape: CR triggers quoting", () => api.csvEscape("a\rb") === '"a\rb"');
await test("csvEscape: empty string unchanged", () => api.csvEscape("") === "");
await test("csvEscape: null coerces to empty string", () => api.csvEscape(null) === "");
await test("csvEscape: undefined coerces to empty string", () => api.csvEscape(undefined) === "");

// 8. isValidHash / isValidStatus
await test("isValidHash: 64 lowercase hex passes", () => api.isValidHash("a".repeat(64)));
await test("isValidHash: 63 chars fails", () => !api.isValidHash("a".repeat(63)));
await test("isValidHash: 65 chars fails", () => !api.isValidHash("a".repeat(65)));
await test("isValidHash: uppercase fails", () => !api.isValidHash("A".repeat(64)));
await test("isValidHash: non-hex fails", () => !api.isValidHash("g".repeat(64)));
await test("isValidStatus: 'active' passes", () => api.isValidStatus("active"));
await test("isValidStatus: 'revoked' passes", () => api.isValidStatus("revoked"));
await test("isValidStatus: 'pending' fails", () => !api.isValidStatus("pending"));
await test("isValidStatus: '' fails", () => !api.isValidStatus(""));

// Summary
console.log(`\n${passed + failed} tests — ${passed} passed, ${failed} failed\n`);
if (failures.length > 0) {
  console.log("FAILURES:");
  failures.forEach(f => console.log(`  ✗ ${f}`));
  process.exit(1);
} else {
  console.log("✅ All tests passed!\n");
  process.exit(0);
}
