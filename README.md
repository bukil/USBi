# EJEC License Generator

A fully static, dependency-free license-management website for the **EJEC** macOS application, designed to run on **GitHub Pages** with zero server infrastructure.

---

## How licensing works

EJEC uses a **hash-only** licensing model:

1. The admin generates a cryptographically random 25-character product key in the browser.
2. The browser computes the **SHA-256 hash** of the normalised key (uppercase, no hyphens).
3. Only the **hash** is saved to `licenses.json` — the plaintext key is shown once in the browser and then discarded.
4. The admin commits the updated `licenses.json` to GitHub and GitHub Pages publishes it.
5. When a customer enters their key in the EJEC app, the app normalises it, hashes it, downloads `licenses.json`, and checks whether a matching hash with `"status": "active"` exists.

---

## Why only hashes are published

GitHub Pages is a **public, read-only** static host. There is no server-side secret and no way to prevent anyone from reading the repository. Publishing only SHA-256 hashes means:

- An observer who reads `licenses.json` cannot reconstruct any valid product key.
- Even knowing the hash algorithm does not help — SHA-256 is a one-way function; brute-forcing a 25-character key from a 128-bit-equivalent random alphabet is computationally infeasible.
- No signing secret needs to be stored anywhere.

---

## Product-key format

| Property | Value |
|---|---|
| Length | 25 characters (normalised) |
| Display | `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` |
| Alphabet | `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` |
| Excluded | `0`, `O`, `1`, `I` (visually ambiguous) |
| Entropy source | `crypto.getRandomValues()` — never `Math.random()` |

---

## How to generate licenses

1. Open `admin.html` in a modern browser (locally or via your GitHub Pages URL). The console loads the latest committed `licenses.json` directly from GitHub before enabling generation.
2. Enter a quantity (1–100), and optionally fill in customer name, email, and reference.
3. Enter a fine-grained GitHub token with `Contents: Read and write` access to `bukil/USBi` if you want the site to publish automatically.
4. Click **Generate**. With automatic publishing enabled, the updated hash allowlist is committed directly to GitHub.
5. Each key is displayed once in the **Session Results** table.
6. Click **Download Private CSV** to save the plaintext keys.
7. The manual **Download Updated licenses.json** option remains available as a fallback.

The token is held only in the password field, is never persisted, and is cleared after every publishing attempt. Use a fine-grained token restricted to the `bukil/USBi` repository with only `Contents: Read and write` permission.

If the published allowlist cannot be loaded, generation remains disabled to prevent accidentally overwriting existing licenses. When running locally with `file://`, import the current `licenses.json` manually before generating keys.

> ⚠️ **If you close the browser or clear results without downloading the CSV, the plaintext keys are permanently lost.** They are never stored in `localStorage`, cookies, or any file.

---

## How to publish `licenses.json`

### Automatic publishing

1. Create a fine-grained GitHub personal access token restricted to the `bukil/USBi` repository.
2. Grant only `Contents: Read and write` repository permission.
3. Enter the token in the generator's **Publish to GitHub** section.
4. Leave **Publish automatically after generating** enabled and generate the license.
5. The site fetches the latest allowlist, merges the new hashes, and commits `licenses.json` directly through GitHub's repository contents API.

The token is not saved to browser storage and is cleared from the page after every publishing attempt. Revoke and replace the token immediately if you believe it has been exposed.

### Manual fallback

1. Download the updated `licenses.json` from the website.
2. Replace the existing `licenses.json` in your GitHub repository root.
3. Commit and push:
   ```bash
   git add licenses.json
   git commit -m "Add licenses for [customer]"
   git push
   ```
4. GitHub Pages will publish the update automatically (usually within 30–60 seconds).
5. Send only the **plaintext product key** to the customer — never share the CSV or the hash.

Generating a key **does not** activate it. The key only becomes valid after its hash is live in `licenses.json`.

---

## How to revoke a license

1. Open `admin.html`.
2. **Import** the current `licenses.json` via the Import section.
3. In the **License Management** table, find the entry by customer name, email, or shortened hash.
4. Click **Revoke**.
5. Download the updated `licenses.json` and commit it.

The EJEC app checks `"status": "active"` on every validation. A revoked entry (`"status": "revoked"`) will cause validation to fail immediately.

---

## How to reactivate a revoked license

Follow the same steps as revocation, but click **Reactivate** instead of **Revoke**. The entry's status changes back to `"active"`.

---

## How to deploy with GitHub Pages

1. Create a new **public** GitHub repository (e.g. `ejec-license`).
2. Copy all files from this project into the repository root:
   - `index.html`
   - `styles.css`
   - `app.js`
   - `licenses.json`
   - `.nojekyll`
   - `README.md`
   - `tests/license-tests.html`
   - `tests/license-tests.js`
3. In the repository **Settings → Pages**, set the source to the `main` branch, root folder.
4. GitHub Pages will serve your site at `https://<username>.github.io/<repo>/`.

> The `.nojekyll` file prevents GitHub Pages from running Jekyll, which would interfere with files whose names begin with an underscore.

---

## Why GitHub Pages cannot automatically write to `licenses.json`

GitHub Pages serves **static files only**. There is no server-side code execution. Writing to a file in the repository requires a Git commit, which requires authentication credentials that must **never** be embedded in a public website. The manual commit step is a deliberate security boundary.

---

## Why the private CSV must not be committed

The private CSV contains **plaintext product keys**. Anyone with access to the repository — including historical commits — could read every key and activate software without a legitimate license. Always store the CSV in a private, encrypted location (e.g. a password manager or encrypted drive) and delete it when no longer needed.

---

## Warning: clearing browser results

When you click **Clear Results**, all plaintext keys are removed from browser memory. **If you have not downloaded the CSV, those keys are permanently lost.** The corresponding hashes remain in the allowlist table and in `licenses.json`, but there is no way to recover the original keys. The customer already has their key, so this is usually acceptable — but ensure you have saved the CSV first.

---

## How to run the browser tests

1. Open `tests/license-tests.html` in any modern browser.
   - Locally: open the file directly (`file://` protocol).
   - On GitHub Pages: navigate to `https://<username>.github.io/<repo>/tests/license-tests.html`.
2. Tests run automatically and results are displayed on the page.
3. All tests should show ✓ (green). Any ✗ (red) indicates a regression.

No build step, no Node.js, no npm — the tests run purely in the browser.

---

## `licenses.json` schema

```json
{
  "version": 1,
  "licenses": [
    {
      "hash": "<64-character-lowercase-sha256-hex>",
      "status": "active",
      "createdAt": "2026-10-15T12:00:00.000Z",
      "customerName": "Acme Corp",
      "customerEmail": "alice@example.com",
      "reference": "ORDER-1042"
    }
  ]
}
```

- `hash` and `status` are read by the EJEC macOS app.
- All other fields are administrative metadata visible only to the admin.
- **Plaintext keys are never stored here.**

---

## Security properties

| Property | Value |
|---|---|
| External dependencies | None |
| External scripts / fonts | None |
| Analytics | None |
| Network requests | Optional: `./licenses.json` from same origin only |
| Content Security Policy | Strict (`default-src 'self'`) |
| Plaintext key storage | In-memory only; cleared on page reload or "Clear Results" |
| Secrets in source code | None |
| `innerHTML` with user data | Never — all user content via `textContent` / DOM construction |

---

## File inventory

| File | Purpose |
|---|---|
| `index.html` | Customer-facing license verification page |
| `admin.html` | Admin UI — generate, publish, manage, and export licenses |
| `user.js` | Customer-side local hashing and license verification |
| `styles.css` | macOS-inspired design system; full light/dark mode |
| `app.js` | All cryptographic and UI logic; no dependencies |
| `licenses.json` | SHA-256 hash allowlist committed to the repository |
| `.nojekyll` | Disables Jekyll on GitHub Pages |
| `README.md` | This file |
| `tests/license-tests.html` | Browser test runner |
| `tests/license-tests.js` | Browser test suite |
