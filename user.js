"use strict";

const LICENSE_API_URL = "https://api.github.com/repos/bukil/USBi/contents/licenses.json?ref=main";
const LICENSE_KEY_LENGTH = 25;

function normalizeLicenseKey(value) {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function formatLicenseKey(value) {
  return normalizeLicenseKey(value)
    .slice(0, LICENSE_KEY_LENGTH)
    .match(/.{1,5}/g)?.join("-") ?? "";
}

async function hashLicenseKey(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function fetchAllowlist() {
  const response = await fetch(LICENSE_API_URL, {
    cache: "no-store",
    headers: {
      Accept: "application/vnd.github.raw+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) throw new Error("License verification is temporarily unavailable.");
  const body = await response.json();
  if (body.version !== 1 || !Array.isArray(body.licenses)) {
    throw new Error("The license directory returned an invalid response.");
  }
  return body.licenses;
}

function showResult(state, title, message) {
  const result = document.getElementById("verification-result");
  result.dataset.state = state;
  document.getElementById("result-title").textContent = title;
  document.getElementById("result-message").textContent = message;
  result.hidden = false;
}

const form = document.getElementById("verify-form");
const keyInput = document.getElementById("license-key");
const error = document.getElementById("license-key-error");
const verifyButton = document.getElementById("verify-button");

keyInput.addEventListener("input", () => {
  keyInput.value = formatLicenseKey(keyInput.value);
  keyInput.removeAttribute("aria-invalid");
  error.hidden = true;
  document.getElementById("verification-result").hidden = true;
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  const normalizedKey = normalizeLicenseKey(keyInput.value);
  if (normalizedKey.length !== LICENSE_KEY_LENGTH) {
    keyInput.setAttribute("aria-invalid", "true");
    error.hidden = false;
    keyInput.focus();
    return;
  }

  verifyButton.disabled = true;
  verifyButton.textContent = "Verifying…";
  try {
    const [hash, licenses] = await Promise.all([hashLicenseKey(normalizedKey), fetchAllowlist()]);
    const license = licenses.find(item => item.hash?.toLowerCase() === hash);
    if (license?.status === "active") {
      showResult("success", "License is active", "This product key is ready to activate in EJEC.");
    } else if (license?.status === "revoked") {
      showResult("error", "License was revoked", "Contact EJEC support if you believe this is a mistake.");
    } else {
      showResult("error", "License not found", "Check the product key and try again.");
    }
  } catch (verificationError) {
    showResult("error", "Couldn’t verify license", verificationError.message);
  } finally {
    verifyButton.disabled = false;
    verifyButton.textContent = "Verify License";
  }
});
