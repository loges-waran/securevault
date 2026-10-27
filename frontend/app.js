const form = document.querySelector("#file-form");
const fileInput = document.querySelector("#file-input");
const dropZone = document.querySelector("#drop-zone");
const filePrompt = document.querySelector("#file-prompt");
const fileDetail = document.querySelector("#file-detail");
const fileChip = document.querySelector("#file-chip");
const passwordInput = document.querySelector("#password-input");
const passwordHint = document.querySelector("#password-hint");
const visibilityToggle = document.querySelector("#visibility-toggle");
const submitButton = document.querySelector("#submit-button");
const submitLabel = document.querySelector("#submit-label");
const feedback = document.querySelector("#feedback");
const operationTitle = document.querySelector("#operation-title");
const operationStep = document.querySelector("#operation-step");
const modeTabs = [...document.querySelectorAll(".mode-tab")];

let mode = "encrypt";
const maxFileSize = 50 * 1024 * 1024;

function showFeedback(message, isError = false) {
  feedback.textContent = message;
  feedback.classList.toggle("is-error", isError);
  feedback.hidden = false;
}

function setMode(nextMode) {
  mode = nextMode;
  const isEncrypt = mode === "encrypt";
  modeTabs.forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  operationStep.textContent = isEncrypt ? "OPERATION 01" : "OPERATION 02";
  operationTitle.textContent = isEncrypt ? "Encrypt a file" : "Decrypt a file";
  submitLabel.textContent = isEncrypt ? "Encrypt file" : "Decrypt file";
  passwordHint.textContent = isEncrypt ? "8 characters minimum" : "Enter the original password";
  passwordInput.placeholder = isEncrypt ? "Create a strong passphrase" : "Enter your passphrase";
  passwordInput.autocomplete = isEncrypt ? "new-password" : "current-password";
  filePrompt.textContent = isEncrypt ? "Drop your file here" : "Drop an encrypted file here";
  feedback.hidden = true;
}

function displayFile(file) {
  if (!file) return;
  if (file.size > maxFileSize) {
    fileInput.value = "";
    fileChip.hidden = true;
    filePrompt.textContent = "Drop your file here";
    showFeedback("This file is larger than the 50 MiB limit.", true);
    return;
  }
  filePrompt.textContent = file.name;
  fileDetail.textContent = `${formatBytes(file.size)} · ready to ${mode}`;
  fileChip.textContent = file.name;
  fileChip.hidden = false;
  feedback.hidden = true;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function downloadName(response, file) {
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/i);
  if (match) return match[1];
  if (mode === "encrypt") return `${file.name}.svlt`;
  return file.name.toLowerCase().endsWith(".svlt")
    ? file.name.slice(0, -5) || "decrypted-file"
    : `${file.name}.decrypted`;
}

for (const tab of modeTabs) {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
}

fileInput.addEventListener("change", () => displayFile(fileInput.files[0]));

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
}

dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const transfer = new DataTransfer();
  transfer.items.add(file);
  fileInput.files = transfer.files;
  displayFile(file);
});

visibilityToggle.addEventListener("click", () => {
  const shouldShow = passwordInput.type === "password";
  passwordInput.type = shouldShow ? "text" : "password";
  visibilityToggle.textContent = shouldShow ? "Hide" : "Show";
  visibilityToggle.setAttribute("aria-label", `${shouldShow ? "Hide" : "Show"} password`);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files[0];
  const password = passwordInput.value;

  if (!file) {
    showFeedback("Choose a file before continuing.", true);
    return;
  }
  if (!password) {
    showFeedback("Enter your password before continuing.", true);
    passwordInput.focus();
    return;
  }
  if (mode === "encrypt" && password.length < 8) {
    showFeedback("Use a password with at least 8 characters.", true);
    passwordInput.focus();
    return;
  }

  submitButton.disabled = true;
  submitLabel.textContent = mode === "encrypt" ? "Encrypting…" : "Decrypting…";
  feedback.hidden = true;

  try {
    const payload = new FormData();
    payload.append("file", file, file.name);
    payload.append("password", password);
    const response = await fetch(`/api/${mode}`, { method: "POST", body: payload });

    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.error || "The file could not be processed.");
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = downloadName(response, file);
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showFeedback(mode === "encrypt" ? "File encrypted and downloaded." : "File decrypted and downloaded.");
    passwordInput.value = "";
  } catch (error) {
    showFeedback(error.message || "Something went wrong. Please try again.", true);
  } finally {
    submitButton.disabled = false;
    submitLabel.textContent = mode === "encrypt" ? "Encrypt file" : "Decrypt file";
  }
});
