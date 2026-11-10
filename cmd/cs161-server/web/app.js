const state = {
  step: 0,
  busy: false,
  suffix: "",
  users: {},
  fileContent: "",
  events: [],
};

// GitHub Pages cannot run the Go service. On github.io the same guided flow uses
// a deterministic in-browser adapter; local/server-hosted builds continue to
// call the real Gin API.
const IS_STATIC_DEMO = location.hostname.endsWith("github.io") || new URLSearchParams(location.search).has("static-demo");
const staticStore = { invitations: 0, audit: [] };

const steps = [
  {
    title: "Initialize the secure vault",
    description: "Create isolated identities for Alice, Bob, and Charlie, then issue scoped Bearer tokens.",
    button: "Create demo users",
    hint: "A unique suffix keeps each run isolated.",
    run: initializeUsers,
  },
  {
    title: "Store and append encrypted data",
    description: "Alice stores a file, then appends another chunk without downloading or rewriting the original content.",
    button: "Encrypt & append file",
    hint: "The append pipeline uses per-file locking and version validation.",
    run: storeAndAppend,
  },
  {
    title: "Build a downstream share chain",
    description: "Alice shares with Bob. Bob accepts, then shares his access onward to Charlie.",
    button: "Share Alice → Bob → Charlie",
    hint: "Invitations contain protected access metadata—not plaintext keys.",
    run: shareChain,
  },
  {
    title: "Revoke Bob and every descendant",
    description: "Alice revokes Bob. BFS discovers Charlie downstream and rotates encryption and integrity keys.",
    button: "Revoke & rotate keys",
    hint: "Alice retains access; Bob and Charlie can no longer decrypt future updates.",
    run: revokeBranch,
  },
  {
    title: "Verify the audit trail",
    description: "Query the authenticated audit endpoint and review the operations performed in this demo session.",
    button: "Load verified audit log",
    hint: "Every API request carries an attributable identity and outcome.",
    run: inspectAudit,
  },
];

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}, user = null) {
  if (IS_STATIC_DEMO) return staticDemoAPI(path, options, user);
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (user?.token) headers.Authorization = `Bearer ${user.token}`;
  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    throw new Error(payload?.error || payload || `Request failed (${response.status})`);
  }
  return payload;
}

async function staticDemoAPI(path, options = {}, user = null) {
  await new Promise((resolve) => setTimeout(resolve, 180));
  const body = options.body ? JSON.parse(options.body) : {};
  const route = path.split("?")[0];
  const actor = user?.username || body.username || "system";

  if (route === "/api/users/init") return { status: "ok", username: body.username };
  if (route === "/api/auth/token") return { token: `demo-${body.username}`, subject: body.username };
  if (route === "/api/files/load") return state.fileContent;
  if (route === "/api/audit") {
    const subject = new URL(path, location.origin).searchParams.get("subject");
    const entries = subject ? staticStore.audit.filter((entry) => entry.Subject === subject) : staticStore.audit;
    return { entries, count: entries.length };
  }
  if (route === "/api/share/invite") {
    staticStore.invitations += 1;
    staticStore.audit.push(demoAudit(actor, "POST", route));
    return { invitation_id: `00000000-0000-4000-8000-${String(staticStore.invitations).padStart(12, "0")}` };
  }

  staticStore.audit.push(demoAudit(actor, options.method || "GET", route));
  if (route === "/api/files/store") return { status: "ok", bytes: body.data?.length || 0 };
  if (route === "/api/files/append") return { status: "ok", appended: body.data?.length || 0 };
  if (route === "/api/share/accept") return { status: "ok", filename: body.filename };
  if (route === "/api/share/revoke") return { status: "ok", revoked: body.recipient };
  throw new Error(`Unsupported static demo route: ${route}`);
}

function demoAudit(subject, method, path) {
  return { Subject: subject, Method: method, Path: path, Result: "success" };
}

function credentials(user, extra = {}) {
  return JSON.stringify({ username: user.username, password: user.password, ...extra });
}

function now() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function addEvent(actor, message, error = false) {
  state.events.unshift({ time: now(), actor, message, error });
  const log = $("#event-log");
  log.innerHTML = state.events
    .slice(0, 16)
    .map((event) => `<div class="event ${event.error ? "error" : ""}"><time>${event.time}</time><b>${escapeHTML(event.actor)}</b><span>${escapeHTML(event.message)}</span></div>`)
    .join("");
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function toast(message, isError = false) {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.className = "toast"; }, 3200);
}

async function createUser(baseName) {
  const username = `${baseName}-${state.suffix}`;
  const password = `vault-${state.suffix}`;
  await api("/api/users/init", { method: "POST", body: JSON.stringify({ username, password }) });
  const session = await api("/api/auth/token", { method: "POST", body: JSON.stringify({ username, password }) });
  state.users[baseName] = { username, password, token: session.token };
  addEvent(baseName, "identity initialized + token issued");
}

async function initializeUsers() {
  state.suffix = `${Date.now().toString(36).slice(-5)}${Math.random().toString(36).slice(2, 5)}`;
  await createUser("alice");
  await createUser("bob");
  await createUser("charlie");
  $("#file-meta").textContent = `Vault ${state.suffix} · owner alice`;
  $("#access-count").textContent = "1 ACTIVE";
  addEvent("system", "isolated demo vault ready");
}

async function storeAndAppend() {
  const alice = state.users.alice;
  const initial = "Security review notes\n- Encrypt every chunk\n- Verify integrity before decrypting";
  const appended = "\n- Rotate keys after revocation";
  await api("/api/files/store", { method: "POST", body: credentials(alice, { filename: "project-notes.txt", data: initial }) }, alice);
  addEvent("alice", "stored encrypted file (3 lines)");
  await api("/api/files/append", { method: "POST", body: credentials(alice, { filename: "project-notes.txt", data: appended }) }, alice);
  addEvent("alice", "appended chunk with version check");
  state.fileContent = initial + appended;
  renderFile(state.fileContent);
  $("#load-file").disabled = false;
}

async function invite(sender, senderFilename, recipient, recipientFilename) {
  const result = await api("/api/share/invite", {
    method: "POST",
    body: credentials(sender, { filename: senderFilename, recipient: recipient.username }),
  }, sender);
  addEvent(sender.username.split("-")[0], `created invitation for ${recipient.username.split("-")[0]}`);
  await api("/api/share/accept", {
    method: "POST",
    body: credentials(recipient, {
      sender: sender.username,
      invitation_id: result.invitation_id,
      filename: recipientFilename,
    }),
  }, recipient);
  addEvent(recipient.username.split("-")[0], `accepted shared file as ${recipientFilename}`);
}

async function shareChain() {
  await invite(state.users.alice, "project-notes.txt", state.users.bob, "shared-notes.txt");
  $(".person.bob").classList.remove("muted");
  $(".line-ab").classList.add("active");
  $("#access-count").textContent = "2 ACTIVE";
  await invite(state.users.bob, "shared-notes.txt", state.users.charlie, "team-notes.txt");
  $(".person.charlie").classList.remove("muted");
  $(".line-bc").classList.add("active");
  $("#access-count").textContent = "3 ACTIVE";
}

async function revokeBranch() {
  const alice = state.users.alice;
  await api("/api/share/revoke", {
    method: "POST",
    body: credentials(alice, { filename: "project-notes.txt", recipient: state.users.bob.username }),
  }, alice);
  addEvent("alice", "revoked Bob + downstream recipients");
  addEvent("crypto", "rotated file encryption and HMAC keys");
  [".person.bob", ".person.charlie"].forEach((selector) => {
    const node = $(selector);
    node.classList.add("revoked");
    node.querySelector("small").textContent = "Revoked";
  });
  [".line-ab", ".line-bc"].forEach((selector) => $(selector).classList.add("revoked"));
  $("#access-count").textContent = "1 ACTIVE";
  $("#rotation-status").innerHTML = '<span class="status-symbol">✓</span><div><strong>Keys rotated</strong><small>Downstream branch can no longer decrypt</small></div>';
}

async function inspectAudit() {
  const alice = state.users.alice;
  const result = await api(`/api/audit?subject=${encodeURIComponent(alice.username)}`, {}, alice);
  const entries = result.entries || [];
  entries.slice(-8).forEach((entry) => {
    addEvent(entry.Subject?.split("-")[0] || "system", `${entry.Method || entry.Action} ${entry.Path} · ${entry.Result}`);
  });
  addEvent("audit", `${result.count} attributable Alice operations verified`);
  toast(`Audit complete — ${result.count} Alice operations verified`);
}

async function loadFile() {
  try {
    const alice = state.users.alice;
    const query = new URLSearchParams({ username: alice.username, password: alice.password, filename: "project-notes.txt" });
    const content = await api(`/api/files/load?${query}`, {}, alice);
    state.fileContent = content;
    renderFile(content);
    addEvent("alice", "loaded + authenticated encrypted chunks");
    toast("File decrypted and integrity verified");
  } catch (error) {
    toast(error.message, true);
  }
}

function renderFile(content) {
  const lines = String(content).split("\n");
  $("#content-preview").innerHTML = lines
    .map((line, index) => `<span class="line-number">${String(index + 1).padStart(2, "0")}</span><span>${escapeHTML(line)}</span>`)
    .join("");
}

function renderStep() {
  const step = steps[state.step];
  $("#step-counter").textContent = state.step < steps.length ? `STEP ${state.step + 1} OF ${steps.length}` : "DEMO COMPLETE";
  $("#action-title").textContent = step?.title || "Security workflow complete";
  $("#action-description").textContent = step?.description || "The file remains available to Alice while the revoked sharing branch no longer has access.";
  $("#action-hint").textContent = step?.hint || "Reset the scenario to run it again with fresh identities.";
  $("#run-step").innerHTML = step ? `${step.button} <span>→</span>` : "Run again <span>↻</span>";
  $$("#steps li").forEach((node, index) => {
    node.classList.toggle("complete", index < state.step);
    node.classList.toggle("active", index === state.step);
  });
}

async function runStep() {
  if (state.busy) return;
  if (state.step >= steps.length) {
    resetDemo();
    return;
  }
  state.busy = true;
  const button = $("#run-step");
  button.disabled = true;
  const oldHTML = button.innerHTML;
  button.textContent = "Working securely…";
  try {
    await steps[state.step].run();
    state.step += 1;
    renderStep();
    toast("Step completed successfully");
  } catch (error) {
    console.error(error);
    addEvent("error", error.message, true);
    toast(error.message, true);
    button.innerHTML = oldHTML;
  } finally {
    state.busy = false;
    button.disabled = false;
  }
}

function resetDemo() {
  state.step = 0;
  state.busy = false;
  state.suffix = "";
  state.users = {};
  state.fileContent = "";
  state.events = [];
  staticStore.invitations = 0;
  staticStore.audit = [];
  $("#event-log").innerHTML = '<div class="empty-log">Run the first step to begin.</div>';
  $("#content-preview").innerHTML = '<span class="line-number">01</span><span class="placeholder">Encrypted content will appear here.</span>';
  $("#file-meta").textContent = "Waiting to initialize demo";
  $("#load-file").disabled = true;
  $("#access-count").textContent = "0 ACTIVE";
  $$(".person:not(.owner)").forEach((node) => {
    node.classList.add("muted");
    node.classList.remove("revoked");
    node.querySelector("small").textContent = "No access";
  });
  $$(".graph-line").forEach((node) => node.classList.remove("active", "revoked"));
  $("#rotation-status").innerHTML = '<span class="status-symbol">◇</span><div><strong>Keys protected</strong><small>Revocation rotates encryption material</small></div>';
  renderStep();
}

$("#run-step").addEventListener("click", runStep);
$("#reset-demo").addEventListener("click", resetDemo);
$("#load-file").addEventListener("click", loadFile);
$$('[data-scroll-demo]').forEach((button) => button.addEventListener("click", () => $("#demo").scrollIntoView({ behavior: "smooth" })));
if (IS_STATIC_DEMO) {
  $("#backend-mode-label").textContent = "PORTFOLIO DEMO";
  $("#backend-mode-copy").textContent = "GitHub Pages runs this walkthrough in-browser. Clone the repository to exercise the real Gin API and cryptographic core.";
  $(".system-status").innerHTML = "<i></i> Demo ready";
}
renderStep();
