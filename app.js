import { initializeApp } from "https://www.gstatic.com/firebasejs/12.6.0/firebase-app.js";
import {
  initializeFirestore, doc, getDoc, getDocs, setDoc, updateDoc, addDoc, deleteDoc,
  collection, query, where, onSnapshot, serverTimestamp, arrayUnion, runTransaction, writeBatch
} from "https://www.gstatic.com/firebasejs/12.6.0/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

const db = initializeFirestore(initializeApp(firebaseConfig), { experimentalAutoDetectLongPolling: true });

/* ================= helpers ================= */
const view = document.getElementById("view");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clean = s => String(s || "").trim().replace(/\s+/g, " ");
const toEn = s => String(s ?? "").replace(/[٠-٩]/g, d => "٠١٢٣٤٥٦٧٨٩".indexOf(d)).replace(/[۰-۹]/g, d => "۰۱۲۳۴۵۶۷۸۹".indexOf(d));
const key = s => clean(s).toLowerCase().replace(/[أإآ]/g, "ا").replace(/ة/g, "ه").replace(/ى/g, "ي").replace(/[ً-ْـ]/g, "");
const num = v => { const n = parseFloat(toEn(v).replace(/[٫,]/g, ".")); return isFinite(n) && n >= 0 ? n : 0; };
const r2 = n => Math.round(n * 100) / 100;
const money = n => r2(n).toLocaleString("en-US", { maximumFractionDigits: 2 }) + " EGP";
const byName = (a, b) => String(a.name).localeCompare(String(b.name));
const rid = () => Math.random().toString(36).slice(2, 10);
const first = n => String(n || "").split(" ")[0];
const go = p => { location.hash = "#" + p; };
const LOADING = `<div class="loading"><div class="spinner"></div></div>`;
const tsDate = t => { try { const d = t?.toDate ? t.toDate() : null; return d ? d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" }) : ""; } catch { return ""; } };
const ms = t => (t?.toMillis ? t.toMillis() : 0);
const pinOk = p => /^\d{4}$/.test(p);
const readPin = id => toEn(document.getElementById(id)?.value || "").replace(/\D/g, "");
const pinInput = (id, label) => `<label class="fld"><span>${label}</span><input type="password" id="${id}" class="code-in pin" inputmode="numeric" pattern="[0-9]*" maxlength="4" autocomplete="off" placeholder="••••"></label>`;

let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2600);
}
function fail(e) { console.error(e); toast("Connection problem, please try again"); }

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch {}
    ta.remove(); return ok;
  }
}

/* Render without killing what the user is typing:
   - if an input inside the view has focus we postpone the full render until it loses focus
   - inputs marked data-keep keep their typed value across renders */
let pendingRender = null;
function typingInView() {
  const a = document.activeElement;
  return a && view.contains(a) && (a.tagName === "INPUT" || a.tagName === "TEXTAREA") && a.type !== "radio" && a.type !== "checkbox";
}
function patch(html) {
  const kept = {};
  view.querySelectorAll("[data-keep][id]").forEach(el => (kept[el.id] = el.value));
  view.innerHTML = html;
  for (const id in kept) { const el = document.getElementById(id); if (el && !el.value) el.value = kept[id]; }
}
function softRender(fn) {
  if (typingInView()) { pendingRender = fn; return false; }
  pendingRender = null; fn(); return true;
}
view.addEventListener("focusout", () => {
  setTimeout(() => { if (pendingRender && !typingInView()) { const f = pendingRender; pendingRender = null; f(); } }, 250);
});

/* ================= identity ================= */
function newId() { return crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + rid() + rid(); }
function saveUid(id) {
  try { localStorage.setItem("ordarna.uid", id); } catch {}
  document.cookie = `ordarna_uid=${id};max-age=${60 * 60 * 24 * 400};path=/;SameSite=Lax`;
}
function getUid() {
  let id = null;
  try { id = localStorage.getItem("ordarna.uid"); } catch {}
  if (!id) { const m = document.cookie.match(/ordarna_uid=([\w-]+)/); id = m && m[1]; }
  if (!id) id = newId();
  saveUid(id); return id;
}
let uid = getUid();
let me = null;

/* PIN is never stored in clear text: PBKDF2(SHA-256) salted with the user id */
async function hashPin(pin, salt) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode("ordarna:" + salt), iterations: 150000, hash: "SHA-256" }, k, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}
/* Slow down PIN guessing on this browser: 5 wrong tries => 10 minute lock */
const FAILS = "ordarna.pinFails";
function failState() { try { return JSON.parse(localStorage.getItem(FAILS)) || { n: 0, until: 0 }; } catch { return { n: 0, until: 0 }; } }
function setFail(s) { try { localStorage.setItem(FAILS, JSON.stringify(s)); } catch {} }

/* ================= data helpers ================= */
const list = async (path, ...q) => (await getDocs(q.length ? query(collection(db, path), ...q) : collection(db, path))).docs.map(d => ({ id: d.id, ...d.data() }));

async function ensureCompany(name) {
  const found = await list("companies", where("nameKey", "==", key(name)));
  if (found.length) return found[0];
  const ref = await addDoc(collection(db, "companies"), { name: clean(name), nameKey: key(name), createdAt: serverTimestamp() });
  return { id: ref.id, name: clean(name) };
}
async function ensureDept(companyId, name) {
  const found = (await list("departments", where("companyId", "==", companyId))).find(d => d.nameKey === key(name));
  if (found) return found;
  const ref = await addDoc(collection(db, "departments"), { companyId, name: clean(name), nameKey: key(name), createdAt: serverTimestamp() });
  return { id: ref.id, companyId, name: clean(name) };
}

/* ================= combo (dropdown + free text) ================= */
function comboHTML(id, label, ph) {
  return `<div class="fld"><span>${label}</span><div class="combo" id="${id}"><input type="text" autocomplete="off" placeholder="${ph}"><ul class="sugg" hidden></ul></div></div>`;
}
function combo(root, { onChange, allowAdd = true } = {}) {
  const input = root.querySelector("input"), ul = root.querySelector(".sugg");
  let opts = [], sel = null;
  const exact = () => opts.find(o => (o.nameKey || key(o.name)) === key(input.value)) || null;
  function show() {
    const q = key(input.value);
    const items = opts.filter(o => !q || key(o.name).includes(q)).sort(byName).slice(0, 40);
    let html = items.map(o => `<li data-id="${esc(o.id)}">${esc(o.name)}</li>`).join("");
    if (allowAdd && clean(input.value) && !exact()) html += `<li class="add" data-add="1">➕ Add “${esc(clean(input.value))}”</li>`;
    if (!html) html = `<li class="empty">${allowAdd ? "Nothing here yet, just type the name" : "No matches"}</li>`;
    ul.innerHTML = html; ul.hidden = false;
  }
  function update() {
    const prev = sel?.id; sel = exact();
    if (onChange && prev !== sel?.id) onChange(api.value());
  }
  input.addEventListener("focus", show);
  input.addEventListener("input", () => { update(); show(); if (onChange) onChange(api.value()); });
  input.addEventListener("blur", () => setTimeout(() => (ul.hidden = true), 150));
  input.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === "Escape") { e.preventDefault(); ul.hidden = true; input.blur(); } });
  ul.addEventListener("pointerdown", e => {
    e.preventDefault();
    const li = e.target.closest("li"); if (!li || li.classList.contains("empty")) return;
    if (li.dataset.id) input.value = opts.find(x => x.id === li.dataset.id)?.name || input.value;
    ul.hidden = true; update(); input.blur();
  });
  const api = {
    value: () => ({ id: sel?.id || null, name: sel?.name || clean(input.value) }),
    setOptions(o) { opts = o || []; sel = exact(); if (!ul.hidden) show(); },
    set(name) { input.value = name || ""; sel = exact(); },
  };
  return api;
}

/* ================= router ================= */
let subs = [];
function stopSubs() { subs.forEach(u => { try { u(); } catch {} }); subs = []; }

async function route() {
  stopSubs(); pendingRender = null;
  view.onclick = view.oninput = view.onchange = view.onsubmit = null;
  view.onkeydown = e => {
    if (e.key === "Enter" && (e.target.id === "ni-price" || e.target.id === "ni-name")) { e.preventDefault(); view.querySelector('[data-act="newItem"]')?.click(); }
  };
  const [p0 = "", p1 = ""] = location.hash.replace(/^#\/?/, "").split("/");
  if (!me && p0 !== "register") {
    if (p0) sessionStorage.setItem("ordarna.after", location.hash);
    location.replace("#/register"); return;
  }
  if (me && !me.pinHash && p0 !== "setpin") { location.replace("#/setpin"); return; }
  window.scrollTo(0, 0);
  try {
    switch (p0) {
      case "register": return await viewRegister();
      case "setpin": return viewSetPin();
      case "profile": return await viewProfile();
      case "new": return await viewNew();
      case "o": return await viewOrder(p1);
      case "restaurants": return await viewRestaurants();
      case "r": return await viewRestaurant(p1);
      case "history": return await viewHistory();
      default: return viewHome();
    }
  } catch (e) {
    console.error(e);
    view.innerHTML = `<section class="card"><h3>Something went wrong 😕</h3><p class="muted">Check your internet connection and try again.</p><button class="btn primary block" onclick="location.reload()">Retry</button></section>`;
  }
}
function afterLogin() {
  const after = sessionStorage.getItem("ordarna.after"); sessionStorage.removeItem("ordarna.after");
  location.hash = after && !after.includes("register") ? after : "#/";
}

/* ================= register / sign in ================= */
async function viewRegister() {
  if (me) return go("/");
  const st = { mode: "new", forceNew: false };
  view.innerHTML = `
    <section class="card">
      <h1>Welcome to Ordarna 👋</h1>
      <p class="muted" style="margin:4px 0 14px">Tell us who you are, we'll remember you on this device.</p>
      <div class="tabs"><button class="tab on" data-mode="new">I'm new</button><button class="tab" data-mode="signin">I already have an account</button></div>
      <label class="fld"><span>Your name</span><input type="text" id="r-name" autocomplete="name" placeholder="e.g. Mahmoud Hamdy"></label>
      ${comboHTML("r-company", "Company", "Pick from the list or type a new one")}
      ${comboHTML("r-dept", "Department", "Pick from the list or type a new one")}
      <div id="pins-new">
        <div class="grid2">${pinInput("r-pin", "Choose a 4-digit PIN")}${pinInput("r-pin2", "Confirm PIN")}</div>
        <p class="muted small" style="margin:-4px 0 12px">You'll need this PIN to open your account from another phone or browser.</p>
      </div>
      <div id="pins-signin" hidden>${pinInput("s-pin", "Your PIN")}</div>
      <div id="msg"></div>
      <button class="btn primary block big" id="r-save">Let's go 🚀</button>
    </section>`;
  const nameEl = document.getElementById("r-name"), msg = document.getElementById("msg"), btn = document.getElementById("r-save");
  let companies = [], depts = [];
  const deptC = combo(document.getElementById("r-dept"));
  const compC = combo(document.getElementById("r-company"), {
    onChange: c => deptC.setOptions(c.id ? depts.filter(d => d.companyId === c.id) : []),
  });
  [companies, depts] = await Promise.all([list("companies"), list("departments")]);
  compC.setOptions(companies);

  function setMode(m) {
    st.mode = m; st.forceNew = false; msg.innerHTML = "";
    view.querySelectorAll(".tab").forEach(t => t.classList.toggle("on", t.dataset.mode === m));
    document.getElementById("pins-new").hidden = m !== "new";
    document.getElementById("pins-signin").hidden = m !== "signin";
    btn.textContent = m === "new" ? "Let's go 🚀" : "Sign in 🔓";
  }
  view.onclick = e => {
    const t = e.target.closest("[data-mode]"); if (t) return setMode(t.dataset.mode);
    const a = e.target.closest("[data-act]"); if (!a) return;
    if (a.dataset.act === "toSignin") setMode("signin");
    if (a.dataset.act === "forceNew") { st.forceNew = true; btn.click(); }
  };

  const wrongPinHelp = left => `<div class="alert"><b>Wrong PIN.</b> ${left > 0 ? `${left} tries left.` : ""}
    <div style="margin-top:8px">Forgot your PIN? You can:</div>
    <ul><li>Open Ordarna on the phone / browser where you're already signed in → <b>My profile</b> → <b>Change PIN</b>, then sign in here with the new PIN.</li>
    <li>Or create a new account using the <a href="#" data-mode="new">I'm new</a> tab.</li></ul></div>`;

  btn.onclick = async () => {
    msg.innerHTML = "";
    const name = clean(nameEl.value), c = compC.value(), d = deptC.value();
    if (!name) return toast("Enter your name");
    if (!c.name) return toast("Pick or type your company");
    if (!d.name) return toast("Pick or type your department");

    if (st.mode === "signin") {
      const fs = failState();
      if (fs.until > Date.now()) return (msg.innerHTML = `<div class="alert">Too many wrong tries. Try again in ${Math.ceil((fs.until - Date.now()) / 60000)} min.</div>`);
      const pin = readPin("s-pin"); if (!pinOk(pin)) return toast("PIN is 4 digits");
      const noAcc = `<div class="alert">No account found with this name in this company / department. Check the spelling, or create a new account from the <a href="#" data-mode="new">I'm new</a> tab.</div>`;
      if (!c.id) return (msg.innerHTML = noAcc);
      btn.disabled = true;
      try {
        const cands = (await list("users", where("nameKey", "==", key(name)))).filter(u => u.companyId === c.id && (!d.id || u.deptId === d.id));
        if (!cands.length) { msg.innerHTML = noAcc; return; }
        for (const u of cands) {
          if (u.pinHash && (await hashPin(pin, u.id)) === u.pinHash) {
            setFail({ n: 0, until: 0 });
            uid = u.id; saveUid(uid); me = { ...u };
            toast(`Welcome back, ${first(u.name)} 🎉`); return afterLogin();
          }
        }
        const n = fs.n + 1;
        setFail({ n: n >= 5 ? 0 : n, until: n >= 5 ? Date.now() + 10 * 60000 : 0 });
        msg.innerHTML = wrongPinHelp(5 - n);
      } catch (err) { fail(err); } finally { btn.disabled = false; }
      return;
    }

    const pin = readPin("r-pin");
    if (!pinOk(pin)) return toast("PIN must be 4 digits");
    if (pin !== readPin("r-pin2")) return toast("PINs don't match");
    btn.disabled = true;
    try {
      const company = c.id ? companies.find(x => x.id === c.id) : await ensureCompany(c.name);
      const dept = d.id && depts.find(x => x.id === d.id)?.companyId === company.id ? depts.find(x => x.id === d.id) : await ensureDept(company.id, d.name);
      if (!st.forceNew) {
        const same = (await list("users", where("nameKey", "==", key(name)))).find(u => u.id !== uid && u.companyId === company.id && u.deptId === dept.id);
        if (same) {
          msg.innerHTML = `<div class="alert">There's already an account named <b>${esc(same.name)}</b> in ${esc(dept.name)}.
            <div class="actions" style="margin-top:10px"><button class="btn primary" data-act="toSignin">That's me, sign in</button><button class="btn ghost" data-act="forceNew">I'm someone else</button></div></div>`;
          return;
        }
      }
      const data = {
        name, nameKey: key(name), companyId: company.id, companyName: company.name, deptId: dept.id, deptName: dept.name,
        pinHash: await hashPin(pin, uid), createdAt: serverTimestamp(), updatedAt: serverTimestamp(),
      };
      await setDoc(doc(db, "users", uid), data);
      me = { id: uid, ...data };
      toast(`Welcome, ${first(name)} 🎉`); afterLogin();
    } catch (err) { fail(err); } finally { btn.disabled = false; }
  };
}

/* existing accounts without a PIN must set one */
function viewSetPin() {
  if (me.pinHash) return go("/");
  view.innerHTML = `<section class="card"><h1>Protect your account 🔐</h1>
    <p class="muted">Choose a 4-digit PIN. You'll need it to open your account from another phone or browser.</p>
    <div class="grid2">${pinInput("p1", "New PIN")}${pinInput("p2", "Confirm PIN")}</div>
    <button class="btn primary block big" id="sp">Save PIN</button></section>`;
  document.getElementById("sp").onclick = async e => {
    const p = readPin("p1"); if (!pinOk(p)) return toast("PIN must be 4 digits");
    if (p !== readPin("p2")) return toast("PINs don't match");
    e.currentTarget.disabled = true;
    try { const h = await hashPin(p, uid); await updateDoc(doc(db, "users", uid), { pinHash: h }); me.pinHash = h; toast("PIN saved ✅"); afterLogin(); }
    catch (err) { fail(err); e.currentTarget.disabled = false; }
  };
}

/* ================= profile ================= */
async function viewProfile() {
  view.innerHTML = `
    <div class="page-title"><a href="#/" class="back">←</a><h1>My profile</h1></div>
    <section class="card">
      <h3>My info</h3>
      <label class="fld"><span>Your name</span><input type="text" id="r-name" autocomplete="name"></label>
      ${comboHTML("r-company", "Company", "Pick from the list or type a new one")}
      ${comboHTML("r-dept", "Department", "Pick from the list or type a new one")}
      <button class="btn primary block" id="r-save">Save</button>
    </section>
    <section class="card">
      <h3>🔐 Change PIN</h3>
      <p class="muted small" style="margin-top:-6px">Forgot your PIN on another device? Set a new one here, then use it there.</p>
      <div class="grid2">${pinInput("p1", "New PIN")}${pinInput("p2", "Confirm PIN")}</div>
      <button class="btn dark block" id="pin-save">Update PIN</button>
    </section>
    <section class="card">
      <h3>Sign out</h3>
      <p class="muted small" style="margin-top:-6px">Sign out from this device (e.g. a shared phone). You can sign back in with your PIN.</p>
      <button class="btn ghost block" id="logout">Sign out</button>
    </section>`;
  const nameEl = document.getElementById("r-name");
  let companies = [], depts = [];
  const deptC = combo(document.getElementById("r-dept"));
  const compC = combo(document.getElementById("r-company"), { onChange: c => deptC.setOptions(c.id ? depts.filter(d => d.companyId === c.id) : []) });
  nameEl.value = me.name; compC.set(me.companyName); deptC.set(me.deptName);
  [companies, depts] = await Promise.all([list("companies"), list("departments")]);
  compC.setOptions(companies);
  const c0 = compC.value(); deptC.setOptions(c0.id ? depts.filter(d => d.companyId === c0.id) : []);

  document.getElementById("r-save").onclick = async e => {
    const name = clean(nameEl.value), c = compC.value(), d = deptC.value();
    if (!name || !c.name || !d.name) return toast("Fill in all fields");
    const btn = e.currentTarget; btn.disabled = true;
    try {
      const company = c.id ? companies.find(x => x.id === c.id) : await ensureCompany(c.name);
      const dept = d.id && depts.find(x => x.id === d.id)?.companyId === company.id ? depts.find(x => x.id === d.id) : await ensureDept(company.id, d.name);
      const data = { name, nameKey: key(name), companyId: company.id, companyName: company.name, deptId: dept.id, deptName: dept.name, updatedAt: serverTimestamp() };
      await updateDoc(doc(db, "users", uid), data); Object.assign(me, data); toast("Saved ✅");
    } catch (err) { fail(err); } finally { btn.disabled = false; }
  };
  document.getElementById("pin-save").onclick = async e => {
    const p = readPin("p1"); if (!pinOk(p)) return toast("PIN must be 4 digits");
    if (p !== readPin("p2")) return toast("PINs don't match");
    const btn = e.currentTarget; btn.disabled = true;
    try {
      const h = await hashPin(p, uid); await updateDoc(doc(db, "users", uid), { pinHash: h }); me.pinHash = h;
      document.getElementById("p1").value = document.getElementById("p2").value = ""; toast("PIN updated ✅");
    } catch (err) { fail(err); } finally { btn.disabled = false; }
  };
  document.getElementById("logout").onclick = () => {
    if (!confirm("Sign out from this device? Make sure you remember your PIN.")) return;
    uid = newId(); saveUid(uid); me = null; location.replace("#/register");
  };
}

/* ================= home ================= */
function viewHome() {
  view.innerHTML = `
    <div class="hello">Hi, ${esc(first(me.name))} 👋</div>
    <div class="sub">${esc(me.deptName)} · ${esc(me.companyName)} · <a href="#/profile">My profile</a></div>
    <a class="bigbtn primary" href="#/new"><div class="ico">＋</div><div>New order<small>You'll be the admin and pick the restaurant</small></div></a>
    <form class="card" id="join">
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px"><div class="ico">🔢</div><div><b style="font-size:18px">Join an order</b><div class="muted small">Enter the order number you got</div></div></div>
      <div class="row"><input type="text" id="code" class="code-in" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="••••" autocomplete="off"><button class="btn primary" style="padding:0 22px">Join</button></div>
    </form>
    <div id="active"></div>
    <div class="grid2">
      <a class="tile" href="#/restaurants">🍽️<b>Restaurants & menus</b></a>
      <a class="tile" href="#/history">🧾<b>My orders</b></a>
    </div>`;
  view.onsubmit = e => {
    e.preventDefault();
    const code = toEn(document.getElementById("code").value).replace(/\D/g, "");
    if (code.length < 4) return toast("Order numbers are 4 digits");
    go("/o/" + code);
  };
  list("orders", where("participants", "array-contains", uid)).then(orders => {
    const act = orders.filter(o => o.status !== "ordered").sort((a, b) => ms(b.createdAt) - ms(a.createdAt));
    const el = document.getElementById("active"); if (!el || !act.length) return;
    el.innerHTML = `<section class="card"><h3>⏳ Active orders</h3><div class="list">${act.map(orderLi).join("")}</div></section>`;
  }).catch(console.error);
}
const STATUS = { open: "Open", locked: "Locked · ordering", ordered: "Ordered ✅" };
function orderLi(o) {
  return `<a class="li" href="#/o/${esc(o.code)}"><div class="ico">${o.adminId === uid ? "👑" : "🍔"}</div>
    <div class="grow"><b>${esc(o.restaurantName)}</b><span class="muted small">#${esc(o.code)} · ${esc(o.adminName)} · ${tsDate(o.createdAt)}</span></div>
    <span class="chip ${o.status}">${STATUS[o.status] || ""}</span></a>`;
}

/* ================= new order ================= */
async function createOrder(data) {
  for (let i = 0; i < 40; i++) {
    const len = i < 25 ? 4 : 5;
    const code = String(Math.floor(Math.random() * 9 * 10 ** (len - 1)) + 10 ** (len - 1));
    const ref = doc(db, "orders", code);
    try {
      await runTransaction(db, async tx => {
        if ((await tx.get(ref)).exists()) throw new Error("taken");
        tx.set(ref, { ...data, code });
      });
      return code;
    } catch (e) { if (e.message !== "taken") throw e; }
  }
  throw new Error("no code");
}

async function viewNew() {
  view.innerHTML = LOADING;
  const st = { rid: sessionStorage.getItem("ordarna.newRid") || "", companyMode: "mine", deptMode: "all", deptIds: new Set([me.deptId]) };
  sessionStorage.removeItem("ordarna.newRid");
  const [rests, depts] = await Promise.all([list("restaurants"), list("departments", where("companyId", "==", me.companyId))]);
  rests.sort(byName); depts.sort(byName);

  const opt = (name, val, cur, title, sub) =>
    `<label class="opt"><input type="radio" name="${name}" value="${val}" ${cur === val ? "checked" : ""}><div><b>${title}</b>${sub ? `<small>${sub}</small>` : ""}</div></label>`;

  function render() {
    patch(`
      <div class="page-title"><a href="#/" class="back">←</a><h1>New order</h1></div>
      <section class="card">
        <h3>1. Restaurant</h3>
        <select id="n-rest"><option value="">— Pick a restaurant —</option>
          ${rests.map(r => `<option value="${esc(r.id)}" ${st.rid === r.id ? "selected" : ""}>${esc(r.name)}${r.area ? ` (${esc(r.area)})` : ""}</option>`).join("")}
        </select>
        <button class="btn ghost block" style="margin-top:10px" data-act="addRest">➕ Not listed? Add a restaurant</button>
      </section>
      <section class="card">
        <h3>2. Who can join this order?</h3>
        <div class="seg">
          ${opt("cm", "mine", st.companyMode, `${esc(me.companyName)} only`, "My company only")}
          ${opt("cm", "all", st.companyMode, "All companies", "Anyone with the order number")}
        </div>
        ${st.companyMode === "mine" ? `
          <h4>Departments</h4>
          <div class="seg">
            ${opt("dm", "mine", st.deptMode, `${esc(me.deptName)} only`, "My department only")}
            ${opt("dm", "all", st.deptMode, "All departments", `Every department in ${esc(me.companyName)}`)}
            ${opt("dm", "selected", st.deptMode, "Specific departments", "Tick the departments allowed to join")}
          </div>
          ${st.deptMode === "selected" ? `
            <div class="seg" style="margin-top:10px">
              ${depts.map(d => `<label class="opt"><input type="checkbox" data-dept="${esc(d.id)}" ${st.deptIds.has(d.id) ? "checked" : ""}><b>${esc(d.name)}</b></label>`).join("")}
            </div>
            <div class="row" style="margin-top:10px"><input type="text" id="n-newdept" data-keep placeholder="Department not listed? Type it"><button class="btn" data-act="addDept">Add</button></div>
          ` : ""}
        ` : ""}
      </section>
      <button class="btn primary block big" data-act="create">🚀 Create order</button>`);
  }
  render();

  view.onchange = e => {
    const t = e.target;
    if (t.id === "n-rest") st.rid = t.value;
    else if (t.name === "cm") { st.companyMode = t.value; render(); }
    else if (t.name === "dm") { st.deptMode = t.value; render(); }
    else if (t.dataset.dept) t.checked ? st.deptIds.add(t.dataset.dept) : st.deptIds.delete(t.dataset.dept);
  };
  view.onclick = async e => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act;
    if (act === "addRest") { sessionStorage.setItem("ordarna.backToNew", "1"); go("/r/new"); }
    else if (act === "addDept") {
      const inp = document.getElementById("n-newdept"); const name = clean(inp.value);
      if (!name) return toast("Type the department name");
      b.disabled = true;
      try {
        const d = await ensureDept(me.companyId, name);
        if (!depts.find(x => x.id === d.id)) { depts.push(d); depts.sort(byName); }
        st.deptIds.add(d.id); inp.value = ""; render();
      } catch (err) { fail(err); b.disabled = false; }
    }
    else if (act === "create") {
      const r = rests.find(x => x.id === st.rid);
      if (!r) return toast("Pick a restaurant first");
      if (st.companyMode === "mine" && st.deptMode === "selected" && !st.deptIds.size) return toast("Tick at least one department");
      let access = { companyMode: "all" };
      if (st.companyMode === "mine") {
        const ids = st.deptMode === "mine" ? [me.deptId] : st.deptMode === "selected" ? [...st.deptIds] : [];
        access = {
          companyMode: "mine", companyId: me.companyId, companyName: me.companyName, deptMode: st.deptMode,
          deptIds: ids, deptNames: ids.map(id => id === me.deptId ? me.deptName : depts.find(d => d.id === id)?.name || ""),
        };
      }
      b.disabled = true;
      try {
        const code = await createOrder({
          adminId: uid, adminName: me.name, restaurantId: r.id, restaurantName: r.name, hotline: r.hotline || "",
          status: "open", access, participants: [uid], fees: 0, split: "equal", prices: {}, createdAt: serverTimestamp(),
        });
        sessionStorage.setItem("ordarna.justCreated", code);
        go("/o/" + code);
      } catch (err) { fail(err); b.disabled = false; }
    }
  };
}

/* ================= order ================= */
function canJoin(o) {
  const a = o.access || {};
  if (a.companyMode !== "mine") return { ok: true };
  if (me.companyId !== a.companyId) return { ok: false, why: `This order is for ${a.companyName} employees only.` };
  if (a.deptMode === "all") return { ok: true };
  if ((a.deptIds || []).includes(me.deptId)) return { ok: true };
  return { ok: false, why: `This order is only for: ${(a.deptNames || []).join(", ")}.` };
}
function accessText(a = {}) {
  if (a.companyMode !== "mine") return "🌍 Open to all companies";
  if (a.deptMode === "all") return `🏢 ${a.companyName} · all departments`;
  return `🏢 ${a.companyName} · ${(a.deptNames || []).join(", ")}`;
}

/* Bill math: shared by preview (admin, locked) and final receipts */
function calc(entries, priceOf, fees, split) {
  const people = entries.map(e => {
    const lines = (e.items || []).filter(l => l.qty > 0).map(l => { const unit = priceOf(l); return { ...l, unit, total: unit * l.qty }; });
    return { ...e, lines, sub: lines.reduce((s, l) => s + l.total, 0) };
  }).filter(p => p.lines.length).sort(byName);
  const food = people.reduce((s, p) => s + p.sub, 0);
  const n = people.length;
  people.forEach(p => {
    p.fee = !n ? 0 : split === "proportional" && food > 0 ? fees * p.sub / food : fees / n;
    p.total = p.sub + p.fee;
  });
  return { people, food, fees, n, grand: food + fees };
}
function aggregate(people, priceOf) {
  const m = new Map();
  for (const p of people) for (const l of p.lines) {
    const a = m.get(l.itemId) || { itemId: l.itemId, name: l.name, qty: 0, notes: [], sample: l };
    a.qty += l.qty;
    if (clean(l.note)) a.notes.push({ qty: l.qty, note: l.note, who: first(p.name) });
    m.set(l.itemId, a);
  }
  return [...m.values()].map(a => ({ ...a, unit: priceOf(a.sample) })).sort(byName);
}

async function viewOrder(codeRaw) {
  const code = toEn(codeRaw).replace(/\D/g, "");
  view.innerHTML = LOADING;
  const oref = doc(db, "orders", code);
  const S = { order: null, entries: [], items: [], itemsRid: null, itemsSub: null, denied: null, joining: false, edit: null, draft: { prices: {}, fees: null, split: null }, filter: "" };
  const justCreated = sessionStorage.getItem("ordarna.justCreated") === code;
  sessionStorage.removeItem("ordarna.justCreated");
  let saveDraftTimer, noteTimer;

  subs.push(onSnapshot(oref, snap => {
    if (!snap.exists()) {
      view.innerHTML = `<section class="card" style="text-align:center"><div style="font-size:48px">🤷‍♂️</div><h3>No order with number ${esc(code)}</h3><p class="muted">Double-check the number and try again.</p><a class="btn primary block" href="#/">Back</a></section>`;
      return;
    }
    S.order = { id: snap.id, ...snap.data() };
    checkJoin();
    if (S.itemsRid !== S.order.restaurantId) {
      S.itemsRid = S.order.restaurantId;
      if (S.itemsSub) S.itemsSub();
      S.itemsSub = onSnapshot(collection(db, "restaurants", S.itemsRid, "items"), s => {
        S.items = s.docs.map(d => ({ id: d.id, ...d.data() })).sort(byItem); render();
      }, fail);
      subs.push(() => S.itemsSub && S.itemsSub());
    }
    render();
  }, fail));
  subs.push(onSnapshot(collection(db, "orders", code, "entries"), s => {
    S.entries = s.docs.map(d => ({ id: d.id, ...d.data() })); render();
  }, fail));

  function checkJoin() {
    const o = S.order;
    if (o.adminId === uid || (o.participants || []).includes(uid)) { S.denied = null; return; }
    const c = canJoin(o);
    if (!c.ok) { S.denied = c.why; return; }
    if (o.status !== "open") { S.denied = "This order is already locked, you can't add items now."; return; }
    S.denied = null;
    if (!S.joining) { S.joining = true; updateDoc(oref, { participants: arrayUnion(uid) }).catch(fail); }
  }

  const isAdmin = () => S.order?.adminId === uid;
  const itemById = id => S.items.find(i => i.id === id);
  const myEntry = () => S.entries.find(e => e.id === uid);
  const myItems = () => (myEntry()?.items || []).map(l => ({ ...l }));
  const menuPrice = l => itemById(l.itemId)?.price ?? l.price ?? 0;
  const draftPrice = l => {
    const d = S.draft.prices[l.itemId];
    return d !== undefined ? num(d) : (S.order.prices?.[l.itemId] ?? menuPrice(l));
  };
  const finalPrice = l => S.order.prices?.[l.itemId] ?? l.price ?? 0;
  const curFees = () => S.draft.fees !== null ? num(S.draft.fees) : (S.order.fees || 0);
  const curSplit = () => S.draft.split || S.order.split || "equal";

  function saveMine(items) {
    const e = myEntry();
    if (e) e.items = items; else S.entries.push({ id: uid, name: me.name, items });
    return setDoc(doc(db, "orders", code, "entries", uid), {
      uid, name: me.name, deptName: me.deptName, companyName: me.companyName, items, updatedAt: serverTimestamp(),
    }, { merge: true }).catch(fail);
  }

  function render() { if (S.order) softRender(draw); }

  /* ---------- templates ---------- */
  function headHTML(o, people) {
    return `<section class="card order-head">
      <div class="top"><div><div class="muted small">Order number</div><div class="code-big">${esc(o.code)}</div></div><span class="chip ${o.status}">${STATUS[o.status]}</span></div>
      <div class="rest-line">🍽️ <b>${esc(o.restaurantName)}</b>${o.hotline ? `<a class="tel" href="tel:${esc(o.hotline)}">📞 ${esc(o.hotline)}</a>` : ""}</div>
      <div class="muted small">👑 Admin: ${esc(o.adminName)} · 👥 ${people} ordered · ${esc(accessText(o.access))}</div>
      ${justCreated && o.status === "open" ? `<div class="banner">✅ Order created! Send the number ${esc(o.code)} to everyone so they can order.</div>` : ""}
      ${o.status === "open" ? `<div class="share">
        <button class="btn wa" data-act="wa">WhatsApp</button>
        <button class="btn ghost" data-act="copy">Copy link</button>
        ${navigator.share ? `<button class="btn ghost" data-act="share">Share</button>` : ""}
      </div>` : ""}
    </section>`;
  }
  function menuItemHTML(it) {
    if (S.edit === it.id) return `<li><div class="editrow">
        <input type="text" id="ei-name" value="${esc(it.name)}" placeholder="Item name">
        <input type="text" id="ei-price" class="p" inputmode="decimal" value="${esc(it.price ?? "")}" placeholder="Price">
        <button class="btn ok" data-act="saveItem" data-id="${esc(it.id)}">Save</button><button class="btn ghost" data-act="cancelEdit">Cancel</button>
      </div></li>`;
    return `<li><span class="nm">${esc(it.name)}</span><span class="pr">${money(it.price || 0)}</span>
      <button class="icon" data-act="edit" data-id="${esc(it.id)}" aria-label="Edit">✏️</button>
      <button class="plus" data-act="addLine" data-id="${esc(it.id)}" aria-label="Add">＋</button></li>`;
  }
  function menuHTML() {
    if (!S.items.length) return `<div class="empty">The menu is empty.. add the first item below 👇</div>`;
    const q = key(S.filter);
    const shown = S.items.filter(i => !q || key(i.name).includes(q) || key(i.category).includes(q));
    const groups = new Map();
    shown.forEach(i => { const c = i.category || ""; if (!groups.has(c)) groups.set(c, []); groups.get(c).push(i); });
    return `${S.items.length > 8 ? `<input type="text" id="menu-filter" class="search" placeholder="🔎 Search the menu" value="${esc(S.filter)}">` : ""}
      <div id="menu-list">${shown.length ? [...groups].map(([c, items]) => `${c ? `<div class="cat">${esc(c)}</div>` : ""}<ul class="menu">${items.map(menuItemHTML).join("")}</ul>`).join("") : `<div class="empty">No matches</div>`}</div>`;
  }
  function peopleHTML(people, title) {
    return `<section class="card"><h3>${title} (${people.length})</h3>
      ${people.length ? people.map(p => `<div class="person"><div class="hd"><b>${esc(p.name)}${p.id === uid ? " (you)" : ""}</b><span class="muted small">${esc(p.deptName || "")}</span><span class="small">${money(p.sub)}</span></div>
        <ul>${p.lines.map(l => `<li>${l.qty}× ${esc(l.name)}${clean(l.note) ? ` <i>(${esc(l.note)})</i>` : ""}</li>`).join("")}</ul></div>`).join("")
        : `<div class="empty">Nobody ordered yet</div>`}
    </section>`;
  }

  function draw() {
    const o = S.order;
    if (S.denied) {
      view.innerHTML = `<section class="card" style="text-align:center"><div style="font-size:48px">🔒</div><h3>You can't join this order</h3><p class="muted">${esc(S.denied)}</p><a class="btn primary block" href="#/">Back</a></section>`;
      return;
    }
    const admin = isAdmin();
    let html = "";

    if (o.status === "open") {
      const live = calc(S.entries, menuPrice, 0, "equal");
      const mine = myItems();
      const mySub = mine.reduce((s, l) => s + menuPrice(l) * l.qty, 0);
      html += headHTML(o, live.n);
      html += `<section class="card"><h3>📋 Menu</h3>${menuHTML()}
        <div class="addrow"><div class="muted small" style="margin-bottom:6px">Item not on the menu? Add it:</div>
          <div class="row"><input type="text" id="ni-name" data-keep placeholder="Item name"><input type="text" id="ni-price" data-keep class="p" inputmode="decimal" placeholder="Price"><button class="btn" data-act="newItem">Add</button></div>
        </div></section>`;
      html += `<section class="card"><h3>🧺 My order</h3>
        ${mine.length ? mine.map(l => `<div class="line"><div class="top"><div class="nm"><b>${esc(l.name)}</b><div class="muted small">${money(menuPrice(l))} each</div></div>
            <div class="qty"><button data-act="dec" data-k="${esc(l.k)}">−</button><span>${l.qty}</span><button data-act="inc" data-k="${esc(l.k)}">＋</button></div></div>
            <input type="text" class="note" id="note-${esc(l.k)}" data-k="${esc(l.k)}" value="${esc(l.note || "")}" placeholder="Note (optional).. e.g. no onions"></div>`).join("")
          + `<div class="sumrow"><span>My items (before extras)</span><b>${money(mySub)}</b></div>`
          : `<div class="empty">Nothing yet.. tap ＋ next to an item on the menu</div>`}
      </section>`;
      html += peopleHTML(live.people, "👥 Everyone's orders");
      if (admin) html += `<button class="btn dark block big" data-act="lock">🔒 Lock order (everyone's done)</button>
        <p class="muted small" style="text-align:center;margin:-6px 0 0">After locking nobody can add or change items, and you'll see the totals to place the order.</p>`;
    }

    else if (o.status === "locked") {
      if (admin) {
        const pr = draftPrice, fees = curFees(), split = curSplit();
        const b = calc(S.entries, pr, fees, split);
        const agg = aggregate(b.people, pr);
        html += headHTML(o, b.n);
        html += `<section class="card"><h3>🧮 Totals.. call and order</h3>
          ${o.hotline ? `<a class="btn block" style="margin-bottom:10px;background:var(--teal);color:#fff" href="tel:${esc(o.hotline)}">📞 Call ${esc(o.restaurantName)}: ${esc(o.hotline)}</a>` : ""}
          <div class="muted small">If a price changed, update it in the box 👇</div>
          ${agg.length ? agg.map(a => `<div class="agg-row"><div class="agg-q">${a.qty}×</div><div><b>${esc(a.name)}</b>
              ${a.notes.map(n => `<div class="muted small">• ${n.qty} ${esc(n.note)} — ${esc(n.who)}</div>`).join("")}</div>
              <input type="text" id="pr-${esc(a.itemId)}" data-price="${esc(a.itemId)}" inputmode="decimal" value="${esc(S.draft.prices[a.itemId] ?? a.unit)}" aria-label="Price of ${esc(a.name)}">
              <div class="agg-t" id="at-${esc(a.itemId)}">${a.qty} × ${money(a.unit)} = <b>${money(a.qty * a.unit)}</b></div></div>`).join("")
            : `<div class="empty">Nobody ordered anything</div>`}
          <div class="tot"><span>Food total</span><span id="t-food">${money(b.food)}</span></div>
        </section>`;
        html += `<section class="card"><h3>💸 Extras on the whole order</h3>
          <label class="fld"><span>Delivery + taxes + service (total)</span><input type="text" id="fees" inputmode="decimal" value="${esc(S.draft.fees ?? (o.fees || ""))}" placeholder="0"></label>
          <div class="seg">
            <label class="opt"><input type="radio" name="split" value="equal" ${split === "equal" ? "checked" : ""}><div><b>Split equally</b><small>Extras divided by the number of people</small></div></label>
            <label class="opt"><input type="radio" name="split" value="proportional" ${split === "proportional" ? "checked" : ""}><div><b>Proportional</b><small>Each pays according to their food (100 EGP of food pays double of 50 EGP)</small></div></label>
          </div></section>`;
        html += `<section class="card"><h3>👥 Who pays what</h3><div id="pp">${ppTable(b)}</div></section>`;
        html += `<div class="actions"><button class="btn ghost" data-act="unlock">🔓 Reopen</button><button class="btn primary" data-act="ordered">✅ Ordered</button></div>
          <p class="muted small" style="text-align:center;margin:-6px 0 0">When you tap “Ordered”, everyone gets their receipt.</p>`;
      } else {
        const b = calc(S.entries, menuPrice, 0, "equal");
        html += headHTML(o, b.n);
        html += `<div class="notice">🔒 The order is locked and ${esc(first(o.adminName))} is placing it now.. your receipt will show up as soon as it's done ⏳</div>`;
        const mine = b.people.find(p => p.id === uid);
        html += `<section class="card"><h3>🧺 My order</h3>${mine ? `<ul style="margin:0;padding-inline-start:18px">${mine.lines.map(l => `<li>${l.qty}× ${esc(l.name)}${clean(l.note) ? ` <i class="muted">(${esc(l.note)})</i>` : ""}</li>`).join("")}</ul>` : `<div class="empty">You didn't order anything in this one</div>`}</section>`;
        html += peopleHTML(b.people, "👥 Everyone's orders");
      }
    }

    else { // ordered
      const b = calc(S.entries, finalPrice, o.fees || 0, o.split);
      html += headHTML(o, b.n);
      const mine = b.people.find(p => p.id === uid);
      html += mine ? receiptHTML(o, b, mine) : `<section class="card"><div class="empty">You didn't order anything in this one 🙂</div></section>`;
      if (admin) {
        const paid = b.people.filter(p => p.paid);
        const collected = paid.reduce((s, p) => s + p.total, 0);
        html += `<section class="card"><h3>📊 Order summary (admin)</h3>
          <div class="receipt" style="border:0"><div class="rrow"><span>Food</span><b>${money(b.food)}</b></div>
          <div class="rrow"><span>Extras (${o.split === "proportional" ? "proportional" : "split equally"})</span><b>${money(b.fees)}</b></div>
          <div class="rrow total"><span>Total</span><b>${money(b.grand)}</b></div>
          <div class="rrow"><span>Collected (${paid.length} of ${b.n})</span><b style="color:var(--ok)">${money(collected)}</b></div></div>
        </section>
        <section class="card"><h3>🧾 Everyone's receipts</h3>
          ${b.people.map(p => `<div class="person"><div class="hd"><b>${esc(p.name)}</b><span class="small">${money(p.total)}</span>
            <button class="paybtn ${p.paid ? "yes" : ""}" data-act="paid" data-id="${esc(p.id)}">${p.paid ? "✅ Paid" : "Not paid"}</button></div>
            <div class="muted small">${p.lines.map(l => `${l.qty}× ${esc(l.name)}`).join(" · ")} — food ${money(p.sub)} + extras ${money(p.fee)}</div></div>`).join("")}
        </section>`;
      }
    }
    patch(html);
  }

  function ppTable(b) {
    if (!b.people.length) return `<div class="empty">Nobody ordered</div>`;
    return `<table class="pp"><thead><tr><th>Name</th><th class="n">Food</th><th class="n">Extras</th><th class="n">Total</th></tr></thead><tbody>
      ${b.people.map(p => `<tr><td>${esc(p.name)}</td><td class="n">${money(p.sub)}</td><td class="n">${money(p.fee)}</td><td class="n"><b>${money(p.total)}</b></td></tr>`).join("")}
      <tr class="grand"><td>All</td><td class="n">${money(b.food)}</td><td class="n">${money(b.fees)}</td><td class="n">${money(b.grand)}</td></tr></tbody></table>`;
  }
  function receiptHTML(o, b, p) {
    const pct = b.food > 0 ? r2(p.sub / b.food * 100) : 0;
    const method = o.split === "proportional"
      ? `Extras (${money(b.fees)}) were split <b>proportionally</b>: your food ${money(p.sub)} of ${money(b.food)} total = ${pct}% → your share ${money(p.fee)}`
      : `Extras (${money(b.fees)}) were split <b>equally</b> between ${b.n} ${b.n === 1 ? "person" : "people"} → your share ${money(p.fee)}`;
    return `<section class="card receipt">
      <div class="rh"><svg width="40" height="40"><use href="#ordarna-icon"/></svg><div><b>Ordarna receipt</b><div class="muted small">${esc(o.restaurantName)} · #${esc(o.code)} · ${tsDate(o.orderedAt)}</div></div></div>
      <div class="muted small" style="margin-bottom:6px">${esc(p.name)} · ${esc(p.deptName || "")}</div>
      <table class="pp"><thead><tr><th>Item</th><th class="n">Qty</th><th class="n">Price</th><th class="n">Total</th></tr></thead><tbody>
        ${p.lines.map(l => `<tr><td>${esc(l.name)}${clean(l.note) ? `<div class="muted small">${esc(l.note)}</div>` : ""}</td><td class="n">${l.qty}</td><td class="n">${money(l.unit)}</td><td class="n">${money(l.total)}</td></tr>`).join("")}
      </tbody></table>
      <div class="rrow" style="margin-top:8px"><span>Food</span><b>${money(p.sub)}</b></div>
      <div class="rrow"><span>Your share of extras</span><b>${money(p.fee)}</b></div>
      <div class="rrow total"><span>You pay</span><b>${money(p.total)}</b></div>
      <div class="method">🧮 ${method}</div>
      <span class="chip ${p.paid ? "open" : "locked"} paid">${p.paid ? "✅ Marked as paid" : "⏳ Not marked as paid yet"}</span>
    </section>`;
  }

  /* live recompute while admin types prices/fees (no full re-render => keyboard stays open) */
  function refreshNumbers() {
    const b = calc(S.entries, draftPrice, curFees(), curSplit());
    aggregate(b.people, draftPrice).forEach(a => {
      const el = document.getElementById("at-" + a.itemId);
      if (el) el.innerHTML = `${a.qty} × ${money(a.unit)} = <b>${money(a.qty * a.unit)}</b>`;
    });
    const f = document.getElementById("t-food"); if (f) f.textContent = money(b.food);
    const pp = document.getElementById("pp"); if (pp) pp.innerHTML = ppTable(b);
  }
  function persistDraft() {
    clearTimeout(saveDraftTimer);
    saveDraftTimer = setTimeout(() => {
      const prices = { ...(S.order.prices || {}) };
      for (const id in S.draft.prices) prices[id] = num(S.draft.prices[id]);
      updateDoc(oref, { prices, fees: curFees(), split: curSplit() }).catch(fail);
    }, 800);
  }

  /* ---------- events ---------- */
  view.oninput = e => {
    const t = e.target;
    if (t.id === "menu-filter") {
      S.filter = t.value;
      const box = document.getElementById("menu-list");
      if (box) { const tmp = document.createElement("div"); tmp.innerHTML = menuHTML(); box.replaceWith(tmp.querySelector("#menu-list")); }
    }
    else if (t.dataset.price) { S.draft.prices[t.dataset.price] = t.value; refreshNumbers(); persistDraft(); }
    else if (t.id === "fees") { S.draft.fees = t.value; refreshNumbers(); persistDraft(); }
    else if (t.classList.contains("note")) {
      const items = myItems(); const l = items.find(x => x.k === t.dataset.k); if (!l) return;
      l.note = t.value; const e2 = myEntry(); if (e2) e2.items = items;
      clearTimeout(noteTimer); noteTimer = setTimeout(() => saveMine(items), 600);
    }
  };
  view.onchange = e => {
    if (e.target.name === "split") { S.draft.split = e.target.value; refreshNumbers(); persistDraft(); }
  };
  view.onclick = async e => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act, o = S.order;
    const link = location.origin + location.pathname + "#/o/" + o.code;
    const msg = `🍔 Order from ${o.restaurantName}\nOrder number: ${o.code}\nJoin and order here 👇\n${link}`;
    switch (act) {
      case "wa": window.open("https://wa.me/?text=" + encodeURIComponent(msg), "_blank"); break;
      case "copy": toast((await copyText(link)) ? "Link copied ✅" : link); break;
      case "share": try { await navigator.share({ title: "Ordarna", text: msg }); } catch {} break;
      case "edit": S.edit = b.dataset.id; draw(); break;
      case "cancelEdit": S.edit = null; draw(); break;
      case "saveItem": {
        const name = clean(document.getElementById("ei-name").value), price = num(document.getElementById("ei-price").value);
        if (!name) return toast("Enter the item name");
        S.edit = null;
        updateDoc(doc(db, "restaurants", o.restaurantId, "items", b.dataset.id), { name, nameKey: key(name), price }).catch(fail);
        toast("Updated ✅"); break;
      }
      case "newItem": {
        const nEl = document.getElementById("ni-name"), pEl = document.getElementById("ni-price");
        const name = clean(nEl.value); if (!name) return toast("Enter the item name");
        if (!clean(pEl.value)) return toast("Enter the price");
        if (S.items.find(i => key(i.name) === key(name))) return toast("This item is already on the menu");
        const price = num(pEl.value);
        nEl.value = ""; pEl.value = "";
        addDoc(collection(db, "restaurants", o.restaurantId, "items"), { name, nameKey: key(name), price, createdAt: serverTimestamp() }).catch(fail);
        toast(`Added to menu: ${name}`);
        break;
      }
      case "addLine": {
        const it = itemById(b.dataset.id); if (!it) return;
        const items = myItems();
        const same = items.find(l => l.itemId === it.id && !clean(l.note));
        if (same) same.qty++; else items.push({ k: rid(), itemId: it.id, name: it.name, price: it.price || 0, qty: 1, note: "" });
        saveMine(items); toast(`Added: ${it.name}`); break;
      }
      case "inc": case "dec": {
        const items = myItems(); const l = items.find(x => x.k === b.dataset.k); if (!l) return;
        l.qty += act === "inc" ? 1 : -1;
        saveMine(items.filter(x => x.qty > 0)); break;
      }
      case "lock":
        if (!confirm("Lock the order? Nobody will be able to add or change items.")) return;
        S.draft = { prices: {}, fees: null, split: null };
        updateDoc(oref, { status: "locked", lockedAt: serverTimestamp() }).catch(fail); break;
      case "unlock":
        updateDoc(oref, { status: "open" }).catch(fail); break;
      case "ordered": {
        const bill = calc(S.entries, draftPrice, curFees(), curSplit());
        if (!bill.n) return toast("Nobody ordered anything");
        if (!confirm(`Total is ${money(bill.grand)}.\nConfirm the order was placed?`)) return;
        clearTimeout(saveDraftTimer);
        const prices = {};
        const batch = writeBatch(db);
        for (const p of bill.people) for (const l of p.lines) {
          prices[l.itemId] = l.unit;
          const it = itemById(l.itemId);
          if (it && it.price !== l.unit) batch.update(doc(db, "restaurants", o.restaurantId, "items", it.id), { price: l.unit });
        }
        batch.update(oref, { status: "ordered", prices, fees: curFees(), split: curSplit(), orderedAt: serverTimestamp() });
        b.disabled = true;
        batch.commit().then(() => toast("Order placed ✅ everyone got their receipt")).catch(err => { fail(err); b.disabled = false; });
        break;
      }
      case "paid": {
        const en = S.entries.find(x => x.id === b.dataset.id);
        updateDoc(doc(db, "orders", o.code, "entries", b.dataset.id), { paid: !en?.paid }).catch(fail); break;
      }
    }
  };
}
const byItem = (a, b) => String(a.category || "").localeCompare(String(b.category || "")) || (a.sort ?? 0) - (b.sort ?? 0) || byName(a, b);

/* ================= restaurants ================= */
async function viewRestaurants() {
  view.innerHTML = LOADING;
  const rests = (await list("restaurants")).sort(byName);
  view.innerHTML = `
    <div class="page-title"><a href="#/" class="back">←</a><h1>Restaurants & menus</h1></div>
    <a class="btn primary block big" href="#/r/new">➕ Add a restaurant</a>
    ${rests.length > 6 ? `<input type="text" id="rf" class="search" placeholder="🔎 Search restaurants">` : ""}
    <section class="card">${rests.length ? `<div class="list" id="rl">${rests.map(r => `<a class="li" data-k="${esc(key(r.name + " " + (r.area || "") + " " + (r.cuisine || "")))}" href="#/r/${esc(r.id)}"><div class="ico">🍽️</div><div class="grow"><b>${esc(r.name)}</b><span class="muted small">${[r.cuisine, r.area, r.hotline].filter(Boolean).map(esc).join(" · ")}</span></div><span class="muted">›</span></a>`).join("")}</div>`
      : `<div class="empty">No restaurants yet.. add the first one 👆</div>`}</section>`;
  view.oninput = e => {
    if (e.target.id !== "rf") return;
    const q = key(e.target.value);
    view.querySelectorAll("#rl .li").forEach(a => (a.hidden = q && !a.dataset.k.includes(q)));
  };
}

async function viewRestaurant(id) {
  const backToNew = sessionStorage.getItem("ordarna.backToNew") === "1";
  if (id === "new") {
    view.innerHTML = `
      <div class="page-title"><a href="${backToNew ? "#/new" : "#/restaurants"}" class="back">←</a><h1>New restaurant</h1></div>
      <section class="card">
        <label class="fld"><span>Restaurant name</span><input type="text" id="rn-name" placeholder="e.g. El Shabrawy"></label>
        <label class="fld"><span>Hotline / phone</span><input type="text" id="rn-tel" inputmode="tel" placeholder="19xxx"></label>
        <button class="btn primary block big" id="rn-save">Save & add items →</button>
      </section>`;
    document.getElementById("rn-save").onclick = async e => {
      const name = clean(document.getElementById("rn-name").value), hotline = clean(toEn(document.getElementById("rn-tel").value));
      if (!name) return toast("Enter the restaurant name");
      e.currentTarget.disabled = true;
      try {
        const dup = await list("restaurants", where("nameKey", "==", key(name)));
        if (dup.length) { toast("This restaurant already exists"); return location.replace("#/r/" + dup[0].id); }
        const ref = await addDoc(collection(db, "restaurants"), { name, nameKey: key(name), hotline, createdBy: uid, createdAt: serverTimestamp() });
        location.replace("#/r/" + ref.id);
      } catch (err) { fail(err); e.currentTarget.disabled = false; }
    };
    return;
  }

  view.innerHTML = LOADING;
  const R = { r: null, items: [], edit: null, editInfo: false };
  const rref = doc(db, "restaurants", id);
  const render = () => softRender(draw);
  subs.push(onSnapshot(rref, s => { R.r = s.exists() ? { id: s.id, ...s.data() } : false; render(); }, fail));
  subs.push(onSnapshot(collection(db, "restaurants", id, "items"), s => { R.items = s.docs.map(d => ({ id: d.id, ...d.data() })).sort(byItem); render(); }, fail));

  function itemLi(it) {
    return R.edit === it.id ? `<li><div class="editrow">
        <input type="text" id="ei-name" value="${esc(it.name)}"><input type="text" id="ei-price" class="p" inputmode="decimal" value="${esc(it.price ?? "")}">
        <button class="btn ok" data-act="saveItem" data-id="${esc(it.id)}">Save</button><button class="btn ghost" data-act="del" data-id="${esc(it.id)}">🗑️</button><button class="btn ghost" data-act="cancelEdit">Cancel</button></div></li>`
      : `<li><span class="nm">${esc(it.name)}</span><span class="pr">${money(it.price || 0)}</span><button class="icon" data-act="edit" data-id="${esc(it.id)}" aria-label="Edit">✏️</button></li>`;
  }
  function draw() {
    if (R.r === null) return;
    if (R.r === false) { view.innerHTML = `<section class="card"><div class="empty">This restaurant doesn't exist</div><a class="btn primary block" href="#/restaurants">Back</a></section>`; return; }
    const r = R.r;
    const groups = new Map();
    R.items.forEach(i => { const c = i.category || ""; if (!groups.has(c)) groups.set(c, []); groups.get(c).push(i); });
    patch(`
      <div class="page-title"><a href="${backToNew ? "#/new" : "#/restaurants"}" class="back">←</a><h1>${esc(r.name)}</h1></div>
      ${backToNew ? `<button class="btn ok block big" data-act="useIt">✅ Done.. back to the new order with this restaurant</button>` : ""}
      <section class="card">
        ${R.editInfo ? `
          <label class="fld"><span>Restaurant name</span><input type="text" id="re-name" value="${esc(r.name)}"></label>
          <label class="fld"><span>Hotline</span><input type="text" id="re-tel" inputmode="tel" value="${esc(r.hotline || "")}"></label>
          <div class="actions"><button class="btn ghost" data-act="cancelInfo">Cancel</button><button class="btn ok" data-act="saveInfo">Save</button></div>`
        : `<div style="display:flex;align-items:center;gap:10px"><div style="flex:1">${r.hotline ? `<a class="tel" href="tel:${esc(r.hotline)}">📞 ${esc(r.hotline)}</a>` : `<span class="muted small">No phone number</span>`}
            ${r.area || r.cuisine ? `<div class="muted small" style="margin-top:6px">${[r.cuisine, r.area].filter(Boolean).map(esc).join(" · ")}</div>` : ""}</div>
            <button class="btn ghost" data-act="editInfo">✏️ Edit</button></div>
          ${r.source ? `<div class="muted small" style="margin-top:8px">Prices from ${esc(r.source)}${r.pricesAsOf ? ` (${esc(r.pricesAsOf)})` : ""} — may have changed, the admin can update them when ordering.</div>` : ""}`}
      </section>
      <section class="card"><h3>📋 Items (${R.items.length})</h3>
        ${R.items.length ? [...groups].map(([c, items]) => `${c ? `<div class="cat">${esc(c)}</div>` : ""}<ul class="menu">${items.map(itemLi).join("")}</ul>`).join("") : `<div class="empty">No items yet</div>`}
        <div class="addrow"><div class="muted small" style="margin-bottom:6px">Add an item:</div>
          <div class="row"><input type="text" id="ni-name" data-keep placeholder="Item name"><input type="text" id="ni-price" data-keep class="p" inputmode="decimal" placeholder="Price"><button class="btn primary" data-act="newItem">Add</button></div>
        </div>
      </section>`);
  }

  view.onclick = async e => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act;
    if (act === "useIt") { sessionStorage.removeItem("ordarna.backToNew"); sessionStorage.setItem("ordarna.newRid", id); go("/new"); }
    else if (act === "editInfo") { R.editInfo = true; draw(); }
    else if (act === "cancelInfo") { R.editInfo = false; draw(); }
    else if (act === "saveInfo") {
      const name = clean(document.getElementById("re-name").value); if (!name) return toast("Enter the restaurant name");
      R.editInfo = false;
      updateDoc(rref, { name, nameKey: key(name), hotline: clean(toEn(document.getElementById("re-tel").value)) }).then(() => toast("Saved ✅")).catch(fail);
    }
    else if (act === "edit") { R.edit = b.dataset.id; draw(); }
    else if (act === "cancelEdit") { R.edit = null; draw(); }
    else if (act === "saveItem") {
      const name = clean(document.getElementById("ei-name").value); if (!name) return toast("Enter the item name");
      R.edit = null;
      updateDoc(doc(db, "restaurants", id, "items", b.dataset.id), { name, nameKey: key(name), price: num(document.getElementById("ei-price").value) }).then(() => toast("Updated ✅")).catch(fail);
    }
    else if (act === "del") {
      const it = R.items.find(i => i.id === b.dataset.id);
      if (!confirm(`Remove “${it?.name}” from the menu?`)) return;
      R.edit = null; deleteDoc(doc(db, "restaurants", id, "items", b.dataset.id)).catch(fail);
    }
    else if (act === "newItem") {
      const nEl = document.getElementById("ni-name"), pEl = document.getElementById("ni-price");
      const name = clean(nEl.value); if (!name) return toast("Enter the item name");
      if (!clean(pEl.value)) return toast("Enter the price");
      if (R.items.find(i => key(i.name) === key(name))) return toast("This item already exists");
      const price = num(pEl.value);
      nEl.value = ""; pEl.value = ""; nEl.focus();
      addDoc(collection(db, "restaurants", id, "items"), { name, nameKey: key(name), price, createdAt: serverTimestamp() }).catch(fail);
    }
  };
}

/* ================= history ================= */
async function viewHistory() {
  view.innerHTML = LOADING;
  const orders = (await list("orders", where("participants", "array-contains", uid))).sort((a, b) => ms(b.createdAt) - ms(a.createdAt));
  view.innerHTML = `
    <div class="page-title"><a href="#/" class="back">←</a><h1>My orders</h1></div>
    <section class="card">${orders.length ? `<div class="list">${orders.map(orderLi).join("")}</div>` : `<div class="empty">You haven't joined any orders yet</div>`}</section>`;
}

/* ================= boot ================= */
(async function boot() {
  try {
    const s = await getDoc(doc(db, "users", uid));
    me = s.exists() ? { id: uid, ...s.data() } : null;
  } catch (e) {
    console.error(e);
    view.innerHTML = `<section class="card"><h3>Can't connect 😕</h3><p class="muted">Check your internet connection.</p><button class="btn primary block" onclick="location.reload()">Retry</button></section>`;
    return;
  }
  window.addEventListener("hashchange", route);
  route();
})();
