/*
 * The try-it page of the local masker.
 *
 * One transport: load mode.json (relative), then POST JSON to "api" or
 * "bundle" with the X-Piimask-Token header. Masking runs in the local app;
 * this page only shows results, collects the tester's checks and asks the
 * app to build the feedback package.
 *
 * Rules this file keeps (tests/localapp/test_web_invariants.py checks them):
 * - every visible string comes from STRINGS (en + nl, identical keys);
 * - user text is only ever put on the page with textContent / text nodes;
 * - no storage, no cookies, no console output, no outside address;
 * - offsets from the app are code points; the DOM counts UTF-16 units, so
 *   cpToUtf16 / utf16ToCp convert at the boundary.
 */
"use strict";

// The STRINGS literal is kept valid JSON so the invariants test can read it.
const STRINGS = {
  "en": {
    "title": "Try the masker",
    "lang_switch_label": "Language",
    "lang_en": "English",
    "lang_nl": "Nederlands",
    "honest": "The masker was built and tested on Dutch text. On English it will likely miss more names, and it only recognises Dutch phone and VAT number formats (IBANs from any country). Try it with made-up data first.",
    "loading": "One moment, the masker is loading. This happens only on your own computer.",
    "stopped": "The masker has stopped. Start it again with the same command you used before.",
    "log_broken": "Your log can't be saved.",
    "counter_reset": "Your codes start fresh; answers from before can't be restored.",
    "step1_title": "1. Paste your question",
    "step1_hint": "Paste the text you want to ask your AI, personal details included.",
    "prompt_label": "Your question",
    "mask_btn": "Hide personal data",
    "new_question": "New question",
    "d41": "Your text already contains codes like PERSON_001001. Did you paste the hidden version? Paste your original text in step 1. If you leave it like this, I may later turn those codes into a real name.",
    "d42": "This text is already hidden. Paste your original text in step 1, not the hidden version.",
    "err_empty": "Paste some text first.",
    "err_too_long": "This text is too long for the masker.",
    "err_internal": "Something went wrong inside the masker. Try again.",
    "err_code": "That didn't work (code: {code}).",
    "step2_title": "2. Copy to your AI",
    "step2_hint": "This is the hidden version. Each code stands for one piece of personal data.",
    "masked_label": "Hidden version",
    "copy_btn": "Copy",
    "copied": "Copied. Paste it into your AI.",
    "copy_failed": "Copying didn't work. Select the text and copy it yourself.",
    "legend_label": "What the colours mean:",
    "none_found": "Nothing was hidden in this text.",
    "original_title": "Check your original text",
    "original_hint": "Did the masker miss something? Select it, choose what it is and click the button. Click a highlighted piece if it didn't need hiding.",
    "miss_kind_label": "What is it?",
    "miss_btn": "This is personal too (missed)",
    "miss_none_selected": "Select a piece of your original text first.",
    "miss_touches": "Select only text that isn't hidden yet.",
    "misses_title": "Marked as missed",
    "remove": "Remove",
    "kind_PERSON": "name",
    "kind_COMPANY": "company",
    "kind_EMAIL": "email",
    "kind_PHONE": "phone",
    "kind_IBAN": "IBAN",
    "kind_VAT": "VAT number",
    "kind_ADDRESS": "address",
    "kind_OTHER": "something else",
    "kind_MISS": "missed",
    "kind_FREE": "not needed",
    "overmask_piece": "You chose: {text}",
    "overmask_confirm": "This is not personal data",
    "overmask_btn": "This doesn't need hiding",
    "overmask_need_tick": "Tick the box first to confirm it isn't personal data.",
    "overmasks_title": "Marked as not needing hiding",
    "cancel": "Cancel",
    "step3_title": "3. Paste the answer back",
    "step3_hint": "Paste your AI's answer. The codes turn back into the real details, only on this page.",
    "answer_label": "Your AI's answer",
    "reveal_btn": "Put the real names back",
    "revealed_label": "Answer with the real details",
    "revealed_hint": "Click a restored piece if it is wrong.",
    "restored_label": "restored",
    "wrong_label": "not right",
    "unresolved": "I couldn't restore these codes; your AI probably changed them: {list}",
    "review_title": "Your checks for this question",
    "useful_q": "Was the answer useful?",
    "useful_ja": "Yes",
    "useful_deels": "Partly",
    "useful_nee": "No",
    "checked_all": "I checked everything",
    "checked_all_hint": "Tick this once you have read the whole text and marked everything the masker got wrong.",
    "note_label": "What did you notice?",
    "note_hint": "Your note is hidden the same way before it is saved.",
    "note_privacy": "Don't put names or other personal details in your note. The masker hides what it recognises, but a name it misses in a note can't be flagged.",
    "save_checks": "Save my checks",
    "saved": "Saved.",
    "save_failed": "Your checks couldn't be saved (code: {code}).",
    "note_refused": "Your note couldn't be hidden, so it wasn't saved.",
    "notes_title": "Your notes (hidden version)",
    "reset_btn": "Start over",
    "reset_confirm": "You start with new codes. Answers from before can't be restored after this.",
    "reset_yes": "Yes, start over",
    "logbook_title": "Logbook",
    "retention": "Your sessions are kept on your own computer, only in hidden form, for 30 days. Nothing is sent.",
    "bundle_btn": "Make feedback package",
    "preview_honest": "This contains the hidden version of your text. Anything the masker didn't recognise and you didn't mark is still in it: read it through before you send it.",
    "include_off_hint": "Questions without a tick go in as counts only.",
    "preview_empty": "There are no questions in your log yet.",
    "preview_question": "Question {n}",
    "preview_reviewed": "Checked by you",
    "preview_include": "Include the full text",
    "preview_refused": "Refused: {reason}",
    "refused_empty_input": "empty question",
    "refused_too_long": "question too long",
    "refused_already_masked": "text was already hidden",
    "refused_internal": "error inside the masker",
    "refused_other": "other reason",
    "preview_no_text": "This question goes in as counts only.",
    "preview_flag_misses": "Missed: {n}",
    "preview_flag_over": "Not needed: {n}",
    "preview_flag_wrong": "Wrong back: {n}",
    "marker_domain": "[DOMAIN]",
    "marker_missed": "[MISSED:{kind}]",
    "preview_useful": "Useful: {useful}",
    "preview_note": "Note: {note}",
    "save_zip": "Save as zip",
    "zip_saved": "Saved in your Downloads folder as {name}",
    "zip_failed": "The package couldn't be saved (code: {code}).",
    "footer": "Everything happens on your own computer. Nothing goes to a server. When you stop the masker, your text and the codes are gone.",
    "version": "Version {v}"
  },
  "nl": {
    "title": "Probeer de verberger",
    "lang_switch_label": "Taal",
    "lang_en": "English",
    "lang_nl": "Nederlands",
    "honest": "De verberger is gebouwd en getest op Nederlandse tekst. Bij Engels mist hij waarschijnlijk meer namen, en hij herkent alleen Nederlandse telefoon- en btw-nummers (IBAN's uit elk land wel). Probeer het eerst met verzonnen gegevens.",
    "loading": "Even geduld, de verberger wordt geladen. Dit gebeurt alleen op je eigen computer.",
    "stopped": "De verberger is gestopt. Start hem opnieuw met dezelfde opdracht als de vorige keer.",
    "log_broken": "Je logboek kan niet worden opgeslagen.",
    "counter_reset": "Je codes beginnen opnieuw; oude antwoorden kan ik niet terugzetten.",
    "step1_title": "1. Plak je vraag",
    "step1_hint": "Plak de tekst die je aan je AI wilt vragen, met de persoonsgegevens erin.",
    "prompt_label": "Je vraag",
    "mask_btn": "Verberg persoonsgegevens",
    "new_question": "Nieuwe vraag",
    "d41": "Je tekst bevat al codes zoals PERSON_001001. Heb je misschien de verborgen versie geplakt? Plak in stap 1 je oorspronkelijke tekst. Laat je het zo, dan kan ik die codes straks omzetten naar een echte naam.",
    "d42": "Deze tekst is al verborgen. Plak in stap 1 je oorspronkelijke tekst, niet de verborgen versie.",
    "err_empty": "Plak eerst wat tekst.",
    "err_too_long": "Deze tekst is te lang voor de verberger.",
    "err_internal": "Er ging iets mis in de verberger. Probeer het opnieuw.",
    "err_code": "Dat lukte niet (code: {code}).",
    "step2_title": "2. Kopieer naar je AI",
    "step2_hint": "Dit is de verborgen versie. Elke code staat voor één persoonsgegeven.",
    "masked_label": "Verborgen versie",
    "copy_btn": "Kopieer",
    "copied": "Gekopieerd. Plak het in je AI.",
    "copy_failed": "Kopiëren lukte niet. Selecteer de tekst en kopieer hem zelf.",
    "legend_label": "Wat de kleuren betekenen:",
    "none_found": "Er is niets verborgen in deze tekst.",
    "original_title": "Controleer je oorspronkelijke tekst",
    "original_hint": "Heeft de verberger iets gemist? Selecteer het, kies wat het is en klik op de knop. Klik op een gemarkeerd stuk als het niet verborgen hoefde te worden.",
    "miss_kind_label": "Wat is het?",
    "miss_btn": "Dit is ook persoonlijk (gemist)",
    "miss_none_selected": "Selecteer eerst een stuk van je oorspronkelijke tekst.",
    "miss_touches": "Selecteer alleen tekst die nog niet verborgen is.",
    "misses_title": "Gemarkeerd als gemist",
    "remove": "Weghalen",
    "kind_PERSON": "naam",
    "kind_COMPANY": "bedrijf",
    "kind_EMAIL": "e-mail",
    "kind_PHONE": "telefoon",
    "kind_IBAN": "IBAN",
    "kind_VAT": "btw-nummer",
    "kind_ADDRESS": "adres",
    "kind_OTHER": "iets anders",
    "kind_MISS": "gemist",
    "kind_FREE": "onnodig",
    "overmask_piece": "Je koos: {text}",
    "overmask_confirm": "Dit is geen persoonsgegeven",
    "overmask_btn": "Dit hoeft niet verborgen te worden",
    "overmask_need_tick": "Vink eerst aan dat het geen persoonsgegeven is.",
    "overmasks_title": "Gemarkeerd als onnodig verborgen",
    "cancel": "Annuleer",
    "step3_title": "3. Plak het antwoord terug",
    "step3_hint": "Plak het antwoord van je AI. De codes worden weer de echte gegevens, alleen op deze pagina.",
    "answer_label": "Het antwoord van je AI",
    "reveal_btn": "Zet de echte namen terug",
    "revealed_label": "Antwoord met de echte gegevens",
    "revealed_hint": "Klik op een teruggezet stuk als het niet klopt.",
    "restored_label": "teruggezet",
    "wrong_label": "klopt niet",
    "unresolved": "Deze codes kon ik niet terugzetten, je AI heeft ze waarschijnlijk veranderd: {list}",
    "review_title": "Jouw controle van deze vraag",
    "useful_q": "Was het antwoord bruikbaar?",
    "useful_ja": "Ja",
    "useful_deels": "Deels",
    "useful_nee": "Nee",
    "checked_all": "Ik heb alles nagelopen",
    "checked_all_hint": "Vink dit aan als je de hele tekst hebt gelezen en alles hebt gemarkeerd wat de verberger fout deed.",
    "note_label": "Wat viel je op?",
    "note_hint": "Je notitie wordt op dezelfde manier verborgen voordat hij wordt bewaard.",
    "note_privacy": "Zet geen namen of andere persoonsgegevens in je notitie. De verberger verbergt wat hij herkent, maar een gemiste naam in een notitie kun je niet markeren.",
    "save_checks": "Bewaar mijn controle",
    "saved": "Bewaard.",
    "save_failed": "Je controle kon niet worden bewaard (code: {code}).",
    "note_refused": "Je notitie kon niet worden verborgen, dus hij is niet bewaard.",
    "notes_title": "Je notities (verborgen versie)",
    "reset_btn": "Begin opnieuw",
    "reset_confirm": "Je begint met nieuwe codes. Antwoorden van hiervoor kan ik daarna niet meer terugzetten.",
    "reset_yes": "Ja, begin opnieuw",
    "logbook_title": "Logboek",
    "retention": "Je sessies worden bewaard op je eigen computer, alleen in verborgen vorm, 30 dagen lang. Niets wordt verstuurd.",
    "bundle_btn": "Maak feedbackpakket",
    "preview_honest": "Hierin staat de verborgen versie van je tekst. Wat de verberger niet heeft herkend en jij niet hebt aangevinkt, staat er nog wél in: lees het even na voordat je het verstuurt.",
    "include_off_hint": "Vragen zonder vinkje gaan alleen als aantallen mee.",
    "preview_empty": "Er staan nog geen vragen in je logboek.",
    "preview_question": "Vraag {n}",
    "preview_reviewed": "Door jou nagelopen",
    "preview_include": "Neem de hele tekst mee",
    "preview_refused": "Geweigerd: {reason}",
    "refused_empty_input": "lege vraag",
    "refused_too_long": "te lange vraag",
    "refused_already_masked": "tekst was al verborgen",
    "refused_internal": "fout in de verberger",
    "refused_other": "andere reden",
    "preview_no_text": "Deze vraag gaat alleen als aantallen mee.",
    "preview_flag_misses": "Gemist: {n}",
    "preview_flag_over": "Onnodig: {n}",
    "preview_flag_wrong": "Fout teruggezet: {n}",
    "marker_domain": "[DOMEIN]",
    "marker_missed": "[GEMIST:{kind}]",
    "preview_useful": "Bruikbaar: {useful}",
    "preview_note": "Notitie: {note}",
    "save_zip": "Bewaar als zip",
    "zip_saved": "Bewaard in je map Downloads als {name}",
    "zip_failed": "Het pakket kon niet worden bewaard (code: {code}).",
    "footer": "Alles gebeurt op je eigen computer. Er gaat niets naar een server. Stop je de verberger, dan zijn je tekst en de codes weg.",
    "version": "Versie {v}"
  }
}; // end STRINGS

const KINDS = ["PERSON", "COMPANY", "EMAIL", "PHONE", "IBAN", "VAT", "ADDRESS", "OTHER"];

// ---------------------------------------------------------------------------
// State (memory only; gone when the tab closes)
// ---------------------------------------------------------------------------

const state = {
  lang: (typeof navigator !== "undefined" && /^nl/i.test(navigator.language || "")) ? "nl" : "en",
  token: null,
  version: null,
  stopped: false,
  logOk: true,
  counterReset: false,
  pageId: null,     // 12 random hex characters, made once per page load
  promptSeq: 0,
  anyMasked: false, // a question was masked on this page
  q: null,          // the current question, see newQuestion()
  step1Msgs: [],    // [{key, vars}]
  revealMsgs: [],
  missMsg: null,
  overmaskMsg: null,
  copyMsg: null,
  saveMsg: null,
  bundleMsg: null,
  pendingSel: null, // {start, end} in UTF-16 units of the original text
  overmaskIdx: null,
  preview: null,    // list from POST bundle preview
  includes: {},     // preview id -> bool
  resetOpen: false
};

function emptyQuestion() {
  return {
    id: null,         // "p-<n>", set when the question is masked
    text: "",         // the original text (on this page only)
    result: null,     // the mask() response
    misses: [],       // [{start, end, kind}] code points
    overMasks: {},    // span_index -> {confirmed: bool, text: string|null}
    restoreWrong: [], // tokens
    reveal: null,     // the reveal() response
    useful: null,
    checkedAll: false,
    notes: [],        // masked notes
    dirty: false
  };
}
state.q = emptyQuestion();

function t(key, vars) {
  const table = STRINGS[state.lang] || STRINGS.en;
  let s = Object.prototype.hasOwnProperty.call(table, key) ? table[key] : STRINGS.en[key];
  if (typeof s !== "string") { s = ""; }
  if (vars) {
    s = s.replace(/\{(\w+)\}/g, function (m, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : m;
    });
  }
  return s;
}

function $(id) { return document.getElementById(id); }

// ---------------------------------------------------------------------------
// Offsets: the app counts code points, the DOM counts UTF-16 units
// ---------------------------------------------------------------------------

function cpToUtf16(text, cp) {
  let units = 0;
  let count = 0;
  for (const ch of text) {
    if (count >= cp) { break; }
    units += ch.length;
    count += 1;
  }
  return units;
}

function utf16ToCp(text, units) {
  return Array.from(text.slice(0, units)).length;
}

function cpSlice(text, start, end) {
  return Array.from(text).slice(start, end).join("");
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

function markStopped() {
  state.stopped = true;
  renderNotices();
}

async function post(path, body) {
  let res;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Piimask-Token": state.token || "" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store"
    });
  } catch (_e) {
    markStopped();
    return null;
  }
  let data = null;
  try {
    data = await res.json();
  } catch (_e) {
    data = null;
  }
  if ((!data || typeof data !== "object") && res.status === 413) {
    return { ok: false, code: "too_long" };
  }
  if (!data || typeof data !== "object") {
    markStopped();
    return null;
  }
  if (data.log_ok === false && state.logOk) {
    state.logOk = false;
    renderNotices();
  }
  return data;
}

function api(body) { return post("api", body); }
function bundle(body) { return post("bundle", body); }

async function loadMode() {
  let data = null;
  try {
    const res = await fetch("mode.json", { cache: "no-store", credentials: "same-origin" });
    if (res.ok) { data = await res.json(); }
  } catch (_e) {
    data = null;
  }
  if (!data || data.transport !== "local" || typeof data.token !== "string") {
    $("loading").hidden = true;
    markStopped();
    return;
  }
  state.token = data.token;
  state.version = typeof data.version === "string" ? data.version : null;
  state.logOk = data.log_ok !== false;
  state.counterReset = Array.isArray(data.notices) && data.notices.indexOf("counter_reset") !== -1;
  $("loading").hidden = true;
  $("app").hidden = false;
  renderAll();
}

// ---------------------------------------------------------------------------
// Rendering helpers (text nodes only)
// ---------------------------------------------------------------------------

function clear(el) {
  while (el.firstChild) { el.removeChild(el.firstChild); }
}

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) { node.className = cls; }
  if (text !== undefined && text !== null) { node.textContent = text; }
  return node;
}

// Fills `box` with `text`, wrapping each mark {start, end} (UTF-16 units,
// sorted, not overlapping) in a span. Labels are shown with CSS ::after from
// data-label, so they are never text nodes and never shift the offsets.
function renderMarked(box, text, marks) {
  clear(box);
  let pos = 0;
  for (const m of marks) {
    if (m.start < pos || m.end <= m.start) { continue; }
    if (m.start > pos) { box.appendChild(document.createTextNode(text.slice(pos, m.start))); }
    const span = el("span", "hl " + m.cls);
    const piece = text.slice(m.start, m.end);
    if (m.label) {
      // The label rides on the piece's last word, which never wraps away
      // from it; the text nodes stay in order, so offsets are unchanged.
      const cut = tailStart(piece);
      if (cut > 0) { span.appendChild(document.createTextNode(piece.slice(0, cut))); }
      const tail = el("span", "hl-tail");
      tail.appendChild(document.createTextNode(piece.slice(cut)));
      tail.setAttribute("data-label", m.label);
      span.appendChild(tail);
    } else {
      span.appendChild(document.createTextNode(piece));
    }
    if (m.kind) { span.setAttribute("data-kind", m.kind); }
    if (m.title) { span.setAttribute("aria-label", m.title); }
    if (m.onActivate) {
      span.tabIndex = 0;
      span.setAttribute("role", "button");
      span.classList.add("clickable");
      span.addEventListener("click", m.onActivate);
      span.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); m.onActivate(); }
      });
    }
    box.appendChild(span);
    pos = m.end;
  }
  if (pos < text.length) { box.appendChild(document.createTextNode(text.slice(pos))); }
}

// Where the unbreakable tail of a highlighted piece starts (UTF-16 units):
// its last word, or its last 8 characters when that word is long.
function tailStart(piece) {
  let cut = piece.search(/\S+\s*$/);
  if (cut < 0) { cut = 0; }
  if (piece.length - cut > 14) {
    cut = piece.length - 8;
    const c = piece.charCodeAt(cut);
    if (c >= 0xDC00 && c <= 0xDFFF) { cut -= 1; }
  }
  return cut;
}

// The bundle's own markers, shown in the page language (display only).
function displayMarkers(text) {
  return text.replace(/\[DOMEIN\]|\[GEMIST:([A-Z_]+)\]/g, function (_m, kind) {
    if (kind === undefined) { return t("marker_domain"); }
    return t("marker_missed", { kind: kindLabel(kind) });
  });
}

const MASK_REFUSALS = ["empty_input", "too_long", "already_masked", "internal"];

function refusedReason(code) {
  if (code === "empty_input") { return t("refused_empty_input"); }
  if (code === "too_long") { return t("refused_too_long"); }
  if (code === "already_masked") { return t("refused_already_masked"); }
  if (code === "internal") { return t("refused_internal"); }
  return t("refused_other");
}

function kindLabel(kind) {
  return KINDS.indexOf(kind) !== -1 ? t("kind_" + kind) : t("kind_OTHER");
}

function kindClass(kind) {
  return "k-" + (KINDS.indexOf(kind) !== -1 ? kind : "OTHER");
}

function renderMsgs(box, msgs) {
  clear(box);
  for (const m of msgs) {
    box.appendChild(el("p", "msg" + (m.warn ? " msg-warn" : ""), t(m.key, m.vars)));
  }
}

function setMsg(node, m) {
  node.textContent = m ? t(m.key, m.vars) : "";
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function applyStatic() {
  document.documentElement.lang = state.lang;
  document.title = t("title");
  const nodes = document.querySelectorAll("[data-i18n]");
  for (const n of nodes) { n.textContent = t(n.getAttribute("data-i18n")); }
  const ariaNodes = document.querySelectorAll("[data-i18n-aria]");
  for (const n of ariaNodes) { n.setAttribute("aria-label", t(n.getAttribute("data-i18n-aria"))); }
  for (const b of document.querySelectorAll(".lang button")) {
    b.setAttribute("aria-pressed", b.getAttribute("data-lang") === state.lang ? "true" : "false");
  }
  $("version").textContent = state.version ? t("version", { v: state.version }) : "";
}

function renderNotices() {
  $("notice-stopped").hidden = !state.stopped;
  $("notice-log").hidden = state.logOk;
  $("notice-counter").hidden = !state.counterReset;
  const busy = state.stopped;
  for (const b of document.querySelectorAll("main button")) {
    if (busy) { b.disabled = true; }
  }
}

function renderStep1() {
  const q = state.q;
  const locked = !!(q.result && q.result.ok);
  $("prompt-input").readOnly = locked;
  $("mask-btn").hidden = locked;
  renderMsgs($("step1-msg"), state.step1Msgs);
}

function spanMarksMasked(q) {
  const masked = q.result.masked;
  return q.result.spans.map(function (sp) {
    return {
      start: cpToUtf16(masked, sp.masked_start),
      end: cpToUtf16(masked, sp.masked_end),
      cls: kindClass(sp.kind),
      kind: sp.kind,
      label: kindLabel(sp.kind),
      title: kindLabel(sp.kind)
    };
  });
}

function renderStep2() {
  const q = state.q;
  const show = !!(q.result && q.result.ok);
  $("step2").hidden = !show;
  if (!show) { return; }
  const spans = q.result.spans;
  renderMarked($("masked-text"), q.result.masked, spanMarksMasked(q));
  setMsg($("copy-status"), state.copyMsg);

  // Legend: the kinds present, each with its colour and its word.
  const list = $("legend-list");
  clear(list);
  const seen = [];
  for (const sp of spans) { if (seen.indexOf(sp.kind) === -1) { seen.push(sp.kind); } }
  if (seen.length === 0) {
    list.appendChild(el("li", null, t("none_found")));
  }
  for (const k of seen) {
    const li = el("li");
    const sw = el("span", "hl " + kindClass(k), kindLabel(k));
    li.appendChild(sw);
    list.appendChild(li);
  }

  // The original text: spans (click = over-mask) and misses.
  const text = q.text;
  const marks = [];
  spans.forEach(function (sp, i) {
    const om = q.overMasks[i];
    marks.push({
      start: cpToUtf16(text, sp.start),
      end: cpToUtf16(text, sp.end),
      cls: kindClass(sp.kind) + (om ? " freed" : ""),
      kind: sp.kind,
      label: om ? kindLabel(sp.kind) + " · " + t("kind_FREE") : kindLabel(sp.kind),
      title: kindLabel(sp.kind),
      onActivate: function () { openOvermask(i); }
    });
  });
  for (const m of q.misses) {
    marks.push({
      start: cpToUtf16(text, m.start),
      end: cpToUtf16(text, m.end),
      cls: "miss",
      label: t("kind_MISS") + " · " + kindLabel(m.kind),
      title: t("kind_MISS")
    });
  }
  marks.sort(function (a, b) { return a.start - b.start; });
  renderMarked($("original-text"), text, marks);
  setMsg($("miss-msg"), state.missMsg);

  // Over-mask panel.
  const panel = $("overmask-panel");
  panel.hidden = state.overmaskIdx === null;
  if (state.overmaskIdx !== null) {
    const sp = spans[state.overmaskIdx];
    $("overmask-piece").textContent = t("overmask_piece", { text: cpSlice(text, sp.start, sp.end) });
    setMsg($("overmask-msg"), state.overmaskMsg);
  }

  // Lists.
  const missList = $("miss-list");
  clear(missList);
  q.misses.forEach(function (m, i) {
    const li = el("li");
    li.appendChild(el("span", "item-text", kindLabel(m.kind) + ": " + cpSlice(text, m.start, m.end)));
    const b = el("button", "small", t("remove"));
    b.type = "button";
    b.addEventListener("click", function () {
      q.misses.splice(i, 1);
      q.dirty = true;
      renderAll();
    });
    li.appendChild(b);
    missList.appendChild(li);
  });
  $("miss-block").hidden = q.misses.length === 0;

  const omList = $("overmask-list");
  clear(omList);
  const omKeys = Object.keys(q.overMasks).map(Number).sort(function (a, b) { return a - b; });
  for (const idx of omKeys) {
    const sp = spans[idx];
    const li = el("li");
    li.appendChild(el("span", "item-text", kindLabel(sp.kind) + ": " + cpSlice(text, sp.start, sp.end)));
    const b = el("button", "small", t("remove"));
    b.type = "button";
    b.addEventListener("click", function () {
      delete q.overMasks[idx];
      q.dirty = true;
      renderAll();
    });
    li.appendChild(b);
    omList.appendChild(li);
  }
  $("overmask-block").hidden = omKeys.length === 0;
}

function renderStep3() {
  const q = state.q;
  const show = !!(q.result && q.result.ok);
  $("step3").hidden = !show;
  if (!show) { return; }
  renderMsgs($("reveal-msg"), state.revealMsgs);
  const rv = q.reveal;
  $("revealed-block").hidden = !rv;
  if (!rv) { return; }
  const text = rv.revealed;
  const marks = rv.restored.map(function (r) {
    const wrong = q.restoreWrong.indexOf(r.token) !== -1;
    return {
      start: cpToUtf16(text, r.start),
      end: cpToUtf16(text, r.end),
      cls: wrong ? "wrong" : "restored",
      label: wrong ? t("wrong_label") : t("restored_label"),
      title: wrong ? t("wrong_label") : t("restored_label"),
      onActivate: function () {
        const at = q.restoreWrong.indexOf(r.token);
        if (at === -1) { q.restoreWrong.push(r.token); } else { q.restoreWrong.splice(at, 1); }
        q.dirty = true;
        renderAll();
      }
    };
  });
  marks.sort(function (a, b) { return a.start - b.start; });
  renderMarked($("revealed-text"), text, marks);
  const un = $("unresolved-msg");
  if (rv.unresolved.length) {
    un.hidden = false;
    un.textContent = t("unresolved", { list: rv.unresolved.map(function (u) { return u.text; }).join(", ") });
  } else {
    un.hidden = true;
    un.textContent = "";
  }
}

function renderReview() {
  const q = state.q;
  const show = !!(q.result && q.result.ok);
  $("review").hidden = !show;
  if (!show) { return; }
  for (const v of ["ja", "deels", "nee"]) { $("useful-" + v).checked = q.useful === v; }
  $("checked-all").checked = q.checkedAll;
  setMsg($("save-status"), state.saveMsg);
  const list = $("note-list");
  clear(list);
  for (const n of q.notes) { list.appendChild(el("li", "item-text", n)); }
  $("note-block").hidden = q.notes.length === 0;
}

function renderSession() {
  $("session").hidden = !state.anyMasked && !state.resetOpen;
  $("new-question-btn").hidden = !(state.q.result && state.q.result.ok);
  $("reset-confirm").hidden = !state.resetOpen;
}

function renderLogbook() {
  const box = $("preview");
  box.hidden = state.preview === null;
  setMsg($("bundle-status"), state.bundleMsg);
  if (state.preview === null) { return; }
  const list = $("preview-list");
  clear(list);
  $("preview-empty").hidden = state.preview.length !== 0;
  $("bundle-save-btn").hidden = state.preview.length === 0;
  let n = 0;
  state.preview.forEach(function (item) {
    // A question the masker refused never had text: one plain line, no tick box.
    if (typeof item.code === "string" && MASK_REFUSALS.indexOf(item.code) !== -1) {
      const li0 = el("li", "preview-item preview-refused");
      li0.appendChild(el("p", "hint", t("preview_refused", { reason: refusedReason(item.code) })));
      list.appendChild(li0);
      return;
    }
    n += 1;
    const li = el("li", "preview-item");
    const head = el("div", "preview-head");
    head.appendChild(el("strong", null, t("preview_question", { n: n })));
    if (item.reviewed) { head.appendChild(el("span", "badge", t("preview_reviewed"))); }
    li.appendChild(head);
    if (typeof item.text === "string") {
      li.appendChild(el("pre", "preview-text", displayMarkers(item.text)));
    }
    if (typeof item.note === "string" && item.note) {
      li.appendChild(el("p", "hint", t("preview_note", { note: displayMarkers(item.note) })));
    }
    const f = item.flags;
    if (f && typeof f === "object") {
      const fl = el("p", "hint flags");
      fl.appendChild(el("span", "nowrap", t("preview_flag_misses", { n: (f.misses || []).length })));
      fl.appendChild(document.createTextNode(" "));
      fl.appendChild(el("span", "nowrap", t("preview_flag_over", { n: (f.over_masks || []).length })));
      fl.appendChild(document.createTextNode(" "));
      fl.appendChild(el("span", "nowrap", t("preview_flag_wrong", { n: (f.restore_wrong || []).length })));
      li.appendChild(fl);
      if (f.useful === "ja" || f.useful === "deels" || f.useful === "nee") {
        li.appendChild(el("p", "hint", t("preview_useful", { useful: t("useful_" + f.useful) })));
      }
    }
    if (!item.can_include) {
      li.appendChild(el("p", "hint", t("preview_no_text")));
      list.appendChild(li);
      return;
    }
    const lab = el("label", "tick");
    const box2 = document.createElement("input");
    box2.type = "checkbox";
    box2.id = "include-" + item.id;
    box2.checked = !!state.includes[item.id];
    box2.addEventListener("change", function () { state.includes[item.id] = box2.checked; });
    lab.appendChild(box2);
    lab.appendChild(document.createTextNode(" "));
    lab.appendChild(el("span", null, t("preview_include")));
    li.appendChild(lab);
    list.appendChild(li);
  });
}

function renderAll() {
  applyStatic();
  renderStep1();
  renderStep2();
  renderStep3();
  renderReview();
  renderSession();
  renderLogbook();
  renderNotices();
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

// One random id per page load, so two page loads (or two copies) never
// hand out the same prompt id: "p-<12 hex>-<n>".
function makePageId() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}

function nextPromptId() {
  if (!state.pageId) { state.pageId = makePageId(); }
  state.promptSeq += 1;
  return "p-" + state.pageId + "-" + state.promptSeq;
}

function refusalKey(code) {
  if (code === "already_masked") { return { key: "d42" }; }
  if (code === "empty_input") { return { key: "err_empty" }; }
  if (code === "too_long") { return { key: "err_too_long" }; }
  if (code === "internal") { return { key: "err_internal" }; }
  return { key: "err_code", vars: { code: String(code) } };
}

async function doMask() {
  const text = $("prompt-input").value;
  const id = nextPromptId(); // a refused attempt keeps its own id; a retry gets a new one
  const res = await api({ op: "mask", text: text, prompt_id: id, ui_lang: state.lang });
  if (!res) { return; }
  state.step1Msgs = [];
  if (!res.ok) {
    state.step1Msgs.push(refusalKey(res.code));
    renderAll();
    return;
  }
  const q = emptyQuestion();
  q.id = id;
  q.text = text;
  q.result = res;
  state.q = q;
  state.anyMasked = true;
  $("miss-kind").selectedIndex = 0;
  if ((res.warnings || []).some(function (w) { return w.code === "token_like_in_input"; })) {
    state.step1Msgs.push({ key: "d41", warn: true });
  }
  state.copyMsg = null;
  state.missMsg = null;
  state.saveMsg = null;
  state.revealMsgs = [];
  state.overmaskIdx = null;
  state.pendingSel = null;
  $("answer-input").value = "";
  $("note-input").value = "";
  renderAll();
}

async function doCopy() {
  const q = state.q;
  if (!q.result || !q.result.ok) { return; }
  let ok = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(q.result.masked);
      ok = true;
    }
  } catch (_e) {
    ok = false;
  }
  if (!ok) {
    const range = document.createRange();
    range.selectNodeContents($("masked-text"));
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  state.copyMsg = ok ? { key: "copied" } : { key: "copy_failed" };
  renderAll();
}

// Turns a selection boundary into a UTF-16 offset by walking the container's
// text nodes in order and summing their lengths.
function boundaryOffset(container, node, offset) {
  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
  let total = 0;
  if (node.nodeType === Node.TEXT_NODE) {
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n === node) { return total + offset; }
      total += n.length;
    }
    return null;
  }
  const ref = node.childNodes[offset] || null;
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (ref) {
      if (ref === n || ref.contains(n) || (ref.compareDocumentPosition(n) & Node.DOCUMENT_POSITION_FOLLOWING)) {
        return total;
      }
    } else if (!node.contains(n) && (node.compareDocumentPosition(n) & Node.DOCUMENT_POSITION_FOLLOWING)) {
      return total;
    }
    total += n.length;
  }
  return total;
}

function captureSelection() {
  const box = $("original-text");
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0 || sel.isCollapsed) { return; }
  const range = sel.getRangeAt(0);
  if (!box.contains(range.startContainer) || !box.contains(range.endContainer)) {
    state.pendingSel = null;
    return;
  }
  const a = boundaryOffset(box, range.startContainer, range.startOffset);
  const b = boundaryOffset(box, range.endContainer, range.endOffset);
  if (a === null || b === null || a === b) { return; }
  state.pendingSel = { start: Math.min(a, b), end: Math.max(a, b) };
}

function doMiss() {
  const q = state.q;
  captureSelection();
  const sel = state.pendingSel;
  if (!sel) {
    state.missMsg = { key: "miss_none_selected" };
    renderAll();
    return;
  }
  const start = utf16ToCp(q.text, sel.start);
  const end = utf16ToCp(q.text, sel.end);
  const touches = q.result.spans.some(function (sp) { return sp.start < end && start < sp.end; }) ||
    q.misses.some(function (m) { return m.start < end && start < m.end; });
  if (touches || end <= start) {
    state.missMsg = { key: "miss_touches" };
    renderAll();
    return;
  }
  q.misses.push({ start: start, end: end, kind: $("miss-kind").value });
  q.misses.sort(function (x, y) { return x.start - y.start; });
  q.dirty = true;
  state.pendingSel = null;
  state.missMsg = null;
  const s = window.getSelection();
  if (s) { s.removeAllRanges(); }
  renderAll();
}

function openOvermask(i) {
  state.overmaskIdx = i;
  state.overmaskMsg = null;
  const om = state.q.overMasks[i];
  $("overmask-confirm").checked = !!(om && om.confirmed);
  renderAll();
  $("overmask-confirm").focus();
}

function doOvermask() {
  const q = state.q;
  const i = state.overmaskIdx;
  if (i === null) { return; }
  if (!$("overmask-confirm").checked) {
    state.overmaskMsg = { key: "overmask_need_tick" };
    renderAll();
    return;
  }
  const sp = q.result.spans[i];
  q.overMasks[i] = { confirmed: true, text: cpSlice(q.text, sp.start, sp.end) };
  q.dirty = true;
  state.overmaskIdx = null;
  renderAll();
}

async function doReveal() {
  const q = state.q;
  if (!q.id) { return; }
  // session.call's reveal op takes its text as "text".
  const res = await api({ op: "reveal", text: $("answer-input").value, prompt_id: q.id, ui_lang: state.lang });
  if (!res) { return; }
  state.revealMsgs = [];
  if (!res.ok) {
    state.revealMsgs.push(refusalKey(res.code));
  } else {
    q.reveal = res;
    q.restoreWrong = [];
    q.dirty = true;
  }
  renderAll();
}

function flagsBody(q) {
  const over = Object.keys(q.overMasks).map(Number).sort(function (a, b) { return a - b; }).map(function (idx) {
    const om = q.overMasks[idx];
    const entry = { span_index: idx, confirmed_not_personal: !!om.confirmed };
    if (om.confirmed && typeof om.text === "string") { entry.text = om.text; }
    return entry;
  });
  return {
    op: "flags",
    prompt_id: q.id,
    misses: q.misses.map(function (m) { return { start: m.start, end: m.end, kind: m.kind }; }),
    over_masks: over,
    restore_wrong: q.restoreWrong.map(function (tok) { return { token: tok }; }),
    checked_all: !!q.checkedAll,
    useful: q.useful
  };
}

// Masks the note (purpose "note", same prompt id) and saves this ONE prompt's flags.
async function saveChecks() {
  const q = state.q;
  if (!q.id) { return true; }
  const note = $("note-input").value;
  if (note.trim()) {
    const nres = await api({ op: "mask", text: note, prompt_id: q.id, purpose: "note", ui_lang: state.lang });
    if (!nres) { return false; }
    if (!nres.ok) {
      state.saveMsg = { key: "note_refused" };
      renderAll();
      return false;
    }
    q.notes.push(nres.masked);
    $("note-input").value = "";
  }
  const res = await api(flagsBody(q));
  if (!res) { return false; }
  if (!res.ok) {
    state.saveMsg = { key: "save_failed", vars: { code: String(res.code) } };
    renderAll();
    return false;
  }
  q.dirty = false;
  state.saveMsg = { key: "saved" };
  renderAll();
  return true;
}

function hasUnsaved() {
  const q = state.q;
  return !!(q.id && q.result && q.result.ok && (q.dirty || $("note-input").value.trim()));
}

// Takes the previous question's text off the page, not just out of sight.
function clearQuestionDom() {
  for (const id of ["masked-text", "original-text", "revealed-text", "legend-list", "miss-list",
    "overmask-list", "note-list", "step1-msg", "reveal-msg"]) {
    clear($(id));
  }
  for (const id of ["unresolved-msg", "overmask-piece", "copy-status", "save-status", "miss-msg", "overmask-msg"]) {
    $(id).textContent = "";
  }
  $("prompt-input").value = "";
  $("answer-input").value = "";
  $("note-input").value = "";
  $("miss-kind").selectedIndex = 0;
  $("overmask-confirm").checked = false;
  for (const v of ["ja", "deels", "nee"]) { $("useful-" + v).checked = false; }
  $("checked-all").checked = false;
  const sel = window.getSelection();
  if (sel) { sel.removeAllRanges(); }
}

async function newQuestion() {
  if (hasUnsaved()) {
    const ok = await saveChecks();
    if (!ok) { return; }
  }
  state.q = emptyQuestion();
  state.step1Msgs = [];
  state.revealMsgs = [];
  state.copyMsg = null;
  state.missMsg = null;
  state.saveMsg = null;
  state.overmaskIdx = null;
  state.pendingSel = null;
  clearQuestionDom();
  renderAll();
  $("prompt-input").focus();
}

async function doReset() {
  if (hasUnsaved()) { await saveChecks(); }
  const res = await api({ op: "reset" });
  if (!res) { return; }
  state.resetOpen = false;
  if (!res.ok) {
    state.step1Msgs = [refusalKey(res.code)];
    renderAll();
    return;
  }
  state.counterReset = false;
  state.q = emptyQuestion();
  state.step1Msgs = [];
  state.revealMsgs = [];
  state.copyMsg = null;
  state.missMsg = null;
  state.saveMsg = null;
  state.overmaskIdx = null;
  state.pendingSel = null;
  clearQuestionDom();
  renderAll();
  $("prompt-input").focus();
}

async function doPreview() {
  if (hasUnsaved()) {
    const ok = await saveChecks();
    if (!ok) { return; }
  }
  const res = await bundle({ action: "preview" });
  if (!res) { return; }
  if (!res.ok || !Array.isArray(res.prompts)) {
    state.bundleMsg = { key: "zip_failed", vars: { code: String(res.code || "internal") } };
    renderAll();
    return;
  }
  state.preview = res.prompts;
  state.includes = {};
  for (const item of res.prompts) { state.includes[item.id] = !!item.include && !!item.can_include; }
  state.bundleMsg = null;
  renderAll();
}

async function doSaveZip() {
  if (!state.preview) { return; }
  const include = state.preview
    .filter(function (item) { return item.can_include && state.includes[item.id]; })
    .map(function (item) { return item.id; });
  const res = await bundle({ action: "save", include: include });
  if (!res) { return; }
  if (!res.ok || typeof res.file_name !== "string") {
    state.bundleMsg = { key: "zip_failed", vars: { code: String(res.code || "internal") } };
  } else {
    state.bundleMsg = { key: "zip_saved", vars: { name: res.file_name } };
  }
  renderAll();
}

function setLang(lang) {
  if (!Object.prototype.hasOwnProperty.call(STRINGS, lang)) { return; }
  state.lang = lang;
  renderAll();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wire() {
  $("lang-en").addEventListener("click", function () { setLang("en"); });
  $("lang-nl").addEventListener("click", function () { setLang("nl"); });
  $("mask-btn").addEventListener("click", doMask);
  $("new-question-btn").addEventListener("click", newQuestion);
  $("copy-btn").addEventListener("click", doCopy);
  $("miss-btn").addEventListener("click", doMiss);
  $("original-text").addEventListener("mouseup", captureSelection);
  $("original-text").addEventListener("keyup", captureSelection);
  document.addEventListener("selectionchange", function () {
    const s = window.getSelection();
    if (s && !s.isCollapsed) { captureSelection(); }
  });
  $("overmask-btn").addEventListener("click", doOvermask);
  $("overmask-cancel").addEventListener("click", function () { state.overmaskIdx = null; renderAll(); });
  $("reveal-btn").addEventListener("click", doReveal);
  for (const v of ["ja", "deels", "nee"]) {
    $("useful-" + v).addEventListener("change", function () {
      state.q.useful = v;
      state.q.dirty = true;
    });
  }
  $("checked-all").addEventListener("change", function () {
    state.q.checkedAll = $("checked-all").checked;
    state.q.dirty = true;
  });
  $("save-checks-btn").addEventListener("click", saveChecks);
  $("reset-btn").addEventListener("click", function () { state.resetOpen = true; renderAll(); $("reset-yes").focus(); });
  $("reset-no").addEventListener("click", function () { state.resetOpen = false; renderAll(); });
  $("reset-yes").addEventListener("click", doReset);
  $("bundle-preview-btn").addEventListener("click", doPreview);
  $("bundle-save-btn").addEventListener("click", doSaveZip);
}

document.addEventListener("DOMContentLoaded", function () {
  state.pageId = makePageId();
  applyStatic();
  wire();
  loadMode();
});
