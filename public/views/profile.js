import { el, api, card, field, primary, secondary, toast } from "../ui.js";
import { shell } from "../spa.js";

export async function viewProfile(){
  const wrap = el("div","space-y-6");

  const info = await api("/api/profile");
  const fmt = (d)=> d ? new Date(d).toLocaleString("de-CH",{ timeZone:"Europe/Zurich"}) : "—";
  const head = el("div","grid md:grid-cols-2 gap-3");
  head.append(
    card("Profil", el("div","space-y-2",`
      <div><span class="text-xs text-gray-500">E-Mail</span><div class="font-medium">${info.email}</div></div>
      <div class="grid grid-cols-2 gap-3">
        <div><span class="text-xs text-gray-500">Erstellt</span><div>${fmt(info.created_at)}</div></div>
        <div><span class="text-xs text-gray-500">Letzter Login</span><div>${fmt(info.last_login_at)}</div></div>
        <div><span class="text-xs text-gray-500">PW geändert</span><div>${fmt(info.password_changed_at)}</div></div>
        <div><span class="text-xs text-gray-500">Gesendete E-Mails</span><div>${info.sent_count}</div></div>
      </div>
    `))
  );
  wrap.append(head);

  const tabsBar = el("div","mb-6 border-b border-gray-200 dark:border-gray-700");
  const tabs = el("div","flex gap-6 -mb-px");
  const baseTab = "pb-2 text-sm font-medium border-b-2 border-transparent " +
                  "text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-white";
  const activeTab = "text-indigo-600 dark:text-indigo-400 border-indigo-500";
  const kontoTabBtn = el("button", baseTab, "Konto");
  const secTabBtn   = el("button", baseTab, "Sicherheit");
  function select(btn){
    [kontoTabBtn,secTabBtn].forEach(b=> b.className = baseTab);
    btn.className = baseTab + " " + activeTab;
  }
  tabs.append(kontoTabBtn, secTabBtn);
  tabsBar.append(tabs);
  wrap.append(tabsBar);

  const viewsWrap = el("div","space-y-6");
  wrap.append(viewsWrap);

  function showTab(which){
    kontoView.classList.toggle("hidden", which!=="konto");
    secView.classList.toggle("hidden", which!=="sec");
    select(which==="konto" ? kontoTabBtn : secTabBtn);
  }
  kontoTabBtn.onclick = ()=> showTab("konto");
  secTabBtn.onclick   = ()=> showTab("sec");

  const kontoView = el("div","space-y-6");

  const cur = field(el("input")); cur.type="password"; cur.placeholder="Aktuelles Passwort";
  const nw  = field(el("input"));  nw.type="password";  nw.placeholder="Neues Passwort";
  const savePw = primary("Passwort ändern");
  savePw.onclick = async ()=>{
    try{
      await api("/api/profile/password",{method:"POST",headers:{"content-type":"application/json"},
        body: JSON.stringify({ current_password: cur.value, new_password: nw.value })});
      cur.value=""; nw.value=""; toast("Passwort aktualisiert");
    }catch(e){ toast(e.message); }
  };
  const pwBox = el("div","space-y-3"); pwBox.append(cur, nw, savePw);
  kontoView.append(card("Passwort ändern", pwBox));

  const mail = field(el("input")); mail.type="email"; mail.placeholder="Neue E-Mail"; mail.value = info.email||"";
  const saveMail = primary("E-Mail ändern");
  saveMail.onclick = async ()=>{
    try{
      await api("/api/profile/email",{method:"POST",headers:{"content-type":"application/json"},
        body: JSON.stringify({ email: mail.value })});
      toast("E-Mail aktualisiert");
    }catch(e){ toast(e.message); }
  };
  const mailBox = el("div","space-y-3"); mailBox.append(mail, saveMail);
  kontoView.append(card("E-Mail ändern", mailBox));

  const secView = el("div","space-y-6");

  const mfaBox = el("div","space-y-4");
  const status = el("div","text-sm",
    info.mfa_enabled ? "MFA ist AKTIV." : "MFA ist deaktiviert."
  );
  const startBtn   = primary("MFA aktivieren");
  const disableBtn = secondary("MFA deaktivieren");

  const setupArea = el("div","space-y-3 hidden");
  const qrImg = el("img","w-44 h-44 rounded-xl border border-white/10 mx-auto");
  const secretRow = el("div","text-xs text-center text-gray-400");
  const otpInput = field(el("input"));
  otpInput.type="text"; otpInput.inputMode="numeric"; otpInput.placeholder="6-stelliger Code";
  otpInput.classList.add("text-center","tracking-widest");
  const verifyBtn = primary("Bestätigen");

  const codesWrap = el("div","hidden");
  const codesHeader = el("div","text-sm mb-1");
  const codesPre = el("pre","text-xs bg-white/5 p-3 rounded-xl border border-white/10");
  const codesActions = el("div","mt-2 flex gap-2");
  const copyBtn = secondary("In Zwischenablage");
  const dlBtn   = secondary("Als Datei speichern");
  codesActions.append(copyBtn, dlBtn);
  codesWrap.append(codesHeader, codesPre, codesActions);

  function setMfaButtons(enabled){
    startBtn.disabled = enabled;
    disableBtn.disabled = !enabled;
  }
  setMfaButtons(info.mfa_enabled);

  async function refreshProfile(){
    const p = await api("/api/profile");
    status.textContent = p.mfa_enabled ? "MFA ist AKTIV." : "MFA ist deaktiviert.";
    setMfaButtons(p.mfa_enabled);
    if (p.mfa_enabled && !codesWrap.dataset.showing){
      setupArea.classList.add("hidden");
      codesWrap.classList.add("hidden");
    }
  }

  startBtn.onclick = async ()=>{
    try{
      const { qr, secret } = await api("/api/mfa/start",{method:"POST"});
      qrImg.src = qr;
      secretRow.innerHTML = `Manuell hinzufügen:
        <code class="px-2 py-1 rounded bg-white/10">${secret}</code>`;
      setupArea.classList.remove("hidden");
      codesWrap.classList.add("hidden");
      delete codesWrap.dataset.showing;
      otpInput.value=""; otpInput.focus();
    }catch(e){ toast(e.message); }
  };

  verifyBtn.onclick = async ()=>{
    try{
      const r = await api("/api/mfa/verify",{
        method:"POST", headers:{"content-type":"application/json"},
        body: JSON.stringify({ otp: otpInput.value })
      });
      codesPre.textContent = (r.backup_codes||[]).join("\n");
      codesHeader.textContent = "Backup-Codes – sicher speichern!";
      codesWrap.classList.remove("hidden");
      codesWrap.dataset.showing = "1";
      setupArea.classList.add("hidden");
      status.textContent = "MFA ist AKTIV.";
      setMfaButtons(true);
      toast("MFA aktiviert");
    }catch(e){ toast(e.message); }
  };

  copyBtn.onclick = async ()=>{
    try{
      await navigator.clipboard.writeText(codesPre.textContent||"");
      toast("Backup-Codes kopiert");
    }catch{ toast("Kopieren fehlgeschlagen"); }
  };
  dlBtn.onclick = ()=>{
    const blob = new Blob([codesPre.textContent||""], { type:"text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "backup-codes.txt"; a.click();
    URL.revokeObjectURL(url);
  };

  disableBtn.onclick = async ()=>{
    try{
      await api("/api/mfa/disable",{method:"POST"});
      toast("MFA deaktiviert");
      delete codesWrap.dataset.showing;
      await refreshProfile();
    }catch(e){ toast(e.message); }
  };

  const qrHolder = el("div","flex justify-center"); qrHolder.append(qrImg);
  setupArea.append(
    el("div","text-sm text-center","Scanne den QR-Code mit deiner Authenticator-App:"),
    qrHolder,
    secretRow,
    otpInput,
    verifyBtn
  );

  const btnRow = el("div","flex gap-2"); btnRow.append(startBtn, disableBtn);
  mfaBox.append(status, btnRow, setupArea, codesWrap);
  secView.append(card("Mehrfaktor-Authentifizierung (TOTP)", mfaBox));

  const spacer = el("div");
  viewsWrap.append(kontoView, secView, spacer);
  showTab("konto");

  return shell(wrap, true);
}
