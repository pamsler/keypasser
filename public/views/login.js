import { el, api, card, field, primary, secondary, toast, fetchBranding, setFavicon } from "../ui.js";
import { shell } from "../spa.js";

export async function viewLogin(){
  const logo = el("div","flex flex-col items-center gap-2 mb-4", `
    <div data-logo-holder class="h-[4.375rem] w-[4.375rem] rounded-full border border-gray-300/70 dark:border-gray-600/60
                bg-white/70 dark:bg-gray-900/60 flex items-center justify-center">
      <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none">
        <path d="M7.5 10a4.5 4.5 0 1 1 7.7 3.2l-3.7 3.7H9v2H7v-2H5v-2h2l4.1-4.1A4.5 4.5 0 0 1 7.5 10Z"
              class="stroke-indigo-500" stroke-width="1.6" stroke="currentColor"/>
        <path d="M14.2 5.8a3 3 0 1 1 4.2 4.2" class="stroke-indigo-500/80" stroke-width="1.4" stroke="currentColor"/>
      </svg>
    </div>
    <div class="text-center">
      <div class="text-lg font-semibold">KeyPasser</div>
      <div class="text-xs text-gray-500 dark:text-gray-400">Sichere Einmal-Links für Passwörter & Secrets</div>
    </div>
  `);

  (async ()=>{
    const url = await fetchBranding();
    if(url){
      const holder = logo.querySelector('[data-logo-holder]');
      holder.innerHTML = `<img src="${url}" class="h-[4.375rem] w-[4.375rem] rounded-full object-cover" alt="Logo">`;
      setFavicon(url);
    }
  })();

  const form = el("form","space-y-4 w-full max-w-md mx-auto");
  const loginWrap = el("div","space-y-4");
  const email = field(el("input")); email.type="email"; email.placeholder="E-Mail"; email.autofocus=true; email.required=true;
  const pw    = field(el("input")); pw.type="password"; pw.placeholder="Passwort"; pw.required=true;
  const btn   = primary("Anmelden"); btn.type="submit"; btn.classList.add("w-full");
  loginWrap.append(email, pw, btn);
  const mfaWrap = el("div","space-y-4 hidden");
  const otp = field(el("input"));
  otp.type="text"; otp.inputMode="numeric"; otp.placeholder="6-stelliger MFA-Code";
  otp.classList.add("text-center","tracking-widest");
  const confirmMfa = primary("OK");   confirmMfa.type="button";
  const backMfa    = secondary("Abbrechen"); backMfa.type="button";
  mfaWrap.append(
    el("div","text-sm text-center","Bitte 6-stelligen MFA-Code eingeben:"),
    otp
  );
  const mfaBtnRow = el("div","flex gap-2");
  mfaBtnRow.append(confirmMfa, backMfa);
  mfaWrap.append(mfaBtnRow);
  let pendingCreds = null;
  let ssoBtn=null;
  try{ const m=await api("/api/auth"); if(m?.login_mode!=="local"){
    ssoBtn = secondary("Mit Microsoft anmelden");
    ssoBtn.type = "button";
    ssoBtn.classList.add("w-full","flex","items-center","justify-center","gap-2");
    ssoBtn.classList.remove("border","border-gray-300","dark:border-gray-700",
                            "hover:bg-gray-100","dark:hover:bg-gray-800");
    ssoBtn.classList.add("bg-blue-600","text-white","hover:bg-blue-500",
                         "border-transparent","focus:ring-2","focus:ring-blue-500/50");
    ssoBtn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23" width="16" height="16">
        <rect x="1" y="1" width="10" height="10" fill="#f25022"/>
        <rect x="12" y="1" width="10" height="10" fill="#7fba00"/>
        <rect x="1" y="12" width="10" height="10" fill="#00a4ef"/>
        <rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
      </svg>
      <span>Mit Microsoft anmelden</span>`;
    ssoBtn.setAttribute("aria-label","Mit Microsoft anmelden");
    ssoBtn.onclick=(e)=>{ e.preventDefault(); window.location.href="/auth/login"; };
  }}catch{}

  form.append(logo, loginWrap, mfaWrap);
  let sepEl=null;
  if(ssoBtn){
    sepEl = el("div","text-center text-[11px] uppercase tracking-wide text-gray-500 dark:text-gray-400","oder");
    form.append(sepEl);
    form.append(ssoBtn);
  }

  form.onsubmit = async (e)=>{
    e.preventDefault();
    btn.disabled = true;
    try{
      await api("/api/login",{
        method:"POST",
        headers:{ "content-type":"application/json" },
        body: JSON.stringify({ email: email.value, password: pw.value })
      });
      location.hash="#/dashboard";
    }catch(err){
      if (String(err.message||"").includes("MFA_REQUIRED")) {
        pendingCreds = { email: email.value, password: pw.value };
        loginWrap.classList.add("hidden");
        mfaWrap.classList.remove("hidden");
        if (ssoBtn) ssoBtn.classList.add("hidden");
        if (sepEl)  sepEl.classList.add("hidden");
        btn.disabled = false;
        otp.focus();
        return;
      }
      toast("Login fehlgeschlagen");
      btn.disabled = false;
    }
  };
  
  confirmMfa.onclick = async ()=>{
    if(!pendingCreds) return;
    confirmMfa.disabled = true;
    try{
      await api("/api/login",{
        method:"POST",
        headers:{ "content-type":"application/json" },
        body: JSON.stringify({ ...pendingCreds, otp: otp.value })
      });
      location.hash="#/dashboard";
    }catch(err){
      toast("MFA ungültig");
      confirmMfa.disabled = false;
      otp.focus();
    }
  };
  backMfa.onclick = ()=>{
    pendingCreds = null;
    otp.value = "";
    mfaWrap.classList.add("hidden");
    loginWrap.classList.remove("hidden");
    if (ssoBtn) ssoBtn.classList.remove("hidden");
    if (sepEl)  sepEl.classList.remove("hidden");
    btn.disabled = false;
    email.focus();
  };

  const box = card("", form);
  const container = el("div","flex items-start md:items-center justify-center pt-16 md:pt-28");
  container.append(box);
  return await shell(container, false);
}
