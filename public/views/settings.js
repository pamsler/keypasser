import { el, api, card, field, primary, secondary, toast } from "../ui.js";
import { shell } from "../spa.js";

export function viewSettings(){
  let isAdmin = false;
  const guard = async ()=>{
    try {
      const me = await api("/api/me");
      isAdmin = !!me?.is_admin;
    } catch {}
  };
  async function notAllowed() {
    const msg = el("div","space-y-2",
      `<p class="text-sm text-gray-600 dark:text-gray-300">
         Diese Seite ist nur für Administratoren verfügbar.
       </p>`
    );
    return shell(card("Einstellungen", msg), true);
  }

  async function ensureAdminOrRender() {
    await guard();
    if (!isAdmin) return await notAllowed();
  }
  if (!("KeyPasserAdminGate" in window)) 
  const tabsBar = el("div","mb-6 border-b border-gray-200 dark:border-gray-700");
  const tabs = el("div","flex gap-6 -mb-px");
  const baseTab = "pb-2 text-sm font-medium border-b-2 border-transparent " +
                  "text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-white";
  const activeTab = "text-indigo-600 dark:text-indigo-400 border-indigo-500";
  const btnSmtp  = el("button", baseTab,  "SMTP");
  const btnLogo  = el("button", baseTab,  "Logo");
  const btnAzure = el("button", baseTab,  "Azure / SSO");
  function select(btn){
    [btnSmtp,btnLogo,btnAzure].forEach(b=>{
      b.className = baseTab;             
    });
    btn.className = baseTab + " " + activeTab;
  }
  tabs.append(btnSmtp, btnLogo, btnAzure);
  tabsBar.append(tabs);

  const labeled = (text, node) => {
    const wrap = el("div","space-y-1");
    const id = "f_"+Math.random().toString(36).slice(2,8);
    node.id = id;
    const lab = el("label","text-sm text-gray-500 dark:text-gray-400", text);
    lab.setAttribute("for", id);
    wrap.append(lab, node);
    return wrap;
  };

  const host=field(el("input")), port=field(el("input")), secure=el("select","w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900"),
        user=field(el("input")), pass=field(el("input")), fromName=field(el("input")), fromEmail=field(el("input"));
  port.type="number"; port.value="587";
  pass.type="password";
  secure.name="secure"; secure.innerHTML='<option value="false">STARTTLS :587</option><option value="true">SMTPS :465</option>';
  const reqLbl=el("label","inline-flex items-center gap-2 select-none cursor-pointer");
  const req=el("input");
  req.type="checkbox"; req.checked=true;
  const reqId="req_tls_"+Math.random().toString(36).slice(2,8);
  req.id=reqId; reqLbl.setAttribute("for", reqId);
  reqLbl.append(req, el("span","", "TLS erzwingen"));
  const save=primary("Speichern");

  save.onclick=async ()=>{ try{
    const v={host:host.value,port:Number(port.value),secure:secure.value==="true",from_name:fromName.value,from_email:fromEmail.value,require_tls:req.checked};
    if (user.value) v.user = user.value;
    if (pass.value) v.pass = pass.value;
    await api("/api/smtp",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(v)});
    toast("SMTP gespeichert.");
  }catch(err){
    if (err?.status===403) return toast("Kein Admin-Zugriff");
    toast("Fehler: "+err.message);
  } };
  (async()=>{ 
    const early = await ensureAdminOrRender(); if (early) return;
    try{
    const cur=await api("/api/smtp");
    if(cur){
      host.value=cur.host||"";
      port.value=cur.port||587;
      secure.value=String(cur.secure);
      fromName.value=cur.from_name||"";
      fromEmail.value=cur.from_email||"";
      req.checked=!!cur.require_tls;
      if (cur.has_creds){
        user.placeholder="(Benutzer vorhanden)";
        pass.placeholder="(Passwort gespeichert – leer lassen, wenn unverändert)";
      }
    }}
  catch(e){
    if (e?.status===403) toast("Kein Admin-Zugriff auf SMTP");
  } })();

  const grid=el("div","grid grid-cols-1 md:grid-cols-2 gap-4");
  host.placeholder="smtp.example.com";
  user.placeholder="SMTP-Benutzer";
  fromName.placeholder="z. B. KeyPasser";
  fromEmail.placeholder="noreply@example.com";
  grid.append(
    labeled("Host", host),
    labeled("Port", port),
    labeled("Verschlüsselung", secure),
    labeled("Benutzer", user),
    labeled("Passwort", pass),
    labeled("Absendername", fromName),
    labeled("Absenderadresse", fromEmail),
    reqLbl,
    el("div","md:col-span-2","").appendChild(save).parentNode
  );

  const file=el("input"); file.type="file"; file.accept="image/*";
  const up=secondary("Logo hochladen"); const prev=el("div","mt-2");
  up.onclick=async ()=>{ 
    try{ 
      const fd=new FormData(); 
      if(!file.files[0]) return toast("Datei wählen");
      fd.append("logo",file.files[0]); 
      await api("/api/settings/logo",{method:"POST",body:fd}); 
      const m=await api("/api/settings"); 
      if(m?.logo_url) prev.innerHTML=`<img src="${m.logo_url}" class="h-[3.75rem]">`; 
      file.value="";                    
      toast("Logo aktualisiert"); 
      window.dispatchEvent(new Event("branding-refresh")); 
    }catch(err){ 
      if (err?.status===403) return toast("Kein Admin-Zugriff"); 
      console.error(err);
      toast("Upload fehlgeschlagen: "+(err?.message||"Unbekannter Fehler"));
    } 
  };
  (async()=>{ try{ const m=await api("/api/settings"); if(m?.logo_url) prev.innerHTML=`<img src="${m.logo_url}" class="h-[3.75rem]">`; }catch{} })();

  const logo=el("div","space-y-3"); logo.append(file,up,prev);

  const tenant = field(el("input"));
  const clientId = field(el("input"));
  const clientSecret = field(el("input"));
  clientSecret.type = "password";
  const secretWrap = el("div","relative");
  clientSecret.classList.add("pr-10");
  const toggleBtn = el(
    "button",
    "absolute right-2 top-1/2 -translate-y-1/2 w-6 h-6 rounded text-sm border " +
    "border-gray-300 dark:border-gray-700 hover:bg-gray-100 dark:hover:bg-gray-800",
    "+"
  );
  toggleBtn.type = "button";
  toggleBtn.onclick = ()=>{
    const show = clientSecret.type === "password";
    clientSecret.type = show ? "text" : "password";
    toggleBtn.textContent = show ? "−" : "+";
  };
  secretWrap.append(clientSecret, toggleBtn);
  const redirect = field(el("input"));
  const allowedGroup = field(el("input"));
  const adminGroup   = field(el("input"));
  const loginMode = el("select","w-full px-3 py-2 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900");
  loginMode.innerHTML = `<option value="local">Nur lokal</option><option value="sso">Nur SSO</option><option value="both">Lokal + SSO</option>`;
  const saveAzure = primary("Azure/SSO speichern");
  saveAzure.onclick = async ()=>{
    try{
      const payload = {
        tenant_id: tenant.value,
        client_id: clientId.value,
        redirect_uri: redirect.value,
        allowed_group: allowedGroup.value,
        admin_group: adminGroup.value
      };
      if (clientSecret.value && clientSecret.value !== "********") {
        payload.client_secret = clientSecret.value;
      }
      await api("/api/azure",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});
      await api("/api/auth",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({login_mode:loginMode.value})});
      toast("Azure/SSO gespeichert");
      clientSecret.value = "********";
      clientSecret.type = "password";
      toggleBtn.textContent = "+";
    }catch(e){
      if (e?.status===403) return toast("Kein Admin-Zugriff");
      toast("Fehler: "+e.message);
    }
  };
  (async ()=>{ try{
    const a = await api("/api/azure"); 
    if(a){
      tenant.value = a.tenant_id || "";
      clientId.value = a.client_id || "";
      redirect.value = a.redirect_uri || "";
      allowedGroup.value = a.allowed_group || "";
      adminGroup.value = a.admin_group || "";
      clientSecret.value = "********";
    }
    const m = await api("/api/auth"); if(m?.login_mode) loginMode.value=m.login_mode;
  }catch(e){
    if (e?.status===403) toast("Kein Admin-Zugriff auf Azure/SSO");
  } })();
  const azGrid = el("div","grid grid-cols-1 md:grid-cols-2 gap-4");
  azGrid.append(
    labeled("Tenant ID", tenant),
    labeled("Client ID", clientId),
    labeled("Client Secret", secretWrap),
    labeled("Redirect URI", redirect),
    labeled("Allowed Group ID (GUID, optional)", allowedGroup),
    labeled("Admin Group ID (GUID, optional)", adminGroup),
    labeled("Login-Modus", loginMode),
    el("div","md:col-span-2","").appendChild(saveAzure).parentNode
  );

  const container = el("div","space-y-4");
  container.append(tabsBar);
  const box = el("div","space-y-8"); container.append(box);
  const show = (name)=>{
    box.innerHTML="";
    if(name==="smtp") box.append(card("SMTP",grid));
    if(name==="logo") box.append(card("Logo",logo));
    if(name==="azure") box.append(card("Azure / SSO", azGrid));
  };
  btnSmtp.onclick=()=>{select(btnSmtp);show("smtp");};
  btnLogo.onclick=()=>{select(btnLogo);show("logo");};
  btnAzure.onclick=()=>{select(btnAzure);show("azure");};
  return (async()=>{ const early = await ensureAdminOrRender(); if (early) return early;
    select(btnSmtp); show("smtp");
    tabs.append(btnSmtp,btnLogo,btnAzure);
    return shell(container, true);
  })();
}
