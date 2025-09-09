import { el, api, card, field, primary, secondary, toast } from "../ui.js";
import { shell } from "../spa.js";

export async function viewUsers(){
  const wrap = el("div","space-y-6");
  let isAdmin = false;
  try { const me = await api("/api/me"); isAdmin = !!me?.is_admin; } catch {}
  if (!isAdmin) {
    const msg = el("div","space-y-2",
      `<p class="text-sm text-gray-600 dark:text-gray-300">
         Benutzerverwaltung ist nur für Administratoren verfügbar.
       </p>`
    );
    return shell(card("Benutzer", msg), true);
  }
  let activeTab = "local";
  let allUsers = [];

  function modalBase(child){
    const overlay = el("div","fixed inset-0 z-50 flex items-center justify-center");
    const scrim   = el("div","absolute inset-0 bg-black/60");
    const boxWrap = el("div","relative w-full max-w-md px-4");
    const box     = el("div","backdrop-blur bg-slate-800/90 text-white border border-white/10 rounded-2xl shadow-xl p-5");
    box.append(child);
    boxWrap.append(box);
    overlay.append(scrim, boxWrap);
    document.body.appendChild(overlay);
    const close = ()=>{ overlay.remove(); };
    scrim.addEventListener("click", close);
    return { overlay, close, box };
  }

  function confirmModal({title="Bestätigen", message, okText="OK", cancelText="Abbrechen"}){
    return new Promise(resolve=>{
      const inner = el("div","space-y-4");
      const head  = el("div","flex items-center justify-between");
      head.append(el("h3","text-base font-semibold",title));
      const x = el("button","p-2 rounded-full hover:bg-white/10","×");
      head.append(x);
      const msg = el("p","text-sm text-slate-300", message||"");
      const act = el("div","flex items-center justify-end gap-2");
      const b1  = el("button","px-4 py-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-500", okText);
      const b2  = el("button","px-4 py-2 rounded-xl border border-white/15 hover:bg-white/10", cancelText);
      act.append(b2,b1); inner.append(head,msg,act);
      const { close } = modalBase(inner);
      const done = v=>{ close(); resolve(v); };
      x.onclick=()=>done(false); b2.onclick=()=>done(false); b1.onclick=()=>done(true);
      document.addEventListener("keydown",(e)=>{ if(e.key==="Escape") done(false); },{once:true});
    });
  }

  function promptModal({title, label, okText="OK", cancelText="Abbrechen", type="password", placeholder=""}){
    return new Promise(resolve=>{
      const inner = el("div","space-y-4");
      const head  = el("div","flex items-center justify-between");
      head.append(el("h3","text-base font-semibold",title||""));
      const x = el("button","p-2 rounded-full hover:bg-white/10","×");
      head.append(x);
      const lbl = el("label","text-sm",label||"");
      const inp = field(el("input")); inp.type=type; inp.placeholder=placeholder; inp.classList.add("bg-slate-900");
      const act = el("div","flex items-center justify-end gap-2");
      const b1  = el("button","px-4 py-2 rounded-xl bg-emerald-600 text-white hover:bg-emerald-500", okText);
      const b2  = el("button","px-4 py-2 rounded-xl border border-white/15 hover:bg-white/10", cancelText);
      act.append(b2,b1); inner.append(head,lbl,inp,act);
      const { close } = modalBase(inner);
      setTimeout(()=>inp.focus(),0);
      const done=v=>{ close(); resolve(v); };
      x.onclick=()=>done(null); b2.onclick=()=>done(null);
      b1.onclick=()=>done(inp.value||"");
      inp.addEventListener("keydown",(e)=>{ if(e.key==="Enter") b1.click(); });
      document.addEventListener("keydown",(e)=>{ if(e.key==="Escape") done(null); },{once:true});
    });
  }

  /* ========== Tabs (mobil scrollbar) ========== */
  const tabsBar = el("div","w-full overflow-x-auto");
  const tabs    = el("nav","mx-auto max-w-[1200px] px-1 flex whitespace-nowrap gap-2");
  const tabBtn  = (t)=> el("button","px-4 py-2 rounded-xl text-sm border border-white/10 text-slate-300 hover:text-white hover:bg-white/10 transition",t);
  const tLocal  = tabBtn("Lokal");
  const tMs     = tabBtn("Microsoft");
  tabs.append(tLocal,tMs); tabsBar.append(tabs);

  function setActiveTab(tab){
    activeTab = tab;
    [tLocal,tMs].forEach(b=>b.classList.remove("bg-white/10","text-white","ring-2","ring-emerald-500/40"));
    const on = tab==="local" ? tLocal : tMs;
    on.classList.add("bg-white/10","text-white","ring-2","ring-emerald-500/40");
    createCard.style.display = tab==="local" ? "" : "none";
    renderList();
  }

  function updateCounts(){
    const nL = allUsers.filter(u=>!u.is_sso).length;
    const nM = allUsers.filter(u=> u.is_sso).length;
    const chip = (n)=> `<span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-white/10 border border-white/10">${n}</span>`;
    tLocal.innerHTML = `Lokal ${chip(nL)}`;
    tMs.innerHTML    = `Microsoft ${chip(nM)}`;
  }

  tLocal.onclick = ()=>setActiveTab("local");
  tMs.onclick    = ()=>setActiveTab("ms");

  /* ========== Liste ========== */
  const list = el("div","space-y-3");

  const badge = (txt, kind)=>{
    const s = el("span","px-2 py-0.5 rounded-full text-xs font-bold border", txt);
    if(kind==="ms") s.className += " bg-blue-500/15 text-blue-300 border-blue-500/30";
    else            s.className += " bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    return s;
  };

  async function resetPwd(u){
    const pw = await promptModal({
      title: location.hostname,
      label: `Neues Passwort für ${u.email}:`,
      type: "password",
      okText: "OK"
    });
    if(!pw) return;
    try{
      await api(`/api/users/${u.id}/password`,{
        method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({password:pw})
      });
      toast("Passwort geändert");
    }catch(e){ toast("Fehler: "+e.message); }
  }

  async function delUser(u){
    const ok = await confirmModal({
      title: location.hostname,
      message: `Benutzer ${u.email} löschen?`,
      okText: "OK", cancelText: "Abbrechen"
    });
    if(!ok) return;
    try{ await api(`/api/users/${u.id}`,{method:"DELETE"}); await load(); }
    catch(e){ toast("Fehler: "+e.message); }
  }

  function renderList(){
    list.innerHTML = "";
    const rows = allUsers.filter(u => activeTab==="local" ? !u.is_sso : u.is_sso);
    rows.forEach(u=>{
      const row = el("div","grid grid-cols-1 md:grid-cols-[1fr,auto] items-center gap-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3");
      const left = el("div","min-w-0 flex items-center gap-3");
      const email = el("div","text-sm md:text-base break-words", u.email);
      left.append(email, u.is_sso ? badge("Microsoft (SSO)","ms") : badge("Lokal","local"));
      row.append(left);

      const actions = el("div","flex flex-col sm:flex-row gap-2 sm:justify-end");
      if(!u.is_sso){
        const reset = secondary("Passwort zurücksetzen");
        reset.classList.remove("border","border-gray-300","dark:border-gray-700","hover:bg-gray-100","dark:hover:bg-gray-800");
        reset.classList.add("w-full","sm:w-auto","bg-blue-600","text-white","hover:bg-blue-500","border-transparent");
        reset.onclick = ()=>resetPwd(u);

        const del = secondary("Löschen");
        del.classList.remove("border","border-gray-300","dark:border-gray-700","hover:bg-gray-100","dark:hover:bg-gray-800");
        del.classList.add("w-full","sm:w-auto","bg-red-600","text-white","hover:bg-red-500","border-transparent");
        del.onclick = ()=>delUser(u);

        actions.append(reset, del);
      } else {
        const info = secondary("Löschen");
        info.disabled = true;
        info.title = "SSO-Benutzer werden in Entra verwaltet";
        info.classList.remove("hover:bg-gray-100","dark:hover:bg-gray-800");
        info.classList.add("w-full","sm:w-auto","opacity-60","cursor-not-allowed");
        actions.append(info);
      }
      row.append(actions);
      list.append(row);
    });
  }

  async function load(){
    try{
      allUsers = await api("/api/users");
    } catch(e){
      if (e?.status===403) {
        list.innerHTML = `<div class="text-sm text-gray-500">Kein Admin-Zugriff.</div>`;
        return;
      }
      throw e;
    }
    updateCounts();
    renderList();
  }
  await load();

  const em = field(el("input")); em.type="email"; em.placeholder="E-Mail";
  const pw = field(el("input")); pw.type="password"; pw.placeholder="Passwort";
  const save = primary("Benutzer speichern");
  save.onclick = async ()=>{
    try{
      const okMail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em.value||"");
      if (!okMail) return toast("Ungültige E-Mail");
      if (!pw.value) return toast("Passwort fehlt");
      await api("/api/users",{
        method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({email:em.value,password:pw.value})
      });
      em.value=""; pw.value=""; toast("Gespeichert"); await load();
    }catch(e){
      if (e?.status===403) return toast("Kein Admin-Zugriff");
      toast("Fehler: "+e.message);
    }
  };
  const createBox  = el("div","space-y-3");
  const formGrid   = el("div","grid grid-cols-1 sm:grid-cols-2 gap-3");
  formGrid.append(em, pw);
  save.classList.add("w-full","sm:w-auto");
  createBox.append(formGrid, save);
  const createCard = card("Benutzer anlegen", createBox);

  /* ========== Layout zusammensetzen ========== */
  const usersArea = el("div","space-y-4");
  usersArea.append(tabsBar, list, createCard);
  wrap.append(card("Benutzer", usersArea));

  setActiveTab("local");
  return shell(wrap, true);
}
