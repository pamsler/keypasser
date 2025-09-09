import { el, api, card, field, primary, secondary, actions, row3, toast } from "../ui.js";
import { shell } from "../spa.js";

export function viewSend(){
  const ta=field(el("textarea")); ta.rows=8; ta.placeholder="Passwort oder Nachricht"; ta.required=true;
  const to=field(el("input")); to.type="email"; to.placeholder="Empfänger-E-Mail (optional)";
  const acWrap = el("div","relative");
  const list = el("div","absolute z-10 mt-1 w-full rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 shadow hidden");
  acWrap.append(to, list);
  let acTimer=null;
  function hideList(){ list.classList.add("hidden"); list.innerHTML=""; }
  function cleanExtMail(s){
    const m = String(s||"").match(/^(.+?)#EXT#@/i);
    if(!m) return s;
    const pre = m[1];
    const cut = pre.lastIndexOf("_");       
    if (cut <= 0) return s;
    const local  = pre.slice(0, cut);        
    const domain = pre.slice(cut + 1).replace(/_/g, "."); 
    return `${local}@${domain}`;
  }
  async function queryRecipients(q){
    try{
      const r = await api(`/api/recipients?q=${encodeURIComponent(q)}`);
      if(!Array.isArray(r)) return [];
      return r.map(x=>({
        name: x.name,
        email: cleanExtMail(x.email)
      }));
    }catch{ return []; }
  }
  to.addEventListener("input", ()=>{
    clearTimeout(acTimer);
    const q = to.value.trim();
    if(q.length<2){ hideList(); return; }
    acTimer=setTimeout(async ()=>{
      const items = await queryRecipients(q);
      if(!items.length){ hideList(); return; }
      list.innerHTML="";
      items.forEach(it=>{
        const row = el("button","w-full text-left px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-800");
        row.type="button";
        row.innerHTML = `<div class="text-sm">${it.name||it.email}</div><div class="text-xs text-gray-500">${it.email}</div>`;
        row.onclick = ()=>{ to.value = it.email; hideList(); };
        list.append(row);
      });
      list.classList.remove("hidden");
    }, 180);
  });
  document.addEventListener("click",(ev)=>{ if(!acWrap.contains(ev.target)) hideList(); });
  const subject=field(el("input")); subject.value="Sicherer Zugriff";
  const ttl=field(el("input")); ttl.type="number"; ttl.min="1"; ttl.max="14400"; ttl.value="60";
  const msg=field(el("input")); msg.value="Klicke auf den Link, um das Secret einmalig zu öffnen.";
  const gen=primary("Nur Link erzeugen"); const send=secondary("Erzeugen + E-Mail senden");
  const resWrap=el("div","hidden mt-4"); const code=el("code","block p-3 rounded-xl border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 break-all"); resWrap.append(el("p","mb-2","URL:"),code);

  gen.onclick=async e=>{ e.preventDefault(); try{
    const r=await api("/api/secrets",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({plaintext:ta.value,ttl_minutes:Number(ttl.value||60)})});
    code.textContent=r.url; resWrap.classList.remove("hidden");
  }catch(err){ toast("Fehler: "+err.message);} };
  send.onclick=async e=>{ e.preventDefault(); try{
    const r=await api("/api/secrets/send",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({plaintext:ta.value,ttl_minutes:Number(ttl.value||60),to:to.value,subject:subject.value,message:msg.value})});
    code.textContent=r.url; resWrap.classList.remove("hidden"); toast("E-Mail gesendet.");
  }catch(err){ toast("Fehler: "+err.message);} };

  const content=el("div","space-y-4");
  content.append(ta,row3(acWrap,subject,ttl),msg,actions(gen,send),resWrap);
  return shell(card("Secret erstellen",content),true);
}
